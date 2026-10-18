namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// How many entries `poll(2)` takes: its screen against the process's
/// `RLIMIT_NOFILE` soft limit, held to `docs/probes/poll-entry-count`, which
/// measured it on Linux 6.18.5 aarch64 (as root and as uid 1000), Linux
/// 6.12.113 x86-64 (as root, booted under QEMU) and Darwin 27.0.0 (as uid 501,
/// and as root with its section D measured as root and as uid 501 in one run).
///
/// The library does not know the process's soft limit, only that it is at
/// least `SimulatedUnixPlatform.descriptorBound`, so it answers a count only
/// where every limit a process can have gives the same answer, and refuses the
/// rest.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPollEntryCount =

    let private pollIn : int16 = 0x0001s
    let private pollOut : int16 = 0x0004s
    let private thread : int = 1

    /// One run of the probe: the flavour it measured, whether it ran as root,
    /// and what it printed.
    type private Run =
        {
            Name : string
            Platform : SimulatedUnixPlatform
            Privileged : bool
            Lines : string list
        }

    let private lines (resource : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.%s{resource}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private runs : Run list =
        [
            {
                Name = "linux-aarch64-uid0"
                Platform = SimulatedUnixPlatform.linuxArm64
                Privileged = true
                Lines = lines "poll-entry-count.linux-aarch64-uid0.txt"
            }
            {
                Name = "linux-aarch64-uid1000"
                Platform = SimulatedUnixPlatform.linuxArm64
                Privileged = false
                Lines = lines "poll-entry-count.linux-aarch64-uid1000.txt"
            }
            {
                Name = "linux-x86_64-uid0"
                Platform = SimulatedUnixPlatform.linuxX64
                Privileged = true
                Lines = lines "poll-entry-count.linux-x86_64-uid0.txt"
            }
            {
                Name = "darwin-uid501"
                Platform = SimulatedUnixPlatform.macOsArm64
                Privileged = false
                Lines = lines "poll-entry-count.darwin-uid501.txt"
            }
            {
                Name = "darwin-uid0"
                Platform = SimulatedUnixPlatform.macOsArm64
                Privileged = true
                Lines = lines "poll-entry-count.darwin-uid0.txt"
            }
        ]

    /// One `poll` the probe made: by root or not, under which soft limit, of
    /// how many entries, and what it answered.
    type private Row =
        {
            Section : string
            Privileged : bool
            Label : string
            SoftLimit : int64
            Count : int64
            Timeout : int
            Rv : int
            Errno : string
            Revents0 : string
        }

    let private rowPattern =
        Regex @"^([ABCD]) (\S+) nfds=(\d+) timeout=(-?\d+) rv=(-?\d+) errno=(.+) revents0=(\S+)$"

    let private limitSet = Regex @"^[ABD] soft limit set to (\d+) "
    let private limitHeld = Regex @"^C setrlimit .* now cur=(\d+) "

    /// Every `poll` row of `run`, each with the soft limit the probe had set
    /// when it made it.
    let private rows (run : Run) : Row list =
        ((None, []), run.Lines)
        ||> List.fold (fun (limit, acc) line ->
            let set = limitSet.Match line
            let held = limitHeld.Match line
            let row = rowPattern.Match line

            if set.Success then
                Some (int64 set.Groups.[1].Value), acc
            elif held.Success then
                Some (int64 held.Groups.[1].Value), acc
            elif row.Success then
                match limit with
                | None -> failwith $"%s{run.Name}: row before any limit was set: %s{line}"
                | Some softLimit ->
                    // Section D names the uid each row ran as.
                    let privileged, label =
                        let label = row.Groups.[2].Value

                        if label.StartsWith "uid0-" then true, label.Substring 5
                        elif label.StartsWith "uid501-" then false, label.Substring 7
                        else run.Privileged, label

                    let parsed =
                        {
                            Section = row.Groups.[1].Value
                            Privileged = privileged
                            Label = label
                            SoftLimit = softLimit
                            Count = int64 row.Groups.[3].Value
                            Timeout = int row.Groups.[4].Value
                            Rv = int row.Groups.[5].Value
                            Errno = row.Groups.[6].Value
                            Revents0 = row.Groups.[7].Value
                        }

                    limit, parsed :: acc
            else
                limit, acc
        )
        |> snd
        |> List.rev

    /// Whether the measured kernel fails a `poll` of `count` entries with
    /// `EINVAL` before reading any entry, for a process whose soft limit is
    /// `softLimit`, and is root if `privileged`: the rule the probe measured.
    /// Darwin lets root past its soft limit up to `FD_SETSIZE` (1024).
    let private failsEinval (flavour : SimulatedUnixFlavour) (privileged : bool) (softLimit : int64) (count : int64) : bool =
        match flavour with
        | SimulatedUnixFlavour.Linux -> count > softLimit
        | SimulatedUnixFlavour.Darwin ->
            count > 10240L
            || count > softLimit && (not privileged || count > 1024L)

    /// `CallerPrivilege.Privileged` if `privileged`.
    let private privilegeOf (privileged : bool) : CallerPrivilege =
        if privileged then
            CallerPrivilege.Privileged
        else
            CallerPrivilege.Unprivileged

    /// The least and the greatest soft limit a process can have. The least is
    /// what the library assumes. On Linux the greatest is the most `fs.nr_open`
    /// takes, above which `setrlimit` refuses every limit (section C, held by
    /// `the soft limit can never pass the largest fs.nr_open`); on Darwin any
    /// limit from `OPEN_MAX` up answers alike, so it is the run's own limit.
    let private limitRange (platform : SimulatedUnixPlatform) : int64 * int64 =
        let least = int64 (SimulatedUnixPlatform.descriptorBound platform)

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> least, 2147483584L
        | SimulatedUnixFlavour.Darwin -> least, 1048576L

    [<Test>]
    let ``every measured row fails with EINVAL exactly where the measured rule says`` () : unit =
        for run in runs do
            let measured = rows run
            let flavour = SimulatedUnixPlatform.flavour run.Platform

            measured
            |> List.exists (fun row -> row.Errno = "Invalid argument")
            |> shouldEqual true

            measured
            |> List.exists (fun row -> row.Errno <> "Invalid argument")
            |> shouldEqual true

            for row in measured do
                let predicted = failsEinval flavour row.Privileged row.SoftLimit row.Count

                if predicted <> (row.Errno = "Invalid argument") then
                    failwith $"%s{run.Name}: the rule predicts EINVAL=%b{predicted} for %A{row}"

    [<Test>]
    let ``the soft limit can never pass the largest fs.nr_open`` () : unit =
        for run in
            runs
            |> List.filter (fun run -> run.Name.EndsWith "uid0" && run.Name.StartsWith "linux") do
            let has (prefix : string) : unit =
                if not (run.Lines |> List.exists (fun line -> line.StartsWith prefix)) then
                    failwith $"%s{run.Name}: no line starts %s{prefix}"

            has "C write fs.nr_open=2147483585 rv=-1 errno=Invalid argument "
            has "C write fs.nr_open=2147483647 rv=-1 errno=Invalid argument "
            has "C write fs.nr_open=2147483584 rv=10 errno=- now=2147483584"
            has "C setrlimit 2147483585 rv=-1 errno=Operation not permitted "
            has "C setrlimit RLIM_INFINITY rv=-1 errno=Operation not permitted "
            has "C setrlimit 2147483584 rv=0 errno=- now cur=2147483584 max=2147483584"

    [<Test>]
    let ``the screen answers exactly the counts whose answer no soft limit changes`` () : unit =
        let platforms =
            [
                SimulatedUnixPlatform.linuxX64
                SimulatedUnixPlatform.linuxArm64
                SimulatedUnixPlatform.macOsArm64
            ]

        let edges (platform : SimulatedUnixPlatform) : int list =
            let bound = SimulatedUnixPlatform.descriptorBound platform

            [
                0
                1
                Int32.MaxValue
                for d in -2 .. 2 do
                    bound + d
                    1024 + d
                    10240 + d
                    2147483584 + d
            ]

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! privileged = Gen.elements [ false ; true ]

                let! count =
                    Gen.frequency
                        [
                            2, Gen.elements (edges platform)
                            1, Gen.choose (0, 20000)
                            1, Gen.choose (0, Int32.MaxValue)
                        ]

                return platform, privileged, count
            }

        let property (platform : SimulatedUnixPlatform, privileged : bool, count : int) : bool =
            let flavour = SimulatedUnixPlatform.flavour platform
            let least, greatest = limitRange platform
            // The rule fails a count for no smaller limit than it fails it for
            // a larger one, so the two ends agreeing means every limit does.
            let atLeast = failsEinval flavour privileged least (int64 count)
            let atGreatest = failsEinval flavour privileged greatest (int64 count)

            match PollEntryCount.screen platform (privilegeOf privileged) count with
            | Ok None -> not atLeast && not atGreatest
            | Ok (Some UnixError.EINVAL) -> atLeast && atGreatest
            | Ok (Some _) -> false
            | Error (PollRefusal.UnmodelledEntryCount (refusedFlavour, refusedCount, assumed)) ->
                atLeast <> atGreatest
                && refusedFlavour = flavour
                && refusedCount = count
                && int64 assumed = least
            | Error _ -> false

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 2000, Prop.forAll (Arb.fromGen gen) property)

        for platform in platforms do
            for privileged in [ false ; true ] do
                for count in edges platform do
                    if not (property (platform, privileged, count)) then
                        failwith
                            $"%A{platform}, privileged %b{privileged}: count %d{count} screened as %A{PollEntryCount.screen platform (privilegeOf privileged) count}"

    /// A system of `platform` whose thread 1 is running, as root if
    /// `privileged`, with a pipe, an empty event queue (an epoll instance under
    /// Linux, a kqueue under Darwin), and those two descriptors.
    let private worldAs (privileged : bool) (platform : SimulatedUnixPlatform) : UnixSystem<int, string> * int * int =
        let configure (launch : ProcessLaunch<int>) : ProcessLaunch<int> =
            if privileged then
                launch
                |> Launched.credentials (Credentials.ofIds UserId.root (GroupId.parseOrFail "TestPollEntryCount" 0u) [])
            else
                launch

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.bootWith configure UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure thread

        let caller = Callers.thread thread system

        let writeEnd, system =
            match UnixPipe.pipe2 caller 0 UserBuffer.Mapped system with
            | Pipe2Answer.Created (_, writeFd), system -> writeFd, system
            | other -> failwith $"pipe2: %A{other}"

        let queue, system =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux ->
                match UnixPoll.epollCreate1 caller 0 system with
                | Ok (fd, system) -> fd, system
                | Error error -> failwith $"epoll_create1: %O{error}"
            | SimulatedUnixFlavour.Darwin -> UnixKqueue.kqueue caller system

        system, writeEnd, queue

    /// `worldAs` for a process that is not root.
    let private world (platform : SimulatedUnixPlatform) : UnixSystem<int, string> * int * int = worldAs false platform

    /// A descriptor the probe chose not open, and which no `world` opens.
    let private closedFd : int = 200

    [<Test>]
    let ``poll screens its entry count before reading any entry, through tryPoll and step`` () : unit =
        let mutable replayed = 0

        for run in runs do
            let flavour = SimulatedUnixPlatform.flavour run.Platform
            let least, greatest = limitRange run.Platform

            for row in rows run do
                let system, writeEnd, queue = worldAs row.Privileged run.Platform

                // An unmapped buffer has no counterpart here, where the
                // entries are a list; nor does a count no list can hold.
                if row.Label <> "unmapped-buffer" && row.Count <= 1_048_577L then
                    let count = int row.Count

                    let lead =
                        match row.Label with
                        | "idle-buffer" ->
                            {
                                PollEntry.Fd = -1
                                Events = pollIn
                            }
                        | "lead=ready-pipe-POLLOUT" ->
                            {
                                PollEntry.Fd = writeEnd
                                Events = pollOut
                            }
                        | "lead=closed-fd" ->
                            {
                                PollEntry.Fd = closedFd
                                Events = pollIn
                            }
                        | "lead=empty-epoll"
                        | "lead=empty-kqueue" ->
                            {
                                PollEntry.Fd = queue
                                Events = pollIn
                            }
                        | other -> failwith $"%s{run.Name}: unknown row label %s{other}"

                    let entries =
                        if count = 0 then
                            []
                        else
                            lead
                            :: List.replicate
                                (count - 1)
                                {
                                    PollEntry.Fd = -1
                                    Events = pollIn
                                }

                    let caller = Callers.thread thread system
                    let viaPoll = UnixPoll.tryPoll caller entries row.Timeout system

                    let viaStep =
                        match UnixSystem.tryStep caller (Syscall.Poll (entries, row.Timeout)) system with
                        | Ok (SteppedCall.Poll (outcome, after)) -> Ok (outcome, after)
                        | Ok other -> failwith $"step of a poll answered %A{other}"
                        | Error (SyscallRefusal.Poll refusal) -> Error refusal
                        | Error other -> failwith $"step of a poll refused %A{other}"

                    if viaStep <> viaPoll then
                        failwith $"%s{run.Name}: step answered %A{viaStep} and tryPoll %A{viaPoll} for %A{row}"

                    let atLeast = failsEinval flavour row.Privileged least row.Count
                    let atGreatest = failsEinval flavour row.Privileged greatest row.Count

                    let fail () : unit =
                        failwith
                            $"%s{run.Name}: tryPoll answered %A{Result.map fst viaPoll} for %A{row} (at the least limit EINVAL=%b{atLeast}, at the greatest %b{atGreatest})"

                    match viaPoll with
                    | _ when atLeast && atGreatest ->
                        match viaPoll with
                        | Ok (PollOutcome.Failed UnixError.EINVAL, after) when after = system -> ()
                        | _ -> fail ()
                    | _ when atLeast <> atGreatest ->
                        match viaPoll with
                        | Error (PollRefusal.UnmodelledEntryCount (f, c, assumed)) when
                            f = flavour && c = count && int64 assumed = least
                            ->
                            ()
                        | _ -> fail ()
                    // Every limit passes the count, so the row's own answer is
                    // the one every process would see.
                    | Ok (PollOutcome.Answered (revents, triggered), after) ->
                        let first =
                            match revents with
                            | [] -> "-"
                            | r :: _ -> $"0x%x{r}"

                        if
                            after <> system
                            || triggered <> row.Rv
                            || first <> row.Revents0
                            || List.length revents <> count
                        then
                            fail ()
                    | Ok (PollOutcome.WouldBlock _, _) ->
                        if row.Errno <> "Interrupted system call" then
                            fail ()
                    | Error (PollRefusal.UnmodelledTarget fd) ->
                        // The library does not poll an event queue it cannot
                        // read the readiness of; the row's answer is still
                        // the scan's, not the screen's.
                        if fd <> queue || row.Errno <> "-" then
                            fail ()
                    | Error (PollRefusal.UnmeasuredNegativeTimeout milliseconds) ->
                        if flavour <> SimulatedUnixFlavour.Darwin || milliseconds <> row.Timeout then
                            fail ()
                    | _ -> fail ()

                    replayed <- replayed + 1

        // Sections A and B of five runs, less their unmapped rows: 17 of A
        // in each, and 2 of B in each Linux run (Darwin's is skipped); and
        // the 16 rows of Darwin's section D, measured as root and as uid 501.
        replayed |> shouldEqual 107

    [<Test>]
    let ``a Linux poll of more entries than the descriptor bound is refused`` () : unit =
        let system, _, _ = world SimulatedUnixPlatform.linuxX64

        let entries (n : int) : PollEntry list =
            List.replicate
                n
                {
                    PollEntry.Fd = -1
                    Events = pollIn
                }

        UnixPoll.tryPoll (Callers.thread thread system) (entries 1025) 0 system
        |> shouldEqual (Error (PollRefusal.UnmodelledEntryCount (SimulatedUnixFlavour.Linux, 1025, 1024)))

        UnixPoll.tryPoll (Callers.thread thread system) (entries 1024) 0 system
        |> Result.map fst
        |> shouldEqual (Ok (PollOutcome.Answered (List.replicate 1024 0s, 0)))

    [<Test>]
    let ``Darwin lets root past its soft limit up to FD_SETSIZE, and no further`` () : unit =
        let entries (n : int) : PollEntry list =
            List.replicate
                n
                {
                    PollEntry.Fd = -1
                    Events = pollIn
                }

        let root, _, _ = worldAs true SimulatedUnixPlatform.macOsArm64
        let user, _, _ = world SimulatedUnixPlatform.macOsArm64

        UnixPoll.tryPoll (Callers.thread thread root) (entries 1024) 0 root
        |> Result.map fst
        |> shouldEqual (Ok (PollOutcome.Answered (List.replicate 1024 0s, 0)))

        UnixPoll.tryPoll (Callers.thread thread root) (entries 1025) 0 root
        |> shouldEqual (Error (PollRefusal.UnmodelledEntryCount (SimulatedUnixFlavour.Darwin, 1025, 256)))

        UnixPoll.tryPoll (Callers.thread thread root) (entries 10241) 0 root
        |> Result.map fst
        |> shouldEqual (Ok (PollOutcome.Failed UnixError.EINVAL))

        UnixPoll.tryPoll (Callers.thread thread user) (entries 257) 0 user
        |> shouldEqual (Error (PollRefusal.UnmodelledEntryCount (SimulatedUnixFlavour.Darwin, 257, 256)))
