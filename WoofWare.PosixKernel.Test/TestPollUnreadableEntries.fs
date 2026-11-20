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

/// `poll(2)` of an array of `struct pollfd` which the kernel cannot read
/// (`PollEntriesArgument.Unreadable`), held to
/// `docs/probes/poll-unreadable-entries`, which measured it on Darwin 27.2.0
/// arm64 (as uid 501) and Linux 6.18.5 aarch64 (as root and as uid 1000).
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPollUnreadableEntries =

    let private pollIn : int16 = 0x0001s
    let private pollOut : int16 = 0x0004s
    let private thread : int = 1

    /// One run of the probe: the platform it measured, whether it ran as
    /// root, and what it printed.
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
                Name = "darwin-uid501"
                Platform = SimulatedUnixPlatform.macOsArm64
                Privileged = false
                Lines = lines "poll-unreadable-entries.darwin-uid501.txt"
            }
            {
                Name = "linux-aarch64-uid0"
                Platform = SimulatedUnixPlatform.linuxArm64
                Privileged = true
                Lines = lines "poll-unreadable-entries.linux-aarch64-uid0.txt"
            }
            {
                Name = "linux-aarch64-uid1000"
                Platform = SimulatedUnixPlatform.linuxArm64
                Privileged = false
                Lines = lines "poll-unreadable-entries.linux-aarch64-uid1000.txt"
            }
        ]

    /// One `poll` the probe made, and what it answered.
    type private Row =
        {
            Section : string
            Label : string
            Count : uint32
            Timeout : int
            Rv : int
            Errno : string
            Slept : bool
            Revents0 : string
        }

    let private rowPattern =
        Regex @"^([OZPW]) (.+) nfds=(\d+) timeout=(-?\d+) rv=(-?\d+) errno=(.+) slept=(yes|no) revents0=(\S+)$"

    let private rows (run : Run) : Row list =
        run.Lines
        |> List.choose (fun line ->
            let m = rowPattern.Match line

            if m.Success then
                Some
                    {
                        Section = m.Groups.[1].Value
                        Label = m.Groups.[2].Value
                        Count = UInt32.Parse m.Groups.[3].Value
                        Timeout = int m.Groups.[4].Value
                        Rv = int m.Groups.[5].Value
                        Errno = m.Groups.[6].Value
                        Slept = m.Groups.[7].Value = "yes"
                        Revents0 = m.Groups.[8].Value
                    }
            else
                None
        )

    let private sectionP =
        Regex @"^k=(\d+) cut=(entry|mid-entry|none) lead=(ready|idle)$"

    /// `CallerPrivilege.Privileged` if `privileged`.
    let private privilegeOf (privileged : bool) : CallerPrivilege =
        if privileged then
            CallerPrivilege.Privileged
        else
            CallerPrivilege.Unprivileged

    /// A system of `platform` whose thread 1 is running, as root if
    /// `privileged`, and the write end of a pipe it holds, which is ready for
    /// `POLLOUT`.
    let private world (privileged : bool) (platform : SimulatedUnixPlatform) : UnixSystem<int, string> * int =
        let configure (launch : ProcessLaunch<int>) : ProcessLaunch<int> =
            if privileged then
                launch
                |> Launched.credentials (
                    Credentials.ofIds UserId.root (GroupId.parseOrFail "TestPollUnreadableEntries" 0u) []
                )
            else
                launch

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.bootWith configure UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure thread

        match UnixPipe.pipe2 (Callers.thread thread system) 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (_, writeFd), system -> system, writeFd
        | other -> failwith $"pipe2: %A{other}"

    /// `tryPoll` of `argument`, checked to agree with `UnixSystem.tryStep` of
    /// the same call.
    let private poll
        (argument : PollEntriesArgument)
        (milliseconds : int)
        (system : UnixSystem<int, string>)
        : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>
        =
        let caller = Callers.thread thread system
        let viaPoll = UnixPoll.tryPoll caller argument milliseconds system

        let viaStep =
            match UnixSystem.tryStep caller (Syscall.Poll (argument, milliseconds)) system with
            | Ok (SteppedCall.Poll (outcome, after)) -> Ok (outcome, after)
            | Ok other -> failwith $"step of a poll answered %A{other}"
            | Error (SyscallRefusal.Poll refusal) -> Error refusal
            | Error other -> failwith $"step of a poll refused %A{other}"

        if viaStep <> viaPoll then
            failwith $"step answered %A{viaStep} and tryPoll %A{viaPoll} for %A{argument}, %d{milliseconds}ms"

        viaPoll

    /// What the library answers for `row`'s call, given the argument the call
    /// passed, judged against what the probe measured; or a description of
    /// the disagreement.
    let private judge
        (run : Run)
        (system : UnixSystem<int, string>)
        (argument : PollEntriesArgument)
        (row : Row)
        (expectReadAnswer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal> -> bool)
        : unit
        =
        let answer = poll argument row.Timeout system

        let fail () : unit =
            failwith $"%s{run.Name}: tryPoll answered %A{Result.map fst answer} for %A{argument}, measured %A{row}"

        match PollEntryCount.screen run.Platform (privilegeOf run.Privileged) row.Count with
        | Ok (Some error) ->
            match answer with
            | Ok (PollOutcome.Failed e, after) when e = error && after = system && row.Errno = "Invalid argument" -> ()
            | _ -> fail ()
        | Error (PollRefusal.UnmodelledEntryCount (flavour, count, _)) ->
            // The answer depends on the process's soft limit, which the
            // library does not model; the probe set its own.
            match answer with
            | Error (PollRefusal.UnmodelledEntryCount (f, c, _)) when f = flavour && c = count -> ()
            | _ -> fail ()
        | Error other -> failwith $"the screen refused %A{other}"
        | Ok None ->
            // The measured kernel did not fail this count with EINVAL either.
            if row.Errno = "Invalid argument" || not (expectReadAnswer answer) then
                fail ()

    /// `EFAULT`, with the system unchanged, for a row the kernel answered
    /// `EFAULT` at once, having written no `revents`.
    let private faulted
        (system : UnixSystem<int, string>)
        (row : Row)
        (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>)
        : bool
        =
        row.Errno = "Bad address"
        && not row.Slept
        && (row.Revents0 = "-" || row.Revents0 = "0x5a5a")
        && answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)

    [<Test>]
    let ``every measured row of an unreadable array is answered as measured, through tryPoll and step`` () : unit =
        for run in runs do
            let mutable replayed = Map.empty<string, int>
            let mutable skipped = 0

            let count (section : string) : unit =
                replayed <- replayed |> Map.change section (fun n -> Some (1 + Option.defaultValue 0 n))

            for row in rows run do
                let system, writeEnd = world run.Privileged run.Platform

                match row.Section with
                | "O" ->
                    // A NULL pointer and an unmapped one are both unreadable.
                    judge run system (PollEntriesArgument.Unreadable row.Count) row (faulted system row)
                    count "O"
                | "Z" ->
                    // No entries are read, so an unreadable array of none is
                    // answered as an empty one, sleeping where it would sleep.
                    let asEmpty = poll (PollEntriesArgument.Readable []) row.Timeout system

                    let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                        answer = asEmpty
                        && match answer with
                           | Ok (PollOutcome.Answered ([], 0), after) -> after = system && row.Rv = 0 && not row.Slept
                           | Ok (PollOutcome.WouldBlock _, _) -> row.Slept && row.Timeout <> 0
                           | _ -> false

                    judge run system (PollEntriesArgument.Unreadable 0u) row expected
                    count "Z"
                | "P" ->
                    let m = sectionP.Match row.Label

                    if not m.Success then
                        failwith $"%s{run.Name}: unknown section P label %s{row.Label}"

                    let k = int m.Groups.[1].Value
                    let ready = m.Groups.[3].Value = "ready"

                    match m.Groups.[2].Value with
                    | "none" ->
                        // The control: the same entries, every one readable.
                        let lead =
                            if ready then
                                {
                                    PollEntry.Fd = writeEnd
                                    Events = pollOut
                                }
                            else
                                {
                                    PollEntry.Fd = -1
                                    Events = pollIn
                                }

                        let entries =
                            lead
                            :: List.replicate
                                (k - 1)
                                {
                                    PollEntry.Fd = -1
                                    Events = pollIn
                                }

                        let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                            match answer with
                            | Ok (PollOutcome.Answered (revents, 1), _) ->
                                ready && row.Rv = 1 && row.Revents0 = "0x4" && List.head revents = pollOut
                            | Ok (PollOutcome.WouldBlock _, _) ->
                                not ready && row.Slept && row.Errno = "Interrupted system call"
                            | _ -> false

                        judge run system (PollEntriesArgument.Readable entries) row expected
                    | _ ->
                        // Readable for its first entries and not the rest.
                        judge run system (PollEntriesArgument.Unreadable row.Count) row (faulted system row)

                    count "P"
                | "W" ->
                    // A readable array whose `revents` cannot be written back,
                    // which this library does not model.
                    skipped <- skipped + 1
                | other -> failwith $"%s{run.Name}: unknown section %s{other}"

            // Section O: 6 counts, at NULL and unmapped, at two timeouts.
            // Section Z: 3 addresses at 3 timeouts. Section P: 17 values of k,
            // 3 cuts, 2 leads. Section W: 2 rows.
            replayed |> shouldEqual (Map.ofList [ "O", 24 ; "P", 102 ; "Z", 9 ])

            skipped |> shouldEqual 2

    /// The partly-readable rows of section P are answered EFAULT by the
    /// measured kernel without polling the entries it could read: a ready
    /// lead is not reported, an idle lead under timeout -1 does not sleep,
    /// and entry 0's revents keeps the value set beforehand.
    [<Test>]
    let ``a partly readable array was measured to fault without polling anything`` () : unit =
        for run in runs do
            let partial =
                rows run
                |> List.filter (fun row -> row.Section = "P" && not (row.Label.Contains "cut=none"))

            List.length partial |> shouldEqual 68

            for row in partial do
                if row.Errno <> "Bad address" || row.Slept || row.Revents0 <> "0x5a5a" then
                    failwith $"%s{run.Name}: %A{row}"

    /// Section S: on Linux, a partly readable array does not poll the entries
    /// it could read, seen through a blocking UDP receiver's reader queue,
    /// which a poll of it refills: the charge of the datagrams taken after a
    /// faulting poll comes back as late as with no poll at all.
    [<Test>]
    let ``a partly readable array was measured to poll none of its readable entries under Linux`` () : unit =
        let pattern =
            Regex
                @"^S k=(\d+) cut=(no-poll|none|entry) lead=udp nfds=(\d+) timeout=0 rv=(-?\d+) errno=(.+) charge-after=(\d+) revents0=(\S+)$"

        for run in runs |> List.filter (fun run -> run.Name.StartsWith "linux") do
            let measured =
                run.Lines
                |> List.choose (fun line ->
                    let m = pattern.Match line

                    if m.Success then
                        Some (m.Groups.[2].Value, m.Groups.[4].Value, m.Groups.[5].Value, m.Groups.[6].Value)
                    else
                        None
                )

            List.length measured |> shouldEqual 9

            for cut, rv, errno, charge in measured do
                match cut with
                | "no-poll" -> (rv, errno, charge) |> shouldEqual ("0", "-", "46080")
                | "none" -> (rv, errno, charge) |> shouldEqual ("1", "-", "23040")
                | _ -> (rv, errno, charge) |> shouldEqual ("-1", "Bad address", "46080")

    [<Test>]
    let ``an unreadable array answers what the screen answers, or EFAULT, or as an empty one`` () : unit =
        let platforms =
            [
                SimulatedUnixPlatform.linuxX64
                SimulatedUnixPlatform.linuxArm64
                SimulatedUnixPlatform.macOsArm64
            ]

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! privileged = Gen.elements [ false ; true ]

                let! count =
                    Gen.frequency
                        [
                            2, Gen.elements [ 0u ; 1u ; 255u ; 256u ; 257u ; 1023u ; 1024u ; 1025u ; 10240u ; 10241u ]
                            2, Gen.choose (0, 1100) |> Gen.map uint32
                            1, Gen.choose (0, Int32.MaxValue) |> Gen.map uint32
                            1, Gen.choose (0, Int32.MaxValue) |> Gen.map (fun n -> uint32 n + 2147483648u)
                        ]

                let! milliseconds = Gen.elements [ 0 ; 1 ; 100 ; -1 ; -2 ]
                return platform, privileged, count, milliseconds
            }

        let property (platform : SimulatedUnixPlatform, privileged : bool, count : uint32, milliseconds : int) : bool =
            let system, _ = world privileged platform
            let unreadable = poll (PollEntriesArgument.Unreadable count) milliseconds system

            if count = 0u then
                unreadable = poll (PollEntriesArgument.Readable []) milliseconds system
            elif count <= 1100u then
                // The same count of readable entries, none of which reports.
                let readable =
                    poll
                        (PollEntriesArgument.Readable (
                            List.replicate
                                (int count)
                                {
                                    PollEntry.Fd = -1
                                    Events = pollIn
                                }
                        ))
                        milliseconds
                        system

                match readable with
                | Ok (PollOutcome.Failed UnixError.EINVAL, _)
                | Error (PollRefusal.UnmodelledEntryCount _) -> unreadable = readable
                | _ -> unreadable = Ok (PollOutcome.Failed UnixError.EFAULT, system)
            else
                match PollEntryCount.screen platform (privilegeOf privileged) count with
                | Ok (Some error) -> unreadable = Ok (PollOutcome.Failed error, system)
                | Error refusal -> unreadable = Error refusal
                | Ok None -> unreadable = Ok (PollOutcome.Failed UnixError.EFAULT, system)

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen gen) property)
