namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `poll(2)` of an array of `struct pollfd` which the kernel cannot read,
/// and of an array of no entries, held to
/// `docs/probes/poll-unreadable-entries`, which measured it on Darwin 27.2.0
/// arm64 (as uid 501), Linux 6.18.5 aarch64 (as root and as uid 1000), and
/// Linux 6.12.113 and 6.18.5 x86-64 with four- and five-level paging (as
/// root, booted under QEMU). Each run is replayed on a platform of the kernel
/// version and architecture that produced it, not on the current presets.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPollUnreadableEntries =

    let private pollIn : int16 = 0x0001s
    let private pollOut : int16 = 0x0004s
    let private thread : int = 1

    /// A Linux platform of `version` on `architecture`, built as `build`.
    let private linuxAt
        (architecture : SimulatedUnixArchitecture)
        (build : LinuxKernelBuild)
        (major : uint32, minor : uint32, patch : uint32)
        : SimulatedUnixPlatform
        =
        SimulatedUnixPlatform.createOrFail
            "TestPollUnreadableEntries"
            (SimulatedUnixKernel.Linux (
                {
                    Major = major
                    Minor = minor
                    Patch = patch
                },
                build
            ))
            architecture
            SimulatedPageSize.FourKiB
            $"%d{major}.%d{minor}.%d{patch}"

    /// The Darwin platform the Darwin run measured.
    let private darwin27_2 : SimulatedUnixPlatform =
        SimulatedUnixPlatform.createOrFail
            "TestPollUnreadableEntries"
            (SimulatedUnixKernel.Darwin
                {
                    VersionMajor = 27u
                    VersionMinor = 2u
                    VersionRevision = 0u
                })
            SimulatedUnixArchitecture.Arm64
            SimulatedPageSize.SixteenKiB
            "27.2.0"

    /// Linux 6.18.5 on arm64, as Apple's `container` runs it.
    let private linuxArm64_6_18_5 : SimulatedUnixPlatform =
        linuxAt SimulatedUnixArchitecture.Arm64 LinuxKernelBuild.SmallBuffer832 (6u, 18u, 5u)

    /// Linux on x86-64, as Debian builds it. Its UDP charge for the probe's
    /// 1000-byte datagrams is measured (section S) to be what the model gives
    /// for this build.
    let private linuxX64At (version : uint32 * uint32 * uint32) : SimulatedUnixPlatform =
        linuxAt SimulatedUnixArchitecture.X64 LinuxKernelBuild.SmallBuffer960 version

    /// One run of the probe: the platform it measured, the machine's user
    /// address limit where the run set one apart from the platform's default,
    /// whether it ran as root, and what it printed.
    type private Run =
        {
            Name : string
            Platform : SimulatedUnixPlatform
            AddressLimit : uint64 option
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
        let x64 (name : string) (version : uint32 * uint32 * uint32) (limit : uint64) : Run =
            {
                Name = name
                Platform = linuxX64At version
                AddressLimit = Some limit
                Privileged = true
                Lines = lines $"poll-unreadable-entries.%s{name}.txt"
            }

        [
            {
                Name = "darwin-27.2.0-uid501"
                Platform = darwin27_2
                AddressLimit = None
                Privileged = false
                Lines = lines "poll-unreadable-entries.darwin-27.2.0-uid501.txt"
            }
            {
                Name = "linux-6.18.5-aarch64-uid0"
                Platform = linuxArm64_6_18_5
                AddressLimit = None
                Privileged = true
                Lines = lines "poll-unreadable-entries.linux-6.18.5-aarch64-uid0.txt"
            }
            {
                Name = "linux-6.18.5-aarch64-uid1000"
                Platform = linuxArm64_6_18_5
                AddressLimit = None
                Privileged = false
                Lines = lines "poll-unreadable-entries.linux-6.18.5-aarch64-uid1000.txt"
            }
            x64 "linux-6.12.113-x86_64-four-level" (6u, 12u, 113u) ObservedUserAddressLimit.X64FourLevelPaging
            x64 "linux-6.12.113-x86_64-five-level" (6u, 12u, 113u) ObservedUserAddressLimit.X64FiveLevelPaging
            x64 "linux-6.18.5-x86_64-four-level" (6u, 18u, 5u) ObservedUserAddressLimit.X64FourLevelPaging
            x64 "linux-6.18.5-x86_64-five-level" (6u, 18u, 5u) ObservedUserAddressLimit.X64FiveLevelPaging
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
            /// The `RLIMIT_NOFILE` soft limit the probe had set.
            SoftLimit : uint32
        }

    let private rowPattern =
        Regex @"^([OZYPW]) (.+) nfds=(\d+) timeout=(-?\d+) rv=(-?\d+) errno=(.+) slept=(yes|no) revents0=(\S+)$"

    let private limitSet = Regex @"^soft limit set to (\d+)$"

    let private rows (run : Run) : Row list =
        ((None, []), run.Lines)
        ||> List.fold (fun (limit, acc) line ->
            let set = limitSet.Match line
            let m = rowPattern.Match line

            if set.Success then
                Some (UInt32.Parse set.Groups.[1].Value), acc
            elif m.Success then
                let softLimit =
                    match limit with
                    | Some limit -> limit
                    | None -> failwith $"%s{run.Name}: a row before any limit was set: %s{line}"

                limit,
                {
                    Section = m.Groups.[1].Value
                    Label = m.Groups.[2].Value
                    Count = UInt32.Parse m.Groups.[3].Value
                    Timeout = int m.Groups.[4].Value
                    Rv = int m.Groups.[5].Value
                    Errno = m.Groups.[6].Value
                    Slept = m.Groups.[7].Value = "yes"
                    Revents0 = m.Groups.[8].Value
                    SoftLimit = softLimit
                }
                :: acc
            else
                limit, acc
        )
        |> snd
        |> List.rev

    let private sectionP =
        Regex @"^k=(\d+) cut=(entry|mid-entry|none) lead=(ready|idle) addr=0x[0-9a-f]+$"

    /// A system of `run`'s platform, with its address limit, whose thread 1
    /// is running, as root if the run was, and the write end of a pipe it
    /// holds, which is ready for `POLLOUT`.
    let private worldOf (run : Run) : UnixSystem<int, string> * int =
        let configure (launch : ProcessLaunch<int>) : ProcessLaunch<int> =
            if run.Privileged then
                launch
                |> Launched.credentials (
                    Credentials.ofIds UserId.root (GroupId.parseOrFail "TestPollUnreadableEntries" 0u) []
                )
            else
                launch

        let image = UnixSystem.initial<int, string> run.Platform

        let image =
            match run.AddressLimit with
            | Some limit -> UnixBootImage.withUserAddressLimit limit image
            | None -> image

        let system =
            image
            |> Launched.bootWith configure UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure thread

        match UnixPipe.pipe2 (Callers.thread thread system) 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (_, writeFd), system -> system, writeFd
        | other -> failwith $"pipe2: %A{other}"

    /// `worldOf` a run of `platform`, as root if `privileged`, at the
    /// platform's default address limit.
    let private world (privileged : bool) (platform : SimulatedUnixPlatform) : UnixSystem<int, string> * int =
        worldOf
            {
                Name = "generated"
                Platform = platform
                AddressLimit = None
                Privileged = privileged
                Lines = []
            }

    /// The array of a `poll`, and its `nfds`, as `Syscall.Poll` holds them.
    type private PollArray = CopiedArgument<PollEntry list> * uint32

    /// An array of `count` entries at `address`, which names no storage, as
    /// a client passes an array the process can read only in part.
    let private unmappedArrayAt (address : uint64) (count : uint32) : PollArray = CopiedArgument.Unmapped address, count

    /// The address a probe row's label names: NULL, the probe's unmapped
    /// address (8), or the address the label writes out after `addr=0x`.
    let private addressOf (label : string) : uint64 =
        let marker = "addr=0x"

        match label with
        | "null" -> 0UL
        | "unmapped" -> 8UL
        | _ when label.Contains marker ->
            let hex = label.Substring (label.IndexOf marker + marker.Length)
            UInt64.Parse (hex, Globalization.NumberStyles.HexNumber)
        | _ -> failwith $"no address for the label %s{label}"

    /// A readable array holding `entries`.
    let private readableArray (entries : PollEntry list) : PollArray =
        CopiedArgument.Readable entries, uint32 (List.length entries)

    /// What the measured kernels' screen of the entry count does, as the
    /// library can answer it without the process's `RLIMIT_NOFILE`: written
    /// out from `docs/probes/poll-entry-count` rather than taken from the
    /// library.
    [<RequireQualifiedAccess>]
    type private Screen =
        /// `EINVAL` whatever the soft limit.
        | Einval
        /// `EINVAL` or not, depending on the soft limit: refused.
        | Refused
        /// Passed whatever the soft limit.
        | Passes

    let private expectedScreen (platform : SimulatedUnixPlatform) (privileged : bool) (count : uint32) : Screen =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            if count > 2147483584u then Screen.Einval
            elif count > 1024u then Screen.Refused
            else Screen.Passes
        | SimulatedUnixFlavour.Darwin ->
            let limitFree = if privileged then 1024u else 256u

            if count > 10240u then Screen.Einval
            elif count > limitFree then Screen.Refused
            else Screen.Passes

    /// Whether `answer` is what a poll of no entries with a timeout of
    /// `milliseconds` answers from `system`: 0 at once for a timeout of 0,
    /// and otherwise a sleep, but for Darwin's negative timeouts other than
    /// -1, which are refused. Written out from `docs/probes/poll-timeout` and
    /// `poll-darwin.c` rather than taken from the library.
    let private isEmptyPoll
        (system : UnixSystem<int, string>)
        (milliseconds : int)
        (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>)
        : bool
        =
        match SimulatedUnixPlatform.flavour (UnixSystem.platform system), milliseconds, answer with
        | _, 0, Ok (PollOutcome.Answered ([], 0), after) -> after = system
        | _, 0, _ -> false
        | SimulatedUnixFlavour.Darwin, milliseconds, Error (PollRefusal.UnmeasuredNegativeTimeout refused) when
            milliseconds < -1
            ->
            refused = milliseconds
        | SimulatedUnixFlavour.Darwin, milliseconds, _ when milliseconds < -1 -> false
        | _, _, Ok (PollOutcome.WouldBlock _, _) -> true
        | _ -> false

    /// Whether the poll asleep in `parked` keeps the measured wait of a
    /// timeout of `milliseconds` from `system`: no deadline for -1, and for a
    /// positive timeout a deadline that many milliseconds on, at which the
    /// finished call answers 0.
    let private waitsAsMeasured
        (system : UnixSystem<int, string>)
        (milliseconds : int)
        (parked : UnixSystem<int, string>)
        : bool
        =
        if milliseconds < 0 then
            Lone.deadlines parked = []
        else
            let wait = int64 milliseconds * 1_000_000L
            let deadline = UnixSystem.nanosecondsSinceBoot system + wait

            Lone.deadlines parked = [ deadline ]
            && (let woken = UnixSystem.advanceClock wait parked |> Woken.thread thread

                match UnixPoll.tryFinishPoll (Callers.thread thread woken) woken with
                | Ok (PollOutcome.Answered ([], 0), _) -> true
                | _ -> false)

    /// `poll` of `argument` through the public protocol, holding where it
    /// paused (`PollCall.tryPollCopied`), checked to agree with
    /// `UnixSystem.tryStep` of the same call.
    let private poll
        (argument : PollArray)
        (milliseconds : int)
        (system : UnixSystem<int, string>)
        : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>
        =
        let caller = Callers.thread thread system
        let fds, nfds = argument
        let viaPoll = PollCall.tryPollCopied caller fds nfds milliseconds system

        let viaStep =
            match UnixSystem.tryStep caller (Syscall.Poll (fds, nfds, milliseconds)) system with
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
        (argument : PollArray)
        (row : Row)
        (expectReadAnswer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal> -> bool)
        : unit
        =
        let answer = poll argument row.Timeout system

        let fail () : unit =
            failwith $"%s{run.Name}: tryPoll answered %A{Result.map fst answer} for %A{argument}, measured %A{row}"

        match expectedScreen run.Platform run.Privileged row.Count with
        | Screen.Einval ->
            match answer with
            | Ok (PollOutcome.Failed UnixError.EINVAL, after) when after = system && row.Errno = "Invalid argument" ->
                ()
            | _ -> fail ()
        | Screen.Refused ->
            // The answer depends on the process's soft limit, which the
            // library does not model. The probe set its own, and the row is
            // EINVAL exactly when the count exceeds it (every run here is of a
            // process for which Darwin does not let root past it).
            if (row.Errno = "Invalid argument") <> (row.Count > row.SoftLimit) then
                failwith $"%s{run.Name}: the measured kernel's screen disagrees with its soft limit: %A{row}"

            match answer with
            | Error (PollRefusal.UnmodelledEntryCount (f, c, _)) when
                f = SimulatedUnixPlatform.flavour run.Platform && c = row.Count
                ->
                ()
            | _ -> fail ()
        | Screen.Passes ->
            // The measured kernel did not fail this count with EINVAL either.
            if row.Errno = "Invalid argument" || not (expectReadAnswer answer) then
                fail ()

    /// `EFAULT`, with the system unchanged, for a row the kernel answered
    /// `EFAULT`, having written no `revents`, and under timeout -1 at once.
    /// `slept`, which a delay in scheduling the probe can also set, is not
    /// consulted for a row under timeout 0, which could not sleep.
    let private faulted
        (system : UnixSystem<int, string>)
        (row : Row)
        (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>)
        : bool
        =
        row.Errno = "Bad address"
        && (row.Timeout = 0 || not row.Slept)
        && (row.Revents0 = "-" || row.Revents0 = "0x5a5a")
        && answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)

    [<Test>]
    let ``every measured row of an unreadable array is answered as measured, through tryPoll and step`` () : unit =
        for run in runs do
            let mutable replayed = Map.empty<string, int>

            let count (section : string) : unit =
                replayed <- replayed |> Map.change section (fun n -> Some (1 + Option.defaultValue 0 n))

            for row in rows run do
                let system, writeEnd = worldOf run

                match row.Section with
                | "O" ->
                    // A NULL pointer and an unmapped one are both unreadable.
                    judge run system (unmappedArrayAt (addressOf row.Label) row.Count) row (faulted system row)
                    count "O"
                | "Y" when row.Count > 0u ->
                    judge run system (unmappedArrayAt (addressOf row.Label) row.Count) row (faulted system row)
                    count "Y"
                | "Y" when row.Errno = "Bad address" ->
                    // Linux's write-back of no entries past the user address
                    // limit: at once for a timeout of 0, and otherwise after
                    // a sleep this kernel does not model.
                    let address = addressOf row.Label

                    let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                        match row.Timeout with
                        // `slept`, which a delay in scheduling the probe can
                        // also set, says nothing of a call that cannot sleep.
                        | 0 -> answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)
                        | timeout ->
                            row.Slept
                            && answer = Error (PollRefusal.UnmodelledWriteBackFault (address, timeout))

                    judge run system (unmappedArrayAt address 0u) row expected
                    count "Y"
                | "Z"
                | "Y" ->
                    // No entries are read, so an unreadable array of none is
                    // answered as an empty one, sleeping where it would sleep.
                    let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                        isEmptyPoll system row.Timeout answer
                        && match answer with
                           | Ok (PollOutcome.Answered ([], 0), after) -> after = system && row.Rv = 0 && row.Timeout = 0
                           // The finite wait ends at its deadline, with 0; the
                           // infinite one is ended by the probe's timer.
                           | Ok (PollOutcome.WouldBlock _, parked) ->
                               row.Slept
                               && waitsAsMeasured system row.Timeout parked
                               && match row.Timeout with
                                  | 0 -> false
                                  | -1 -> row.Rv = -1 && row.Errno = "Interrupted system call"
                                  | _ -> row.Rv = 0 && row.Errno = "-"
                           | _ -> false

                    judge run system (unmappedArrayAt (addressOf row.Label) 0u) row expected
                    count row.Section
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

                        judge run system (readableArray entries) row expected
                    | _ ->
                        // Readable for its first entries and not the rest,
                        // passed at its address as an unmapped array.
                        judge run system (unmappedArrayAt (addressOf row.Label) row.Count) row (faulted system row)

                    count "P"
                | "W" ->
                    // A readable array that the kernel cannot write back. The
                    // model answers what the kernel polled; the fault at the
                    // copy-out that follows is the client's (see the README).
                    let ready = row.Label.EndsWith "lead=ready"

                    let entries =
                        [
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
                        ]

                    let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                        row.Errno = "Bad address"
                        && row.Revents0 = "0x5a5a"
                        && match answer with
                           | Ok (PollOutcome.Answered ([ revents ], 1), _) -> ready && revents = pollOut
                           | Ok (PollOutcome.WouldBlock _, _) -> not ready && row.Slept && row.Timeout = 100
                           | _ -> false

                    judge run system (readableArray entries) row expected
                    count "W"
                | other -> failwith $"%s{run.Name}: unknown section %s{other}"

            // Section O: 6 counts, at NULL and unmapped, at four timeouts.
            // Section Z: 3 addresses at 3 timeouts. Section Y: 4 addresses
            // (arm64) or 9 (x86-64) at 5 counts and timeouts. Section P: 17
            // values of k, 3 cuts, 2 leads. Section W: 2 rows.
            let addresses =
                match SimulatedUnixPlatform.architecture run.Platform with
                | SimulatedUnixArchitecture.Arm64 -> 4
                | SimulatedUnixArchitecture.X64 -> 9

            replayed
            |> shouldEqual (Map.ofList [ "O", 48 ; "P", 102 ; "W", 2 ; "Y", 5 * addresses ; "Z", 9 ])

    /// The partly-readable rows of section P are answered EFAULT by the
    /// measured kernel: a ready lead is not reported, an idle lead under
    /// timeout -1 does not sleep, and entry 0's revents keeps the value set
    /// beforehand. Checked here whether or not the model refuses the row's
    /// count.
    [<Test>]
    let ``a partly readable array was measured to fault without reporting or sleeping`` () : unit =
        for run in runs do
            let partial =
                rows run
                |> List.filter (fun row -> row.Section = "P" && not (row.Label.Contains "cut=none"))

            List.length partial |> shouldEqual 68

            for row in partial do
                if
                    row.Errno <> "Bad address"
                    || row.Revents0 <> "0x5a5a"
                    || (row.Timeout = -1 && row.Slept)
                then
                    failwith $"%s{run.Name}: %A{row}"

    /// Section S, replayed through the model: on Linux, a partly readable
    /// array does not poll the entries it could read. A poll of a blocking
    /// UDP receiver refills its reader queue, which shows in the charge left
    /// after ten more datagrams arrive and ten are taken: as late as with no
    /// poll at all after a faulting poll, and given back after a poll of the
    /// whole array.
    [<Test>]
    let ``a partly readable array polls none of its readable entries under Linux, as measured`` () : unit =
        let pattern =
            Regex
                @"^S k=(\d+) cut=(no-poll|none|entry) lead=udp addr=0x([0-9a-f]+) nfds=(\d+) timeout=0 rv=(-?\d+) errno=(.+) charge-after=(\d+) revents0=(\S+)$"

        let payload = ImmutableArray.CreateRange (Array.create 1000 (byte 'r'))
        let msgDontWait = 0x40

        for run in runs do
            let measured =
                run.Lines
                |> List.choose (fun line ->
                    let m = pattern.Match line

                    if m.Success then
                        Some (
                            int m.Groups.[1].Value,
                            m.Groups.[2].Value,
                            UInt64.Parse (m.Groups.[3].Value, Globalization.NumberStyles.HexNumber),
                            int m.Groups.[5].Value,
                            m.Groups.[6].Value,
                            int m.Groups.[7].Value,
                            m.Groups.[8].Value
                        )
                    else
                        None
                )

            let expected =
                match SimulatedUnixPlatform.flavour run.Platform with
                | SimulatedUnixFlavour.Linux -> 9
                | SimulatedUnixFlavour.Darwin -> 0

            List.length measured |> shouldEqual expected

            for k, cut, address, rv, errno, charge, revents0 in measured do
                let system, _ = worldOf run
                let caller = Callers.thread thread system

                let receiver, system =
                    NewSocket.createAs caller SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

                let system =
                    match
                        CopyIn.bindAs
                            caller
                            receiver
                            UserBuffer.Mapped
                            16u
                            (CopyIn.inet run.Platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                            system
                    with
                    | Ok (BindAnswer.Bound _, system) -> system
                    | other -> failwith $"bind: %A{other}"

                let socketId =
                    match FileDescriptorRegistry.tryFindTarget receiver (Lone.fileDescriptors system) with
                    | Some (OpenFileTarget.Socket socketId) -> socketId
                    | other -> failwith $"fd %d{receiver} is %A{other}"

                let port =
                    match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
                    | Some binding -> binding.Endpoint.Port
                    | None -> failwith "the receiver has no binding"

                let sender, system =
                    NewSocket.createAs caller SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

                let system =
                    match
                        CopyIn.connectAs
                            caller
                            sender
                            UserBuffer.Mapped
                            16u
                            (CopyIn.inet run.Platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port))
                            system
                    with
                    | Ok (SyscallAnswer.Completed 0L, system) -> system
                    | other -> failwith $"connect: %A{other}"

                let ten (system : UnixSystem<int, string>) : UnixSystem<int, string> =
                    (system, [ 1..10 ])
                    ||> List.fold (fun system _ ->
                        match WriteOutcomes.admitThenSendAs caller sender UserBuffer.Mapped payload 0 system with
                        | Ok (WriteStep.Returns (WriteAnswer.Completed 1000L, system)) -> system
                        | other -> failwith $"send: %A{other}"
                    )

                let idle =
                    {
                        PollEntry.Fd = -1
                        Events = pollIn
                    }

                let lead =
                    {
                        PollEntry.Fd = receiver
                        Events = pollIn
                    }

                let system = ten system

                // Entry 0's revents as the probe prints it: what the poll
                // reported for the receiver, or 0x5a5a, set beforehand, where
                // no poll wrote it.
                let answered, system =
                    match cut with
                    | "no-poll" -> (0, "-", "0x5a5a"), system
                    | _ ->
                        let argument =
                            match cut with
                            | "none" -> readableArray (lead :: List.replicate (k - 1) idle)
                            // Readable in part: passed at its address as an
                            // unmapped array.
                            | _ -> unmappedArrayAt address (uint32 (k + 1))

                        match poll argument 0 system with
                        | Ok (PollOutcome.Answered (first :: _, count), system) -> (count, "-", $"0x%x{first}"), system
                        | Ok (PollOutcome.Failed UnixError.EFAULT, system) -> (-1, "Bad address", "0x5a5a"), system
                        | other -> failwith $"%s{run.Name}: poll of %A{argument} answered %A{other}"

                let system = ten system

                let system =
                    (system, [ 1..10 ])
                    ||> List.fold (fun system _ ->
                        match UnixReadWrite.tryRecv caller receiver UserBuffer.Mapped 2000UL msgDontWait system with
                        | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) when bytes.Length = 1000 ->
                            system
                        | other -> failwith $"recv: %A{other}"
                    )

                let modelledCharge =
                    DatagramReceiver.charged (UnixMachineState.datagramReceiver socketId (Kernel.machine system))

                (k, cut, answered, modelledCharge)
                |> shouldEqual (k, cut, (rv, errno, revents0), charge)

    /// Section H: Linux reads only the low 32 bits of a wider `nfds_t`, so a
    /// client gives `Unreadable` the count those bits hold.
    [<Test>]
    let ``Linux reads the low 32 bits of nfds, as measured`` () : unit =
        let pattern =
            Regex @"^H (null|unmapped) nfds=(\d+) timeout=0 rv=(-?\d+) errno=(.+)$"

        for run in runs do
            let measured =
                run.Lines
                |> List.choose (fun line ->
                    let m = pattern.Match line

                    if m.Success then
                        Some (
                            addressOf m.Groups.[1].Value,
                            UInt64.Parse m.Groups.[2].Value,
                            int m.Groups.[3].Value,
                            m.Groups.[4].Value
                        )
                    else
                        None
                )

            let expected =
                match SimulatedUnixPlatform.flavour run.Platform with
                | SimulatedUnixFlavour.Linux -> 6
                | SimulatedUnixFlavour.Darwin -> 0

            List.length measured |> shouldEqual expected

            for address, nfds, rv, errno in measured do
                nfds |> shouldBeGreaterThan (uint64 UInt32.MaxValue)
                let system, _ = worldOf run
                let count = uint32 (nfds &&& 0xFFFFFFFFUL)

                match poll (unmappedArrayAt address count) 0 system, rv, errno with
                | Ok (PollOutcome.Answered ([], 0), after), 0, "-" when after = system -> ()
                | Ok (PollOutcome.Failed UnixError.EFAULT, after), -1, "Bad address" when after = system -> ()
                // 1025 entries pass Linux's screen for a soft limit of 1025 or
                // more, which the library does not assume; the probe's was 1024.
                | Error (PollRefusal.UnmodelledEntryCount (_, c, _)), -1, "Invalid argument" when c = count -> ()
                | other -> failwith $"%s{run.Name}: nfds %d{nfds} answered %A{other}"

    [<Test>]
    let ``every array answers what the screen answers, then as an empty one, then by its buffer`` () : unit =
        // The presets, and the platforms the probe measured.
        let platforms =
            [
                SimulatedUnixPlatform.linuxX64
                SimulatedUnixPlatform.linuxArm64
                SimulatedUnixPlatform.macOsArm64
                darwin27_2
                linuxArm64_6_18_5
                linuxX64At (6u, 12u, 113u)
                linuxX64At (6u, 18u, 5u)
            ]

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! privileged = Gen.elements [ false ; true ]

                let! count =
                    Gen.frequency
                        [
                            2, Gen.constant 0u
                            2, Gen.elements [ 0u ; 1u ; 255u ; 256u ; 257u ; 1023u ; 1024u ; 1025u ; 10240u ; 10241u ]
                            2, Gen.choose (0, 1100) |> Gen.map uint32
                            1, Gen.choose (0, Int32.MaxValue) |> Gen.map uint32
                            1, Gen.choose (0, Int32.MaxValue) |> Gen.map (fun n -> uint32 n + 2147483648u)
                        ]

                let! buffer =
                    Gen.elements
                        [
                            UserBuffer.Unmapped 0UL
                            UserBuffer.Unmapped 8UL
                            // Either side of the x86-64 and arm64 limits.
                            UserBuffer.Unmapped ObservedUserAddressLimit.X64FourLevelPaging
                            UserBuffer.Unmapped (ObservedUserAddressLimit.X64FourLevelPaging + 1UL)
                            UserBuffer.Unmapped ObservedUserAddressLimit.Arm64FortyEightBit
                            UserBuffer.Unmapped (ObservedUserAddressLimit.Arm64FortyEightBit + 1UL)
                            UserBuffer.Unmapped UInt64.MaxValue
                            UserBuffer.Opaque
                            UserBuffer.Addressless
                        ]

                let! milliseconds = Gen.elements [ 0 ; 1 ; 100 ; -1 ; -2 ]
                return platform, privileged, count, buffer, milliseconds
            }

        let property
            (
                platform : SimulatedUnixPlatform,
                privileged : bool,
                count : uint32,
                buffer : UserBuffer,
                milliseconds : int
            )
            : bool
            =
            let system, _ = world privileged platform

            let fds : CopiedArgument<PollEntry list> =
                match buffer with
                | UserBuffer.Unmapped address -> CopiedArgument.Unmapped address
                | UserBuffer.Opaque -> CopiedArgument.Opaque
                | UserBuffer.Addressless -> CopiedArgument.Addressless
                | UserBuffer.Mapped -> failwith "the generator makes no readable array"

            let answer = poll (fds, count) milliseconds system

            // What the buffer decides, once the count has passed the screen.
            let byBuffer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal> =
                match buffer with
                | UserBuffer.Unmapped _ -> Ok (PollOutcome.Failed UnixError.EFAULT, system)
                | UserBuffer.Opaque -> Error (PollRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
                | UserBuffer.Addressless -> Error (PollRefusal.Buffer BufferRefusal.AddresslessAtTransfer)
                | UserBuffer.Mapped -> failwith "unreachable"

            if count = 0u then
                // Linux checks the address of no entries against its limit
                // as it writes them back, after polling (section Y).
                let limit =
                    match UnixMachineState.userBufferCheck (Kernel.machine system) with
                    | UserBufferCheck.BeforeOperation limit -> Some limit
                    | UserBufferCheck.AtCopyTime -> None

                // Measured on exactly these kernels, and refused elsewhere.
                let measured =
                    match SimulatedUnixPlatform.kernel platform, SimulatedUnixPlatform.architecture platform with
                    | SimulatedUnixKernel.Linux (version, _), architecture ->
                        let v = version.Major, version.Minor, version.Patch

                        match architecture with
                        | SimulatedUnixArchitecture.Arm64 -> v = (6u, 18u, 5u)
                        | SimulatedUnixArchitecture.X64 -> v = (6u, 12u, 113u) || v = (6u, 18u, 5u)
                    | SimulatedUnixKernel.Darwin _, _ -> false

                match buffer, limit with
                | UserBuffer.Unmapped address, Some limit when address > limit && not measured ->
                    answer = Error (
                        PollRefusal.UnmeasuredZeroEntryAddress (
                            address,
                            SimulatedUnixPlatform.kernel platform,
                            SimulatedUnixPlatform.architecture platform
                        )
                    )
                | UserBuffer.Unmapped address, Some limit when address > limit ->
                    if milliseconds = 0 then
                        answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)
                    else
                        answer = Error (PollRefusal.UnmodelledWriteBackFault (address, milliseconds))
                | UserBuffer.Addressless, Some _ -> answer = Error PollRefusal.AddresslessZeroEntryArray
                | _ -> isEmptyPoll system milliseconds answer
            else
                match expectedScreen platform privileged count with
                | Screen.Einval -> answer = Ok (PollOutcome.Failed UnixError.EINVAL, system)
                | Screen.Refused ->
                    match answer with
                    | Error (PollRefusal.UnmodelledEntryCount (flavour, refused, _)) ->
                        flavour = SimulatedUnixPlatform.flavour platform && refused = count
                    | _ -> false
                | Screen.Passes -> answer = byBuffer

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen gen) property)

    [<Test>]
    let ``a readable array stops at its copy, naming eight bytes an entry`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxArm64 ; SimulatedUnixPlatform.macOsArm64 ] do
            let system, writeEnd = world false platform
            let caller = Callers.thread thread system

            match UnixPoll.tryPoll caller UserBuffer.Mapped 3u 0 system with
            | Ok (CallProgress.NeedsCopyIn paused) ->
                PausedPoll.count paused |> shouldEqual 3

                PausedPoll.copyRange paused
                |> shouldEqual
                    {
                        FirstByte = 0
                        ByteCount = 24
                    }

                let entries =
                    [
                        {
                            PollEntry.Fd = -1
                            Events = pollIn
                        }
                        {
                            PollEntry.Fd = writeEnd
                            Events = pollOut
                        }
                        {
                            PollEntry.Fd = -1
                            Events = pollIn
                        }
                    ]

                UnixPoll.tryPollWithEntries entries paused
                |> Result.map fst
                |> shouldEqual (Ok (PollOutcome.Answered ([ 0s ; pollOut ; 0s ], 1)))

                (fun () -> UnixPoll.tryPollWithEntries (List.take 2 entries) paused |> ignore)
                |> shouldFail<InvalidOperationException>
            | other -> failwith $"%A{platform}: a readable array of three entries answered %A{other}"

    [<Test>]
    let ``a zero-entry poll past the address limit is refused where unmeasured`` () : unit =
        let unmeasured =
            [
                linuxAt SimulatedUnixArchitecture.Arm64 LinuxKernelBuild.SmallBuffer960 (6u, 17u, 0u)
                linuxAt SimulatedUnixArchitecture.Arm64 LinuxKernelBuild.SmallBuffer832 (6u, 18u, 6u)
                linuxX64At (6u, 17u, 0u)
                linuxX64At (6u, 18u, 6u)
            ]

        let measured =
            [ linuxArm64_6_18_5 ; linuxX64At (6u, 12u, 113u) ; linuxX64At (6u, 18u, 5u) ]

        let pastTheLimit (platform : SimulatedUnixPlatform) : uint64 =
            match SimulatedUnixPlatform.architecture platform with
            | SimulatedUnixArchitecture.Arm64 -> ObservedUserAddressLimit.Arm64FortyEightBit + 1UL
            | SimulatedUnixArchitecture.X64 -> ObservedUserAddressLimit.X64FourLevelPaging + 1UL

        for platform in unmeasured do
            let system, _ = world false platform
            let address = pastTheLimit platform

            poll (unmappedArrayAt address 0u) 0 system
            |> shouldEqual (
                Error (
                    PollRefusal.UnmeasuredZeroEntryAddress (
                        address,
                        SimulatedUnixPlatform.kernel platform,
                        SimulatedUnixPlatform.architecture platform
                    )
                )
            )

        for platform in measured do
            let system, _ = world false platform

            poll (unmappedArrayAt (pastTheLimit platform) 0u) 0 system
            |> shouldEqual (Ok (PollOutcome.Failed UnixError.EFAULT, system))

    /// A poll that changes nothing hands back the very system it was made
    /// in, through its pause as through no pause, so that a client comparing
    /// systems by reference (as `UnixWait.wake`'s memo does) sees no change.
    [<Test>]
    let ``a poll that changes nothing hands back the system it was made in`` () : unit =
        for platform in [ linuxArm64_6_18_5 ; darwin27_2 ] do
            let system, _ = world false platform

            let idle =
                [
                    {
                        PollEntry.Fd = -1
                        Events = pollIn
                    }
                ]

            for fds, nfds in [ readableArray idle ; readableArray [] ; unmappedArrayAt 8UL 1u ] do
                match PollCall.tryPollCopied (Callers.thread thread system) fds nfds 0 system with
                | Ok (_, after) ->
                    if not (obj.ReferenceEquals (after, system)) then
                        failwith $"%A{platform}: a poll of %A{fds} changed nothing but handed back another system"
                | Error refusal -> failwith $"%A{platform}: refused %A{refusal}"
