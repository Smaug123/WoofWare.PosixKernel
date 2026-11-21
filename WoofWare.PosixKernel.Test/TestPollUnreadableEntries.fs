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
        Regex @"^([OZYPW]) (.+) nfds=(\d+) timeout=(-?\d+) rv=(-?\d+) errno=(.+) slept=(yes|no) revents0=(\S+)$"

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

    /// The array of a `poll`, and its `nfds`, as `Syscall.Poll` holds them.
    type private PollArray = CopiedArgument<PollEntry list> * uint32

    /// An array of `count` entries at `address`, which names no storage, as
    /// a client passes an array the process can read only in part.
    let private unmappedArrayAt (address : uint64) (count : uint32) : PollArray = CopiedArgument.Unmapped address, count

    /// `unmappedArrayAt` the probe's unmapped address, 8.
    let private unmappedArray (count : uint32) : PollArray = unmappedArrayAt 8UL count

    /// The address a probe row's label names: NULL, the probe's unmapped
    /// address (8), a `PROT_NONE` page (somewhere below the user address
    /// limit; the probe does not print it, and no answer depends on it), or
    /// the address written out.
    let private addressOf (label : string) : uint64 =
        match label with
        | "null" -> 0UL
        | "unmapped" -> 8UL
        | "prot-none" -> 0x10_0000UL
        | _ when label.StartsWith "addr=0x" -> UInt64.Parse (label.Substring 7, Globalization.NumberStyles.HexNumber)
        | _ -> failwith $"no address for the label %s{label}"

    /// A readable array holding `entries`.
    let private readableArray (entries : PollEntry list) : PollArray =
        CopiedArgument.Readable entries, uint32 (List.length entries)

    /// `poll` of `argument` through the public protocol (`UnixPoll.tryPoll`,
    /// then `tryPollWithEntries` if it stops at the copy), checked to agree
    /// with `UnixSystem.tryStep` of the same call.
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
            let mutable skipped = 0

            let count (section : string) : unit =
                replayed <- replayed |> Map.change section (fun n -> Some (1 + Option.defaultValue 0 n))

            for row in rows run do
                let system, writeEnd = world run.Privileged run.Platform

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
                        | 0 -> not row.Slept && answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)
                        | timeout ->
                            row.Slept
                            && answer = Error (PollRefusal.UnmodelledWriteBackFault (address, timeout))

                    judge run system (unmappedArrayAt address 0u) row expected
                    count "Y"
                | "Z"
                | "Y" ->
                    // No entries are read, so an unreadable array of none is
                    // answered as an empty one, sleeping where it would sleep.
                    let asEmpty = poll (readableArray []) row.Timeout system

                    let expected (answer : Result<PollOutcome * UnixSystem<int, string>, PollRefusal>) : bool =
                        answer = asEmpty
                        && match answer with
                           | Ok (PollOutcome.Answered ([], 0), after) -> after = system && row.Rv = 0 && row.Timeout = 0
                           // The finite wait ends at its deadline, with 0; the
                           // infinite one is ended by the probe's timer.
                           | Ok (PollOutcome.WouldBlock _, _) ->
                               row.Slept
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
                        // Readable for its first entries and not the rest.
                        judge run system (unmappedArray row.Count) row (faulted system row)

                    count "P"
                | "W" ->
                    // A readable array whose `revents` cannot be written back,
                    // which this library does not model.
                    skipped <- skipped + 1
                | other -> failwith $"%s{run.Name}: unknown section %s{other}"

            // Section O: 6 counts, at NULL and unmapped, at two timeouts.
            // Section Z: 3 addresses at 3 timeouts. Section Y: 4 addresses at
            // 5 counts and timeouts. Section P: 17 values of k, 3 cuts, 2
            // leads. Section W: 2 rows.
            replayed |> shouldEqual (Map.ofList [ "O", 24 ; "P", 102 ; "Y", 20 ; "Z", 9 ])

            skipped |> shouldEqual 2

    /// The partly-readable rows of section P are answered EFAULT by the
    /// measured kernel: a ready lead is not reported, an idle lead under
    /// timeout -1 does not sleep (it would end in EINTR), and entry 0's
    /// revents keeps the value set beforehand.
    [<Test>]
    let ``a partly readable array was measured to fault without reporting or sleeping`` () : unit =
        for run in runs do
            let partial =
                rows run
                |> List.filter (fun row -> row.Section = "P" && not (row.Label.Contains "cut=none"))

            List.length partial |> shouldEqual 68

            for row in partial do
                if row.Errno <> "Bad address" || row.Revents0 <> "0x5a5a" then
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
                @"^S k=(\d+) cut=(no-poll|none|entry) lead=udp nfds=(\d+) timeout=0 rv=(-?\d+) errno=(.+) charge-after=(\d+) revents0=(\S+)$"

        let payload = ImmutableArray.CreateRange (Array.create 1000 (byte 'r'))
        let msgDontWait = 0x40

        for run in runs |> List.filter (fun run -> run.Name.StartsWith "linux") do
            let measured =
                run.Lines
                |> List.choose (fun line ->
                    let m = pattern.Match line

                    if m.Success then
                        Some (
                            int m.Groups.[1].Value,
                            m.Groups.[2].Value,
                            int m.Groups.[4].Value,
                            m.Groups.[5].Value,
                            int m.Groups.[6].Value
                        )
                    else
                        None
                )

            List.length measured |> shouldEqual 9

            for k, cut, rv, errno, charge in measured do
                let system, _ = world run.Privileged run.Platform
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

                let answered, system =
                    match cut with
                    | "no-poll" -> (0, "-"), system
                    | _ ->
                        let argument =
                            match cut with
                            | "none" -> readableArray (lead :: List.replicate (k - 1) idle)
                            | _ -> unmappedArray (uint32 (k + 1))

                        match poll argument 0 system with
                        | Ok (PollOutcome.Answered (_, count), system) -> (count, "-"), system
                        | Ok (PollOutcome.Failed UnixError.EFAULT, system) -> (-1, "Bad address"), system
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

                (k, cut, answered, modelledCharge) |> shouldEqual (k, cut, (rv, errno), charge)

    /// Section H: Linux reads only the low 32 bits of a wider `nfds_t`, so a
    /// client gives `Unreadable` the count those bits hold.
    [<Test>]
    let ``Linux reads the low 32 bits of nfds, as measured`` () : unit =
        let pattern =
            Regex @"^H (null|unmapped) nfds=(\d+) timeout=0 rv=(-?\d+) errno=(.+)$"

        for run in runs |> List.filter (fun run -> run.Name.StartsWith "linux") do
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

            List.length measured |> shouldEqual 6

            for address, nfds, rv, errno in measured do
                nfds |> shouldBeGreaterThan (uint64 UInt32.MaxValue)
                let system, _ = world run.Privileged run.Platform
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

                match buffer, limit with
                | UserBuffer.Unmapped address, Some limit when address > limit ->
                    if milliseconds = 0 then
                        answer = Ok (PollOutcome.Failed UnixError.EFAULT, system)
                    else
                        answer = Error (PollRefusal.UnmodelledWriteBackFault (address, milliseconds))
                | UserBuffer.Addressless, Some _ ->
                    answer = Error (PollRefusal.Buffer BufferRefusal.AddresslessAtScreen)
                | _ -> answer = poll (readableArray []) milliseconds system
            elif count <= 1100u then
                // The same count of readable entries, none of which reports.
                let readable =
                    poll
                        (readableArray (
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
                | Error (PollRefusal.UnmodelledEntryCount _) -> answer = readable
                | _ -> answer = byBuffer
            else
                match PollEntryCount.screen platform (privilegeOf privileged) count with
                | Ok (Some error) -> answer = Ok (PollOutcome.Failed error, system)
                | Error refusal -> answer = Error refusal
                | Ok None -> answer = byBuffer

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
