namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// When `accept(2)` reads the caller's length cell, what it answers when the
/// cell cannot be read, and what becomes of the connection: every row of
/// `docs/probes/accept-length-cell`, measured on Linux 6.18.5 (aarch64, under
/// Apple's `container`) and Darwin 27.2.0, replayed against a platform running
/// the kernel that measured it, through the paused protocol.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestAcceptLengthCellMeasured =

    /// How a row gives the length cell or the address buffer.
    [<RequireQualifiedAccess>]
    type private Pointer =
        | Null
        | Unmapped
        /// Real storage; for the cell, holding this `int`.
        | Holds of value : int

    /// What the probe printed after `->`, as named fields.
    type private Printed = Map<string, string>

    /// One row of a probe output: its section, its fixture, its pointers, and
    /// what the probe printed.
    type private Row =
        {
            Line : string
            Section : string
            Fixture : string
            Cell : Pointer
            /// For section C, what another thread wrote to the cell while the
            /// call slept.
            ChangedTo : int option
            Destination : Pointer
            Answer : string
            Printed : Printed
        }

    type private Measurement =
        {
            Resource : string
            Platform : SimulatedUnixPlatform
            Rows : Row list
        }

    let private resources : string list =
        [ "darwin-27.2.0-arm64.txt" ; "linux-6.18.5-aarch64.txt" ]

    let private platformOf (resource : string) (header : string) : SimulatedUnixPlatform =
        match header.Split ' ' |> List.ofArray with
        | [ "uname:" ; "Darwin" ; release ; "arm64" ] ->
            let version =
                match DarwinRelease.version release with
                | Some version -> version
                | None -> failwith $"%s{resource}: release %s{release} names no version"

            SimulatedUnixPlatform.createOrFail
                resource
                (SimulatedUnixKernel.Darwin version)
                SimulatedUnixArchitecture.Arm64
                SimulatedPageSize.SixteenKiB
                release
        | [ "uname:" ; "Linux" ; release ; "aarch64" ] ->
            let version =
                match LinuxRelease.version release with
                | Some version -> version
                | None -> failwith $"%s{resource}: release %s{release} names no version"

            SimulatedUnixPlatform.createOrFail
                resource
                (SimulatedUnixKernel.Linux (version, LinuxKernelBuild.SmallBuffer832))
                SimulatedUnixArchitecture.Arm64
                SimulatedPageSize.FourKiB
                release
        | _ -> failwith $"%s{resource}: unexpected header %s{header}"

    let private rowPattern : Regex =
        Regex
            @"^([ABC])(?: ([a-z0-9-]+))? cell=(null|unmapped|-?[0-9]+)(?: changed-to=(-?[0-9]+))? dest=(null|unmapped|mapped) -> (\S+)((?: [a-z]+=\S+)*)$"

    let private pointer (text : string) : Pointer =
        match text with
        | "null" -> Pointer.Null
        | "unmapped" -> Pointer.Unmapped
        | "mapped" -> Pointer.Holds 0
        | held -> Pointer.Holds (Int32.Parse held)

    let private measurement (resource : string) : Measurement =
        let name = $"WoofWare.PosixKernel.Test.accept-length-cell.%s{resource}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        match
            reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> List.ofArray
        with
        | [] -> failwith $"%s{resource} is empty"
        | header :: rest ->
            {
                Resource = resource
                Platform = platformOf resource header
                Rows =
                    rest
                    |> List.map (fun line ->
                        let m = rowPattern.Match line

                        if not m.Success then
                            failwith $"%s{resource}: unparsed row %s{line}"

                        let printed =
                            m.Groups.[7].Value.Split (' ', StringSplitOptions.RemoveEmptyEntries)
                            |> Array.map (fun field ->
                                match field.Split '=' with
                                | [| key ; value |] -> key, value
                                | _ -> failwith $"%s{resource}: unparsed field %s{field}"
                            )
                            |> Map.ofArray

                        {
                            Line = line
                            Section = m.Groups.[1].Value
                            Fixture =
                                if m.Groups.[2].Success then
                                    m.Groups.[2].Value
                                else
                                    "blocking-empty"
                            Cell = pointer m.Groups.[3].Value
                            ChangedTo =
                                if m.Groups.[4].Success then
                                    Some (Int32.Parse m.Groups.[4].Value)
                                else
                                    None
                            Destination = pointer m.Groups.[5].Value
                            Answer = m.Groups.[6].Value
                            Printed = printed
                        }
                    )
            }

    let private measurements : Lazy<Measurement list> =
        lazy (resources |> List.map measurement)

    // ------------------------------------------------------------------
    // The fixtures, built as the probe builds them
    // ------------------------------------------------------------------

    let private listenerPort : uint16 = 5000us

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private fresh (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private socket (kind : SocketKind) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        NewSocket.create SocketDomain.Inet kind SocketProtocol.Default system

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed _, system) -> system
        | other -> failwith $"close of fd %d{fd} answered %A{other}"

    let private listener (nonBlocking : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system = socket SocketKind.Stream system

        let system =
            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet (UnixSystem.platform system) (loopback listenerPort))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"binding the listener: %A{other}"

        let system =
            match UnixSocket.tryListen (Callers.leader system) fd 4 system with
            | Ok (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"listen answered %A{other}"

        fd, (if nonBlocking then NonBlocking.set fd system else system)

    let private connectClient (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system = socket SocketKind.Stream system

        match
            CopyIn.connect
                fd
                UserBuffer.Mapped
                16u
                (CopyIn.inet (UnixSystem.platform system) (loopback listenerPort))
                system
        with
        | Ok (SyscallAnswer.Completed 0L, system) -> fd, system
        | other -> failwith $"connecting a client: %A{other}"

    let private queued (fd : int) (system : UnixSystem<int, string>) : bool =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            match (UnixMachineState.socket socketId (Kernel.machine system)).Phase with
            | SocketPhase.Listening listenState -> not (List.isEmpty (ListenState.connections listenState))
            | phase -> failwith $"fd %d{fd} is %A{phase}, not listening"
        | other -> failwith $"fd %d{fd} names %A{other}, not a socket"

    /// What the client `fd` sees, as the probe prints it: `eof` for a read
    /// answering 0, `none` for one that would block, or the errno's name.
    let private clientView (fd : int) (system : UnixSystem<int, string>) : string =
        let system = NonBlocking.set fd system

        match ReadOutcomes.read fd UserBuffer.Mapped 1UL system with
        | Ok (ReadAnswer.Completed bytes, _) when bytes.IsEmpty -> "eof"
        | Ok (ReadAnswer.Completed _, _) -> "data"
        | Ok (ReadAnswer.Failed UnixError.EAGAIN, _) -> "none"
        | Ok (ReadAnswer.Failed error, _) -> $"%A{error}"
        | other -> failwith $"the client's read answered %A{other}"

    /// A section A fixture: the descriptor the call is made on, the client
    /// connected to it if any, and the system.
    let private build
        (fixture : string)
        (platform : SimulatedUnixPlatform)
        : int * int option * UnixSystem<int, string>
        =
        let system = fresh platform

        match fixture with
        | "closed" ->
            let fd, system = socket SocketKind.Stream system
            fd, None, close fd system
        // Descriptor 0 is a pipe end in a booted system.
        | "pipe" -> 0, None, system
        | "tcp-idle" ->
            let fd, system = socket SocketKind.Stream system
            fd, None, NonBlocking.set fd system
        | "udp" ->
            let fd, system = socket SocketKind.Datagram system
            fd, None, NonBlocking.set fd system
        | "listener-empty" ->
            let fd, system = listener true system
            fd, None, system
        | "listener-queued"
        | "accept4-bad-flags" ->
            let fd, system = listener true system
            let client, system = connectClient system
            fd, Some client, system
        | other -> failwith $"unknown fixture %s{other}"

    let private buffer (pointer : Pointer) : UserBuffer =
        match pointer with
        | Pointer.Null -> UserBuffer.Unmapped 0UL
        | Pointer.Unmapped -> UserBuffer.Unmapped 0x10000UL
        | Pointer.Holds _ -> UserBuffer.Mapped

    let private contents (pointer : Pointer) : uint32 =
        match pointer with
        | Pointer.Holds value -> uint32 value
        | Pointer.Null
        | Pointer.Unmapped -> 0u

    /// What the probe would print for `outcome`: the answer, the cell after,
    /// and the bytes written.
    let private shown (row : Row) (held : int option) (outcome : AcceptOutcome) : string * string * int =
        let cellText (value : int option) =
            match value with
            | Some value -> string<int> value
            | None -> "-"

        match outcome with
        | AcceptOutcome.Accepted (_, PeerAddressCopy.Written (copied, reported)) ->
            let written =
                match row.Destination with
                | Pointer.Holds _ -> copied.Length
                | Pointer.Null
                | Pointer.Unmapped -> 0

            "OK", cellText (held |> Option.map (fun _ -> reported)), written
        | AcceptOutcome.Accepted (_, PeerAddressCopy.NotRequested) -> "OK", cellText held, 0
        | AcceptOutcome.Failed error
        | AcceptOutcome.DroppedConnection error -> $"%A{error}", cellText held, 0
        | other -> failwith $"%s{row.Line}: the model answered %A{other}"

    let private stops (progress : Result<CallProgress<PausedAccept<int, string>, _>, AcceptRefusal>) : bool =
        match progress with
        | Ok (CallProgress.NeedsCopyIn _) -> true
        | Ok (CallProgress.Answered _)
        | Error _ -> false

    /// The answers of the rows through a NULL cell, by section, fixture and
    /// destination: EFAULT there is how the probe shows that the kernel reads
    /// the cell.
    let private nullCell (measurement : Measurement) : Map<string * string * Pointer, string> =
        measurement.Rows
        |> List.filter (fun row -> row.Cell = Pointer.Null)
        |> List.map (fun row -> (row.Section, row.Fixture, row.Destination), row.Answer)
        |> Map.ofList

    let private fail (measurement : Measurement) (row : Row) (message : string) : 'a =
        failwith $"%s{measurement.Resource}: %s{row.Line}\n  %s{message}"

    /// Section A: a call that cannot sleep.
    let private replayA (measurement : Measurement) (control : Map<string * string * Pointer, string>) (row : Row) =
        let fd, client, system = build row.Fixture measurement.Platform
        let flags = if row.Fixture = "accept4-bad-flags" then 1 else 0
        let destination = buffer row.Destination
        let cell = buffer row.Cell

        let held =
            match row.Cell with
            | Pointer.Holds value -> Some value
            | Pointer.Null
            | Pointer.Unmapped -> None

        // The call stops for the cell where the cell is real storage and the
        // probe's NULL-cell row for the same fixture and destination answered
        // EFAULT, which shows the kernel reads it.
        let shouldStop =
            held.IsSome
            && Map.find (row.Section, row.Fixture, row.Destination) control = "EFAULT"

        let stopped =
            stops (UnixConnection.tryAccept (Callers.leader system) fd destination cell flags system)

        if stopped <> shouldStop then
            fail
                measurement
                row
                $"the call stopped for the length cell: %b{stopped}, where the probe says %b{shouldStop}"

        match
            AcceptCalls.tryAcceptThrough (Callers.leader system) fd destination cell (contents row.Cell) flags system
        with
        | Error refusal ->
            // Only a fault while the peer's address is copied out is refused.
            match refusal with
            | AcceptRefusal.UnmeasuredCopyOutFault _ when row.Destination = Pointer.Unmapped -> false
            | _ -> fail measurement row $"the model refused: %s{AcceptRefusal.describe refusal}"
        | Ok (outcome, after) ->
            let answer, cellAfter, written = shown row held outcome

            let measured =
                row.Answer, row.Printed.["cellafter"], Int32.Parse row.Printed.["written"]

            if (answer, cellAfter, written) <> measured then
                fail
                    measurement
                    row
                    $"the model answered %A{outcome}, which the probe would print as %A{(answer, cellAfter, written)}"

            match client with
            | None -> ()
            | Some client ->
                // The probe closes a descriptor the call made at once.
                let after =
                    match outcome with
                    | AcceptOutcome.Accepted (accepted, _) -> close accepted after
                    | _ -> after

                let modelled = clientView client after, (if queued fd after then "yes" else "no")
                let printed = row.Printed.["client"], row.Printed.["queued"]

                if modelled <> printed then
                    fail measurement row $"the client saw and the queue held %A{modelled}"

            true

    /// Sections B and C: a call that sleeps on an empty blocking listener, a
    /// client connecting while it does, and for C, the cell holding
    /// `ChangedTo` by the time the call finishes.
    let private replaySleep (measurement : Measurement) (row : Row) : unit =
        let flavour = SimulatedUnixPlatform.flavour measurement.Platform
        let fd, system = listener false (fresh measurement.Platform)
        let system = Threads.ensure 1 system
        let caller = Callers.thread 1 system
        let destination = buffer row.Destination
        let cell = buffer row.Cell

        let held =
            match row.Cell with
            | Pointer.Holds value -> Some value
            | Pointer.Null
            | Pointer.Unmapped -> None

        let atFinish = row.ChangedTo |> Option.orElse held

        match AcceptCalls.tryAcceptThrough caller fd destination cell (contents row.Cell) 0 system with
        | Error refusal -> fail measurement row $"the model refused: %s{AcceptRefusal.describe refusal}"
        | Ok (AcceptOutcome.WouldBlock _, asleep) ->
            if row.Printed.["slept"] <> "yes" then
                fail measurement row "the model slept, and the probe did not"

            let client, asleep = connectClient asleep
            let woken = Lone.wake asleep |> snd

            // A Linux call reads its cell only now, and stops for it where it
            // is real storage; a Darwin one read it before it slept.
            let shouldStop =
                flavour = SimulatedUnixFlavour.Linux
                && held.IsSome
                && row.Destination <> Pointer.Null

            let stopped = stops (UnixConnection.tryFinishAccept caller woken)

            if stopped <> shouldStop then
                fail measurement row $"the finishing call stopped for the cell: %b{stopped}"

            match
                AcceptCalls.tryFinishAccept (atFinish |> Option.defaultValue 0 |> uint32) (Callers.thread 1 woken) woken
            with
            | Error refusal ->
                fail measurement row $"the finishing call was refused: %s{AcceptRefusal.describe refusal}"
            | Ok (outcome, after) ->
                let answer, cellAfter, written = shown row atFinish outcome

                if answer <> row.Answer || written <> Int32.Parse row.Printed.["written"] then
                    fail measurement row $"the model finished with %A{outcome}"

                match row.Printed |> Map.tryFind "cellafter" with
                | Some printed when printed <> cellAfter ->
                    fail measurement row $"the model leaves the cell holding %s{cellAfter}"
                | _ -> ()

                let after =
                    match outcome with
                    | AcceptOutcome.Accepted (accepted, _) -> close accepted after
                    | _ -> after

                let modelled = clientView client after, (if queued fd after then "yes" else "no")

                if modelled <> (row.Printed.["client"], row.Printed.["queued"]) then
                    fail measurement row $"the client saw and the queue held %A{modelled}"
        | Ok (outcome, after) ->
            if row.Printed.["slept"] <> "no" then
                fail measurement row $"the model answered %A{outcome} without sleeping"

            let answer, _, written = shown row held outcome

            if answer <> row.Answer || written <> Int32.Parse row.Printed.["written"] then
                fail measurement row $"the model answered %A{outcome}"

            // The client connects later, and finds the queue as the call left
            // it.
            let client, after = connectClient after
            let modelled = clientView client after, (if queued fd after then "yes" else "no")

            if modelled <> (row.Printed.["client"], row.Printed.["queued"]) then
                fail measurement row $"the client saw and the queue held %A{modelled}"

    [<Test>]
    let ``every measured row of either flavour is answered as measured`` () : unit =
        for measurement in measurements.Value do
            let control = nullCell measurement
            let mutable compared = 0
            let mutable refused = 0

            for row in measurement.Rows do
                match row.Section with
                | "A" ->
                    if replayA measurement control row then
                        compared <- compared + 1
                    else
                        refused <- refused + 1
                | _ ->
                    replaySleep measurement row
                    compared <- compared + 1

            // Not vacuous: section A holds 15 rows for each of six fixtures,
            // and Linux's accept4 a seventh; B 4 and C 3. The refused rows are
            // those of the queued listener through an unmapped destination
            // whose copy would fault: the cell holding 16 on both, and holding
            // -1 on Darwin, which reads it as a length; Linux answers EINVAL
            // for that, and a length of 0 copies nothing on either.
            let fixtures, refusedRows =
                match SimulatedUnixPlatform.flavour measurement.Platform with
                | SimulatedUnixFlavour.Linux -> 7, 1
                | SimulatedUnixFlavour.Darwin -> 6, 2

            let rows = 15 * fixtures + 4 + 3
            measurement.Rows |> List.length |> shouldEqual rows
            (compared, refused) |> shouldEqual (rows - refusedRows, refusedRows)
