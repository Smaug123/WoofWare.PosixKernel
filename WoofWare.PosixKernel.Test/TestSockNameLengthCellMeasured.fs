namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// When `getsockname(2)` and `getpeername(2)` read the caller's length cell,
/// and what they answer when it cannot be read: every row of
/// `docs/probes/sockname-length-cell`, measured on Linux 6.18.5 (aarch64, under
/// Apple's `container`) and Darwin 27.2.0, replayed against a platform running
/// the kernel that measured it, through the paused protocol.
///
/// A row through a NULL or unmapped cell that still answers its errno shows
/// the errno is decided before the cell is read; one that answers EFAULT shows
/// the cell is read first.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSockNameLengthCellMeasured =

    /// How a row gives the length cell or the address buffer.
    [<RequireQualifiedAccess>]
    type private Pointer =
        | Null
        | Unmapped
        /// Real storage; for the cell, holding this `int`.
        | Holds of value : int

    /// One row of a probe output.
    type private Row =
        {
            Line : string
            Call : string
            Fixture : string
            Cell : Pointer
            Destination : Pointer
            /// The errno's name, or `OK`.
            Answer : string
            /// What the cell held afterwards, where it is real storage.
            CellAfter : int option
            /// How many bytes of a mapped address buffer the call overwrote,
            /// through either of the probe's two fills.
            Written : int
        }

    /// One probe output: the kernel it ran on, and its rows.
    type private Measurement =
        {
            Resource : string
            Platform : SimulatedUnixPlatform
            Rows : Row list
            /// What the probe's connect to port 0 answered as it built
            /// `udp-port-zero`: `OK` or the errno's name.
            PortZeroConnect : string
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
            @"^(getsockname|getpeername) (\S+) cell=(null|unmapped|-?[0-9]+) dest=(null|unmapped|mapped) -> (\S+) cellafter=(-|-?[0-9]+) written=([0-9]+)$"

    let private pointer (text : string) : Pointer =
        match text with
        | "null" -> Pointer.Null
        | "unmapped" -> Pointer.Unmapped
        | "mapped" -> Pointer.Holds 0
        | held -> Pointer.Holds (Int32.Parse held)

    let private measurement (resource : string) : Measurement =
        let name = $"WoofWare.PosixKernel.Test.sockname-length-cell.%s{resource}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        let lines =
            reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> Array.map (fun line -> line.TrimEnd '\r')
            |> List.ofArray

        match lines with
        | [] -> failwith $"%s{resource} is empty"
        | header :: rest ->
            {
                Resource = resource
                Platform = platformOf resource header
                PortZeroConnect =
                    let prefix = "# udp-port-zero: connect to port 0 -> "

                    match rest |> List.filter (fun line -> line.StartsWith prefix) with
                    | [ line ] -> line.Substring prefix.Length
                    | other -> failwith $"%s{resource}: expected one port-zero connect line, got %A{other}"
                Rows =
                    rest
                    |> List.filter (fun line -> not (line.StartsWith '#'))
                    |> List.map (fun line ->
                        let m = rowPattern.Match line

                        if not m.Success then
                            failwith $"%s{resource}: unparsed row %s{line}"

                        {
                            Line = line
                            Call = m.Groups.[1].Value
                            Fixture = m.Groups.[2].Value
                            Cell = pointer m.Groups.[3].Value
                            Destination = pointer m.Groups.[4].Value
                            Answer = m.Groups.[5].Value
                            CellAfter =
                                match m.Groups.[6].Value with
                                | "-" -> None
                                | value -> Some (Int32.Parse value)
                            Written = Int32.Parse m.Groups.[7].Value
                        }
                    )
            }

    let private measurements : Lazy<Measurement list> =
        lazy (resources |> List.map measurement)

    // ------------------------------------------------------------------
    // The fixtures, built as the probe builds them
    // ------------------------------------------------------------------

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private listenerPort : uint16 = 5000us

    /// Nothing listens or is bound here in any system these tests build.
    let private nobody : Ipv4Endpoint = loopback 5999us

    let private fresh (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private socket
        (domain : SocketDomain)
        (kind : SocketKind)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        NewSocket.create domain kind SocketProtocol.Default system

    let private bindAt (fd : int) (endpoint : Ipv4Endpoint) (system : UnixSystem<int, string>) =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) endpoint) system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"binding fd %d{fd} to %O{endpoint} answered %A{other}"

    let private connect
        (fd : int)
        (destination : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        match CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) destination) system with
        | Ok answer -> answer
        | Error refusal -> failwith $"connect refused: %s{ConnectRefusal.describe refusal}"

    let private listener (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system = socket SocketDomain.Inet SocketKind.Stream system
        let system = bindAt fd (loopback listenerPort) system

        match UnixSocket.tryListen (Callers.leader system) fd 4 system with
        | Ok (ListenAnswer.Listening _, system) -> fd, system
        | other -> failwith $"listen answered %A{other}"

    let private accept (listener : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixConnection.tryAccept (Callers.leader system) listener UserBuffer.Mapped (Some 16u) 0 system with
        | Ok (AcceptOutcome.Accepted (fd, _), system) -> fd, system
        | other -> failwith $"accept answered %A{other}"

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed _, system) -> system
        | other -> failwith $"close of fd %d{fd} answered %A{other}"

    let private shutWrite (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixConnection.tryShutdown (Callers.leader system) fd 1 system with
        | Ok (ShutdownAnswer.Shut, system) -> system
        | other -> failwith $"shutdown(%d{fd}, SHUT_WR) answered %A{other}"

    let private lingerZero (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let platform = UnixSystem.platform system
        let value = OptionValue.ofLinger 1 0

        match
            SockOptCalls.set
                fd
                (SimulatedUnixPlatform.socketOptionLevel platform)
                (SimulatedUnixPlatform.lingerOption platform)
                UserBuffer.Mapped
                (uint32 value.Length)
                (fun count -> ImmutableArray.Create (Seq.toArray value, 0, count))
                system
        with
        | Ok (SetSockOptAnswer.Set, system) -> system
        | other -> failwith $"setsockopt(SO_LINGER) on fd %d{fd} answered %A{other}"

    /// `system` once a `getsockopt(SO_ERROR)` on `fd` has taken the error
    /// pending there, failing the test unless one was.
    let private takeError (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let platform = UnixSystem.platform system

        match
            SockOptCalls.get
                fd
                (SimulatedUnixPlatform.socketOptionLevel platform)
                (SimulatedUnixPlatform.socketErrorOption platform)
                UserBuffer.Mapped
                UserBuffer.Mapped
                4u
                system
        with
        | Ok (GetSockOptAnswer.Reported (OptionValue.Int error), system) when error <> 0 -> system
        | other -> failwith $"getsockopt(SO_ERROR) on fd %d{fd} answered %A{other}"

    /// A client connected to a listener, the server end accepted, and both
    /// descriptors.
    let private connected (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        let l, system = listener system
        let c, system = socket SocketDomain.Inet SocketKind.Stream system
        let answer, system = connect c (loopback listenerPort) system
        answer |> shouldEqual (SyscallAnswer.Completed 0L)
        let s, system = accept l system
        c, s, system

    /// The probe's fixture `fixture` in `measurement`, as its descriptor and
    /// the system it is in, or `None` for one this library cannot build.
    let private build (fixture : string) (measurement : Measurement) : (int * UnixSystem<int, string>) option =
        let system = fresh measurement.Platform

        match fixture with
        | "closed" ->
            let fd, system = socket SocketDomain.Inet SocketKind.Stream system
            Some (fd, close fd system)
        // Descriptor 0 is a pipe end in a booted system.
        | "pipe" -> Some (0, system)
        | "tcp-fresh" -> Some (socket SocketDomain.Inet SocketKind.Stream system)
        | "tcp-listening" -> Some (listener system)
        | "tcp-connected" ->
            let c, _, system = connected system
            Some (c, system)
        | "tcp-refused" ->
            let c, system = socket SocketDomain.Inet SocketKind.Stream system
            let answer, system = connect c nobody system
            answer |> shouldEqual (SyscallAnswer.Failed UnixError.ECONNREFUSED)
            Some (c, system)
        | "tcp-refusal-pending" ->
            let c, system = socket SocketDomain.Inet SocketKind.Stream system
            let system = NonBlocking.set c system
            let answer, system = connect c nobody system
            answer |> shouldEqual (SyscallAnswer.Failed UnixError.EINPROGRESS)
            Some (c, system)
        | "tcp-refusal-taken" ->
            let c, system = socket SocketDomain.Inet SocketKind.Stream system
            let system = NonBlocking.set c system
            let answer, system = connect c nobody system
            answer |> shouldEqual (SyscallAnswer.Failed UnixError.EINPROGRESS)
            Some (c, takeError c system)
        | "tcp-reset" ->
            let c, s, system = connected system
            Some (c, system |> lingerZero s |> close s)
        | "tcp-reset-taken" ->
            let c, s, system = connected system
            Some (c, system |> lingerZero s |> close s |> takeError c)
        | "tcp-fins-exchanged" ->
            let c, s, system = connected system
            Some (c, system |> shutWrite c |> shutWrite s)
        | "udp-fresh" -> Some (socket SocketDomain.Inet SocketKind.Datagram system)
        | "udp-connected" ->
            let r, system = socket SocketDomain.Inet SocketKind.Datagram system
            let system = bindAt r (loopback 5001us) system
            let s, system = socket SocketDomain.Inet SocketKind.Datagram system
            let answer, system = connect s (loopback 5001us) system
            answer |> shouldEqual (SyscallAnswer.Completed 0L)
            Some (s, system)
        | "udp-port-zero" ->
            // Linux connects; Darwin answers EADDRNOTAVAIL and leaves the
            // socket fresh. The model's connect must answer as the probe's did.
            let s, system = socket SocketDomain.Inet SocketKind.Datagram system
            let answer, system = connect s (loopback 0us) system

            let shown =
                match answer with
                | SyscallAnswer.Completed 0L -> "OK"
                | SyscallAnswer.Failed error -> $"%A{error}"
                | other -> failwith $"the connect to port 0 answered %A{other}"

            shown |> shouldEqual measurement.PortZeroConnect
            Some (s, system)
        | "inet6-stream-fresh" -> Some (socket SocketDomain.Inet6 SocketKind.Stream system)
        | "inet6-dgram-fresh" -> Some (socket SocketDomain.Inet6 SocketKind.Datagram system)
        | "unix-stream-fresh" -> Some (socket SocketDomain.Unix SocketKind.Stream system)
        | "unix-dgram-fresh" -> Some (socket SocketDomain.Unix SocketKind.Datagram system)
        | "unix-seqpacket-fresh" -> Some (socket SocketDomain.Unix SocketKind.SeqPacket system)
        // `socketpair(2)` has no function here.
        | "unix-socketpair" -> None
        | other -> failwith $"unknown fixture %s{other}"

    /// The fixtures whose own address this library does not model, so that a
    /// `getsockname` which reaches the address is refused.
    let private unnamed : Set<string> =
        Set.ofList
            [
                "inet6-dgram-fresh"
                "unix-stream-fresh"
                "unix-dgram-fresh"
                "unix-seqpacket-fresh"
            ]

    /// An address the probe's unmapped page might have had: this library takes
    /// any unmapped address the same way.
    let private unmappedPage : uint64 = 0x10000UL

    let private buffer (pointer : Pointer) : UserBuffer =
        match pointer with
        | Pointer.Null -> UserBuffer.Unmapped 0UL
        | Pointer.Unmapped -> UserBuffer.Unmapped unmappedPage
        | Pointer.Holds _ -> UserBuffer.Mapped

    /// What the model's answer would make the probe print, as the probe
    /// prints it after `->`.
    let private shown (row : Row) (answer : GetSockNameAnswer) : string * int option * int =
        let held =
            match row.Cell with
            | Pointer.Holds value -> Some value
            | Pointer.Null
            | Pointer.Unmapped -> None

        match answer with
        | GetSockNameAnswer.Reported (copied, reported) ->
            let written =
                match row.Destination with
                | Pointer.Holds _ -> copied.Length
                | Pointer.Null
                | Pointer.Unmapped ->
                    if copied.Length <> 0 then
                        failwith $"%s{row.Line}: the model copied %d{copied.Length} bytes out through no storage"

                    0

            "OK", held |> Option.map (fun _ -> reported), written
        | GetSockNameAnswer.Failed (error, overwritten) ->
            let after =
                match held, overwritten with
                | Some _, Some stored -> Some stored
                | Some value, None -> Some value
                | None, Some stored ->
                    failwith $"%s{row.Line}: the model stored %d{stored} in a cell that is no storage"
                | None, None -> None

            $"%A{error}", after, 0

    /// The rows through a NULL or unmapped cell, by call and fixture, each with
    /// the one answer every destination gave.
    let private beforeTheCell (measurement : Measurement) : Map<string * string, string> =
        measurement.Rows
        |> List.filter (fun row ->
            match row.Cell with
            | Pointer.Null
            | Pointer.Unmapped -> true
            | Pointer.Holds _ -> false
        )
        |> List.groupBy (fun row -> row.Call, row.Fixture)
        |> List.map (fun (key, rows) ->
            match rows |> List.map (fun row -> row.Answer) |> List.distinct with
            | [ answer ] -> key, answer
            | answers -> failwith $"%s{measurement.Resource}: %A{key} answered %A{answers} by destination"
        )
        |> Map.ofList

    /// How many of `measurement`'s rows the model answered as measured, and
    /// how many it refused, failing the test at any other row.
    let private replayed (measurement : Measurement) : int * int =
        let mutable compared = 0
        let mutable refused = 0
        let control = beforeTheCell measurement

        for row in measurement.Rows do
            match build row.Fixture measurement with
            | None -> ()
            | Some (fd, system) ->
                // The call stops for the client to read the cell where the cell
                // is real storage and the probe's NULL-cell row of the same call
                // and fixture answered EFAULT, which shows the kernel reads it.
                let shouldStop =
                    match row.Cell with
                    | Pointer.Holds _ -> Map.find (row.Call, row.Fixture) control = "EFAULT"
                    | Pointer.Null
                    | Pointer.Unmapped -> false

                let stops =
                    let caller = Callers.leader system
                    let destination = buffer row.Destination
                    let length = buffer row.Cell

                    match row.Call with
                    | "getsockname" ->
                        match UnixSocket.tryGetsockname caller fd destination length system with
                        | Ok (CallProgress.NeedsCopyIn _) -> true
                        | Ok (CallProgress.Answered _)
                        | Error _ -> false
                    | _ ->
                        match UnixSocket.tryGetpeername caller fd destination length system with
                        | Ok (CallProgress.NeedsCopyIn _) -> true
                        | Ok (CallProgress.Answered _)
                        | Error _ -> false

                if stops <> shouldStop then
                    failwith
                        $"%s{measurement.Resource}: %s{row.Line}\n  the call stopped for the length cell: %b{stops}, where the probe's NULL-cell row says %b{shouldStop}"

                let call =
                    match row.Call with
                    | "getsockname" -> SockNameCalls.getsockname
                    | _ -> SockNameCalls.getpeername

                let cell =
                    match row.Cell with
                    | Pointer.Holds value -> uint32 value
                    | Pointer.Null
                    | Pointer.Unmapped -> 0u

                match call (Callers.leader system) fd (buffer row.Destination) (buffer row.Cell) cell system with
                | Ok answer ->
                    let measured = row.Answer, row.CellAfter, row.Written
                    let modelled = shown row answer

                    if modelled <> measured then
                        failwith
                            $"%s{measurement.Resource}: %s{row.Line}\n  the model answered %A{answer}, which the probe would print as %A{modelled}"

                    compared <- compared + 1
                | Error refusal ->
                    // Only a call that reaches an address this library does not
                    // model may be refused, and only once it has the cell.
                    match refusal, row.Cell with
                    | (GetSockNameRefusal.UnmodelledDomain _ | GetSockNameRefusal.UnmodelledInet6Kind _),
                      Pointer.Holds _ when row.Call = "getsockname" && Set.contains row.Fixture unnamed ->
                        refused <- refused + 1
                    | _ ->
                        failwith
                            $"%s{measurement.Resource}: %s{row.Line}\n  the model refused: %s{GetSockNameRefusal.describe refusal}"

        compared, refused

    [<Test>]
    let ``every measured row of either flavour is answered as measured, or refused where the address is unmodelled``
        ()
        : unit
        =
        for measurement in measurements.Value do
            // Not vacuous: each output holds 30 rows, 15 per call, for each of
            // 20 fixtures on Linux and 19 on Darwin, which has no Unix-domain
            // SOCK_SEQPACKET. The 30 of `unix-socketpair` cannot be built here.
            // Of the `getsockname` rows of each fixture in `unnamed`, the 9
            // through a cell of real storage reach the unmodelled address,
            // except on Linux the 3 holding -1, which answer EINVAL first.
            let rows, refusedRows =
                match SimulatedUnixPlatform.flavour measurement.Platform with
                | SimulatedUnixFlavour.Linux -> 20 * 30, 4 * 6
                | SimulatedUnixFlavour.Darwin -> 19 * 30, 3 * 9

            measurement.Rows |> List.length |> shouldEqual rows
            replayed measurement |> shouldEqual (rows - 30 - refusedRows, refusedRows)

    [<Test>]
    let ``the probe measured what its docstrings claim: which answers come before each kernel reads the cell`` () =
        // The rows the library's comments cite, as the literal table they
        // summarise: a NULL or unmapped cell answers the descriptor's and the
        // missing peer's errno on both flavours, and EFAULT otherwise, whatever
        // the destination.
        let expected (flavour : SimulatedUnixFlavour) : Map<string * string, string> =
            let noPeer =
                match flavour with
                | SimulatedUnixFlavour.Linux -> "ENOTCONN"
                | SimulatedUnixFlavour.Darwin -> "EINVAL"

            let peer (fixture : string) : string =
                match fixture with
                | "closed" -> "EBADF"
                | "pipe" -> "ENOTSOCK"
                | "tcp-connected"
                | "udp-connected"
                | "unix-socketpair" -> "EFAULT"
                | "tcp-refused"
                | "tcp-refusal-pending"
                | "tcp-refusal-taken"
                | "tcp-reset"
                | "tcp-reset-taken"
                | "tcp-fins-exchanged" -> noPeer
                | _ -> "ENOTCONN"

            let name (fixture : string) : string =
                match fixture with
                | "closed" -> "EBADF"
                | "pipe" -> "ENOTSOCK"
                | _ -> "EFAULT"

            [
                "closed"
                "pipe"
                "tcp-fresh"
                "tcp-listening"
                "tcp-connected"
                "tcp-refused"
                "tcp-refusal-pending"
                "tcp-refusal-taken"
                "tcp-reset"
                "tcp-reset-taken"
                "tcp-fins-exchanged"
                "udp-fresh"
                "udp-connected"
                "udp-port-zero"
                "inet6-stream-fresh"
                "inet6-dgram-fresh"
                "unix-stream-fresh"
                "unix-dgram-fresh"
                if flavour = SimulatedUnixFlavour.Linux then
                    "unix-seqpacket-fresh"
                "unix-socketpair"
            ]
            |> List.collect (fun fixture ->
                [
                    ("getsockname", fixture), name fixture
                    ("getpeername", fixture), peer fixture
                ]
            )
            |> Map.ofList

        for measurement in measurements.Value do
            beforeTheCell measurement
            |> shouldEqual (expected (SimulatedUnixPlatform.flavour measurement.Platform))
