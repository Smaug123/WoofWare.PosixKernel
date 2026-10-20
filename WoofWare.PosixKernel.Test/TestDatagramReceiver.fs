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

/// One call on a UDP receiver.
[<RequireQualifiedAccess>]
type internal DatagramReceiverOp =
    /// A datagram of `length` bytes arrives, while the socket is `connected`
    /// or not.
    | Arrive of length : int * connected : bool
    /// `count` datagrams of `length` bytes arrive, the socket unconnected.
    | Flood of length : int * count : int
    | Receive of call : DatagramReceiveCall * count : int
    /// `FIONREAD`.
    | Query
    /// A Linux `poll` of a blocking socket, which refills its reader queue.
    | Polled
    /// The socket sends a datagram.
    | Sent
    /// An ICMP error reaches the socket.
    | Refused
    /// `getsockopt(SO_ERROR)`.
    | TakeError

/// What one call answered, in a form both the library and the reference give.
[<RequireQualifiedAccess>]
type internal DatagramReceiverSeen =
    | Arrived of queued : bool
    /// How many of a flood's datagrams were queued.
    | Flooded of queued : int
    /// A datagram: the source port that names it, the bytes given, and what the call returned.
    | Datagram of id : uint16 * given : int * returned : int
    | Zero
    | Empty
    | Failed of UnixError
    | Available of int
    | Done
    | Error of UnixError option

/// A naive statement of each flavour's receive accounting, held to the
/// library's `DatagramReceiver`.
///
/// Written from section 2.4 of `docs/plans/2026-10-18-udp-data-path.md`
/// rather than from the library: every datagram held is one entry in one list,
/// oldest first, with a flag for whether Linux's reader queue holds it, and
/// every total is recomputed from the list.
[<RequireQualifiedAccess>]
module internal DatagramReceiverReference =

    type Entry =
        {
            Id : uint16
            Length : int
            Bytes : int
            Mbufs : int
            InReader : bool
        }

    type Model =
        {
            Linux : bool
            Buffer : int
            Held : Entry list
            /// Linux's charge taken and not given back.
            Owed : int
            /// Darwin: the socket has sent or received.
            Active : bool
            Error : bool
        }

    let create (linux : bool) (buffer : int) : Model =
        {
            Linux = linux
            Buffer = buffer
            Held = []
            Owed = 0
            Active = false
            Error = false
        }

    let private linuxTruesize (length : int) : int =
        if length < 198 then 832
        elif length < 646 then 1280
        elif length < 1670 then 2304
        elif length < 3718 then 4352
        elif length < 7814 then 8448
        elif length < 16005 then 16640
        else length + 832

    let private darwinMbufs (bare : bool) (length : int) : int =
        // The table of section 2.4, row by row.
        let rows =
            [
                0, 0, 2048, 1536
                1, 256, 1536, 1024
                257, 288, 3584, 1536
                289, 2016, 3584, 3584
                2017, 2048, 5632, 3584
                2049, 4064, 5632, 5632
                4065, 4096, 10240, 5632
                4097, 8160, 10240, 10240
                8161, 8192, 14848, 10240
                8193, 9216, 14848, 14848
            ]

        let _, _, full, bareCharge =
            rows |> List.find (fun (low, high, _, _) -> low <= length && length <= high)

        if bare then bareCharge else full

    let charged (m : Model) : int =
        (m.Held |> List.sumBy (fun e -> e.Bytes)) + m.Owed

    let mbufs (m : Model) : int = m.Held |> List.sumBy (fun e -> e.Mbufs)

    let private refill (m : Model) : Model =
        if m.Linux && not (List.exists (fun e -> e.InReader) m.Held) then
            { m with
                Held =
                    m.Held
                    |> List.map (fun e ->
                        { e with
                            InReader = true
                        }
                    )
            }
        else
            m

    let arrive (id : uint16) (length : int) (connected : bool) (m : Model) : bool * Model =
        if m.Linux then
            let size = linuxTruesize length

            if charged m + size > m.Buffer then
                false, m
            else
                true,
                { m with
                    Held =
                        m.Held
                        @ [
                            {
                                Id = id
                                Length = length
                                Bytes = size
                                Mbufs = 0
                                InReader = false
                            }
                        ]
                }
        else
            let bare = not m.Active && not connected
            let bytes = length + (if bare then 16 else 32)

            if charged m + bytes > m.Buffer || mbufs m + bytes > min (8 * m.Buffer) 8388608 then
                false, m
            else
                true,
                { m with
                    Held =
                        m.Held
                        @ [
                            {
                                Id = id
                                Length = length
                                Bytes = bytes
                                Mbufs = darwinMbufs bare length
                                InReader = false
                            }
                        ]
                    Active = true
                }

    let private takeOldest (m : Model) : Entry * Model =
        let m = refill m

        match m.Held with
        | [] -> failwith "reference: nothing to take"
        | oldest :: rest ->
            if m.Linux then
                let owed = m.Owed + oldest.Bytes
                let readerLeft = rest |> List.exists (fun e -> e.InReader)

                oldest,
                { m with
                    Held = rest
                    Owed = (if owed >= m.Buffer / 4 || not readerLeft then 0 else owed)
                }
            else
                oldest,
                { m with
                    Held = rest
                }

    let receive (call : DatagramReceiveCall) (count : int) (m : Model) : DatagramReceiverSeen * Model =
        let peek, truncate =
            match call with
            | DatagramReceiveCall.Read -> false, false
            | DatagramReceiveCall.Receive (peek, truncate) -> peek, truncate

        let datagram () =
            let entry, after =
                if peek then
                    let m = refill m
                    List.head m.Held, m
                else
                    takeOldest m

            let returned =
                if m.Linux && truncate then
                    entry.Length
                else
                    min count entry.Length

            DatagramReceiverSeen.Datagram (entry.Id, min count entry.Length, returned), after

        if m.Linux then
            match call with
            | DatagramReceiveCall.Read when count = 0 -> DatagramReceiverSeen.Zero, m
            | _ ->
                if m.Error then
                    DatagramReceiverSeen.Failed UnixError.ECONNREFUSED,
                    { m with
                        Error = false
                    }
                elif not m.Held.IsEmpty then
                    datagram ()
                else
                    DatagramReceiverSeen.Empty, m
        else if not m.Held.IsEmpty then
            datagram ()
        elif m.Error then
            DatagramReceiverSeen.Failed UnixError.ECONNREFUSED,
            { m with
                Error = false
            }
        elif count = 0 then
            DatagramReceiverSeen.Zero, m
        else
            DatagramReceiverSeen.Empty, m

    let query (m : Model) : int * Model =
        let m = refill m

        if m.Linux then
            (match m.Held with
             | oldest :: _ -> oldest.Length
             | [] -> 0),
            m
        else
            charged m, m

    let apply (id : uint16) (op : DatagramReceiverOp) (m : Model) : DatagramReceiverSeen * Model =
        match op with
        | DatagramReceiverOp.Arrive (length, connected) ->
            let queued, m = arrive id length connected m
            DatagramReceiverSeen.Arrived queued, m
        | DatagramReceiverOp.Flood (length, count) ->
            let queued, m =
                List.fold
                    (fun (queued, m) _ ->
                        let arrived, m = arrive id length false m
                        (if arrived then queued + 1 else queued), m
                    )
                    (0, m)
                    [ 1..count ]

            DatagramReceiverSeen.Flooded queued, m
        | DatagramReceiverOp.Receive (call, count) -> receive call count m
        | DatagramReceiverOp.Query ->
            let available, m = query m
            DatagramReceiverSeen.Available available, m
        | DatagramReceiverOp.Polled -> DatagramReceiverSeen.Done, refill m
        | DatagramReceiverOp.Sent ->
            DatagramReceiverSeen.Done,
            { m with
                Active = true
            }
        | DatagramReceiverOp.Refused ->
            DatagramReceiverSeen.Done,
            { m with
                Error = true
            }
        | DatagramReceiverOp.TakeError ->
            if m.Error then
                DatagramReceiverSeen.Error (Some UnixError.ECONNREFUSED),
                { m with
                    Error = false
                }
            else
                DatagramReceiverSeen.Error None, m

/// `DatagramReceiver`: each flavour's rule for how many datagrams a UDP
/// socket holds and what each receive takes, replayed from the probes in
/// `docs/plans/2026-10-18-udp-data-path/` and held to a naive reference over
/// random calls.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramReceiver =

    let private linuxBuffer : int = 212992
    let private darwinBuffer : int = 786896

    let private fresh (flavour : SimulatedUnixFlavour) : DatagramReceiver =
        match flavour with
        | SimulatedUnixFlavour.Linux -> DatagramReceiver.create flavour linuxBuffer
        | SimulatedUnixFlavour.Darwin -> DatagramReceiver.create flavour darwinBuffer

    let private source (id : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback id

    let private payload (length : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Array.init length (fun i -> byte (i % 251)))

    let private resource (name : string) : string list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.toList
        |> List.map (fun line -> line.TrimEnd '\r')

    let private arrive (length : int) (receiver : DatagramReceiver) : bool * DatagramReceiver =
        match DatagramReceiver.arrive false (source 9us) (payload length) receiver with
        | DatagramArrival.Queued, after -> true, after
        | DatagramArrival.Dropped, after -> false, after

    let private take (receiver : DatagramReceiver) : DatagramReceiver =
        match DatagramReceiver.receive (DatagramReceiveCall.Receive (false, false)) 65536 receiver with
        | DatagramReceiveAnswer.Datagram _, after -> after
        | answer, _ -> failwith $"expected a datagram to take, got %A{answer}"

    /// How many datagrams of `length` an unread receiver holds, after one
    /// datagram of 1 byte was taken first if `primed`.
    let private holds (flavour : SimulatedUnixFlavour) (primed : bool) (length : int) : int =
        let start =
            if primed then
                fresh flavour |> arrive 1 |> snd |> take
            else
                fresh flavour

        let rec fill (count : int) (receiver : DatagramReceiver) : int =
            match arrive length receiver with
            | true, after -> fill (count + 1) after
            | false, _ -> count

        fill 0 start

    // ------------------------------------------------------------ capacity

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``an unread receiver holds as many datagrams as udp-capacity.c measured`` (which : string) : unit =
        let flavour, name =
            match which with
            | "linux" -> SimulatedUnixFlavour.Linux, "WoofWare.PosixKernel.Test.udpCapacity.linux.txt"
            | _ -> SimulatedUnixFlavour.Darwin, "WoofWare.PosixKernel.Test.udpCapacity.darwin.txt"

        let rows =
            resource name
            |> List.collect (fun line ->
                let probe =
                    Regex.Match (line, @"^size (\d+): unpaced (\d+), (\d+); paced (\d+); primed (\d+)$")

                let step = Regex.Match (line, @"^size (\d+) holds (\d+); size (\d+) holds (\d+)$")

                let checkedRow =
                    Regex.Match (line, @"^size (\d+): fresh (\d+)(?: \(formula \d+\))?, primed (\d+)")

                let int (m : Match) (i : int) = Int32.Parse m.Groups.[i].Value

                if probe.Success then
                    [
                        int probe 1, false, int probe 2
                        int probe 1, false, int probe 3
                        int probe 1, false, int probe 4
                        int probe 1, true, int probe 5
                    ]
                elif step.Success then
                    [ int step 1, false, int step 2 ; int step 3, false, int step 4 ]
                elif checkedRow.Success then
                    [
                        int checkedRow 1, false, int checkedRow 2
                        int checkedRow 1, true, int checkedRow 3
                    ]
                else
                    []
            )
            |> List.distinct

        rows.Length |> shouldBeGreaterThan 20

        for length, primed, measured in rows do
            (length, primed, holds flavour primed length)
            |> shouldEqual (length, primed, measured)

    [<Test>]
    let ``Linux charges each datagram the truesize udp-truesize.c read`` () : unit =
        let lines = resource "WoofWare.PosixKernel.Test.udpTruesize.linux.txt"

        let steps =
            lines
            |> List.choose (fun line ->
                let m = Regex.Match (line, @"^charge: size (\d+) is (\d+); size (\d+) is (\d+)$")

                if m.Success then
                    Some
                        [
                            for i in [ 1 ; 3 ] -> Int32.Parse m.Groups.[i].Value, Int32.Parse m.Groups.[i + 1].Value
                        ]
                else
                    None
            )
            |> List.concat

        steps.Length |> shouldBeGreaterThan 10

        for length, charge in steps do
            (length, DatagramAccounting.linuxCharge length) |> shouldEqual (length, charge)

        // Above the staircase, the sampled sizes.
        for length in 16005..97..65507 do
            DatagramAccounting.linuxCharge length |> shouldEqual (length + 832)

        // Each fill: the charge each, how many were admitted, the final charge.
        let fills =
            lines
            |> List.choose (fun line ->
                let m =
                    Regex.Match (
                        line,
                        @"^fill (\d+): charge each (\d+); admitted (\d+) .* admissions against the rule 0; final charge (\d+)$"
                    )

                if m.Success then
                    Some (
                        Int32.Parse m.Groups.[1].Value,
                        Int32.Parse m.Groups.[2].Value,
                        Int32.Parse m.Groups.[3].Value,
                        Int32.Parse m.Groups.[4].Value
                    )
                else
                    None
            )

        fills.Length |> shouldEqual 9

        for length, each, admitted, final in fills do
            DatagramAccounting.linuxCharge length |> shouldEqual each
            holds SimulatedUnixFlavour.Linux false length |> shouldEqual admitted
            admitted * each |> shouldEqual final

    [<Test>]
    let ``Linux gives a taken datagram's charge back as udp-truesize.c's release rows measured`` () : unit =
        let lines = resource "WoofWare.PosixKernel.Test.udpTruesize.linux.txt"

        let filled (count : int) =
            List.fold (fun receiver _ -> arrive 1000 receiver |> snd) (fresh SimulatedUnixFlavour.Linux) [ 1..count ]

        // The charge after each take from a fill of 92.
        let afterEach =
            lines
            |> List.pick (fun line ->
                let prefix = "release: 92 datagrams of 1000 held, charge 211968; after each take: "

                if line.StartsWith prefix then
                    Some (line.Substring(prefix.Length).Split ' ' |> Array.map Int32.Parse |> Array.toList)
                else
                    None
            )

        afterEach.Length |> shouldEqual 92

        let modelled =
            List.scan (fun receiver _ -> take receiver) (filled 92) [ 1..92 ]
            |> List.tail
            |> List.map DatagramReceiver.charged

        modelled |> shouldEqual afterEach

        // Take one, send one, from 40 held.
        let pairs =
            lines
            |> List.pick (fun line ->
                let prefix =
                    "release: 40 held; take one, send one, 30 times; charge after each pair, and whether the send was queued: "

                if line.StartsWith prefix then
                    Some (line.Substring(prefix.Length).Split ' ' |> Array.map Int32.Parse |> Array.toList)
                else
                    None
            )

        let modelledPairs =
            List.scan (fun receiver _ -> receiver |> take |> arrive 1000 |> snd) (filled 40) [ 1..30 ]
            |> List.tail
            |> List.map DatagramReceiver.charged

        modelledPairs |> shouldEqual pairs

        // A full receiver, partly drained.
        for line in lines do
            let m =
                Regex.Match (
                    line,
                    @"^release: 92 of 1000 held, (\d+) taken \(charge then (\d+)\): (\d+) more admitted$"
                )

            if m.Success then
                let taken = Int32.Parse m.Groups.[1].Value
                let drained = List.fold (fun receiver _ -> take receiver) (filled 92) [ 1..taken ]
                DatagramReceiver.charged drained |> shouldEqual (Int32.Parse m.Groups.[2].Value)

                let more =
                    List.fold
                        (fun (count, receiver) _ ->
                            match arrive 1000 receiver with
                            | true, after -> count + 1, after
                            | false, after -> count, after
                        )
                        (0, drained)
                        [ 1..100 ]
                    |> fst

                more |> shouldEqual (Int32.Parse m.Groups.[3].Value)

    [<Test>]
    let ``Linux's reader queue refills on the calls udp-release.c found refilling it`` () : unit =
        let rows =
            resource "WoofWare.PosixKernel.Test.udpRelease.linux.txt"
            |> List.choose (fun line ->
                let m =
                    Regex.Match (
                        line,
                        @"^(.*) \(answered .*\): charge (\d+) before the takes, (\d+) after (\d+) takes$"
                    )

                if m.Success then
                    Some (m.Groups.[1].Value, Int32.Parse m.Groups.[3].Value, Int32.Parse m.Groups.[4].Value)
                else
                    None
            )

        rows.Length |> shouldEqual 9

        for call, after, takes in rows do
            // What the row's call does before the second ten arrive, and after.
            let between (receiver : DatagramReceiver) : DatagramReceiver =
                match call with
                | "no call"
                | "poll(POLLIN) on a non-blocking socket"
                | "epoll_wait (registered before the arrivals) on a non-blocking socket" -> receiver
                | "FIONREAD" -> DatagramReceiver.queried receiver |> snd
                | "poll(POLLIN) on a blocking socket"
                | "epoll_ctl(ADD, EPOLLIN) on a blocking socket"
                | "epoll_wait (registered before the arrivals) on a blocking socket" ->
                    DatagramReceiver.refilled receiver
                | "recv(MSG_PEEK)" ->
                    DatagramReceiver.receive (DatagramReceiveCall.Receive (true, false)) 2000 receiver
                    |> snd
                | "FIONREAD, then one take, then the ten more, then FIONREAD" ->
                    receiver |> DatagramReceiver.queried |> snd |> take
                | other -> failwith $"udp-release.c row %s{other} has no replay"

            let afterwards (receiver : DatagramReceiver) : DatagramReceiver =
                match call with
                | "FIONREAD, then one take, then the ten more, then FIONREAD" ->
                    DatagramReceiver.queried receiver |> snd
                | _ -> receiver

            let ten (receiver : DatagramReceiver) =
                List.fold (fun receiver _ -> arrive 1000 receiver |> snd) receiver [ 1..10 ]

            let ended =
                fresh SimulatedUnixFlavour.Linux
                |> ten
                |> between
                |> ten
                |> afterwards
                |> fun receiver -> List.fold (fun receiver _ -> take receiver) receiver [ 1..takes ]

            (call, DatagramReceiver.charged ended) |> shouldEqual (call, after)

    // ------------------------------------------------------------ Darwin's charges

    [<Test>]
    let ``Darwin charges each datagram the bytes and mbufs udp-mbufs.c read`` () : unit =
        let lines = resource "WoofWare.PosixKernel.Test.udpMbufs.darwin.txt"

        let runs =
            lines
            |> List.choose (fun line ->
                let m =
                    Regex.Match (
                        line,
                        @"^1 sizes (\d+)\.\.(\d+): first datagram cc \+size\+(\d+) mbcnt \+(\d+); second cc \+size\+(\d+) mbcnt \+(\d+)$"
                    )

                if m.Success then
                    Some [ for i in 1..6 -> Int32.Parse m.Groups.[i].Value ]
                else
                    None
            )

        runs.Length |> shouldEqual 10

        for run in runs do
            match run with
            | [ low ; high ; firstBytes ; firstMbufs ; laterBytes ; laterMbufs ] ->
                for length in low..high do
                    (length, DatagramAccounting.darwinBytes true length, DatagramAccounting.darwinMbufs true length)
                    |> shouldEqual (length, length + firstBytes, firstMbufs)

                    (length, DatagramAccounting.darwinBytes false length, DatagramAccounting.darwinMbufs false length)
                    |> shouldEqual (length, length + laterBytes, laterMbufs)
            | _ -> failwith "unreachable"

        // The runs cover every length a default Darwin socket sends.
        runs |> List.sumBy (fun run -> run.[1] - run.[0] + 1) |> shouldEqual 9217

        DatagramAccounting.darwinMbufBudget darwinBuffer |> shouldEqual 6295168

    [<Test>]
    let ``Darwin's cheaper charge goes to a socket that has not sent, received or connected, as udp-mbufs.c found``
        ()
        : unit
        =
        let rows =
            resource "WoofWare.PosixKernel.Test.udpMbufs.darwin.txt"
            |> List.choose (fun line ->
                let m =
                    Regex.Match (line, @"^2 (.*): first datagram arrived, cc \+(\d+) mbcnt \+(\d+); the next arrived")

                if m.Success then
                    Some (m.Groups.[1].Value, Int32.Parse m.Groups.[2].Value)
                else
                    None
            )

        rows.Length |> shouldEqual 28

        for history, firstBytes in rows do
            // What the history did to the receiver, and whether it is connected
            // when the datagram arrives.
            let receiver, connected =
                let receiver = fresh SimulatedUnixFlavour.Darwin

                match history with
                | "nothing"
                | "getsockname"
                | "SO_REUSEADDR"
                | "a non-blocking recv on its empty queue"
                | "poll"
                | "FIONREAD"
                | "the sender connected to it first"
                | "bind only (the fresh receiver is bound)"
                | "connect, then AF_UNSPEC"
                // A failed connect, and a call that never reaches the socket.
                | "connect to port 0 (EADDRNOTAVAIL)"
                | "sendto to a closed descriptor (EBADF)"
                | "recv of 0 on its empty queue" -> receiver, false
                | "connect to a bound socket"
                | "connect to the sender, which sends" -> receiver, true
                | "sendto another socket"
                | "sendto another socket, then AF_UNSPEC"
                | "connect, send, then AF_UNSPEC"
                // A send call that reached the socket, whatever it answered.
                | "send(2) unconnected (EDESTADDRREQ)"
                | "write(2) unconnected (EDESTADDRREQ)"
                | "sendto of 9217 bytes (EMSGSIZE)"
                | "sendto from an unmapped buffer (EFAULT)"
                | "sendto with a 15-byte address (EINVAL)"
                | "sendto to family 99 (EAFNOSUPPORT)"
                | "sendto to 0.0.0.0 (EHOSTUNREACH)"
                | "send of 0 bytes, connected to the sender" -> DatagramReceiver.sent receiver, false
                | "sendto itself (the datagram it then receives)" -> DatagramReceiver.sent receiver, false
                | "a datagram from another sender, taken"
                | "a datagram taken, then AF_UNSPEC" -> receiver |> arrive 4 |> snd |> take, false
                | other -> failwith $"udp-mbufs.c section 2 row %s{other} has no replay"

            let before = DatagramReceiver.charged receiver

            match DatagramReceiver.arrive connected (source 9us) (payload 4) receiver with
            | DatagramArrival.Queued, after ->
                (history, DatagramReceiver.charged after - before)
                |> shouldEqual (history, firstBytes)
            | DatagramArrival.Dropped, _ -> failwith $"%s{history}: the datagram was dropped"

    [<Test>]
    let ``Darwin keeps what udp-mbufs.c's mixture of five large datagrams and many small ones kept`` () : unit =
        let line =
            resource "WoofWare.PosixKernel.Test.udpMbufs.darwin.txt"
            |> List.find (fun line -> line.StartsWith "3 five of 9216 then 1737 of 257: ")

        let m = Regex.Match (line, @": (\d+) arrived; cc (\d+) mbcnt (\d+)$")

        let arrived, receiver =
            List.replicate 5 9216 @ List.replicate 1737 257
            |> List.fold
                (fun (count, receiver) length ->
                    match arrive length receiver with
                    | true, after -> count + 1, after
                    | false, after -> count, after
                )
                (0, fresh SimulatedUnixFlavour.Darwin)

        (arrived, DatagramReceiver.charged receiver, DatagramReceiver.mbufsCharged receiver)
        |> shouldEqual (Int32.Parse m.Groups.[1].Value, Int32.Parse m.Groups.[2].Value, Int32.Parse m.Groups.[3].Value)

    // ------------------------------------------------------------ FIONREAD

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``FIONREAD follows udp-transfer.c's sequence F5`` (which : string) : unit =
        let flavour, name =
            match which with
            | "linux" -> SimulatedUnixFlavour.Linux, "WoofWare.PosixKernel.Test.udpTransfer.linux.txt"
            | _ -> SimulatedUnixFlavour.Darwin, "WoofWare.PosixKernel.Test.udpTransfer.darwin.txt"

        let line = resource name |> List.find (fun line -> line.StartsWith "F5 sequence:")

        let steps =
            line.Substring("F5 sequence:".Length).Trim().Split ' '
            |> Array.map (fun step ->
                let m = Regex.Match (step, @"^(\+(\d+)|-)=(\d+)")

                (if m.Groups.[2].Success then
                     Some (Int32.Parse m.Groups.[2].Value)
                 else
                     None),
                Int32.Parse m.Groups.[3].Value
            )
            |> Array.toList

        steps.Length |> shouldEqual 15

        List.fold
            (fun receiver (step, measured) ->
                let receiver =
                    match step with
                    | Some length -> arrive length receiver |> snd
                    | None -> take receiver

                let available, receiver = DatagramReceiver.queried receiver
                available |> shouldEqual measured
                receiver
            )
            (fresh flavour)
            steps
        |> ignore

    // ------------------------------------------------------------ receives

    let private receiving (flavour : SimulatedUnixFlavour) (lengths : int list) : DatagramReceiver =
        lengths
        |> List.fold (fun receiver length -> arrive length receiver |> snd) (fresh flavour)

    let private answer
        (call : DatagramReceiveCall)
        (count : int)
        (receiver : DatagramReceiver)
        : string * DatagramReceiver
        =
        match DatagramReceiver.receive call count receiver with
        | DatagramReceiveAnswer.Datagram (bytes, returned, _), after -> $"%d{bytes.Length}/%d{returned}", after
        | DatagramReceiveAnswer.Zero, after -> "0", after
        | DatagramReceiveAnswer.Empty, after -> "empty", after
        | DatagramReceiveAnswer.Failed error, after -> $"%O{error}", after

    let private recv : DatagramReceiveCall = DatagramReceiveCall.Receive (false, false)

    let private truncating : DatagramReceiveCall =
        DatagramReceiveCall.Receive (false, true)

    let private peek : DatagramReceiveCall = DatagramReceiveCall.Receive (true, false)

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``receives answer as udp-transfer.c sections B to D measured`` (which : string) : unit =
        let flavour, linux =
            match which with
            | "linux" -> SimulatedUnixFlavour.Linux, true
            | _ -> SimulatedUnixFlavour.Darwin, false

        // B1: boundaries.
        let receiver = receiving flavour [ 10 ; 20 ; 30 ]
        let a, receiver = answer recv 100 receiver
        let b, receiver = answer recv 100 receiver
        let c, receiver = answer recv 100 receiver
        let d, _ = answer recv 100 receiver
        [ a ; b ; c ; d ] |> shouldEqual [ "10/10" ; "20/20" ; "30/30" ; "empty" ]

        // C1: a short receive discards the rest.
        let a, receiver = answer recv 10 (receiving flavour [ 100 ; 4 ])
        let b, _ = answer recv 200 receiver
        [ a ; b ] |> shouldEqual [ "10/10" ; "4/4" ]

        // C2: MSG_TRUNC.
        fst (answer truncating 10 (receiving flavour [ 100 ]))
        |> shouldEqual (if linux then "10/100" else "10/10")

        // C3 and C5: a zero-length recv takes the datagram; Linux's
        // zero-length read leaves it.
        let a, receiver = answer recv 0 (receiving flavour [ 100 ])
        [ a ; fst (answer recv 200 receiver) ] |> shouldEqual [ "0/0" ; "empty" ]

        let a, receiver = answer DatagramReceiveCall.Read 0 (receiving flavour [ 100 ])

        [ a ; fst (answer recv 200 receiver) ]
        |> shouldEqual (if linux then [ "0" ; "100/100" ] else [ "0/0" ; "empty" ])

        // C4: a zero-length recv with MSG_TRUNC.
        fst (answer truncating 0 (receiving flavour [ 100 ]))
        |> shouldEqual (if linux then "0/100" else "0/0")

        // C6: a zero-length recv of nothing.
        fst (answer recv 0 (fresh flavour))
        |> shouldEqual (if linux then "empty" else "0")

        // D1: peeks leave both datagrams.
        let receiver = receiving flavour [ 20 ; 3 ]
        let a, receiver = answer peek 10 receiver
        let b, receiver = answer peek 100 receiver
        let c, receiver = answer (DatagramReceiveCall.Receive (true, true)) 10 receiver

        [ a ; b ; c ]
        |> shouldEqual [ "10/10" ; "20/20" ; (if linux then "10/20" else "10/10") ]

        DatagramReceiver.held receiver
        |> List.map (fun d -> d.Payload.Length)
        |> shouldEqual [ 20 ; 3 ]

        // E1 and E2: an empty datagram.
        let a, receiver = answer recv 100 (receiving flavour [ 0 ])
        [ a ; fst (answer recv 100 receiver) ] |> shouldEqual [ "0/0" ; "empty" ]

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``the pending error answers as udp-transfer.c section L measured`` (which : string) : unit =
        let flavour, linux =
            match which with
            | "linux" -> SimulatedUnixFlavour.Linux, true
            | _ -> SimulatedUnixFlavour.Darwin, false

        let refused = DatagramReceiver.refused (fresh flavour)

        // L1 and L3: a receive takes it, and so does SO_ERROR.
        let a, receiver = answer recv 64 refused

        [ a ; fst (answer recv 64 receiver) ]
        |> shouldEqual [ "ECONNREFUSED" ; "empty" ]

        let error, receiver = DatagramReceiver.takeError refused

        (error, DatagramReceiver.takeError receiver |> fst)
        |> shouldEqual (Some UnixError.ECONNREFUSED, None)

        // L5: an error and a datagram both waiting.
        let both = refused |> arrive 4 |> snd
        let a, receiver = answer recv 64 both
        let b, receiver = answer recv 64 receiver
        let c, _ = answer recv 64 receiver

        [ a ; b ; c ]
        |> shouldEqual (
            if linux then
                [ "ECONNREFUSED" ; "4/4" ; "empty" ]
            else
                [ "4/4" ; "ECONNREFUSED" ; "empty" ]
        )

        // L8 and L14: zero-length receives.
        fst (answer recv 0 refused) |> shouldEqual "ECONNREFUSED"

        let a, receiver = answer DatagramReceiveCall.Read 0 refused

        (a, DatagramReceiver.errorPending receiver)
        |> shouldEqual (if linux then "0", true else "ECONNREFUSED", false)

    // ------------------------------------------------------------ the reference

    let private opGen (flavour : SimulatedUnixFlavour) : Gen<DatagramReceiverOp> =
        let maxLength =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 65507
            | SimulatedUnixFlavour.Darwin -> 9216

        let length =
            Gen.frequency
                [
                    4, Gen.choose (0, 300)
                    2, Gen.choose (0, 2100)
                    1, Gen.choose (0, maxLength)
                    1,
                    Gen.elements
                        [
                            0
                            197
                            198
                            256
                            257
                            288
                            289
                            2016
                            2017
                            4096
                            8192
                            maxLength
                        ]
                ]

        let call =
            Gen.oneof
                [
                    Gen.constant DatagramReceiveCall.Read
                    Gen.map2
                        (fun peek truncate -> DatagramReceiveCall.Receive (peek, truncate))
                        (Gen.elements [ false ; true ])
                        (Gen.elements [ false ; true ])
                ]

        Gen.frequency
            [
                12,
                Gen.map2
                    (fun length connected -> DatagramReceiverOp.Arrive (length, connected))
                    length
                    (Gen.frequency [ 5, Gen.constant false ; 1, Gen.constant true ])
                1, Gen.map2 (fun length count -> DatagramReceiverOp.Flood (length, count)) length (Gen.choose (1, 5000))
                6,
                Gen.map2
                    (fun call count -> DatagramReceiverOp.Receive (call, count))
                    call
                    (Gen.frequency [ 1, Gen.constant 0 ; 4, Gen.choose (1, 3000) ])
                1, Gen.constant DatagramReceiverOp.Query
                1, Gen.constant DatagramReceiverOp.Polled
                1, Gen.constant DatagramReceiverOp.Sent
                1, Gen.constant DatagramReceiverOp.Refused
                1, Gen.constant DatagramReceiverOp.TakeError
            ]

    let private applyLibrary
        (id : uint16)
        (op : DatagramReceiverOp)
        (receiver : DatagramReceiver)
        : DatagramReceiverSeen * DatagramReceiver
        =
        match op with
        | DatagramReceiverOp.Arrive (length, connected) ->
            match DatagramReceiver.arrive connected (source id) (payload length) receiver with
            | DatagramArrival.Queued, after -> DatagramReceiverSeen.Arrived true, after
            | DatagramArrival.Dropped, after -> DatagramReceiverSeen.Arrived false, after
        | DatagramReceiverOp.Flood (length, count) ->
            let queued, after =
                List.fold
                    (fun (queued, receiver) _ ->
                        match DatagramReceiver.arrive false (source id) (payload length) receiver with
                        | DatagramArrival.Queued, after -> queued + 1, after
                        | DatagramArrival.Dropped, after -> queued, after
                    )
                    (0, receiver)
                    [ 1..count ]

            DatagramReceiverSeen.Flooded queued, after
        | DatagramReceiverOp.Receive (call, count) ->
            match DatagramReceiver.receive call count receiver with
            | DatagramReceiveAnswer.Datagram (bytes, returned, from), after ->
                // Every byte given is the datagram's own, from its start.
                let held = payload bytes.Length |> Seq.toArray
                Seq.toArray bytes |> shouldEqual held
                DatagramReceiverSeen.Datagram (from.Port, bytes.Length, returned), after
            | DatagramReceiveAnswer.Zero, after -> DatagramReceiverSeen.Zero, after
            | DatagramReceiveAnswer.Empty, after -> DatagramReceiverSeen.Empty, after
            | DatagramReceiveAnswer.Failed error, after -> DatagramReceiverSeen.Failed error, after
        | DatagramReceiverOp.Query ->
            let available, after = DatagramReceiver.queried receiver
            DatagramReceiverSeen.Available available, after
        | DatagramReceiverOp.Polled -> DatagramReceiverSeen.Done, DatagramReceiver.refilled receiver
        | DatagramReceiverOp.Sent -> DatagramReceiverSeen.Done, DatagramReceiver.sent receiver
        | DatagramReceiverOp.Refused -> DatagramReceiverSeen.Done, DatagramReceiver.refused receiver
        | DatagramReceiverOp.TakeError ->
            let error, after = DatagramReceiver.takeError receiver
            DatagramReceiverSeen.Error error, after

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``DatagramReceiver agrees with the reference over random calls, and keeps its own rules``
        (which : string)
        : unit
        =
        let flavour, buffer =
            match which with
            | "linux" -> SimulatedUnixFlavour.Linux, linuxBuffer
            | _ -> SimulatedUnixFlavour.Darwin, darwinBuffer

        let mutable drops = 0
        let mutable releases = 0

        let property (ops : DatagramReceiverOp list) : unit =
            let mutable library = DatagramReceiver.create flavour buffer

            let mutable reference =
                DatagramReceiverReference.create (flavour = SimulatedUnixFlavour.Linux) buffer

            ops
            |> List.iteri (fun index op ->
                // Each datagram is named by its source port.
                let id = uint16 (index + 1)
                let libSeen, libAfter = applyLibrary id op library

                let refSeen, refAfter = DatagramReceiverReference.apply id op reference
                (index, op, libSeen) |> shouldEqual (index, op, refSeen)
                DatagramReceiver.violations libAfter |> shouldEqual []

                DatagramReceiver.held libAfter
                |> List.map (fun d -> d.Source.Port)
                |> shouldEqual (refAfter.Held |> List.map (fun e -> e.Id))

                DatagramReceiver.charged libAfter
                |> shouldEqual (DatagramReceiverReference.charged refAfter)

                match op, libSeen with
                | _, DatagramReceiverSeen.Arrived false -> drops <- drops + 1
                | DatagramReceiverOp.Flood (_, count), DatagramReceiverSeen.Flooded queued when queued < count ->
                    drops <- drops + 1
                | _ -> ()

                if
                    DatagramReceiver.charged libAfter < DatagramReceiver.charged library
                    && List.length (DatagramReceiver.held libAfter) = List.length (DatagramReceiver.held library) - 1
                then
                    releases <- releases + 1

                library <- libAfter
                reference <- refAfter
            )

        let gen = Gen.listOf (opGen flavour) |> Gen.map (List.truncate 400)

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen gen) property)

        // The random calls reached full queues and given-back charges.
        drops |> shouldBeGreaterThan 0
        releases |> shouldBeGreaterThan 0
