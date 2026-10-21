namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// One datagram a UDP socket holds: where it came from, its bytes, and what
/// it is charged against the socket's receive buffer.
///
/// Two are equal when they hold the same source, bytes and charge.
[<CustomEquality ; NoComparison>]
type internal QueuedDatagram =
    {
        /// The sender's address and port, as the receiver reports them.
        Source : Ipv4Endpoint
        /// The datagram's bytes, every one of them, however many a receive
        /// then takes.
        Payload : ImmutableArray<byte>
        /// What the datagram is charged against its receiver's buffer while
        /// it is held: on Linux its truesize (`DatagramAccounting.linuxCharge`),
        /// and on Darwin its bytes in `sb_cc` (`DatagramAccounting.darwinBytes`).
        Charge : int
        /// On Darwin, what the datagram is charged in mbuf memory
        /// (`DatagramAccounting.darwinMbufs`); 0 on Linux, which has one
        /// budget.
        MbufCharge : int
    }

    override this.Equals (other : obj) : bool =
        match other with
        | :? QueuedDatagram as other ->
            this.Source = other.Source
            && this.Charge = other.Charge
            && this.MbufCharge = other.MbufCharge
            && System.MemoryExtensions.SequenceEqual (this.Payload.AsSpan (), other.Payload.AsSpan ())
        | _ -> false

    override this.GetHashCode () : int = hash (this.Source, this.Payload.Length)

/// What each flavour charges a UDP receiver for a datagram it holds.
[<RequireQualifiedAccess>]
module internal DatagramAccounting =

    /// What a Linux kernel built as `build` charges for the smallest buffer a
    /// datagram arrives in, which holds a datagram of up to that charge less
    /// 635 bytes.
    let private linuxSmallBuffer (build : LinuxKernelBuild) : int =
        match build with
        | LinuxKernelBuild.SmallBuffer832 -> 832
        | LinuxKernelBuild.SmallBuffer960 -> 960

    /// What a Linux kernel built as `build` charges a receiver for an IPv4
    /// datagram of `length` bytes that arrived over loopback: the truesize of
    /// the buffer it arrived in.
    let linuxCharge (build : LinuxKernelBuild) (length : int) : int =
        // Read through SO_MEMINFO (`udp-truesize.c` in
        // docs/plans/2026-10-18-udp-data-path), on Linux 6.18.5 aarch64 in
        // Apple's container and on GitHub's Azure kernels 6.17.0 and 7.0.0
        // (x86-64 and aarch64): a staircase of slab sizes up to 16004 bytes,
        // each step found by bisection, and above that the length plus the
        // smallest buffer's charge, sampled at 512 sizes without an exception.
        // The builds differ only in the smallest buffer, the first step.
        let small = linuxSmallBuffer build

        if length < 0 || length > 65507 then
            failwith
                $"DatagramAccounting.linuxCharge: a datagram of %d{length} bytes, which no IPv4 UDP datagram is (this is a bug in this library)."
        elif length <= small - 635 then
            small
        elif length <= 645 then
            1280
        elif length <= 1669 then
            2304
        elif length <= 3717 then
            4352
        elif length <= 7813 then
            8448
        elif length <= 16004 then
            16640
        else
            length + small

    /// What Darwin adds to a receiver's `sb_cc`, which `FIONREAD` reports, for
    /// a datagram of `length` bytes: its bytes and its 16-byte source address,
    /// and a 16-byte control record unless `bare`.
    let darwinBytes (bare : bool) (length : int) : int =
        // Read from net.inet.udp.pcblist_n on Darwin 27.0.0 (`udp-mbufs.c`
        // sections 0 and 1, in docs/plans/2026-10-18-udp-data-path), at
        // every length from 0 to 9216.
        if bare then length + 16 else length + 32

    /// What Darwin adds to a receiver's `sb_mbcnt`, the mbuf memory it holds,
    /// for a datagram of `length` bytes, with its control record unless
    /// `bare`.
    let darwinMbufs (bare : bool) (length : int) : int =
        // Read as `darwinBytes` was, at every length from 0 to 9216 (the
        // largest datagram net.inet.udp.maxdgram admits by default).
        if length < 0 || length > 9216 then
            failwith
                $"DatagramAccounting.darwinMbufs: a datagram of %d{length} bytes, which no default Darwin UDP socket sends (this is a bug in this library)."
        elif length = 0 then
            (if bare then 1536 else 2048)
        elif length <= 256 then
            (if bare then 1024 else 1536)
        elif length <= 288 then
            (if bare then 1536 else 3584)
        elif length <= 2016 then
            3584
        elif length <= 2048 then
            (if bare then 3584 else 5632)
        elif length <= 4064 then
            5632
        elif length <= 4096 then
            (if bare then 5632 else 10240)
        elif length <= 8160 then
            10240
        elif length <= 8192 then
            (if bare then 10240 else 14848)
        else
            14848

    /// Darwin's `sb_mbmax` for a receive buffer of `receiveSpace` bytes:
    /// eight times it, up to `kern.ipc.maxsockbuf`.
    let darwinMbufBudget (receiveSpace : int) : int =
        // Read as 6295168 for the default 786896 (`udp-mbufs.c` section 0).
        min (8 * receiveSpace) 8388608

/// What became of a datagram that reached a UDP receiver.
[<RequireQualifiedAccess>]
type internal DatagramArrival =
    /// The receiver holds it.
    | Queued
    /// The receiver had no room for it, so it is lost, and nobody learns of
    /// that: the sender's call succeeded all the same.
    | Dropped

/// Which call a datagram receive is.
[<RequireQualifiedAccess>]
type internal DatagramReceiveCall =
    /// `read(2)`.
    | Read
    /// `recv(2)`, and the other receiving calls, with the flags that change
    /// what they take or return.
    | Receive of peek : bool * truncate : bool

/// What a receive of a UDP receiver's next datagram answers, before any byte
/// is copied to the caller.
[<RequireQualifiedAccess ; NoEquality ; NoComparison>]
type internal DatagramReceiveAnswer =
    /// The call returns `returned` and gives the caller `bytes`, the first of
    /// the datagram's bytes that fit, which came from `source`. A zero-length
    /// receive of a datagram gives no bytes.
    | Datagram of bytes : ImmutableArray<byte> * returned : int * source : Ipv4Endpoint
    /// The call returns 0 without a datagram: Darwin's zero-length receive of
    /// a receiver holding nothing, and Linux's zero-length `read`.
    | Zero
    /// The receiver holds nothing to answer: a non-blocking call answers
    /// `EAGAIN`, and a blocking one sleeps.
    | Empty
    /// The call fails with `error`, the receiver's pending error, which it
    /// takes.
    | Failed of error : UnixError

/// A Linux UDP socket's receive side: its two queues, and the charge against
/// its receive buffer that it has not given back.
type internal LinuxDatagramReceiver =
    {
        /// `SO_RCVBUF`, fixed when the socket was made.
        ReceiveBuffer : int
        /// How the kernel was built, which fixes each datagram's charge.
        Build : LinuxKernelBuild
        /// How the kernel's version admits a datagram against `ReceiveBuffer`.
        Admission : LinuxDatagramAdmission
        /// The datagrams a receive moved here from `Arrivals`, oldest first:
        /// Linux's reader queue, which a receive refills from the arrival
        /// queue, all of it at once, only when it is empty.
        Reader : QueuedDatagram list
        /// The datagrams that have arrived since, newest first.
        Arrivals : QueuedDatagram list
        /// The charge of the datagrams taken whose charge has not been given
        /// back: Linux gives it back once it reaches a quarter of
        /// `ReceiveBuffer`, or once `Reader` is empty.
        Deficit : int
        /// Every datagram held's charge, and `Deficit`.
        Charged : int
        /// Whether an ICMP error has left `ECONNREFUSED` pending.
        ErrorPending : bool
    }

/// A Darwin UDP socket's receive side.
[<CustomEquality ; NoComparison>]
type internal DarwinDatagramReceiver =
    {
        /// `sb_hiwat`: `net.inet.udp.recvspace` when the socket was made.
        ReceiveSpace : int
        /// The datagrams held, oldest first.
        Queue : ImmutableQueue<QueuedDatagram>
        /// How many datagrams `Queue` holds.
        Held : int
        /// `sb_cc`: every datagram held's `Charge`, which `FIONREAD` reports.
        Charged : int
        /// `sb_mbcnt`: every datagram held's `MbufCharge`.
        MbufsCharged : int
        /// Whether the socket has sent or received a datagram, after which
        /// every datagram arriving carries its control record.
        Active : bool
        /// Whether an ICMP error has left `ECONNREFUSED` pending.
        ErrorPending : bool
    }

    override this.Equals (other : obj) : bool =
        match other with
        | :? DarwinDatagramReceiver as other ->
            this.ReceiveSpace = other.ReceiveSpace
            && this.Held = other.Held
            && this.Charged = other.Charged
            && this.MbufsCharged = other.MbufsCharged
            && this.Active = other.Active
            && this.ErrorPending = other.ErrorPending
            && Seq.forall2 (fun (a : QueuedDatagram) b -> a.Equals b) this.Queue other.Queue
        | _ -> false

    override this.GetHashCode () : int = hash (this.Held, this.Charged)

/// A UDP socket's receive side: the datagrams it holds for a receive, what they
/// cost its receive buffer, and its pending error, each by its flavour's
/// rules.
[<RequireQualifiedAccess ; NoComparison>]
type internal DatagramReceiver =
    | Linux of LinuxDatagramReceiver
    | Darwin of DarwinDatagramReceiver

[<RequireQualifiedAccess>]
module internal DatagramReceiver =

    /// A receiver holding nothing, for a socket made on a machine whose UDP
    /// receive side keeps `rules` (`SimulatedUnixPlatform.datagramReceiveRules`)
    /// and whose UDP receive buffer is `receiveBuffer` bytes: Linux's
    /// `net.core.rmem_default`, Darwin's `net.inet.udp.recvspace`.
    let create (rules : DatagramReceiveRules) (receiveBuffer : int) : DatagramReceiver =
        match rules with
        | DatagramReceiveRules.Linux (build, admission) ->
            DatagramReceiver.Linux
                {
                    ReceiveBuffer = receiveBuffer
                    Build = build
                    Admission = admission
                    Reader = []
                    Arrivals = []
                    Deficit = 0
                    Charged = 0
                    ErrorPending = false
                }
        | DatagramReceiveRules.Darwin ->
            DatagramReceiver.Darwin
                {
                    ReceiveSpace = receiveBuffer
                    Queue = ImmutableQueue.Empty
                    Held = 0
                    Charged = 0
                    MbufsCharged = 0
                    Active = false
                    ErrorPending = false
                }

    /// The flavour whose rules the receiver keeps.
    let flavour (receiver : DatagramReceiver) : SimulatedUnixFlavour =
        match receiver with
        | DatagramReceiver.Linux _ -> SimulatedUnixFlavour.Linux
        | DatagramReceiver.Darwin _ -> SimulatedUnixFlavour.Darwin

    /// What the receiver's buffer is charged: on Linux the truesize of what it
    /// holds and of what it has taken without giving back; on Darwin `sb_cc`.
    let charged (receiver : DatagramReceiver) : int =
        match receiver with
        | DatagramReceiver.Linux linux -> linux.Charged
        | DatagramReceiver.Darwin darwin -> darwin.Charged

    /// What a Darwin receiver's mbuf budget is charged (`sb_mbcnt`); 0 on
    /// Linux, which has one budget.
    let mbufsCharged (receiver : DatagramReceiver) : int =
        match receiver with
        | DatagramReceiver.Linux _ -> 0
        | DatagramReceiver.Darwin darwin -> darwin.MbufsCharged

    /// Every datagram held, oldest first.
    let held (receiver : DatagramReceiver) : QueuedDatagram list =
        match receiver with
        | DatagramReceiver.Linux linux -> linux.Reader @ List.rev linux.Arrivals
        | DatagramReceiver.Darwin darwin -> List.ofSeq darwin.Queue

    /// Whether the receiver holds a datagram.
    let isEmpty (receiver : DatagramReceiver) : bool =
        match receiver with
        | DatagramReceiver.Linux linux -> List.isEmpty linux.Reader && List.isEmpty linux.Arrivals
        | DatagramReceiver.Darwin darwin -> darwin.Held = 0

    /// Whether an ICMP error has left `ECONNREFUSED` pending.
    let errorPending (receiver : DatagramReceiver) : bool =
        match receiver with
        | DatagramReceiver.Linux linux -> linux.ErrorPending
        | DatagramReceiver.Darwin darwin -> darwin.ErrorPending

    /// What `FIONREAD` reports: on Linux, the length of the oldest datagram,
    /// or 0 with none; on Darwin, the charge of every datagram held. Reading
    /// it changes nothing: see `queried` for the call itself.
    let bytesAvailable (receiver : DatagramReceiver) : int =
        // Measured (`udp-transfer.c` F1 to F6): Linux 10 for datagrams of 10,
        // 20 and 30, and 0 for an empty datagram ahead of others; Darwin
        // their bytes and 32 for each, less 16 for the socket's first.
        match receiver with
        | DatagramReceiver.Linux linux ->
            match linux.Reader, List.tryLast linux.Arrivals with
            | oldest :: _, _ -> oldest.Payload.Length
            | [], Some oldest -> oldest.Payload.Length
            | [], None -> 0
        | DatagramReceiver.Darwin darwin -> darwin.Charged

    /// What the receiver does with a datagram of `payload` from `source`,
    /// arriving while its socket is `connected` or not.
    let arrive
        (connected : bool)
        (source : Ipv4Endpoint)
        (payload : ImmutableArray<byte>)
        (receiver : DatagramReceiver)
        : DatagramArrival * DatagramReceiver
        =
        match receiver with
        | DatagramReceiver.Linux linux ->
            let charge = DatagramAccounting.linuxCharge linux.Build payload.Length

            // Measured (`udp-truesize.c`): against the charge already held,
            // which includes what was taken and not yet given back, 6.17
            // admits while that is at most SO_RCVBUF, and 6.18 and later only
            // when the datagram's own fits beside it.
            let admitted =
                match linux.Admission with
                | LinuxDatagramAdmission.WhileHeldFits -> linux.Charged <= linux.ReceiveBuffer
                | LinuxDatagramAdmission.WhenBothFit -> linux.Charged + charge <= linux.ReceiveBuffer

            if not admitted then
                DatagramArrival.Dropped, receiver
            else
                let datagram =
                    {
                        Source = source
                        Payload = payload
                        Charge = charge
                        MbufCharge = 0
                    }

                DatagramArrival.Queued,
                DatagramReceiver.Linux
                    { linux with
                        Arrivals = datagram :: linux.Arrivals
                        Charged = linux.Charged + charge
                    }
        | DatagramReceiver.Darwin darwin ->
            // Measured (`udp-mbufs.c` section 2): the datagram goes without
            // its control record at a socket on which no send call has been
            // made, that has received nothing, and that is not connected as
            // it arrives.
            let bare = not darwin.Active && not connected
            let bytes = DatagramAccounting.darwinBytes bare payload.Length

            // Measured (`udp-mbufs.c` section 3, every arrival of eight random
            // mixtures): admitted exactly when both budgets have room for the
            // datagram's bytes. Its mbufs are what it then occupies.
            if
                darwin.Charged + bytes > darwin.ReceiveSpace
                || darwin.MbufsCharged + bytes > DatagramAccounting.darwinMbufBudget darwin.ReceiveSpace
            then
                DatagramArrival.Dropped, receiver
            else
                let datagram =
                    {
                        Source = source
                        Payload = payload
                        Charge = bytes
                        MbufCharge = DatagramAccounting.darwinMbufs bare payload.Length
                    }

                DatagramArrival.Queued,
                DatagramReceiver.Darwin
                    { darwin with
                        Queue = darwin.Queue.Enqueue datagram
                        Held = darwin.Held + 1
                        Charged = darwin.Charged + bytes
                        MbufsCharged = darwin.MbufsCharged + datagram.MbufCharge
                        Active = true
                    }

    /// The receiver of a socket on which a send call has just been made,
    /// whatever the call answered: on Darwin, every datagram the socket
    /// receives from now on carries its control record.
    let sent (receiver : DatagramReceiver) : DatagramReceiver =
        match receiver with
        | DatagramReceiver.Linux _ -> receiver
        | DatagramReceiver.Darwin darwin ->
            DatagramReceiver.Darwin
                { darwin with
                    Active = true
                }

    /// The receiver after a call that refills Linux's reader queue when it is
    /// empty, as a receive does: `FIONREAD`, and a `poll` or `epoll` of a
    /// socket whose description lacks `O_NONBLOCK`. Darwin has one queue.
    let refilled (receiver : DatagramReceiver) : DatagramReceiver =
        // Measured (`udp-release.c`): each of those calls moves every arrival
        // into the reader queue when it is empty, which changes when the
        // charge of what is taken comes back.
        match receiver with
        | DatagramReceiver.Linux linux when List.isEmpty linux.Reader && not (List.isEmpty linux.Arrivals) ->
            DatagramReceiver.Linux
                { linux with
                    Reader = List.rev linux.Arrivals
                    Arrivals = []
                }
        | DatagramReceiver.Linux _
        | DatagramReceiver.Darwin _ -> receiver

    /// The receiver with `ECONNREFUSED` pending, as an ICMP port-unreachable
    /// error leaves a connected socket whose datagram reached no one.
    let refused (receiver : DatagramReceiver) : DatagramReceiver =
        match receiver with
        | DatagramReceiver.Linux linux ->
            DatagramReceiver.Linux
                { linux with
                    ErrorPending = true
                }
        | DatagramReceiver.Darwin darwin ->
            DatagramReceiver.Darwin
                { darwin with
                    ErrorPending = true
                }

    /// The pending error, if there is one, and the receiver without it, as a
    /// read of `SO_ERROR` takes it.
    let takeError (receiver : DatagramReceiver) : UnixError option * DatagramReceiver =
        match receiver with
        | DatagramReceiver.Linux linux when linux.ErrorPending ->
            Some UnixError.ECONNREFUSED,
            DatagramReceiver.Linux
                { linux with
                    ErrorPending = false
                }
        | DatagramReceiver.Darwin darwin when darwin.ErrorPending ->
            Some UnixError.ECONNREFUSED,
            DatagramReceiver.Darwin
                { darwin with
                    ErrorPending = false
                }
        | DatagramReceiver.Linux _
        | DatagramReceiver.Darwin _ -> None, receiver

    /// The oldest datagram, and the receiver without it, its charge given
    /// back as its flavour gives it back. Loudly partial on an empty receiver.
    let private dequeue (receiver : DatagramReceiver) : QueuedDatagram * DatagramReceiver =
        match receiver with
        | DatagramReceiver.Linux linux ->
            // A receive takes from the reader queue, refilling it from the
            // arrivals first when it is empty (`__skb_recv_udp`).
            let reader, arrivals =
                match linux.Reader with
                | [] -> List.rev linux.Arrivals, []
                | reader -> reader, linux.Arrivals

            match reader with
            | [] -> failwith "DatagramReceiver.dequeue: the receiver holds no datagram (this is a bug in this library)."
            | oldest :: rest ->
                // Measured (`udp-truesize.c`, the release rows): the charge
                // of what was taken comes back once it reaches a quarter of
                // SO_RCVBUF, or once the reader queue is empty.
                let deficit = linux.Deficit + oldest.Charge

                let deficit, charged =
                    if deficit >= linux.ReceiveBuffer / 4 || List.isEmpty rest then
                        0, linux.Charged - deficit
                    else
                        deficit, linux.Charged

                oldest,
                DatagramReceiver.Linux
                    { linux with
                        Reader = rest
                        Arrivals = arrivals
                        Deficit = deficit
                        Charged = charged
                    }
        | DatagramReceiver.Darwin darwin ->
            if darwin.Held = 0 then
                failwith "DatagramReceiver.dequeue: the receiver holds no datagram (this is a bug in this library)."

            let mutable oldest = Unchecked.defaultof<QueuedDatagram>
            let queue = darwin.Queue.Dequeue &oldest

            oldest,
            DatagramReceiver.Darwin
                { darwin with
                    Queue = queue
                    Held = darwin.Held - 1
                    Charged = darwin.Charged - oldest.Charge
                    MbufsCharged = darwin.MbufsCharged - oldest.MbufCharge
                }

    /// The oldest datagram, if there is one.
    let private oldest (receiver : DatagramReceiver) : QueuedDatagram option =
        match receiver with
        | DatagramReceiver.Linux linux ->
            match linux.Reader with
            | oldest :: _ -> Some oldest
            | [] -> List.tryLast linux.Arrivals
        | DatagramReceiver.Darwin darwin ->
            if darwin.Held = 0 then
                None
            else
                Some (darwin.Queue.Peek ())

    /// The oldest `count` bytes of `datagram`, or all of them if it is shorter.
    let private fitting (count : int) (datagram : QueuedDatagram) : ImmutableArray<byte> =
        if datagram.Payload.Length <= count then
            datagram.Payload
        else
            ImmutableArray.Create (datagram.Payload, 0, count)

    /// What `call` of `count` bytes answers, and the receiver after it, by each
    /// flavour's rules, as if every byte it gives were copied to the caller.
    let receive
        (call : DatagramReceiveCall)
        (count : int)
        (receiver : DatagramReceiver)
        : DatagramReceiveAnswer * DatagramReceiver
        =
        let peek, truncate =
            match call with
            | DatagramReceiveCall.Read -> false, false
            | DatagramReceiveCall.Receive (peek, truncate) -> peek, truncate

        let datagram () : DatagramReceiveAnswer * DatagramReceiver =
            // Linux refills its reader queue from the arrivals, if it is
            // empty, before it looks for a datagram, to take or to peek at
            // (`udp-release.c`).
            let receiver = refilled receiver

            let next, after =
                if peek then
                    match oldest receiver with
                    | Some next -> next, receiver
                    | None -> failwith "DatagramReceiver.receive: no datagram to peek (this is a bug in this library)."
                else
                    dequeue receiver

            let returned =
                match receiver with
                // Measured (`udp-transfer.c` C2, C4, D1 and P3): Linux's
                // MSG_TRUNC returns the datagram's length, and Darwin
                // ignores it.
                | DatagramReceiver.Linux _ when truncate -> next.Payload.Length
                | DatagramReceiver.Linux _
                | DatagramReceiver.Darwin _ -> min count next.Payload.Length

            DatagramReceiveAnswer.Datagram (fitting count next, returned, next.Source), after

        let failed () : DatagramReceiveAnswer * DatagramReceiver =
            match takeError receiver with
            | Some error, after -> DatagramReceiveAnswer.Failed error, after
            | None, _ -> failwith "DatagramReceiver.receive: no error to take (this is a bug in this library)."

        match receiver with
        | DatagramReceiver.Linux _ ->
            // Measured (`udp-transfer.c` C5, L14): a zero-length `read`
            // answers 0 in every state, taking neither a datagram nor the
            // error. A zero-length `recv` is a receive like any other (C3,
            // C6, L8).
            match call with
            | DatagramReceiveCall.Read when count = 0 -> DatagramReceiveAnswer.Zero, receiver
            | DatagramReceiveCall.Read
            | DatagramReceiveCall.Receive _ ->
                // Measured (L5): the error before a queued datagram.
                if errorPending receiver then failed ()
                elif not (isEmpty receiver) then datagram ()
                else DatagramReceiveAnswer.Empty, receiver
        | DatagramReceiver.Darwin _ ->
            // Measured (L5): a queued datagram before the error. Every
            // zero-length receive is a receive (C3, C5, L8, L14), and one
            // with nothing to take answers 0 (C6).
            if not (isEmpty receiver) then datagram ()
            elif errorPending receiver then failed ()
            elif count = 0 then DatagramReceiveAnswer.Zero, receiver
            else DatagramReceiveAnswer.Empty, receiver

    /// What `FIONREAD` answers, and the receiver after it, whose reader queue
    /// Linux refills.
    let queried (receiver : DatagramReceiver) : int * DatagramReceiver =
        let receiver = refilled receiver
        bytesAvailable receiver, receiver

    /// Why the receiver breaks a rule its flavour's accounting keeps: an empty
    /// list for one that keeps them all.
    let violations (receiver : DatagramReceiver) : string list =
        match receiver with
        | DatagramReceiver.Linux linux ->
            let heldCharge =
                (linux.Reader @ linux.Arrivals) |> List.sumBy (fun datagram -> datagram.Charge)

            [
                if linux.Charged <> heldCharge + linux.Deficit then
                    $"its charge is %d{linux.Charged}, but it holds %d{heldCharge} and owes %d{linux.Deficit}"
                // The last datagram admitted while what was held fitted may
                // take the charge past the buffer by at most its own.
                let ceiling =
                    match linux.Admission with
                    | LinuxDatagramAdmission.WhileHeldFits ->
                        linux.ReceiveBuffer + DatagramAccounting.linuxCharge linux.Build 65507
                    | LinuxDatagramAdmission.WhenBothFit -> linux.ReceiveBuffer

                if linux.Charged > ceiling then
                    $"its charge is %d{linux.Charged}, above the %d{ceiling} its receive buffer of %d{linux.ReceiveBuffer} allows"

                if linux.Deficit < 0 || linux.Deficit >= linux.ReceiveBuffer / 4 then
                    $"it owes %d{linux.Deficit}, outside [0, %d{linux.ReceiveBuffer / 4})"

                if linux.Deficit > 0 && List.isEmpty linux.Reader then
                    $"it owes %d{linux.Deficit} with nothing in its reader queue"

                for datagram in linux.Reader @ linux.Arrivals do
                    if
                        datagram.Charge
                        <> DatagramAccounting.linuxCharge linux.Build datagram.Payload.Length
                    then
                        $"a datagram of %d{datagram.Payload.Length} bytes is charged %d{datagram.Charge}"
            ]
        | DatagramReceiver.Darwin darwin ->
            let queue = List.ofSeq darwin.Queue

            [
                if darwin.Held <> List.length queue then
                    $"it counts %d{darwin.Held} datagrams and holds %d{List.length queue}"
                if
                    darwin.Charged
                    <> List.sumBy (fun (datagram : QueuedDatagram) -> datagram.Charge) queue
                then
                    $"its byte charge is %d{darwin.Charged}, not the sum of what it holds"
                if
                    darwin.MbufsCharged
                    <> List.sumBy (fun (datagram : QueuedDatagram) -> datagram.MbufCharge) queue
                then
                    $"its mbuf charge is %d{darwin.MbufsCharged}, not the sum of what it holds"
                if darwin.Held > 0 && not darwin.Active then
                    "it holds a datagram, but records none received"
                for (index, datagram) in List.indexed queue do
                    let length = datagram.Payload.Length

                    let bare =
                        DatagramAccounting.darwinBytes true length, DatagramAccounting.darwinMbufs true length

                    let full =
                        DatagramAccounting.darwinBytes false length, DatagramAccounting.darwinMbufs false length

                    // Only the oldest datagram can have arrived at a socket
                    // that had received none.
                    if
                        (datagram.Charge, datagram.MbufCharge) <> full
                        && (index > 0 || (datagram.Charge, datagram.MbufCharge) <> bare)
                    then
                        $"datagram %d{index} of %d{length} bytes is charged %d{datagram.Charge} bytes and %d{datagram.MbufCharge} of mbufs"
            ]
