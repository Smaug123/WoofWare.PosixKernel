namespace WoofWare.PosixKernel

/// One filter a Darwin-flavoured `poll(2)` registered in the kqueue it makes
/// for its own use, keyed beside it by the descriptor number and the filter.
///
/// Darwin's `poll` registers, for each entry, one filter per group of the bits
/// it asks for, each added once only (`EV_ONESHOT`): the first report it makes
/// removes it, whether or not that report adds anything to the entry.
type internal PollRegistration =
    {
        /// The index, in the call's entries, of the entry the filter reports
        /// into: the last entry naming this descriptor and filter, since a
        /// later entry's registration of the same pair replaces the earlier's
        /// `udata` rather than adding a filter (measured).
        Entry : int
        /// Whether the entry that first registered the pair asked for
        /// `POLLPRI` or `POLLRDBAND`, which registers `EVFILT_READ` with
        /// `EV_OOBAND`. A later entry's registration keeps the first one's
        /// flags (measured). A socket's filter ignores the flag; every other
        /// target's reports it back, and `poll` then answers `POLLPRI` and
        /// `POLLRDBAND` for a ready read.
        OutOfBand : bool
        /// Where the pair's first registration stands in the order the call
        /// made them. One event that activates several registrations of a
        /// socket's filter, made through different descriptors onto it,
        /// queues the latest-made first, as it does in a kqueue `kevent` fills.
        RegisteredAt : int
        /// For a socket's filter, the socket the descriptor named when the
        /// call registered it: what the filter is attached to, so that an
        /// event on the socket reaches it whichever process's call caused the
        /// event, without reading any descriptor table. `None` for a pipe's or
        /// a regular file's filter, which nothing activates (see
        /// `PollQueue.Active`).
        Socket : SocketId option
    }

/// The identity of the kqueue a Darwin `poll(2)` made for its own use
/// (`PollQueue`). Minted from a counter the machine keeps, and never reused.
type PollQueueId =
    | PollQueueId of int64

    /// A human-readable description of the identity.
    override this.ToString () =
        match this with
        | PollQueueId.PollQueueId i -> $"<poll queue #%i{i}>"

/// The kqueue a Darwin `poll(2)` made for its own use, while the call sleeps.
///
/// Darwin builds `poll` over kqueue: the call registers a filter per group of
/// requested bits in a kqueue that has no descriptor, and translates what the
/// filters report back into `revents`. A sleeping call keeps that kqueue, and
/// what it reports when it wakes depends on what has been activated in it, and
/// in which order -- not only on what its descriptors present then.
///
/// Held on the machine rather than in the call's park, because a socket event
/// in any process's call activates its filters, as one does a kqueue's. It
/// lives exactly as long as the park
/// naming it (`ParkedKqueuePoll.Queue`): the park's end destroys it.
///
/// Its representation is internal, so a later version may change what a
/// registration holds and what it is attached to without breaking a client. A
/// client reads one through `PollQueue.registered`, `PollQueue.entry` and
/// `PollQueue.activated`, and builds none.
type PollQueue =
    internal
        {
            /// The process whose `poll` made the queue, whose descriptor table its
            /// registrations' descriptor numbers are read in.
            Owner : ProcessId
            /// The filters still registered: those that have not yet reported, keyed
            /// by descriptor number and filter. Closing a descriptor removes every
            /// one made through it, as it does from a kqueue a process holds.
            Registrations : Map<int * KqueueFilter, PollRegistration>
            /// The registrations of sockets' filters something has activated since
            /// the call last scanned, in the order they were activated: the order
            /// a scan reports them in, which decides whether a reported `POLLHUP`
            /// suppresses a socket's `POLLOUT`. Always a subset of
            /// `Registrations`, with no duplicates, naming sockets alone.
            ///
            /// A pipe's filters are not listed: every operation that makes one
            /// ready activates it (measured), and the order a pipe entry's two
            /// filters report in cannot change what the entry answers, so a scan
            /// reports a pipe's registration exactly while its filter is ready.
            Active : (int * KqueueFilter) list
        }

/// What a client reads of a sleeping Darwin poll's kqueue (`UnixSystem.pollQueue`).
[<RequireQualifiedAccess>]
module PollQueue =
    /// The filters the call registered that have not yet reported, each as the
    /// descriptor it was registered through and its filter, in ascending order.
    let registered (queue : PollQueue) : (int * KqueueFilter) list =
        queue.Registrations |> Map.toList |> List.map fst

    /// The index, in the call's entries, of the entry that the filter `filter`
    /// registered through `fd` reports into; `None` when no such filter is
    /// registered. Where several entries name the same descriptor and filter,
    /// it is the last of them.
    let entry (fd : int) (filter : KqueueFilter) (queue : PollQueue) : int option =
        queue.Registrations
        |> Map.tryFind (fd, filter)
        |> Option.map (fun (registration : PollRegistration) -> registration.Entry)

    /// The registered filters that something has activated since the call
    /// last scanned, in the order they were activated, which is the order the
    /// call reports them in. In this version only a socket's filters are
    /// listed: the call reports a pipe's filter exactly while it is ready.
    let activated (queue : PollQueue) : (int * KqueueFilter) list = queue.Active

/// The kqueue of every Darwin `poll(2)` asleep on the machine (`PollQueue`), by
/// identity, and two indexes of them: which queues registered through each
/// descriptor of each process, which a close reads, as Darwin keeps a list per
/// descriptor of the knotes made through it (`fd_knlist`); and which queues
/// registered each socket, which a wake of the socket reads, as XNU hangs a
/// socket's knotes off the socket.
///
/// The representation is private to this file, so every change to a queue
/// goes through `add`, `set`, `remove`, `map` or `dropRegistrationsThrough`,
/// which keep the index, and nothing else can change one.
type internal PollQueueTable =
    private
        {
            Queues : Map<PollQueueId, PollQueue>
            /// The queues with a registration through each descriptor of each
            /// process, keyed as `RegistrationIndex.throughDescriptor` keys the
            /// queue's owner and the descriptor, by the value of each queue's
            /// identity, and the filters it registers through the descriptor.
            Through : Map<int64, Map<int64, Set<KqueueFilter>>>
            /// The queues with a registration attached to each socket
            /// (`PollRegistration.Socket`), keyed by the socket's value, by
            /// the value of each queue's identity, and the keys it registers
            /// the socket under.
            OnSocket : Map<int64, Map<int64, Set<int * KqueueFilter>>>
        }

[<RequireQualifiedAccess>]
module internal PollQueueTable =

    /// A machine with no Darwin poll asleep.
    let empty : PollQueueTable =
        {
            Queues = Map.empty
            Through = Map.empty
            OnSocket = Map.empty
        }

    /// Every queue, by its identity.
    let all (table : PollQueueTable) : Map<PollQueueId, PollQueue> = table.Queues

    /// The queue `id`, if the machine holds it.
    let tryFind (id : PollQueueId) (table : PollQueueTable) : PollQueue option = Map.tryFind id table.Queues

    /// `table`'s indexes with each registration of `queue`, the queue `id`,
    /// filed in them (`filing` true) or no longer filed.
    let private fileQueue
        (filing : bool)
        (PollQueueId raw)
        (queue : PollQueue)
        (table : PollQueueTable)
        : PollQueueTable
        =
        let file (key : 'Key) (distinct : 'Distinct) (index : Map<'Key, Map<int64, Set<'Distinct>>>) =
            if filing then
                RegistrationIndex.file key raw distinct index
            else
                RegistrationIndex.unfile key raw distinct index

        let through, onSocket =
            ((table.Through, table.OnSocket), queue.Registrations)
            ||> Map.fold (fun (through, onSocket) (fd, filter as key) registration ->
                let through =
                    file (RegistrationIndex.throughDescriptor queue.Owner fd) filter through

                let onSocket =
                    match registration.Socket with
                    | Some (SocketId socket) -> file socket key onSocket
                    | None -> onSocket

                through, onSocket
            )

        { table with
            Through = through
            OnSocket = onSocket
        }

    /// Whether `before` and `after`, states of one queue, are certainly filed
    /// alike in the index: they share their owner and their registrations.
    /// Constant time, and false for some queues filed alike.
    let private filedAlike (before : PollQueue) (after : PollQueue) : bool =
        before.Owner = after.Owner
        && LanguagePrimitives.PhysicalEquality before.Registrations after.Registrations

    /// `table`'s indexes with the queue `id` filed as `after` says rather than
    /// as `before` does, where an absent queue is filed under nothing: in time
    /// logarithmic in the index for each registration of either, unless they
    /// are certainly filed alike (`filedAlike`).
    let private refile
        (id : PollQueueId)
        (before : PollQueue option)
        (after : PollQueue option)
        (table : PollQueueTable)
        : PollQueueTable
        =
        let alike =
            match before, after with
            | Some before, Some after -> filedAlike before after
            | None, None -> true
            | Some _, None
            | None, Some _ -> false

        if alike then
            table
        else
            let table =
                match before with
                | Some before -> fileQueue false id before table
                | None -> table

            match after with
            | Some after -> fileQueue true id after table
            | None -> table

    /// `table` holding `queue` as the new queue `id`. Loudly partial on an
    /// identity the table already holds: a new queue's identity is fresh.
    let add (id : PollQueueId) (queue : PollQueue) (table : PollQueueTable) : PollQueueTable =
        if Map.containsKey id table.Queues then
            failwith
                $"PollQueueTable.add: %O{id} is already on the machine, and a new poll's kqueue has a fresh identity (this is a bug in this library)."

        { refile id None (Some queue) table with
            Queues = Map.add id queue table.Queues
        }

    /// `table` with the queue `id` replaced by `queue`. Loudly partial on a
    /// queue the table does not hold: the caller read the identity from a
    /// park, which holds its queue.
    let set (id : PollQueueId) (queue : PollQueue) (table : PollQueueTable) : PollQueueTable =
        match Map.tryFind id table.Queues with
        | None -> failwith $"PollQueueTable.set: %O{id} is not on the machine (this is a bug in this library)."
        | Some before ->
            { refile id (Some before) (Some queue) table with
                Queues = Map.add id queue table.Queues
            }

    /// `table` without the queue `id`, if it holds it.
    let remove (id : PollQueueId) (table : PollQueueTable) : PollQueueTable =
        match Map.tryFind id table.Queues with
        | None -> table
        | Some before ->
            { refile id (Some before) None table with
                Queues = Map.remove id table.Queues
            }

    /// `table` with each queue rewritten by `f`, in time linear in the number
    /// of queues, plus, for each queue `f` gives another owner or other
    /// registrations, time logarithmic in the index and linear in what that
    /// queue registers.
    let map (f : PollQueue -> PollQueue) (table : PollQueueTable) : PollQueueTable =
        let refiled = ResizeArray<struct (PollQueueId * PollQueue * PollQueue)> ()

        let queues =
            table.Queues
            |> Map.map (fun id queue ->
                let rewritten = f queue

                if not (filedAlike queue rewritten) then
                    refiled.Add (struct (id, queue, rewritten))

                rewritten
            )

        ({ table with
            Queues = queues
         },
         refiled)
        ||> Seq.fold (fun table (struct (id, before, after)) -> refile id (Some before) (Some after) table)

    /// The queues `owner`'s polls made with a registration through its
    /// descriptor `fd`, in identity order, in time logarithmic in the number
    /// of registrations and linear in the number of queues answered.
    let registeringThrough (owner : ProcessId) (fd : int) (table : PollQueueTable) : PollQueueId list =
        RegistrationIndex.membersUnder (RegistrationIndex.throughDescriptor owner fd) table.Through
        |> Seq.map (fun (KeyValue (queue, _)) -> PollQueueId queue)
        |> List.ofSeq

    /// The queues with a registration attached to the socket `socketId`, in
    /// identity order, each with the keys it registers the socket under, in
    /// time logarithmic in the number of registrations and linear in the
    /// number of queues answered.
    let registeringOnSocket
        (socketId : SocketId)
        (table : PollQueueTable)
        : (PollQueueId * Set<int * KqueueFilter>) list
        =
        let (SocketId socket) = socketId

        RegistrationIndex.membersUnder socket table.OnSocket
        |> Seq.map (fun (KeyValue (queue, keys)) -> PollQueueId queue, keys)
        |> List.ofSeq

    /// `table` with every registration made through the descriptor `fd`
    /// removed from every queue the process `owner`'s polls made, active or
    /// not: what closing `fd` does to them. Visits only the queues with such a
    /// registration (`registeringThrough`).
    let dropRegistrationsThrough (owner : ProcessId) (fd : int) (table : PollQueueTable) : PollQueueTable =
        (table, registeringThrough owner fd table)
        ||> List.fold (fun table id ->
            match Map.tryFind id table.Queues with
            | Some queue when queue.Owner = owner ->
                table
                |> set
                    id
                    { queue with
                        Registrations = queue.Registrations |> Map.filter (fun (registered, _) _ -> registered <> fd)
                        Active = queue.Active |> List.filter (fun (active, _) -> active <> fd)
                    }
            | other ->
                failwith
                    $"PollQueueTable.dropRegistrationsThrough: the index says %O{id} is a queue of process %O{owner} registering through fd %d{fd}, but it is %A{other} (this is a bug in this library)."
        )

    /// Whether the indexes are those of the queues, as adding each afresh
    /// would build them.
    let indexFresh (table : PollQueueTable) : bool =
        let fresh =
            (empty, table.Queues) ||> Map.fold (fun fresh id queue -> add id queue fresh)

        fresh.Through = table.Through && fresh.OnSocket = table.OnSocket
