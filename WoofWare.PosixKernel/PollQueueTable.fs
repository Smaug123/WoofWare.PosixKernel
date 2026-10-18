namespace WoofWare.PosixKernel

/// The kqueue of every Darwin `poll(2)` asleep on the machine (`PollQueue`), by
/// identity, and an index of them that a close reads: which queues registered
/// through each descriptor of each process, as Darwin keeps a list per
/// descriptor of the knotes made through it (`fd_knlist`).
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
        }

[<RequireQualifiedAccess>]
module internal PollQueueTable =

    /// A machine with no Darwin poll asleep.
    let empty : PollQueueTable =
        {
            Queues = Map.empty
            Through = Map.empty
        }

    /// Every queue, by its identity.
    let all (table : PollQueueTable) : Map<PollQueueId, PollQueue> = table.Queues

    /// The queue `id`, if the machine holds it.
    let tryFind (id : PollQueueId) (table : PollQueueTable) : PollQueue option = Map.tryFind id table.Queues

    /// `index` with each registration of `queue`, the queue `id`, filed in it
    /// by `file`.
    let private fileQueue
        (file :
            int64
                -> int64
                -> KqueueFilter
                -> Map<int64, Map<int64, Set<KqueueFilter>>>
                -> Map<int64, Map<int64, Set<KqueueFilter>>>)
        (PollQueueId raw)
        (queue : PollQueue)
        (index : Map<int64, Map<int64, Set<KqueueFilter>>>)
        : Map<int64, Map<int64, Set<KqueueFilter>>>
        =
        (index, queue.Registrations)
        ||> Map.fold (fun index (fd, filter) _ ->
            file (RegistrationIndex.throughDescriptor queue.Owner fd) raw filter index
        )

    /// Whether `before` and `after`, states of one queue, are certainly filed
    /// alike in the index: they share their owner and their registrations.
    /// Constant time, and false for some queues filed alike.
    let private filedAlike (before : PollQueue) (after : PollQueue) : bool =
        before.Owner = after.Owner
        && LanguagePrimitives.PhysicalEquality before.Registrations after.Registrations

    /// `table`'s index with the queue `id` filed as `after` says rather than
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
            let through =
                match before with
                | Some before -> fileQueue RegistrationIndex.unfile id before table.Through
                | None -> table.Through

            let through =
                match after with
                | Some after -> fileQueue RegistrationIndex.file id after through
                | None -> through

            { table with
                Through = through
            }

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

    /// Whether the index is that of the queues, as adding each afresh would
    /// build it.
    let indexFresh (table : PollQueueTable) : bool =
        let fresh =
            (empty, table.Queues) ||> Map.fold (fun fresh id queue -> add id queue fresh)

        fresh.Through = table.Through
