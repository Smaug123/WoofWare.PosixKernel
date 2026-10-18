namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `OpenFileTable` keeps a count of the descriptions naming each end of each
/// pipe and a record of the `flock`s held on each object, which
/// `OpenFileTable.describesPipeEnd` and `OpenFileTable.flockConflicts` read;
/// and a record of the epoll instances registering each description and of the
/// kqueues registering through each descriptor of each process, which
/// `OpenFileTable.epollsRegistering` and
/// `OpenFileTable.kqueuesRegisteringThrough` read. Over random walks of the
/// table's own changes, each answers what a scan of every description answers.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestOpenFileIndex =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    /// A seed for a walk's own `System.Random`, from the whole range, and with
    /// no shrinker: a smaller seed is another walk, not a simpler one.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private pipes : PipeId list = [ PipeId 0L ; PipeId 1L ; PipeId 2L ]

    /// What a walk opens: the ends of a few pipes, a few sockets, and a few
    /// files, so that several descriptions share each object.
    let private targets : OpenFileTarget list =
        [
            for pipe in pipes do
                OpenFileTarget.Pipe (pipe, PipeEnd.Read)
                OpenFileTarget.Pipe (pipe, PipeEnd.Write)
            OpenFileTarget.Socket (SocketId 0L)
            OpenFileTarget.Socket (SocketId 1L)
            OpenFileTarget.File (InodeNumber 10L, 0L)
            OpenFileTarget.File (InodeNumber 11L, 0L)
        ]

    let private locks : FlockMode option list =
        [ None ; Some FlockMode.Shared ; Some FlockMode.Exclusive ]

    let private description (target : OpenFileTarget) : OpenFileDescription =
        {
            Target = target
            AccessMode = FileAccessMode.ReadWrite
            NonBlocking = false
            Flock = None
            Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
        }

    let private live (table : OpenFileTable) : OpenFileDescriptionId list =
        OpenFileTable.toSeq table |> Seq.map fst |> List.ofSeq

    /// One of the table's own changes, at random, to `table`.
    let private step (rng : System.Random) (table : OpenFileTable) : OpenFileTable =
        let pick (items : 'a list) : 'a = items.[rng.Next items.Length]

        match live table, rng.Next 7 with
        | [], _
        | _, 0 ->
            let target = pick targets

            let through =
                if OpenFileTable.namesInode target then
                    Some ReachedThrough.Unnamed
                else
                    None

            OpenFileTable.create (description target) through table |> snd
        | ids, 1 -> OpenFileTable.retain (pick ids) table
        | ids, 2 ->
            // The last close of a descriptor, or a call's last hold let go
            // of: whichever the description has, and then its destruction if
            // nothing references it any more.
            let id = pick ids

            let released =
                if OpenFileTable.descriptorCount id table = Some 0 then
                    OpenFileTable.releaseHold id table
                else
                    OpenFileTable.release id table

            OpenFileTable.destroyIfUnreferenced id released |> fst
        | ids, 3 -> OpenFileTable.hold (pick ids) table
        | ids, 4 ->
            let mode = pick locks

            OpenFileTable.mapDescription
                "TestOpenFileIndex"
                (pick ids)
                (fun description ->
                    { description with
                        Flock = mode
                    }
                )
                table
        | ids, 5 ->
            // However unsoundly: an index must follow a description that
            // names something else, though no syscall makes one.
            let target = pick targets

            OpenFileTable.mapDescription
                "TestOpenFileIndex"
                (pick ids)
                (fun description ->
                    { description with
                        Target = target
                    }
                )
                table
        | _, _ ->
            // A change that rewrites every description it reaches and leaves
            // the rest as they were.
            OpenFileTable.signalEpollInstances (Set.ofList (live table)) None table

    let private conflictsByScan
        (object : OpenFileObject)
        (requester : OpenFileDescriptionId)
        (mode : FlockMode)
        (table : OpenFileTable)
        : bool
        =
        OpenFileTable.toSeq table
        |> Seq.exists (fun (other, description) ->
            other <> requester
            && OpenFileDescription.object other description = object
            && (
                match mode, description.Flock with
                | _, None -> false
                | FlockMode.Shared, Some FlockMode.Shared -> false
                | FlockMode.Shared, Some FlockMode.Exclusive
                | FlockMode.Exclusive, Some _ -> true
            )
        )

    /// Every question the indexes answer about `table`, answered by them and
    /// by a scan, which must agree.
    let private agree (table : OpenFileTable) : unit =
        for pipe in pipes do
            for pipeEnd in [ PipeEnd.Read ; PipeEnd.Write ] do
                let scanned =
                    OpenFileTable.toSeq table
                    |> Seq.exists (fun (_, description) -> description.Target = OpenFileTarget.Pipe (pipe, pipeEnd))

                OpenFileTable.describesPipeEnd pipe pipeEnd table |> shouldEqual scanned

        // A requester need not be live: one that has gone, or never was, asks
        // too.
        let requesters = OpenFileDescriptionId 1000L :: live table

        let objects =
            OpenFileTable.toSeq table
            |> Seq.map (fun (id, description) -> OpenFileDescription.object id description)
            |> Seq.append [ OpenFileObject.Pipe (PipeId 9L) ]
            |> Seq.distinct
            |> List.ofSeq

        for object in objects do
            for requester in requesters do
                for mode in [ FlockMode.Shared ; FlockMode.Exclusive ] do
                    OpenFileTable.flockConflicts object requester mode table
                    |> shouldEqual (conflictsByScan object requester mode table)

        OpenFileTable.checkInvariants [] table
        |> List.contains FileDescriptorRegistryDefect.StaleIndex
        |> shouldEqual false

    [<Test>]
    let ``the pipe-end and flock indexes answer what a scan of the descriptions answers`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (OpenFileTable.empty, [ 1 .. rng.Next (1, 40) ])
            ||> List.fold (fun table _ ->
                let next = step rng table
                agree next
                next
            )
            |> ignore<OpenFileTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)

    let private owners : ProcessId list =
        [
            ProcessId.parseOrFail "TestOpenFileIndex" 1
            ProcessId.parseOrFail "TestOpenFileIndex" 2
        ]

    /// The descriptor numbers a walk registers through.
    let private fds : int list = [ 0 ; 1 ; 2 ]

    let private epolls (table : OpenFileTable) : (OpenFileDescriptionId * EpollState) list =
        OpenFileTable.toSeq table
        |> Seq.choose (fun (id, description) ->
            match description.Target with
            | OpenFileTarget.Epoll state -> Some (id, state)
            | _ -> None
        )
        |> List.ofSeq

    let private kqueues (table : OpenFileTable) : (OpenFileDescriptionId * KqueueState) list =
        OpenFileTable.toSeq table
        |> Seq.choose (fun (id, description) ->
            match description.Target with
            | OpenFileTarget.Kqueue state -> Some (id, state)
            | _ -> None
        )
        |> List.ofSeq

    /// One of the table's own changes, at random, to `table`, weighted
    /// towards making epoll instances and kqueues and changing what they
    /// register.
    let private registrationStep (rng : System.Random) (table : OpenFileTable) : OpenFileTable =
        let pick (items : 'a list) : 'a = items.[rng.Next items.Length]

        match rng.Next 13 with
        | 0 ->
            let epoll =
                OpenFileTarget.Epoll
                    {
                        Registrations = Map.empty
                        Ready = []
                    }

            OpenFileTable.create (description epoll) None table |> snd
        | 1 ->
            let kqueue =
                OpenFileTarget.Kqueue
                    {
                        Owner = pick owners
                        Drained = false
                        Registrations = Map.empty
                        Active = []
                    }

            OpenFileTable.create (description kqueue) None table |> snd
        | 2
        | 3 ->
            // `EPOLL_CTL_ADD` of a live description, sometimes found ready at
            // once, or `EPOLL_CTL_DEL` of one already registered.
            match epolls table, live table with
            | [], _
            | _, [] -> table
            | epolls, ids ->
                let epoll, state = pick epolls
                let key = pick fds, pick ids

                if Map.containsKey key state.Registrations then
                    OpenFileTable.removeEpollRegistration epoll key table
                else
                    let registration : EpollRegistration =
                        {
                            Events = EpollEvents.In
                            Data = 0UL
                            RegisteredAt = 0L
                        }

                    let added = OpenFileTable.addEpollRegistration epoll key registration table

                    if rng.Next 2 = 0 then
                        OpenFileTable.appendEpollReady epoll key added
                    else
                        added
        | 4 ->
            // `EV_ADD` or `EV_DELETE` of a filter through a descriptor, as
            // `kevent` makes one.
            match kqueues table with
            | [] -> table
            | kqueues ->
                let kqueue, state = pick kqueues
                let key = pick fds, pick [ KqueueFilter.Read ; KqueueFilter.Write ]

                if Map.containsKey key state.Registrations then
                    OpenFileTable.unregisterFromKqueue kqueue key table
                else
                    let registration : KqueueRegistration =
                        {
                            Clear = false
                            Receipt = false
                            UserData = 0UL
                            RegisteredAt = 0L
                            Socket = SocketId 0L
                        }

                    let added = OpenFileTable.registerInKqueue kqueue key registration table

                    if rng.Next 2 = 0 then
                        added
                    else
                        match OpenFileTable.tryFind kqueue added with
                        | Some {
                                   Target = OpenFileTarget.Kqueue state
                               } ->
                            OpenFileTable.setKqueueState
                                kqueue
                                { state with
                                    Active = state.Active @ [ key ]
                                }
                                added
                        | other -> failwith $"%O{kqueue} is %A{other} rather than a kqueue"
        | 5 ->
            // The same, as a whole new state; and, however unsoundly, now and
            // then another owner, with the same registrations or others.
            match kqueues table with
            | [] -> table
            | kqueues ->
                let kqueue, state = pick kqueues
                let key = pick fds, pick [ KqueueFilter.Read ; KqueueFilter.Write ]

                let state =
                    if rng.Next 4 = 0 then
                        state
                    elif Map.containsKey key state.Registrations then
                        { state with
                            Registrations = Map.remove key state.Registrations
                            Active = state.Active |> List.filter (fun active -> active <> key)
                        }
                    else
                        let registration : KqueueRegistration =
                            {
                                Clear = false
                                Receipt = false
                                UserData = 0UL
                                RegisteredAt = 0L
                                Socket = SocketId 0L
                            }

                        { state with
                            Registrations = Map.add key registration state.Registrations
                            Active =
                                if rng.Next 2 = 0 then
                                    state.Active @ [ key ]
                                else
                                    state.Active
                        }

                let state =
                    if rng.Next 3 = 0 then
                        { state with
                            Owner = pick owners
                        }
                    else
                        state

                OpenFileTable.setKqueueState kqueue state table
        | 6 ->
            // However unsoundly: an index must follow a description that
            // comes to register what another does, or stops registering.
            match live table with
            | [] -> table
            | ids ->
                let target =
                    match OpenFileTable.tryFind (pick ids) table with
                    | Some description -> description.Target
                    | None -> failwith "a live description is not in the table"

                OpenFileTable.mapDescription
                    "TestOpenFileIndex"
                    (pick ids)
                    (fun description ->
                        { description with
                            Target = target
                        }
                    )
                    table
        | 7 ->
            // A change that rewrites every epoll instance's ready list and
            // nothing it registers.
            OpenFileTable.signalEpollInstances (Set.ofList (live table)) None table
        | 8 ->
            // A close, which drops every registration made through the
            // descriptor in a kqueue of the closing process's.
            OpenFileTable.dropKqueueRegistrationsThrough (pick owners) (pick fds) table
        | 9 ->
            // However unsoundly: an epoll instance's registrations, as a whole
            // new state.
            match epolls table, live table with
            | [], _
            | _, [] -> table
            | epolls, ids ->
                let epoll, state = pick epolls
                let key = pick fds, pick ids

                let registration : EpollRegistration =
                    {
                        Events = EpollEvents.In
                        Data = 0UL
                        RegisteredAt = 0L
                    }

                let state =
                    if Map.containsKey key state.Registrations then
                        {
                            Registrations = Map.remove key state.Registrations
                            Ready = state.Ready |> List.filter (fun ready -> ready <> key)
                        }
                    else
                        { state with
                            Registrations = Map.add key registration state.Registrations
                        }

                OpenFileTable.mapDescription
                    "TestOpenFileIndex"
                    epoll
                    (fun description ->
                        { description with
                            Target = OpenFileTarget.Epoll state
                        }
                    )
                    table
        | _ -> step rng table

    /// What `OpenFileTable.dropKqueueRegistrationsThrough` must make of
    /// `table`, by a scan of every description.
    let private droppedByScan (owner : ProcessId) (fd : int) (table : OpenFileTable) : OpenFileTable =
        (table, kqueues table)
        ||> List.fold (fun table (kqueue, state) ->
            if state.Owner = owner then
                OpenFileTable.setKqueueState
                    kqueue
                    { state with
                        Registrations = state.Registrations |> Map.filter (fun (registered, _) _ -> registered <> fd)
                        Active = state.Active |> List.filter (fun (active, _) -> active <> fd)
                    }
                    table
            else
                table
        )

    /// Every question the epoll and kqueue indexes answer about `table`,
    /// answered by them and by a scan, which must agree; and what the table
    /// says of its own indexes and of the epoll instances' registrations.
    let private registrationsAgree (table : OpenFileTable) : unit =
        for target in OpenFileDescriptionId 1000L :: live table do
            let scanned =
                epolls table
                |> List.filter (fun (_, state) ->
                    state.Registrations |> Map.exists (fun (_, registered) _ -> registered = target)
                )
                |> List.map fst

            OpenFileTable.epollsRegistering target table |> List.sort |> shouldEqual scanned

        for owner in owners do
            for fd in 9 :: fds do
                let scanned =
                    kqueues table
                    |> List.filter (fun (_, state) ->
                        state.Owner = owner
                        && state.Registrations |> Map.exists (fun (registered, _) _ -> registered = fd)
                    )
                    |> List.map fst

                OpenFileTable.kqueuesRegisteringThrough owner fd table
                |> List.sort
                |> shouldEqual scanned

                OpenFileTable.descriptions (OpenFileTable.dropKqueueRegistrationsThrough owner fd table)
                |> shouldEqual (OpenFileTable.descriptions (droppedByScan owner fd table))

        OpenFileTable.checkInvariants [] table
        |> List.filter (fun defect ->
            match defect with
            | FileDescriptorRegistryDefect.StaleIndex
            | FileDescriptorRegistryDefect.EpollRegistrationTargetDead _
            | FileDescriptorRegistryDefect.EpollReadyEntryUnregistered _
            | FileDescriptorRegistryDefect.KqueueActiveEntryUnregistered _ -> true
            | _ -> false
        )
        |> shouldEqual []

    [<Test>]
    let ``the epoll and kqueue indexes answer what a scan of the descriptions answers`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (OpenFileTable.empty, [ 1 .. rng.Next (1, 60) ])
            ||> List.fold (fun table _ ->
                let next = registrationStep rng table
                agree next
                registrationsAgree next
                next
            )
            |> ignore<OpenFileTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)
