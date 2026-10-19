namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `OpenFileTable` keeps a record of the inotify watches on each inode and of
/// the instances and watches each user owns, which inotify's delivery and
/// `inotify_add_watch` read; and a record of the descriptions opened through
/// each name and of the inodes the descriptions hold, which an unlink, a
/// rename and the release of a name read. Over random walks of the table's
/// own changes, each answers what a scan of every description answers, and
/// what reads them (`InotifyDelivery.deliver`, `OpenFileTable.followChanges`,
/// `OpenFileTable.create`) does what its scan of every description did.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFileSystemIndex =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    /// A seed for a walk's own `System.Random`, from the whole range, and with
    /// no shrinker: a smaller seed is another walk, not a simpler one.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private context : string = "TestFileSystemIndex"

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private directories : InodeNumber list = [ InodeNumber 1L ; InodeNumber 2L ]
    let private files : InodeNumber list = [ InodeNumber 10L ; InodeNumber 11L ]
    let private inodes : InodeNumber list = directories @ files
    let private names : DirectoryEntryName list = [ name "a" ; name "b" ]

    let private owners : UserId list =
        [ UserId.root ; UserId.parseOrFail context 1000u ]

    /// Every name a walk opens through, and what else a description onto an
    /// inode can record.
    let private throughs : ReachedThrough list =
        [
            for directory in directories do
                for entry in names do
                    for unlinked in [ false ; true ] do
                        ReachedThrough.Name (
                            {
                                Parent = directory
                                Name = entry
                            },
                            unlinked
                        )
            ReachedThrough.Unnamed
        ]

    let private events : InotifyEvent list =
        [
            InotifyEvent.Create
            InotifyEvent.Delete
            InotifyEvent.Attrib
            InotifyEvent.DeleteSelf
        ]

    let private description (target : OpenFileTarget) : OpenFileDescription =
        {
            Target = target
            AccessMode = FileAccessMode.ReadOnly
            NonBlocking = false
            Flock = None
            Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
        }

    let private live (table : OpenFileTable) : OpenFileDescriptionId list =
        OpenFileTable.toSeq table |> Seq.map fst |> List.ofSeq

    let private instances (table : OpenFileTable) : (OpenFileDescriptionId * InotifyState) list =
        OpenFileTable.toSeq table
        |> Seq.choose (fun (id, description) ->
            match description.Target with
            | OpenFileTarget.Inotify state -> Some (id, state)
            | _ -> None
        )
        |> List.ofSeq

    let private pick (rng : System.Random) (items : 'a list) : 'a = items.[rng.Next items.Length]

    let private mask (rng : System.Random) : InotifyMask =
        {
            Events = events |> List.filter (fun _ -> rng.Next 2 = 0) |> Set.ofList
            ExcludeUnlinked = rng.Next 3 = 0
        }

    /// A target onto `inode`: a directory's description for a directory, a
    /// file's for a file.
    let private onto (inode : InodeNumber) : OpenFileTarget =
        if List.contains inode directories then
            OpenFileTarget.Directory (inode, DirectoryPosition.Cursor DirectoryCursor.Start)
        else
            OpenFileTarget.File (inode, 0L)

    /// The identity `OpenFileTable.create` must give the name a description
    /// onto `target` opened through `through` holds, by a scan of every
    /// description: that of the first live description onto the same inode
    /// recording the same name, still linked, or unlinked onto a directory,
    /// or `fresh`.
    let private identityByScan
        (target : OpenFileTarget)
        (through : ReachedThrough option)
        (fresh : OpenFileDescriptionId)
        (table : OpenFileTable)
        : OpenFileDescriptionId
        =
        let shares =
            match through, target with
            | Some (ReachedThrough.Name (_, false)), _
            | Some (ReachedThrough.Name (_, true)), OpenFileTarget.Directory _ -> true
            | _ -> false

        match through, OpenFileTable.inodeOf target with
        | Some (ReachedThrough.Name _), Some inode when shares ->
            OpenFileTable.toSeqOpenedThrough table
            |> Seq.tryPick (fun (id, other, otherThrough) ->
                if Some otherThrough = through && OpenFileTable.inodeOf other.Target = Some inode then
                    Some (OpenFileTable.nameIdentity id table)
                else
                    None
            )
            |> Option.defaultValue fresh
        | _ -> fresh

    /// Each name, still linked, a live description in `table` was opened
    /// through, and the inode that description is onto.
    let private linkedNames (table : OpenFileTable) : (ReachedThrough * InodeNumber) list =
        OpenFileTable.toSeqOpenedThrough table
        |> Seq.choose (fun (_, description, through) ->
            match through, OpenFileTable.inodeOf description.Target with
            | ReachedThrough.Name (_, false), Some inode -> Some (through, inode)
            | _ -> None
        )
        |> List.ofSeq

    /// Each name a walk could open through again that a live description in
    /// `table` holds, and a target onto the inode that description is onto: a
    /// name still linked, or a removed directory's, which a walk reaches by
    /// ".", and so only onto a directory.
    let private reachableNames (table : OpenFileTable) : (ReachedThrough * OpenFileTarget) list =
        OpenFileTable.toSeqOpenedThrough table
        |> Seq.choose (fun (_, description, through) ->
            match through, description.Target with
            | ReachedThrough.Name (_, false), target ->
                OpenFileTable.inodeOf target |> Option.map (fun inode -> through, onto inode)
            | ReachedThrough.Name (_, true), (OpenFileTarget.Directory _ as target) -> Some (through, target)
            | _ -> None
        )
        |> List.ofSeq

    /// A change of names among the walk's names, at random: often of a name
    /// a description in `table` was opened through, of the inode it is onto.
    let private change (rng : System.Random) (table : OpenFileTable) : FsChange =
        match linkedNames table with
        | (_ :: _) as linked when rng.Next 2 = 0 ->
            match pick rng linked with
            | ReachedThrough.Name (dentry, _), inode ->
                if rng.Next 3 = 0 then
                    FsChange.EntryRemoved (dentry.Parent, dentry.Name, inode)
                elif rng.Next 2 = 0 then
                    let displaced = if rng.Next 2 = 0 then Some (pick rng inodes) else None

                    FsChange.EntryMoved (
                        dentry.Parent,
                        dentry.Name,
                        pick rng directories,
                        pick rng names,
                        inode,
                        displaced
                    )
                else
                    // A rename onto the name, displacing the inode.
                    FsChange.EntryMoved (
                        pick rng directories,
                        pick rng names,
                        dentry.Parent,
                        dentry.Name,
                        pick rng inodes,
                        Some inode
                    )
            | _ -> failwith "a linked name is not a name"
        | _ ->

        match rng.Next 4 with
        | 0 -> FsChange.EntryRemoved (pick rng directories, pick rng names, pick rng inodes)
        | 1 ->
            let displaced = if rng.Next 2 = 0 then Some (pick rng inodes) else None

            FsChange.EntryMoved (
                pick rng directories,
                pick rng names,
                pick rng directories,
                pick rng names,
                pick rng inodes,
                displaced
            )
        | 2 -> FsChange.EntryAdded (pick rng directories, pick rng names, pick rng inodes)
        | _ -> FsChange.AttributesChanged (pick rng inodes)

    /// What `OpenFileTable.followChanges` must make of each live
    /// description's record of the name it was opened through, by a fold of
    /// every change over every description.
    let private followedByScan
        (changes : FsChange list)
        (table : OpenFileTable)
        : Map<OpenFileDescriptionId, ReachedThrough option>
        =
        OpenFileTable.toSeq table
        |> Seq.map (fun (id, description) ->
            let through =
                match OpenFileTable.openedThrough id table, OpenFileTable.inodeOf description.Target with
                | Some through, Some inode ->
                    (through, changes)
                    ||> List.fold (fun through change -> ReachedThrough.followChange inode change through)
                    |> Some
                | through, _ -> through

            id, through
        )
        |> Map.ofSeq

    let private openedThroughAll (table : OpenFileTable) : Map<OpenFileDescriptionId, ReachedThrough option> =
        live table
        |> List.map (fun id -> id, OpenFileTable.openedThrough id table)
        |> Map.ofList

    /// One of the table's own changes, at random, to `table`, weighted
    /// towards opening through names, making inotify instances, changing
    /// their watches, and following changes of names.
    let private step (rng : System.Random) (table : OpenFileTable) : OpenFileTable =
        match rng.Next 12, live table with
        | 0, _
        | _, [] ->
            // Often through a name that a live description holds and a walk
            // could reach again, onto its inode: a linked name, or a removed
            // directory's unlinked one.
            let target, through =
                match reachableNames table with
                | _ :: _ as reachable when rng.Next 2 = 0 ->
                    let through, target = pick rng reachable
                    target, Some through
                | _ -> onto (pick rng inodes), Some (pick rng throughs)

            let id, created = OpenFileTable.create (description target) through table

            OpenFileTable.nameIdentity id created
            |> shouldEqual (identityByScan target through id table)

            created
        | 1, _ ->
            let target =
                if rng.Next 2 = 0 then
                    OpenFileTarget.Pipe (PipeId 0L, PipeEnd.Read)
                else
                    OpenFileTarget.Inotify
                        {
                            Owner = pick rng owners
                            Watches = Map.empty
                            NextWatchDescriptor = 1
                            Queue = InotifyQueue.empty
                        }

            OpenFileTable.create (description target) None table |> snd
        | 2, _
        | 3, _ ->
            // `inotify_add_watch` of a new watch, or of one held, or
            // `inotify_rm_watch` of one held.
            match instances table with
            | [] -> table
            | held ->
                let instance, state = pick rng held
                let wd = WatchDescriptor (rng.Next (1, 4))

                if Map.containsKey wd state.Watches && rng.Next 2 = 0 then
                    OpenFileTable.removeInotifyWatch instance wd table
                else
                    let watch : InotifyWatch =
                        {
                            Inode = pick rng inodes
                            Mask = mask rng
                        }

                    OpenFileTable.setInotifyWatch instance wd watch table
        | 4, _ ->
            // The same, as a whole new state; and, now and then, another
            // owner, or a new queue and nothing else.
            match instances table with
            | [] -> table
            | held ->
                let instance, state = pick rng held
                let wd = WatchDescriptor (rng.Next (1, 4))

                let state =
                    match rng.Next 3 with
                    | 0 ->
                        { state with
                            Queue = InotifyQueue.enqueue 4 (InotifyRecord.Ignored wd) state.Queue |> fst
                        }
                    | 1 ->
                        { state with
                            Watches = Map.remove wd state.Watches
                        }
                    | _ ->
                        { state with
                            Watches =
                                Map.add
                                    wd
                                    {
                                        Inode = pick rng inodes
                                        Mask = mask rng
                                    }
                                    state.Watches
                        }

                let state =
                    if rng.Next 4 = 0 then
                        { state with
                            Owner = pick rng owners
                        }
                    else
                        state

                OpenFileTable.setInotifyState context instance state table
        | 5, _ ->
            let changes = List.init (rng.Next (1, 4)) (fun _ -> change rng table)
            let expected = followedByScan changes table
            let followed = OpenFileTable.followChanges changes table
            openedThroughAll followed |> shouldEqual expected
            followed
        | 6, ids
        | 7, ids ->
            // The last close of a descriptor, and then the description's
            // destruction.
            let id = pick rng ids
            OpenFileTable.destroyIfUnreferenced id (OpenFileTable.release id table) |> fst
        | 8, ids -> OpenFileTable.retain (pick rng ids) table
        | 9, ids ->
            // However unsoundly: an index must follow a description that
            // comes to be onto another inode, or onto none.
            let target =
                if rng.Next 3 = 0 then
                    OpenFileTarget.Pipe (PipeId 1L, PipeEnd.Write)
                else
                    let inode = pick rng inodes

                    if rng.Next 2 = 0 then
                        OpenFileTarget.Directory (inode, DirectoryPosition.Cursor DirectoryCursor.Start)
                    else
                        OpenFileTarget.File (inode, 0L)

            OpenFileTable.mapDescription
                context
                (pick rng ids)
                (fun description ->
                    { description with
                        Target = target
                    }
                )
                table
        | _, ids ->
            // A change that rewrites every description it reaches and leaves
            // what the indexes read as it was.
            OpenFileTable.signalEpollInstances (Set.ofList ids) None table

    /// Each instance watching `inode`, in identity order, and the descriptors
    /// of its watches on it, in order, by a scan of every description.
    let private watchesOnByScan
        (inode : InodeNumber)
        (table : OpenFileTable)
        : (OpenFileDescriptionId * WatchDescriptor list) list
        =
        instances table
        |> List.choose (fun (instance, state) ->
            match
                state.Watches
                |> Map.toList
                |> List.filter (fun (_, watch) -> watch.Inode = inode)
                |> List.map fst
            with
            | [] -> None
            | watches -> Some (instance, watches)
        )

    /// Every question the indexes answer about `table`, answered by them and
    /// by a scan, which must agree.
    let private agree (table : OpenFileTable) : unit =
        for inode in InodeNumber 99L :: inodes do
            OpenFileTable.inotifyWatchesOn inode table
            |> shouldEqual (watchesOnByScan inode table)

            let held =
                OpenFileTable.toSeq table
                |> Seq.exists (fun (id, description) ->
                    OpenFileTable.inodeOf description.Target = Some inode
                    || (
                        match OpenFileTable.openedThrough id table with
                        | Some (ReachedThrough.Name (dentry, _)) -> dentry.Parent = inode
                        | _ -> false
                    )
                )

            OpenFileTable.holdsInode inode table |> shouldEqual held

        let heldByScan (directoriesOnly : bool) : Set<InodeNumber> =
            OpenFileTable.toSeq table
            |> Seq.collect (fun (id, description) ->
                [
                    match description.Target with
                    | OpenFileTarget.Directory (inode, _) -> inode
                    | target when not directoriesOnly ->
                        match OpenFileTable.inodeOf target with
                        | Some inode -> inode
                        | None -> ()
                    | _ -> ()
                    match OpenFileTable.openedThrough id table with
                    | Some (ReachedThrough.Name (dentry, _)) -> dentry.Parent
                    | _ -> ()
                ]
            )
            |> Set.ofSeq

        OpenFileTable.heldInodes table |> Set.ofSeq |> shouldEqual (heldByScan false)

        OpenFileTable.heldDirectories table
        |> Set.ofSeq
        |> shouldEqual (heldByScan true)

        for owner in owners do
            let owned = instances table |> List.filter (fun (_, state) -> state.Owner = owner)
            OpenFileTable.inotifyInstancesOwnedBy owner table |> shouldEqual owned.Length

            OpenFileTable.inotifyWatchesOwnedBy owner table
            |> shouldEqual (owned |> List.sumBy (fun (_, state) -> Map.count state.Watches))

        for directory in directories do
            for entry in names do
                for inode in inodes do
                    let scanned =
                        OpenFileTable.toSeqOpenedThrough table
                        |> Seq.exists (fun (_, description, through) ->
                            through = ReachedThrough.ofEntry directory entry
                            && OpenFileTable.inodeOf description.Target = Some inode
                        )

                    OpenFileTable.holdsLinkedName directory entry inode table |> shouldEqual scanned

        let identities = OpenFileDescriptionId 1000L :: live table

        for through in throughs do
            for identity in identities do
                let scanned =
                    OpenFileTable.toSeqOpenedThrough table
                    |> Seq.exists (fun (id, _, other) ->
                        other = through && OpenFileTable.nameIdentity id table = identity
                    )

                OpenFileTable.nameHeldElsewhere through identity table |> shouldEqual scanned

        OpenFileTable.checkInvariants [] table
        |> List.contains FileDescriptorRegistryDefect.StaleIndex
        |> shouldEqual false

    [<Test>]
    let ``the watch, name and held-inode indexes answer what a scan of the descriptions answers`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (OpenFileTable.empty, [ 1 .. rng.Next (1, 60) ])
            ||> List.fold (fun table _ ->
                let next = step rng table
                agree next
                next
            )
            |> ignore<OpenFileTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)

    [<Test>]
    let ``a name two identities hold gives a new description the identity of the earliest holder`` () : unit =
        let file = InodeNumber 10L

        let through (entry : string) =
            Some (ReachedThrough.ofEntry (InodeNumber 1L) (name entry))

        let first, table =
            OpenFileTable.create (description (onto file)) (through "a") OpenFileTable.empty

        let second, table =
            OpenFileTable.create (description (onto file)) (through "a") table

        let _, table = OpenFileTable.create (description (onto file)) (through "b") table

        let table =
            OpenFileTable.destroyIfUnreferenced first (OpenFileTable.release first table)
            |> fst

        // However unsoundly, as a rename onto another name of the same inode
        // would: "b" is now held by the second description, of the first's
        // identity, and by the third, of its own, which is later.
        let table =
            OpenFileTable.followChanges
                [
                    FsChange.EntryMoved (InodeNumber 1L, name "a", InodeNumber 1L, name "b", file, None)
                ]
                table

        let created, table =
            OpenFileTable.create (description (onto file)) (through "b") table

        OpenFileTable.nameIdentity created table |> shouldEqual first
        OpenFileTable.nameIdentity second table |> shouldEqual first

    /// `InotifyDelivery.deliver` as it was before the table indexed the
    /// watches: every instance's watches read from every description, once,
    /// and again after each end of the watches on an inode.
    let private deliverByScan
        (maxQueuedEvents : int)
        (effects : InotifyEffect list)
        (openFiles : OpenFileTable)
        : OpenFileTable
        =
        let watchesByInode (table : OpenFileTable) =
            instances table
            |> List.map (fun (id, state) ->
                let byInode =
                    state.Watches
                    |> Map.toSeq
                    |> Seq.map (fun (watch, watched) -> watched.Inode, (watch, watched.Mask))
                    |> Map.ofSeq

                id, byInode
            )

        ((openFiles, watchesByInode openFiles), effects)
        ||> List.fold (fun (table, instances) effect ->
            match effect with
            | InotifyEffect.Notify notification ->
                let table =
                    (table, instances)
                    ||> List.fold (fun table (instance, watches) ->
                        match Map.tryFind notification.Watched watches with
                        | None -> table
                        | Some (watch, mask) ->

                        if
                            Set.intersect notification.Events mask.Events |> Set.isEmpty
                            || notification.HiddenByExclUnlink && mask.ExcludeUnlinked
                        then
                            table
                        else
                            let record =
                                InotifyRecord.Event (
                                    watch,
                                    notification.Events,
                                    notification.SubjectIsDirectory,
                                    notification.Cookie,
                                    notification.Name
                                )

                            OpenFileTable.enqueueInotify maxQueuedEvents instance record table
                    )

                table, instances
            | InotifyEffect.WatchesEnd inode ->
                let watching =
                    instances
                    |> List.choose (fun (instance, watches) ->
                        Map.tryFind inode watches |> Option.map (fun watched -> instance, watched)
                    )

                let table =
                    (table, watching)
                    ||> List.fold (fun table (instance, (watch, mask)) ->
                        let state = OpenFileTable.inotifyState context instance table

                        let table =
                            OpenFileTable.setInotifyState
                                context
                                instance
                                { state with
                                    Watches = Map.remove watch state.Watches
                                }
                                table

                        let table =
                            if Set.contains InotifyEvent.DeleteSelf mask.Events then
                                OpenFileTable.enqueueInotify
                                    maxQueuedEvents
                                    instance
                                    (InotifyRecord.Event (
                                        watch,
                                        Set.singleton InotifyEvent.DeleteSelf,
                                        false,
                                        0u,
                                        None
                                    ))
                                    table
                            else
                                table

                        OpenFileTable.enqueueInotify maxQueuedEvents instance (InotifyRecord.Ignored watch) table
                    )

                table, watchesByInode table
        )
        |> fst

    let private effect (rng : System.Random) : InotifyEffect =
        if rng.Next 4 = 0 then
            InotifyEffect.WatchesEnd (pick rng inodes)
        else
            InotifyEffect.Notify
                {
                    Watched = pick rng inodes
                    Events = Set.singleton (pick rng events)
                    SubjectIsDirectory = rng.Next 2 = 0
                    Cookie = uint32 (rng.Next 3)
                    Name = if rng.Next 2 = 0 then Some (pick rng names) else None
                    HiddenByExclUnlink = rng.Next 2 = 0
                }

    [<Test>]
    let ``delivery queues and ends what a scan of every instance's watches does`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (OpenFileTable.empty, [ 1 .. rng.Next (1, 60) ])
            ||> List.fold (fun table _ ->
                let effects = List.init (rng.Next (0, 6)) (fun _ -> effect rng)
                let maxQueuedEvents = rng.Next (1, 5)

                let delivered = InotifyDelivery.deliver maxQueuedEvents effects table

                OpenFileTable.descriptions delivered
                |> shouldEqual (OpenFileTable.descriptions (deliverByScan maxQueuedEvents effects table))

                agree delivered

                // Delivery and the walk's own changes, in turn.
                step rng delivered
            )
            |> ignore<OpenFileTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    /// The paths a system walk names: directories nested two deep, and names
    /// in each.
    let private paths : string list =
        [ "/a" ; "/a/b" ; "/c" ; "/a/f" ; "/a/b/g" ; "/c/h" ; "/a/b/c" ]

    /// One syscall of a walk, at random, by `caller`, holding the descriptors
    /// `kept`; a call the model refuses changes nothing.
    let private systemStep
        (rng : System.Random)
        (caller : Caller<int>)
        (kept : int list, system : UnixSystem<int, unit>)
        : int list * UnixSystem<int, unit>
        =
        let flavour = SimulatedUnixPlatform.flavour (UnixSystem.platform system)
        let path () = PathArg.ofText (pick rng paths)

        let answered (call : unit -> SyscallAnswer * UnixSystem<int, unit>) : UnixSystem<int, unit> =
            try
                call () |> snd |> resume caller
            with :? UnmodelledException ->
                system

        match rng.Next 8 with
        | 0 -> kept, answered (fun () -> UnixNamespace.mkdir caller (path ()) 0o755 system)
        | 1 -> kept, answered (fun () -> UnixNamespace.rmdir caller (path ()) system)
        | 2 -> kept, answered (fun () -> UnixNamespace.unlink caller (path ()) system)
        | 3 -> kept, answered (fun () -> UnixPathResolution.chdir caller (path ()) system)
        | 4 ->
            let destination = path ()

            let renamed =
                try
                    match
                        UnixNamespace.tryRename caller (path ()) system
                        |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination destination)
                    with
                    | Ok (_, system) -> resume caller system
                    | Error _ -> system
                with :? UnmodelledException ->
                    system

            kept, renamed
        | 5 ->
            // An open for reading, of a directory or a file, or for writing,
            // creating the file.
            let flags =
                match rng.Next 2, flavour with
                | 0, _ -> 0
                | _, SimulatedUnixFlavour.Linux -> 0x2 ||| 0x40
                | _, SimulatedUnixFlavour.Darwin -> 0x2 ||| 0x200

            let opened =
                try
                    match UnixNamespace.openat caller (AtDirectory.atFdCwd flavour) (path ()) flags 0o644 system with
                    | SyscallOutcome.Answered (SyscallAnswer.Completed fd), system ->
                        Some (int fd, resume caller system)
                    | _ -> None
                with :? UnmodelledException ->
                    None

            match opened with
            | Some (fd, system) -> fd :: kept, system
            | None -> kept, system
        | _ ->
            match kept with
            | [] -> kept, system
            | _ ->
                let fd = pick rng kept
                List.filter ((<>) fd) kept, answered (fun () -> UnixDescriptor.close caller fd system)

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``an inode is pinned exactly when the closure of what the machine holds has it`` (flavour : string) : unit =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | "darwin" -> SimulatedUnixPlatform.macOsArm64
            | flavour -> failwith $"no platform for %s{flavour}"

        let property (seed : int) : unit =
            let rng = System.Random seed

            let booted =
                UnixSystem.initial platform
                |> UnixBootImage.boot (ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0))

            let caller = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0

            (([], booted), [ 1 .. rng.Next (1, 40) ])
            ||> List.fold (fun state _ ->
                let kept, system = systemStep rng caller state
                let graph = UnixSystem.fileSystem system
                let pinned = ObjectLifetime.pinnedInodes system

                for inode in Seq.append (VirtualFileSystem.inodes graph |> Map.keys) [ InodeNumber 999L ] do
                    ObjectLifetime.isPinned graph inode (Kernel.machine system)
                    |> shouldEqual (Set.contains inode pinned)

                UnixSystem.checkInvariants system |> shouldEqual []
                VirtualFileSystem.checkInvariants pinned graph |> shouldEqual []
                kept, system
            )
            |> ignore<int list * UnixSystem<int, unit>>

        Check.One (propertyConfig, Prop.forAll walkSeed property)
