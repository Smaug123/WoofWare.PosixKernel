namespace WoofWare.PosixKernel

/// The flags `inotify_init1(2)` accepts, in Linux's `<fcntl.h>` numbering,
/// which every architecture this library models shares for these two.
[<RequireQualifiedAccess>]
module InotifyInitFlags =
    /// `IN_CLOEXEC`: give the new descriptor `FD_CLOEXEC`. The same value as
    /// `O_CLOEXEC`.
    [<Literal>]
    let CloseOnExec : int = OpenFlagNumbering.LinuxCloseOnExec

    /// `IN_NONBLOCK`: make the new description non-blocking. The same value as
    /// `O_NONBLOCK`.
    [<Literal>]
    let NonBlock : int = OpenFlagNumbering.LinuxNonBlock

/// Why this kernel will not answer an `inotify_init1(2)` or an
/// `inotify_rm_watch(2)`.
[<RequireQualifiedAccess>]
type internal InotifyRefusal =
    /// This kernel is of `flavour` (Darwin), which has no inotify: no Darwin
    /// kernel has the call, so there is no answer to measure.
    | Flavour of flavour : SimulatedUnixFlavour
    /// A descriptor `inotify_init1` would make lies at or above the bound this
    /// kernel assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal

[<RequireQualifiedAccess>]
module internal InotifyRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which of its entry points asked.
    let describe (refusal : InotifyRefusal) : string =
        match refusal with
        | InotifyRefusal.Flavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and inotify exists on Linux only, so no kernel of this flavour has the call."
        | InotifyRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : InotifyRefusal) : RefusalKind =
        match refusal with
        | InotifyRefusal.Flavour _ -> RefusalKind.NotOnPlatform
        | InotifyRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer an `inotify_add_watch(2)`.
[<RequireQualifiedAccess>]
type internal InotifyAddWatchRefusal =
    /// This kernel is of `flavour` (Darwin), which has no inotify.
    | Flavour of flavour : SimulatedUnixFlavour
    /// The call would succeed, and the watch would ask for `events`, none of
    /// which this kernel raises (see `InotifyEvent.modelled`). Unmodelled.
    | UnmodelledEvents of events : InotifyEvent list
    /// The call would succeed with `IN_ONESHOT`, which removes a watch after
    /// its first event. Unmodelled.
    | OneShot
    /// The path has no answer here.
    | Path of PathRefusal
    /// The call would make a new watch, and the instance has handed out every
    /// watch descriptor up to `Int32.MaxValue`. Linux would hand out that one
    /// and then start again from 1, skipping those in use; this kernel does
    /// not model the wrap.
    | WatchDescriptorsExhausted

[<RequireQualifiedAccess>]
module internal InotifyAddWatchRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which of its entry points asked.
    let describe (refusal : InotifyAddWatchRefusal) : string =
        match refusal with
        | InotifyAddWatchRefusal.Flavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and inotify exists on Linux only, so no kernel of this flavour has the call."
        | InotifyAddWatchRefusal.UnmodelledEvents events ->
            let names = events |> List.map (sprintf "%O") |> String.concat ", "
            $"the watch would ask for %s{names}, which this kernel never raises: it reports no open or read of a file to a watch, and unmounts nothing. Ask for the other events only."
        | InotifyAddWatchRefusal.OneShot ->
            "the watch would carry IN_ONESHOT, which removes the watch after its first event, and that removal is not modelled."
        | InotifyAddWatchRefusal.Path refusal -> PathRefusal.describe refusal
        | InotifyAddWatchRefusal.WatchDescriptorsExhausted ->
            "the instance has handed out every watch descriptor below Int32.MaxValue. Linux would hand out that one and then start again from 1, skipping those in use, and this kernel does not model the wrap."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : InotifyAddWatchRefusal) : RefusalKind =
        match refusal with
        | InotifyAddWatchRefusal.Flavour _ -> RefusalKind.NotOnPlatform
        | InotifyAddWatchRefusal.UnmodelledEvents _ -> RefusalKind.Unmodelled
        | InotifyAddWatchRefusal.OneShot -> RefusalKind.Unmodelled
        | InotifyAddWatchRefusal.Path inner -> PathRefusal.kind inner
        | InotifyAddWatchRefusal.WatchDescriptorsExhausted -> RefusalKind.Unmodelled

/// An `inotify_add_watch(2)` whose mask and descriptor this kernel has
/// screened and accepted, paused at the point where it copies its path in.
/// Obtain one from `UnixInotify.inotifyAddWatch`, and finish it with
/// `UnixInotify.inotifyAddWatchWithPath`.
[<NoEquality ; NoComparison>]
type PausedInotifyAddWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
            Instance : OpenFileDescriptionId
            State : InotifyState
            Word : InotifyMaskWord
        }

/// `inotify_init1(2)`, `inotify_add_watch(2)` and `inotify_rm_watch(2)`: Linux's
/// interface for watching the filesystem.
///
/// An instance is an open file description (`OpenFileTarget.Inotify`); its
/// watches and its queued records are the description's own. `read(2)` takes
/// records from it (`UnixReadWrite.read`), `poll(2)` and epoll report it
/// readable while it holds one, and `ioctl(FIONREAD)` reports their bytes.
///
/// A change to the filesystem, by any process, queues records on the instances
/// watching it.
[<RequireQualifiedAccess>]
module UnixInotify =

    /// How many inotify instances `user` holds on the machine, in every
    /// process.
    let private instancesOf (user : UserId) (machine : UnixMachineState) : int =
        OpenFileTable.inotifyInstancesOwnedBy user machine.OpenFiles

    /// How many watches the inotify instances `user` holds have, on the
    /// machine, in every process.
    let private watchesOf (user : UserId) (machine : UnixMachineState) : int =
        OpenFileTable.inotifyWatchesOwnedBy user machine.OpenFiles

    /// The inotify instance `fd` names and its state: `EBADF` for a descriptor
    /// that is not open, and `EINVAL` for one that names anything else
    /// (measured, `inotify-probe.c` row W bad-fd, and
    /// `inotify-instance-probe.c` section G).
    let private instanceOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<OpenFileDescriptionId * InotifyState, UnixError>
        =
        match FileDescriptorRegistry.tryFindWithId fd (UnixSystemState.fileDescriptors system) with
        | None -> Error UnixError.EBADF
        | Some (id, description) ->
            match description.Target with
            | OpenFileTarget.Inotify state -> Ok (id, state)
            | OpenFileTarget.Epoll _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Socket _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Pipe _ -> Error UnixError.EINVAL

    /// `tryInotifyInit1` once `Entry` has admitted its caller.
    let private tryInotifyInit1In<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DescriptorAnswer * ProcessView<'Thread, 'Handler>, InotifyRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (InotifyRefusal.Flavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        if flags &&& ~~~(InotifyInitFlags.CloseOnExec ||| InotifyInitFlags.NonBlock) <> 0 then
            Ok (DescriptorAnswer.Failed UnixError.EINVAL, system)
        else

        let owner = system.Process.Credentials.EffectiveUser

        // Linux counts the instance against its user as it makes the group,
        // before it makes the descriptor.
        if
            instancesOf owner system.Machine
            >= system.Machine.InotifyLimits.MaxUserInstances
        then
            Ok (DescriptorAnswer.Failed UnixError.EMFILE, system)
        else

        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal -> Error (InotifyRefusal.DescriptorLimit refusal)
        | Ok () ->

        let fd, registry =
            FileDescriptorRegistry.createInotify
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                owner
                (flags &&& InotifyInitFlags.NonBlock <> 0)
                (UnixSystemState.fileDescriptors system)

        let registry =
            FileDescriptorRegistry.setFlags
                fd
                (DescriptorFlags.closingOnExec
                    (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                    (flags &&& InotifyInitFlags.CloseOnExec <> 0))
                registry

        Ok (DescriptorAnswer.Returned fd, UnixSystemState.withFileDescriptors registry system)

    /// `inotifyInit1`, with a refusal answered as the `Error` rather than raised.
    let internal tryInotifyInit1<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, InotifyRefusal>
        =
        Entry.call
            "UnixInotify.inotifyInit1"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryInotifyInit1In flags)
            system

    /// <summary>
    /// `inotify_init1(2)`: create an inotify instance with no watches, owned by
    /// the process's effective user, and a descriptor onto it, the lowest one
    /// not in use.
    ///
    /// `flags` is Linux's: 0, or any of `InotifyInitFlags.CloseOnExec` (the
    /// descriptor's `FD_CLOEXEC`) and `InotifyInitFlags.NonBlock` (the
    /// description's `O_NONBLOCK`). Any other bit is `EINVAL`, and changes
    /// nothing (measured, `inotify-instance-probe.c` section F). A user who
    /// already holds `InotifyLimits.MaxUserInstances` instances, in any process
    /// on the machine, is answered `EMFILE` (section U).
    ///
    /// Under the Darwin flavour every call is refused: Darwin has no inotify.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is of `flavour` (Darwin), which has no inotify: no Darwin kernel has the call, so there is no answer to measure.</exception>
    let inotifyInit1<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : DescriptorAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryInotifyInit1 caller flags system
        |> Refusal.orRaise "UnixInotify.inotifyInit1" InotifyRefusal.kind InotifyRefusal.describe

    /// `tryInotifyAddWatch` once `Entry` has admitted its caller.
    let private tryInotifyAddWatchIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (mask : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedInotifyAddWatch<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              InotifyAddWatchRefusal
           >
        =
        let failed (error : UnixError) =
            Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (InotifyAddWatchRefusal.Flavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        match InotifyMaskWord.parse mask with
        | None -> failed UnixError.EINVAL
        | Some word ->

        match FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system) with
        | None -> failed UnixError.EBADF
        | Some _ ->

        if word.MaskAdd && word.MaskCreate then
            failed UnixError.EINVAL
        else

        match instanceOf fd system with
        | Error error -> failed error
        | Ok (instance, state) ->

        Ok (
            CallProgress.NeedsCopyIn
                {
                    System = system
                    Instance = instance
                    State = state
                    Word = word
                }
        )

    /// `inotifyAddWatch`, with a refusal answered as the `Error` rather than raised.
    let internal tryInotifyAddWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (mask : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedInotifyAddWatch<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>,
              InotifyAddWatchRefusal
           >
        =
        Entry.call
            "UnixInotify.inotifyAddWatch"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryInotifyAddWatchIn fd mask)
            system

    /// <summary>
    /// `inotify_add_watch(2)`: watch the inode a path names, through the
    /// inotify instance `fd` names, for what `mask` asks; or change what an
    /// existing watch of that inode asks. Answers the watch's descriptor.
    ///
    /// `mask` is raw, in Linux's `&lt;sys/inotify.h&gt;` numbering. Linux's checks,
    /// in its order (measured, `inotify-probe.c` section W and
    /// `inotify-instance-probe.c` sections G, M and U):
    /// - a bit `&lt;sys/inotify.h&gt;` does not define, or no bit at all, is
    ///   `EINVAL`, ahead of the descriptor;
    /// - a descriptor not open is `EBADF`;
    /// - `IN_MASK_ADD` with `IN_MASK_CREATE` is `EINVAL`, and so is a
    ///   descriptor that names anything but an inotify instance;
    /// - the path is copied in and walked from the current directory, the
    ///   final symbolic link followed unless `IN_DONT_FOLLOW`; with
    ///   `IN_ONLYDIR`, an inode that is not a directory is `ENOTDIR`;
    /// - a caller who may not read the inode is `EACCES`;
    /// - a watch of the inode already held answers its descriptor, `EEXIST`
    ///   under `IN_MASK_CREATE`. Its events and `IN_EXCL_UNLINK` are replaced,
    ///   or added to under `IN_MASK_ADD`;
    /// - otherwise a new watch takes the next descriptor, which is never
    ///   reused. If the instance's owner already holds
    ///   `InotifyLimits.MaxUserWatches` watches, in any of its instances, the
    ///   call is `ENOSPC`, and the descriptor it took is spent all the same.
    ///
    /// The first three checks never read the path: a call they answer is
    /// `CallProgress.Answered`, with the system unchanged, and the path may be
    /// a pointer the client could not read at all. Otherwise the call stops
    /// where the kernel copies the path in, and `inotifyAddWatchWithPath`,
    /// given its bytes, finishes it.
    ///
    /// The bits Linux adds to a record (`IN_ISDIR`, `IN_IGNORED`,
    /// `IN_Q_OVERFLOW`) are accepted and mean nothing. A call that would
    /// succeed asking for an event this kernel does not raise, or with
    /// `IN_ONESHOT`, is refused; one that fails answers its errno.
    ///
    /// Adding a watch queues nothing. Under the Darwin flavour every call is
    /// refused.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is of `flavour` (Darwin), which has no inotify.</exception>
    let inotifyAddWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (mask : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedInotifyAddWatch<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryInotifyAddWatch caller fd mask system
        |> Refusal.orRaise "UnixInotify.inotifyAddWatch" InotifyAddWatchRefusal.kind InotifyAddWatchRefusal.describe

    /// `tryInotifyAddWatchWithPath`, before `Entry.resume` hands its answer back.
    let private tryInotifyAddWatchWithPathIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedInotifyAddWatch<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, InotifyAddWatchRefusal>
        =
        CallProgress.requirePaused "UnixInotify.inotifyAddWatchWithPath" "UnixInotify.inotifyAddWatch" paused

        let system = paused.System
        let instance = paused.Instance
        let state = paused.State
        let word = paused.Word
        let failed (error : UnixError) = Ok (SyscallAnswer.Failed error, system)

        match UnixPathResolution.copyIn path system with
        | Error error -> failed error
        | Ok path ->

        let policy =
            if word.DontFollow then
                SymlinkPolicy.NoFollowFinal
            else
                SymlinkPolicy.Follow

        match UnixPathResolution.resolvePath AtDirectory.CurrentDirectory policy path system with
        | Error (PathFailure.Errno error) -> failed error
        | Error (PathFailure.Refused refusal) -> Error (InotifyAddWatchRefusal.Path refusal)
        | Ok inode ->

        let found =
            VirtualFileSystem.get "UnixInotify.inotifyAddWatch" inode system.Machine.FileSystem

        let isDirectory =
            match found.Content with
            | InodeContent.Directory _ -> true
            | InodeContent.RegularFile _
            | InodeContent.Symlink _
            | InodeContent.CharacterDevice _
            | InodeContent.Socket _
            | InodeContent.Fifo _ -> false

        // `LOOKUP_DIRECTORY`: the walk itself refuses a final inode that is not
        // a directory, ahead of any permission the watch needs.
        if word.OnlyDirectory && not isDirectory then
            failed UnixError.ENOTDIR
        // "You can only watch an inode if you have read permissions on it":
        // Linux's `path_permission(MAY_READ)`, measured for a directory with
        // search but not read permission, and for a write-only file.
        elif
            PermissionBits.deniedTo
                (Standing.toward system.Process.Credentials found.Owner)
                AccessRequest.Read
                (Inode.permissions found)
        then
            failed UnixError.EACCES
        else

        let refusedFor (events : Set<InotifyEvent>) : InotifyAddWatchRefusal option =
            match events |> Set.toList |> List.filter (InotifyEvent.modelled >> not) with
            | _ :: _ as unmodelled -> Some (InotifyAddWatchRefusal.UnmodelledEvents unmodelled)
            | [] when word.OneShot -> Some InotifyAddWatchRefusal.OneShot
            | [] -> None

        let modelledEvents = word.Events |> Set.filter InotifyEvent.modelled

        let commit (state : InotifyState) : ProcessView<'Thread, 'Handler> =
            UnixSystemState.mapOpenFiles
                (OpenFileTable.setInotifyState "UnixInotify.inotifyAddWatch" instance state)
                system

        let existing =
            match OpenFileTable.inotifyWatchesOfInstanceOn instance inode system.Machine.OpenFiles with
            | watch :: _ -> Some (watch, Map.find watch state.Watches)
            | [] -> None

        match existing with
        | Some _ when word.MaskCreate -> failed UnixError.EEXIST
        | Some (watch, held) ->
            match refusedFor word.Events with
            | Some refusal -> Error refusal
            | None ->

            let mask =
                if word.MaskAdd then
                    {
                        Events = Set.union held.Mask.Events modelledEvents
                        ExcludeUnlinked = held.Mask.ExcludeUnlinked || word.ExcludeUnlinked
                    }
                else
                    {
                        Events = modelledEvents
                        ExcludeUnlinked = word.ExcludeUnlinked
                    }

            let changed =
                UnixSystemState.mapOpenFiles
                    (OpenFileTable.setInotifyWatch
                        instance
                        watch
                        { held with
                            Mask = mask
                        })
                    system

            Ok (SyscallAnswer.Completed (int64 (WatchDescriptor.toInt watch)), changed)
        | None ->

        if state.NextWatchDescriptor = System.Int32.MaxValue then
            Error InotifyAddWatchRefusal.WatchDescriptorsExhausted
        else

        let watch = WatchDescriptor state.NextWatchDescriptor

        let state =
            { state with
                NextWatchDescriptor = state.NextWatchDescriptor + 1
            }

        // Linux allocates the descriptor before it counts the watch against
        // its user, and gives it back to nobody when the count is full
        // (measured, `inotify-instance-probe.c` row U after-rm).
        if
            watchesOf state.Owner system.Machine
            >= system.Machine.InotifyLimits.MaxUserWatches
        then
            Ok (SyscallAnswer.Failed UnixError.ENOSPC, commit state)
        else

        match refusedFor word.Events with
        | Some refusal -> Error refusal
        | None ->

        let added =
            UnixSystemState.mapOpenFiles
                (OpenFileTable.setInotifyWatch
                    instance
                    watch
                    {
                        Inode = inode
                        Mask =
                            {
                                Events = modelledEvents
                                ExcludeUnlinked = word.ExcludeUnlinked
                            }
                    })
                (commit state)

        Ok (SyscallAnswer.Completed (int64 (WatchDescriptor.toInt watch)), added)

    /// `inotifyAddWatchWithPath`, with a refusal answered as the `Error` rather than raised.
    let internal tryInotifyAddWatchWithPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedInotifyAddWatch<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, InotifyAddWatchRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryInotifyAddWatchWithPathIn path paused)

    /// <summary>
    /// The second half of `inotify_add_watch(2)`: copy in `path`, the
    /// argument's bytes, and answer the call `paused` describes.
    /// </summary>
    /// <remarks>
    /// See `inotifyAddWatch` for what it answers and refuses.
    /// </remarks>
    let inotifyAddWatchWithPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedInotifyAddWatch<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryInotifyAddWatchWithPath path paused
        |> Refusal.orRaise
            "UnixInotify.inotifyAddWatchWithPath"
            InotifyAddWatchRefusal.kind
            InotifyAddWatchRefusal.describe

    /// `tryInotifyRmWatch` once `Entry` has admitted its caller.
    let private tryInotifyRmWatchIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (wd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, InotifyRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (InotifyRefusal.Flavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        match instanceOf fd system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok (instance, state) ->

        let watch = WatchDescriptor wd

        if not (Map.containsKey watch state.Watches) then
            Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
        else

        let removed =
            UnixSystemState.mapOpenFiles
                (OpenFileTable.removeInotifyWatch instance watch
                 >> OpenFileTable.enqueueInotify
                     system.Machine.InotifyLimits.MaxQueuedEvents
                     instance
                     (InotifyRecord.Ignored watch))
                system

        Ok (SyscallAnswer.Completed 0L, removed)

    /// `inotifyRmWatch`, with a refusal answered as the `Error` rather than raised.
    let internal tryInotifyRmWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (wd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, InotifyRefusal>
        =
        Entry.call
            "UnixInotify.inotifyRmWatch"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryInotifyRmWatchIn fd wd)
            system

    /// <summary>
    /// `inotify_rm_watch(2)`: remove the watch `wd` names from the inotify
    /// instance `fd` names, and queue an `IN_IGNORED` record for it, which
    /// wakes a reader asleep on the instance.
    ///
    /// `EBADF` for a descriptor not open, `EINVAL` for one naming anything but
    /// an inotify instance, and `EINVAL` for a `wd` the instance does not hold
    /// (measured, `inotify-probe.c` row W rm and `inotify-instance-probe.c`
    /// section G). A queue already holding `InotifyLimits.MaxQueuedEvents`
    /// records drops the record, and takes an `IN_Q_OVERFLOW` record in its
    /// place unless it holds one.
    ///
    /// Under the Darwin flavour every call is refused.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is of `flavour` (Darwin), which has no inotify: no Darwin kernel has the call, so there is no answer to measure.</exception>
    let inotifyRmWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (wd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryInotifyRmWatch caller fd wd system
        |> Refusal.orRaise "UnixInotify.inotifyRmWatch" InotifyRefusal.kind InotifyRefusal.describe
