namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The path syscalls that copy a pathname in partway, made with every pathname
/// to hand: the call, then, if it stops at the copy, its resume with the rest.
[<RequireQualifiedAccess>]
module internal Eager =

    /// `renameat(2)`: `UnixNamespace.tryRenameat`, then
    /// `tryRenameWithDestination` of `newpath`.
    let tryRenameat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (newpath : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RenameRefusal>
        =
        UnixNamespace.tryRenameat (Callers.leader system) olddirfd oldpath newdirfd system
        |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination newpath)

    /// `rename(2)`: `UnixNamespace.tryRename`, then `tryRenameWithDestination`
    /// of `destination`.
    let tryRename<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (destination : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RenameRefusal>
        =
        UnixNamespace.tryRename (Callers.leader system) source system
        |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination destination)

    /// `symlink(2)`: `UnixNamespace.symlink`, then `trySymlinkWithPath` of
    /// `path`.
    let trySymlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (target : PathArgumentBytes)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SymlinkRefusal>
        =
        Ok (UnixNamespace.symlink (Callers.leader system) target system)
        |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)

    /// `link(2)`: `UnixNamespace.tryLink`, then `tryLinkWithDestination` of
    /// `newpath`.
    let tryLink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldpath : PathArgumentBytes)
        (newpath : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, LinkRefusal>
        =
        UnixNamespace.tryLink (Callers.leader system) oldpath system
        |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)

    /// `symlinkat(2)` by `caller`: `UnixNamespace.symlinkat`, then
    /// `trySymlinkWithPath` of `path`.
    let trySymlinkatAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (target : PathArgumentBytes)
        (dirfd : int)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SymlinkRefusal>
        =
        Ok (UnixNamespace.symlinkat caller target dirfd system)
        |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)

    /// `linkat(2)` by `caller`: `UnixNamespace.tryLinkat`, then
    /// `tryLinkWithDestination` of `newpath`.
    let tryLinkatAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (newpath : PathArgumentBytes)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, LinkRefusal>
        =
        UnixNamespace.tryLinkat caller olddirfd oldpath newdirfd flags system
        |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)

    /// Darwin's `clonefile(2)` by `caller`: `UnixNamespace.tryCloneFile`, then
    /// `tryCloneFileWithSource` of `source` and `tryCloneFileWithDestination`
    /// of `destination`.
    let tryCloneFileAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (source : PathArgumentBytes)
        (destination : PathArgumentBytes)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, CloneFileRefusal>
        =
        UnixNamespace.tryCloneFile caller flags system
        |> CallProgress.resumeWith (fun paused ->
            UnixNamespace.tryCloneFileWithSource source paused
            |> CallProgress.resumeWith (UnixNamespace.tryCloneFileWithDestination destination)
        )

    /// `faccessat(2)` by `caller`: `UnixPathResolution.tryFaccessat`, then
    /// `tryAccessWithPath` of `path`.
    let tryFaccessatAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer, AccessRefusal>
        =
        UnixPathResolution.tryFaccessat caller dirfd mode flags system
        |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)

    /// `access(2)`: `UnixPathResolution.tryAccess`, then `tryAccessWithPath`
    /// of `path`.
    let tryAccess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer, AccessRefusal>
        =
        UnixPathResolution.tryAccess (Callers.leader system) mode system
        |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)

    /// `inotify_add_watch(2)` by `caller`: `UnixInotify.tryInotifyAddWatch`,
    /// then `tryInotifyAddWatchWithPath` of `path`.
    let tryInotifyAddWatchAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (path : PathArgumentBytes)
        (mask : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, InotifyAddWatchRefusal>
        =
        UnixInotify.tryInotifyAddWatch caller fd mask system
        |> CallProgress.resumeWith (UnixInotify.tryInotifyAddWatchWithPath path)

    /// `tryInotifyAddWatchAs` the leader of the only process on the machine.
    let tryInotifyAddWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (path : PathArgumentBytes)
        (mask : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, InotifyAddWatchRefusal>
        =
        tryInotifyAddWatchAs (Callers.leader system) fd path mask system
