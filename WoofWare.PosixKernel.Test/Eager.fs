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
        UnixNamespace.tryRenameat olddirfd oldpath newdirfd system
        |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination newpath)

    /// `rename(2)`: `UnixNamespace.tryRename`, then `tryRenameWithDestination`
    /// of `destination`.
    let tryRename<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (destination : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RenameRefusal>
        =
        UnixNamespace.tryRename source system
        |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination destination)

    /// `symlink(2)`: `UnixNamespace.symlink`, then `trySymlinkWithPath` of
    /// `path`.
    let trySymlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (target : PathArgumentBytes)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SymlinkRefusal>
        =
        Ok (UnixNamespace.symlink target system)
        |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)

    /// `link(2)`: `UnixNamespace.tryLink`, then `tryLinkWithDestination` of
    /// `newpath`.
    let tryLink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldpath : PathArgumentBytes)
        (newpath : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, LinkRefusal>
        =
        UnixNamespace.tryLink oldpath system
        |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)

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

    /// `inotify_add_watch(2)`: `UnixInotify.tryInotifyAddWatch`, then
    /// `tryInotifyAddWatchWithPath` of `path`.
    let tryInotifyAddWatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (path : PathArgumentBytes)
        (mask : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, InotifyAddWatchRefusal>
        =
        UnixInotify.tryInotifyAddWatch fd mask system
        |> CallProgress.resumeWith (UnixInotify.tryInotifyAddWatchWithPath path)
