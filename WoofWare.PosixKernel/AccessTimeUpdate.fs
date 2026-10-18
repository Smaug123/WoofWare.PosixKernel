namespace WoofWare.PosixKernel

/// When a read of a file or a directory moves its access time. That is a
/// mount option (Linux's `noatime`, `relatime` and `strictatime`; Darwin's
/// `noatime` and `strictatime`), so it is a fact about a mount rather than
/// about a kernel.
[<RequireQualifiedAccess>]
type internal AccessTimeUpdate =
    /// No read moves it.
    | Never
    /// A read moves it to now when it is before the modification time, and
    /// leaves it alone otherwise, however old it is.
    | WhenBeforeModification

[<RequireQualifiedAccess>]
module internal AccessTimeUpdate =
    /// The rule of the filesystem `mount` describes.
    let ofMount (mount : EmulatedMount) : AccessTimeUpdate =
        match mount with
        // The tmpfs this kernel models is mounted `noatime`, which its
        // `statfs(2)` reports. Linux's default, `relatime`, would also move a
        // symbolic link's atime whenever a path walk follows the link, under
        // `stat(2)` and `access(2)` among others, which answer no system
        // (measured, `docs/probes/atime`: the `follow` rows).
        | EmulatedMount.Tmpfs _ -> AccessTimeUpdate.Never
        // APFS with neither `noatime` nor `strictatime`, which is how a Mac
        // mounts its data volume, and how a fresh disk image is attached.
        // Measured on both (`docs/probes/atime`): a read moved the atime when
        // it was before the mtime, and not when it was equal to it or after
        // it, whatever the ctime, and however far in the past it was (up to
        // 9000 hours).
        | EmulatedMount.Apfs _ -> AccessTimeUpdate.WhenBeforeModification
        // Unmeasured: an NFS file's times are the server's. This kernel moves
        // none of them, as it moves no other time on NFS that a server would.
        | EmulatedMount.Nfs -> AccessTimeUpdate.Never

    /// What a read under `rule` at `now` makes of an inode's `times`, or
    /// `None` where it moves none of them. A read moves no time but the
    /// access time.
    let afterRead (rule : AccessTimeUpdate) (now : UnixTimestamp) (times : InodeTimes) : InodeTimes option =
        match rule with
        | AccessTimeUpdate.Never -> None
        | AccessTimeUpdate.WhenBeforeModification ->
            if times.Access < times.Modification then
                Some
                    { times with
                        Access = now
                    }
            else
                None
