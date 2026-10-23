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
    /// Linux's `relatime`: a read moves it to now when it is not after the
    /// modification time, or not after the change time, or when its whole
    /// seconds are at least 86400 behind now's.
    | Relative
    /// Every read moves it to now: Linux's and Darwin's `strictatime`, and
    /// Darwin's devfs, which has no mount option for it.
    | Always

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
        | AccessTimeUpdate.Always ->
            Some
                { times with
                    Access = now
                }
        | AccessTimeUpdate.WhenBeforeModification ->
            if times.Access < times.Modification then
                Some
                    { times with
                        Access = now
                    }
            else
                None
        | AccessTimeUpdate.Relative ->
            // Measured on a Linux 6.18.5 devtmpfs (`docs/probes/devtmpfs-listing`):
            // a listing moved the atime when it equalled the mtime and ctime,
            // and when a chmod had put the ctime after it; not when it was
            // after both, nor 86399 s later; and at 86400 s, counted in whole
            // seconds of each.
            if
                times.Access <= times.Modification
                || times.Access <= times.StatusChange
                || UnixTimestamp.seconds now - UnixTimestamp.seconds times.Access >= 86400L
            then
                Some
                    { times with
                        Access = now
                    }
            else
                None
