namespace WoofWare.PosixKernel

/// What a flavour's `fchmodat(2)` does when `AT_SYMLINK_NOFOLLOW` leaves it at
/// a symbolic link.
[<RequireQualifiedAccess>]
type SymlinkModeChange =
    /// EOPNOTSUPP, changing nothing, whoever asks: the link's owner, root, or
    /// a caller who could not have changed it anyway. Linux.
    | NotSupported
    /// The link's own mode changes, by the rule `chmod(2)` applies to a
    /// regular file (see `UnixPathResolution.chmod`), set-ID and sticky bits
    /// included, moving the link's `ctime`, even to the mode it already has,
    /// and nothing of its target's or its directory's. Darwin.
    | ChangesLink
