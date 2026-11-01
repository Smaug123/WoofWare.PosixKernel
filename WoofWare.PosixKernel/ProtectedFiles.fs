namespace WoofWare.PosixKernel

/// <summary>
/// Configuration for when a platform refuses to follow symlinks.
/// </summary>
/// <remarks>
/// This applies only to Linux. Darwin behaves as <c>Off</c>.
/// <para />
/// This is Linux's <c>fs.protected_symlinks</c> sysctl.
/// </remarks>
[<RequireQualifiedAccess>]
type SymlinkProtection =
    /// <summary>
    /// Walks follow all links.
    /// </summary>
    /// <remarks>
    /// On Linux, this is what you'd get by setting <c>fs.protected_symlinks</c> to <c>0</c> (the default).
    /// It's also the only option on Darwin.
    /// </remarks>
    | Off
    /// <summary>
    /// A walk refuses (returning EACCES) to follow a link in the final position of a path, when the
    /// containing directory is sticky and world-writable, unless the follower or the directory's owner owns the link.
    /// </summary>
    /// <remarks>
    /// Darwin doesn't have this.
    /// <para />
    /// On Linux, path resolution depends also on the state of the dentry cache, because the kernel
    /// may eventually return ELOOP if there are too many links to follow. WoofWare.PosixKernel
    /// currently throws <c>UnmodelledException</c> in some of those cases, rather than correctly
    /// giving EACCES or ELOOP.
    /// <para />
    /// On Linux, this is what you'd get by setting <c>fs.protected_symlinks</c> to <c>1</c>.
    /// <para />
    /// Many distributions set this through <c>sysctl.d</c>.
    /// </remarks>
    | InWorldWritableStickyDirectories

/// <summary>
/// Configuration for when a platform refuses to create an existing file or FIFO with <c>O_CREAT</c> in <c>open(2)</c>.
/// </summary>
/// <remarks>
/// This applies only to Linux. Darwin behaves as <c>Off</c>.
/// <para />
/// This models Linux's <c>fs.protected_regular</c> and <c>fs.protected_fifos</c> sysctls.
/// </remarks>
[<RequireQualifiedAccess>]
type CreationProtection =
    /// <summary>
    /// There's no protection preventing an open with <c>O_CREAT</c> in a sticky directory.
    /// </summary>
    /// <remarks>
    /// On Linux, this is what you'd get by setting <c>fs.protected_regular</c> (or <c>fs.protected_fifos</c>) to 0 (the default).
    /// It's also the only option on Darwin.
    /// </remarks>
    | Off
    /// <summary>
    /// An <c>O_CREAT</c> open of an existing object in a sticky, world-writable directory
    /// is refused with EACCES, unless the caller or the directory's owner owns the object.
    /// </summary>
    /// <remarks>
    /// Darwin doesn't have this.
    /// <para />
    /// On Linux, this is what you'd get by setting <c>fs.protected_regular</c> (or <c>fs.protected_fifos</c>) to 1.
    /// </remarks>
    | InWorldWritableStickyDirectories
    /// <summary>
    /// In addition to <c>InWorldWritableStickyDirectories</c>'s restrictions, an <c>O_CREAT</c> open
    /// of an existing object in a sticky group-writable but not world-writable directory is refused
    /// with EACCES, unless the caller or the directory's owner owns the object.
    /// </summary>
    /// <remarks>
    /// Darwin doesn't have this.
    /// <para />
    /// On Linux, this is what you'd get by setting <c>fs.protected_regular</c> (or <c>fs.protected_fifos</c>) to 2.
    /// </remarks>
    | InGroupOrWorldWritableStickyDirectories

/// <summary>
/// Configuration for when a platform refuses to create a hardlink.
/// </summary>
/// <remarks>
/// This applies only to Linux. Darwin behaves as <c>Off</c>.
/// <para />
/// This is Linux's <c>fs.protected_hardlinks</c> sysctl.
/// </remarks>
[<RequireQualifiedAccess>]
type HardlinkProtection =
    /// <summary>
    /// A caller may link any inode.
    /// </summary>
    /// <remarks>
    /// On Linux, this is what you'd get by setting <c>fs.protected_hardlinks</c> to 0 (the default).
    /// It's also the only option on Darwin.
    /// </remarks>
    | Off
    /// <summary>
    /// An unprivileged caller which doesn't own the inode may only link a regular file if it can both read and write
    /// that file, the file is not setuid, and the file isn't simultaneously setgid and group-executable.
    /// </summary>
    /// <remarks>
    /// Darwin doesn't have this.
    /// <para />
    /// The condition takes a lot of words to say, but the gist is "you can only link the file if: you can
    /// already access it, and setsid/setgid are such that you can't execute its contents as someone else after you
    /// write them".
    /// <para />
    /// On Linux, this is what you'd get by setting <c>fs.protected_hardlinks</c> to 1.
    /// <para />
    /// <c>link(2)</c> returns EPERM for callers who are forbidden.
    /// <para />
    /// Many distributions set this through <c>sysctl.d</c>.
    /// </remarks>
    | NonOwnersNeedReadAndWrite

/// <summary>
/// Linux's <c>fs.protected_*</c> sysctls that decide what a caller may do with
/// another user's files.
/// </summary>
type ProtectedFiles =
    // This is machine configuration, not a fact of the kernel, because an administrator
    // sets these.
    {
        /// <summary><c>fs.protected_symlinks</c>.</summary>
        Symlinks : SymlinkProtection
        /// <summary><c>fs.protected_regular</c>.</summary>
        RegularFiles : CreationProtection
        /// <summary><c>fs.protected_fifos</c>.</summary>
        Fifos : CreationProtection
        /// <summary><c>fs.protected_hardlinks</c>.</summary>
        /// <remarks>
        /// <c>link(2)</c> consults this.
        /// </remarks>
        Hardlinks : HardlinkProtection
    }

[<RequireQualifiedAccess>]
module ProtectedFiles =
    let private groupWritable : int = 0o0020
    let private worldWritable : int = 0o0002
    let private stickyWorldWritable : int = PermissionBits.sticky ||| worldWritable

    /// <summary>
    /// Represents setting all the protection sysctls to <c>0</c>.
    /// </summary>
    /// <remarks>
    /// Also represents how Darwin behaves, because it doesn't have those sysctls.
    /// </remarks>
    let off : ProtectedFiles =
        {
            Symlinks = SymlinkProtection.Off
            RegularFiles = CreationProtection.Off
            Fifos = CreationProtection.Off
            Hardlinks = HardlinkProtection.Off
        }

    /// Whether a walk on behalf of `credentials`, following a symbolic link
    /// owned by `linkOwner` from the final position of a path, may not follow
    /// it, the link being in a directory owned by `directoryOwner` with the
    /// permission bits `directoryPermissions`.
    ///
    /// The effective user decides it, and privilege does not exempt a caller:
    /// root is refused like anyone else.
    let internal refusesToFollow
        (protection : SymlinkProtection)
        (credentials : Credentials)
        (directoryOwner : InodeOwner)
        (directoryPermissions : PermissionBits)
        (linkOwner : InodeOwner)
        : bool
        =
        // Measured on Linux 6.18.5 (`protected-sysctls.c`, SYMLINKS rows): each
        // value, every combination of the sticky, group-write and other-write
        // bits on a 0755 directory, and every relation between the directory's
        // owner, the link's owner and the follower among root, 1000, 1001 and
        // 1002. Group write never matters, and neither does privilege.
        match protection with
        | SymlinkProtection.Off -> false
        | SymlinkProtection.InWorldWritableStickyDirectories ->
            PermissionBits.toInt directoryPermissions &&& stickyWorldWritable = stickyWorldWritable
            && not (Standing.toward credentials linkOwner).Owns
            && linkOwner.User <> directoryOwner.User

    /// Whether an `open(2)` with `O_CREAT` on behalf of `credentials`, landing
    /// on the existing inode `existing` in a directory owned by
    /// `directoryOwner` with the permission bits `directoryPermissions`, is
    /// refused because of who owns them: Linux's screen of a sticky
    /// directory's entries.
    ///
    /// A regular file is screened as `protection.RegularFiles` says, and a FIFO
    /// as `protection.Fifos` says. Any other inode (a symbolic link, which only
    /// `O_NOFOLLOW` leaves unfollowed, or a directory) is screened whatever the
    /// sysctls say, as
    /// `CreationProtection.InWorldWritableStickyDirectories` would screen it.
    /// The effective user decides it, and privilege does not exempt a caller.
    let internal refusesCreatingOpen
        (protection : ProtectedFiles)
        (credentials : Credentials)
        (directoryOwner : InodeOwner)
        (directoryPermissions : PermissionBits)
        (existing : Inode)
        : bool
        =
        // Measured on Linux 6.18.5 (`protected-sysctls.c`, REGULAR and FIFOS
        // rows) over the geometry `refusesToFollow` was, for each value of each
        // sysctl: a regular file, a FIFO, a link opened `O_NOFOLLOW` and a
        // directory. The FIFO rows are the regular file's under the other
        // sysctl, value for value.
        let bits = PermissionBits.toInt directoryPermissions

        // `None` for a kind no sysctl governs.
        let governing =
            match existing.Content with
            | InodeContent.RegularFile _ -> Some protection.RegularFiles
            | InodeContent.Fifo _ -> Some protection.Fifos
            | InodeContent.Socket _
            | InodeContent.CharacterDevice _
            | InodeContent.Symlink _
            | InodeContent.Directory _ -> None

        if bits &&& PermissionBits.sticky = 0 then
            false
        elif governing = Some CreationProtection.Off then
            false
        elif existing.Owner.User = directoryOwner.User then
            false
        elif (Standing.toward credentials existing.Owner).Owns then
            false
        elif bits &&& worldWritable <> 0 then
            true
        elif bits &&& groupWritable <> 0 then
            governing = Some CreationProtection.InGroupOrWorldWritableStickyDirectories
        else
            false

    /// Whether `link(2)` on behalf of `credentials` may not give the inode
    /// `source` another name, under `protection`: a caller that neither owns
    /// the inode nor is privileged may link only a regular file that is
    /// neither set-user-ID nor set-group-ID and group-executable, and that it
    /// may both read and write.
    let internal refusesToLink (protection : HardlinkProtection) (credentials : Credentials) (source : Inode) : bool =
        // Measured on Linux 6.18.5 (`link-rules.c`, ORDER rows, as uid 1000
        // and root): another user's 0600 and 0644 files, a 04666 file, a 02676
        // file, a symbolic link and a directory are refused; a 0666 and a
        // 02666 file are linked; root and the owner are never refused.
        match protection with
        | HardlinkProtection.Off -> false
        | HardlinkProtection.NonOwnersNeedReadAndWrite ->

        let standing = Standing.toward credentials source.Owner

        if standing.Owns || standing.Privilege = CallerPrivilege.Privileged then
            false
        else

        match source.Content with
        | InodeContent.RegularFile (_, bits) ->
            let raw = PermissionBits.toInt bits

            raw &&& PermissionBits.setUserId <> 0
            || (raw &&& PermissionBits.setGroupId <> 0
                && raw &&& PermissionBits.groupExecute <> 0)
            || PermissionBits.deniedTo standing AccessRequest.Read bits
            || PermissionBits.deniedTo standing AccessRequest.Write bits
        | InodeContent.Directory _
        | InodeContent.Symlink _
        | InodeContent.Socket _
        | InodeContent.Fifo _
        | InodeContent.CharacterDevice _ -> true
