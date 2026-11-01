namespace WoofWare.PosixKernel

/// <summary>
/// Identity of a file within the emulated filesystem.
/// </summary>
/// <remarks>
/// This is the <c>st_ino</c> a process reads back from <c>stat</c>.
///
/// The exact values are observable by the guest: a program commonly decides whether two
/// paths name the same file by comparing their device and inode numbers as
/// integers.
/// </remarks>
[<Struct>]
type InodeNumber =
    | InodeNumber of value : int64

    /// <summary>
    /// The underlying integer, formatted as a string.
    /// </summary>
    override this.ToString () : string =
        match this with
        | InodeNumber value -> string<int64> value

/// <summary>
/// The timestamp metadata a kernel keeps for an inode.
/// </summary>
/// <remarks>
/// All these timestamps are stored on every platform.
/// That includes <c>Birth</c>, even though some syscalls (like Linux's <c>stat</c>) might not report it.
/// (<c>statx</c> does.)
/// </remarks>
type InodeTimes =
    {
        /// <summary>
        /// <c>st_atim</c>: last read.
        /// </summary>
        Access : UnixTimestamp
        /// <summary>
        /// <c>st_mtim</c>: last change to the contents.
        /// </summary>
        Modification : UnixTimestamp
        /// <summary>
        /// <c>st_ctim</c>: last change to the inode.
        /// </summary>
        /// <example>
        /// <c>chmod</c>, <c>link</c>, and <c>rename</c> all move this, even though they touch no content.
        /// </example>
        StatusChange : UnixTimestamp
        /// <summary>
        /// <c>st_birthtim</c>: when the inode was created.
        /// </summary>
        /// <remarks>
        /// After creation, this moves only when Darwin's <c>utimensat</c> sets a
        /// modification time earlier than the current birth time, in which case it moves backwards; see
        /// <c>UnixPathResolution.utimensat</c>.
        /// </remarks>
        Birth : UnixTimestamp
    }

[<RequireQualifiedAccess>]
module internal InodeTimes =
    /// <summary>
    /// The timing metadata of a freshly-created inode.
    /// </summary>
    /// <remarks>
    /// All four timestamps are equal, because creation is simultaneously its birth,
    /// its last content change, its last inode change, and its last access.
    /// </remarks>
    let createdAt (now : UnixTimestamp) : InodeTimes =
        {
            Access = now
            Modification = now
            StatusChange = now
            Birth = now
        }

    /// <summary>
    /// Record a change to the inode's contents.
    /// </summary>
    /// <remarks>
    /// <c>mtime</c> and <c>ctime</c> both move,
    /// because changing what's in a file or directory also changes the inode
    /// that describes it.
    /// <c>atime</c> and <c>birth</c> do not move.
    /// </remarks>
    let contentsChangedAt (now : UnixTimestamp) (times : InodeTimes) : InodeTimes =
        { times with
            Modification = now
            StatusChange = now
        }

    /// <summary>
    /// Set the status-change time to <c>now</c>.
    /// </summary>
    /// <remarks>
    /// There may be platform-specific logic required to compute which timestamps need
    /// to be updated in response to any given syscall; this function doesn't do that.
    /// </remarks>
    /// <example>
    /// This is the timestamp change that happens when the inode gains or loses a link,
    /// since a link count lives on the inode rather than in what the inode holds.
    /// </example>
    let statusChangedAt (now : UnixTimestamp) (times : InodeTimes) : InodeTimes =
        // Measured on both platforms through a held descriptor's `fstat`, which is
        // the only way to watch an inode whose last name has just gone: after
        // `unlink`, `ctime` has moved and `mtime` and `atime` have not — the same
        // for an inode that still has links left as for one that does not.
        { times with
            StatusChange = now
        }

/// <summary>
/// The contents of a directory: what it holds, and what contains it.
/// </summary>
type DirectoryContent =
    {
        /// <summary>
        /// The inodes contained in this directory.
        /// </summary>
        /// <remarks>
        /// Holds only <i>real</i> names. "." and ".." are genuine directory entries in the kernel,
        /// but we don't store them here (because that would make recursion harder).
        /// <c>readdir</c> synthesises them on demand.
        /// </remarks>
        Entries : Map<DirectoryEntryName, InodeNumber>
        /// <summary>
        /// The directory that holds this one, which is what ".." resolves to.
        /// </summary>
        /// <example>
        /// The root is its own parent.
        /// </example>
        /// <remarks>
        /// This is the <i>physical</i> parent, so it is still correct after a walk
        /// has crossed a symlink.
        /// By contrast, the <i>lexical</i> predecessor in the path need not be.
        /// </remarks>
        Parent : InodeNumber
        /// <summary>
        /// The <c>chmod</c>-able bits of this directory's mode.
        /// </summary>
        Permissions : PermissionBits
    }

/// <summary>
/// The number a device node holds.
/// </summary>
/// <example>
/// This is what <c>open(2)</c> uses to look up a driver, and what <c>stat(2)</c> reports
/// as <c>st_rdev</c>.
/// </example>
[<Struct>]
type DeviceNumber =
    | DeviceNumber of major : uint32 * minor : uint32

    /// <summary>The pair as <c>major:minor</c></summary>.
    override this.ToString () : string =
        match this with
        | DeviceNumber (major, minor) -> $"%d{major}:%d{minor}"

/// <summary>
/// A well-known character device.
/// </summary>
/// <remarks>
/// Not all of these are necessarily implemented yet; see <c>CharacterDevice.all</c> for the implemented ones.
/// </remarks>
[<RequireQualifiedAccess>]
type CharacterDevice =
    /// <summary>
    /// <c>/dev/null</c>.
    /// </summary>
    | Null
    /// <summary>
    /// <c>/dev/urandom</c>.
    /// </summary>
    | URandom
    /// <summary>
    /// <c>/dev/zero</c>.
    /// </summary>
    /// <remarks>
    /// Not yet implemented.
    /// </remarks>
    | Zero
    /// <summary>
    /// <c>/dev/random</c>.
    /// </summary>
    /// <remarks>
    /// Not yet implemented.
    /// </remarks>
    | Random
    /// <summary>
    /// <c>/dev/tty</c>: the calling process's controlling terminal.
    /// </summary>
    /// <remarks>
    /// Not yet implemented.
    /// </remarks>
    | Tty

/// <summary>
/// What lives at an inode.
/// </summary>
/// <remarks>
/// Carries only the metadata whose shape depends on which kind of thing this inode is.
/// Metadata whose shape is the same for all inodes lives on <c>Inode</c> instead.
///
/// The emulated filesystem is case-sensitive and normalisation-preserving:
/// a directory binds a name under exactly the bytes it was created with.
/// On Linux, a lookup reaches only the entry bound under exactly the bytes looked up.
/// On Darwin, as on APFS, a lookup reaches the entry bound under any canonically
/// equivalent Unicode spelling of them; but this library doesn't hold any Unicode tables, so
/// a call which would rely on that equivalence throws <c>UnmodelledException</c>.
/// </remarks>
[<RequireQualifiedAccess>]
type InodeContent =
    | RegularFile of contents : FileContents * permissions : PermissionBits
    | Directory of directory : DirectoryContent
    /// <summary>
    /// The link's target (unresolved), and the link's own permission bits.
    /// </summary>
    /// <remarks>
    /// The kernel treats a symlink's target as a string to be re-resolved
    /// on every traversal; it's not a reference to whatever it pointed at
    /// when it was made.
    ///
    /// The permission bits are what the link was created with, which depends
    /// on the flavour. Linux's are
    /// always <c>0o777</c>; Darwin's depend on the creating process's umask.
    /// </remarks>
    | Symlink of target : SymlinkTarget * permissions : PermissionBits
    /// <summary>
    /// A character special file: what <c>stat(2)</c> reports as <c>S_IFCHR</c>.
    /// </summary>
    /// <remarks>
    /// This inode stands for the device <c>number</c> names, rather than holding
    /// any contents of its own.
    /// Opening it reaches the driver registered for that number, if this
    /// kernel has one.
    /// </remarks>
    | CharacterDevice of number : DeviceNumber * permissions : PermissionBits
    /// <summary>
    /// A socket special file: what <c>stat(2)</c> reports as <c>S_IFSOCK</c>.
    /// </summary>
    /// <example>
    /// Created, for example, by a `bind(2)` of a Unix-domain socket.
    /// </example>
    | Socket of permissions : PermissionBits
    /// <summary>
    /// A FIFO special file, or named pipe: what <c>stat(2)</c> reports as
    /// <c>S_IFIFO</c>.
    /// </summary>
    /// <example>
    /// Created, for example, by <c>mkfifo</c> or <c>mknod(2)</c> of <c>S_IFIFO</c>.
    /// </example>
    /// <remarks>
    /// The bytes in transit are not part of the content: they live only while
    /// some end of the FIFO is open, and go at the last close.
    /// </remarks>
    | Fifo of permissions : PermissionBits

[<RequireQualifiedAccess>]
module InodeContent =
    /// <summary>
    /// The <c>S_IFMT</c> band of <c>st_mode</c>, indicating which kind of thing (directory, regular file, socket etc)
    /// lives at an inode.
    /// </summary>
    let fileTypeBits (content : InodeContent) : int =
        match content with
        | InodeContent.RegularFile _ -> 0o100000
        | InodeContent.Directory _ -> 0o40000
        | InodeContent.Symlink _ -> 0o120000
        | InodeContent.CharacterDevice _ -> 0o020000
        // `S_IFSOCK`, `0140000` in both flavours' `<sys/stat.h>`.
        | InodeContent.Socket _ -> 0o140000
        // `S_IFIFO`, `0010000` in both flavours' `<sys/stat.h>`.
        | InodeContent.Fifo _ -> 0o010000

/// <summary>
/// Who owns an inode: the <c>st_uid</c> and <c>st_gid</c> that <c>stat(2)</c> reports for it.
/// </summary>
[<Struct>]
type InodeOwner =
    {
        User : UserId
        Group : GroupId
    }

/// <summary>
/// How a platform determines where a newly created inode's group comes from.
/// </summary>
[<RequireQualifiedAccess>]
type NewInodeGroupRule =
    /// <summary>
    /// The creator's effective group, unless the directory the inode is created
    /// in is set-group-ID, in which case that directory's group.
    /// </summary>
    /// <example>
    /// This is how Linux behaves, on a filesystem not mounted <c>grpid</c>.
    /// </example>
    | CreatorsUnlessParentSetGroupId
    /// <summary>
    /// Always the group of the directory the inode is created in.
    /// </summary>
    /// <example>
    /// This is how Darwin behaves, as does every BSD.
    /// </example>
    | Parents

[<RequireQualifiedAccess>]
module InodeOwner =
    /// <summary>
    /// The effective user and group of a process with <c>credentials</c>.
    /// </summary>
    let ofProcess (credentials : Credentials) : InodeOwner =
        {
            User = credentials.EffectiveUser
            Group = credentials.EffectiveGroup
        }

    /// The owner of an inode the process with `credentials` creates now, in a
    /// directory owned by `parentOwner` whose permission bits are
    /// `parentPermissions`.
    ///
    /// The user is always the creator's effective user ID.
    let internal ofNewInode
        (rule : NewInodeGroupRule)
        (credentials : Credentials)
        (parentOwner : InodeOwner)
        (parentPermissions : PermissionBits)
        : InodeOwner
        =
        // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/new-inode-owner.c`,
        // for `open(O_CREAT)` and `mkdir` alike. Linux 6.18.5 (tmpfs and ext4):
        // real 1000 / effective 1001 creates uid 1001; the gid is the effective
        // gid in a plain parent whatever the parent's group, and the parent's gid
        // in a set-group-ID parent whether or not the creator is in that group.
        // Darwin 27.0: the parent's gid every time, including a `wheel` parent
        // the creator is not in, and whether or not the parent is set-group-ID.

        let group =
            match rule with
            | NewInodeGroupRule.Parents -> parentOwner.Group
            | NewInodeGroupRule.CreatorsUnlessParentSetGroupId ->
                if PermissionBits.toInt parentPermissions &&& PermissionBits.setGroupId <> 0 then
                    parentOwner.Group
                else
                    credentials.EffectiveGroup

        {
            User = credentials.EffectiveUser
            Group = group
        }

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module internal Standing =
    /// How a process with `credentials` stands towards an inode owned by
    /// `owner`.
    ///
    /// The effective IDs decide it, and the supplementary groups count as
    /// membership exactly as the effective group does; the real and saved IDs
    /// play no part.
    let toward (credentials : Credentials) (owner : InodeOwner) : Standing =
        // Measured on Linux 6.18.5 (`permission-standing.c`): real 1001 and
        // effective 1000 may read a 1000-owned 0400 file; real group 2000 and
        // effective group 1000, with no supplementary groups, may not read a
        // group-2000 0040 file and may read a group-1000 one; and a group
        // reached only through a supplementary group selects the group triple
        // over all 4096 modes. A Darwin process cannot have differing real and
        // effective IDs in this library (`ProcessLaunch.withCredentials`).
        {
            Privilege = Credentials.privilege credentials
            Owns = owner.User = credentials.EffectiveUser
            InGroup = Credentials.isInGroup credentials owner.Group
        }

/// <summary>
/// One inode: what lives there, and the metadata every inode carries whatever
/// kind of thing it is.
/// </summary>
type Inode =
    {
        Content : InodeContent
        Times : InodeTimes
        /// <summary>
        /// Who owns this inode.
        /// </summary>
        Owner : InodeOwner
    }

[<RequireQualifiedAccess>]
module Inode =
    /// <summary>
    /// An inode's permission bits.
    /// </summary>
    let permissions (inode : Inode) : PermissionBits =
        match inode.Content with
        | InodeContent.RegularFile (_, permissions) -> permissions
        | InodeContent.Directory directory -> directory.Permissions
        | InodeContent.Symlink (_, permissions) -> permissions
        | InodeContent.CharacterDevice (_, permissions) -> permissions
        | InodeContent.Socket permissions -> permissions
        | InodeContent.Fifo permissions -> permissions
