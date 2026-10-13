namespace WoofWare.PosixKernel

/// When a flavour's `link(2)` refuses a source that is a directory.
[<RequireQualifiedAccess>]
type DirectorySourceRefusal =
    /// EPERM as soon as the source has resolved, before the new pathname is
    /// copied in. Darwin.
    | BeforeDestination
    /// EPERM only once every other check has passed, the write check's EACCES
    /// included. Linux.
    | Last

/// Everything a flavour's `link(2)` and `linkat(2)` do differently from the
/// other's.
type LinkRules =
    {
        /// Whether plain `link(2)` follows a symbolic link in its source's
        /// final position: Darwin's is `linkat(AT_SYMLINK_FOLLOW)`, Linux's
        /// `linkat(0)`.
        PlainLinkSource : SymlinkPolicy
        /// The walk the new pathname is resolved with: Linux's ignores a
        /// trailing separator, Darwin's resolves it, exactly as `symlink`'s do
        /// (`SymlinkRules.TrailingSeparator`).
        TrailingSeparator : TrailingSeparatorPolicy
        /// When a directory source is refused.
        DirectorySource : DirectorySourceRefusal
    }

/// What `link(2)` should do, now that both pathnames have resolved.
[<RequireQualifiedAccess>]
type internal LinkVerdict =
    /// Answer the caller with this errno.
    | Refuse of error : UnixError
    /// Bind the source under `name` in `directory`.
    | Create of directory : InodeNumber * name : DirectoryEntryName

[<RequireQualifiedAccess>]
module internal LinkRules =

    /// Decide what a `link(2)` owes once its source has resolved to the inode
    /// `source` and its new pathname to `resolution`.
    ///
    /// In order, each beating those below it:
    ///
    ///  * a new pathname with no final name ("/", ".", "..") is EEXIST;
    ///  * nothing can be created in a directory whose last name has gone:
    ///    ENOENT;
    ///  * an existing final name is EEXIST, whatever it is;
    ///  * a free final name with a trailing separator is ENOENT;
    ///  * a source on another filesystem than the new name's directory is
    ///    EXDEV;
    ///  * a source `protection` forbids the caller to link is EPERM (see
    ///    `ProtectedFiles.refusesToLink`);
    ///  * binding a name needs write on the directory that will hold it:
    ///    EACCES;
    ///  * a directory source is EPERM, where the flavour refuses it last (see
    ///    `LinkRules.DirectorySource`);
    ///  * a source with no name left, which only Linux's `AT_EMPTY_PATH` can
    ///    name, is ENOENT;
    ///  * a name `bindable` does not admit is EILSEQ.
    let verdict
        (rules : LinkRules)
        (protection : HardlinkProtection)
        (bindable : BindableEntryNames)
        (credentials : Credentials)
        (source : InodeNumber)
        (resolution : Resolution)
        (vfs : VirtualFileSystem)
        : LinkVerdict
        =
        // Measured by `link-symlink.c` (LINKDST, LINKDEV, LINKPERM) and
        // `link-rules.c` (ORDER, DESTMORE) on Linux 6.18.5 and Darwin 27.0, and
        // the orphan's ENOENT by `at-dirfd.c`.
        match resolution.Target with
        | ResolvedTarget.Directory _ -> LinkVerdict.Refuse UnixError.EEXIST
        | ResolvedTarget.Entry (directory, name, existing) ->

        if VirtualFileSystem.isOrphanedDirectory directory vfs then
            LinkVerdict.Refuse UnixError.ENOENT
        else

        match existing with
        | Some _ -> LinkVerdict.Refuse UnixError.EEXIST
        | None ->

        if resolution.TrailingSeparatorDemanded then
            LinkVerdict.Refuse UnixError.ENOENT
        elif
            VirtualFileSystem.mountedRootOf source vfs
            <> VirtualFileSystem.mountedRootOf directory vfs
        then
            LinkVerdict.Refuse UnixError.EXDEV
        else

        let sourceInode, parent =
            match VirtualFileSystem.tryGet source vfs, VirtualFileSystem.tryGet directory vfs with
            | Some sourceInode, Some parent -> sourceInode, parent
            | _ ->
                failwith
                    $"LinkRules.verdict: the source (inode %O{source}) or the directory to bind \"%s{DirectoryEntryName.toEscaped name}\" in (inode %O{directory}) is not in the filesystem. Run VirtualFileSystem.checkInvariants."

        if ProtectedFiles.refusesToLink protection credentials sourceInode then
            LinkVerdict.Refuse UnixError.EPERM
        elif
            PermissionBits.deniedTo
                (Standing.toward credentials parent.Owner)
                AccessRequest.Write
                (Inode.permissions parent)
        then
            LinkVerdict.Refuse UnixError.EACCES
        else

        let directorySource =
            match sourceInode.Content with
            | InodeContent.Directory _ -> true
            | InodeContent.RegularFile _
            | InodeContent.Symlink _
            | InodeContent.Socket _
            | InodeContent.Fifo _
            | InodeContent.CharacterDevice _ -> false

        match rules.DirectorySource with
        | DirectorySourceRefusal.Last when directorySource -> LinkVerdict.Refuse UnixError.EPERM
        | DirectorySourceRefusal.BeforeDestination when directorySource ->
            failwith
                $"LinkRules.verdict: the source (inode %O{source}) is a directory, which this flavour refuses before the destination is resolved (this is a bug in the caller)."
        | DirectorySourceRefusal.Last
        | DirectorySourceRefusal.BeforeDestination ->

        // Measured by `link-empty-path.c` (UNLINKED) on Linux 6.18.5: a file
        // with no name left, which only Linux's `AT_EMPTY_PATH` reaches, is
        // ENOENT only once every other check has passed.
        if VirtualFileSystem.bindingCount source vfs = 0 then
            LinkVerdict.Refuse UnixError.ENOENT
        elif not (BindableEntryNames.admits bindable name) then
            LinkVerdict.Refuse UnixError.EILSEQ
        else
            LinkVerdict.Create (directory, name)
