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
        // Darwin refuses a directory source before the new pathname is
        // copied in, so a directory reaching here is Linux's, refused last.
        match rules.DirectorySource, VirtualFileSystem.tryGetContent source vfs with
        | DirectorySourceRefusal.BeforeDestination, Some (InodeContent.Directory _) ->
            failwith
                $"LinkRules.verdict: the source (inode %O{source}) is a directory, which this flavour refuses before the destination is resolved (this is a bug in the caller)."
        | DirectorySourceRefusal.BeforeDestination, _
        | DirectorySourceRefusal.Last, _ ->

        // Darwin's devfs refuses an unprivileged caller a link from it or into
        // it EPERM once the destination has been walked, ahead of the existing
        // name's EEXIST, the cross-mount EXDEV and the write check, and behind
        // only a free name's trailing separator (measured on Darwin 27.0,
        // `docs/probes/devfs-darwin`, NS link rows, and `link-symlink.c`
        // LINKDEV rows).
        let devfsRefuses =
            Credentials.privilege credentials = CallerPrivilege.Unprivileged
            && match resolution.Target with
               | ResolvedTarget.Entry (directory, _, existing) ->
                   (VirtualFileSystem.isOnDevfs source vfs
                    || VirtualFileSystem.isOnDevfs directory vfs)
                   && (existing.IsSome || not resolution.TrailingSeparatorDemanded)
               | ResolvedTarget.Directory _ -> false

        if devfsRefuses then
            LinkVerdict.Refuse UnixError.EPERM
        else

        match
            NewNameRules.verdict
                FreeNameTrailingSeparator.NoSuchEntry
                (NewNameSource.Linked (source, protection))
                bindable
                credentials
                resolution
                vfs
        with
        | NewNameVerdict.Refuse error -> LinkVerdict.Refuse error
        | NewNameVerdict.Bind (directory, name, _) -> LinkVerdict.Create (directory, name)
