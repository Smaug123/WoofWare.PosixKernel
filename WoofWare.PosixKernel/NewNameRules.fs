namespace WoofWare.PosixKernel

/// What a call that binds a new name binds to it, which decides what the
/// call owes besides what the name owes.
[<RequireQualifiedAccess>]
type internal NewNameSource =
    /// An inode the call makes: `mkdir(2)`, `mknod(2)`, `symlink(2)` and a
    /// creating `open(2)`.
    | Fresh
    /// The existing inode `source`, which `link(2)` gives a further name,
    /// under the flavour's `protection`.
    | Linked of source : InodeNumber * protection : HardlinkProtection
    /// A clone of the regular file `source`, which `clonefile(2)` makes.
    | Cloned of source : InodeNumber

/// What a free final name carrying a trailing separator owes a call that
/// would bind it, where the walk demanded the separator.
[<RequireQualifiedAccess>]
type internal FreeNameTrailingSeparator =
    /// ENOENT: `symlink(2)`, `link(2)`, a creating `open(2)` and
    /// `clonefile(2)` never bind "n/".
    | NoSuchEntry
    /// Nothing: `mkdir(2)` binds "n/" as "n".
    | Binds

/// What a call that binds a new name should do, now that its path has
/// resolved.
[<RequireQualifiedAccess>]
type internal NewNameVerdict =
    /// Answer the caller with this errno.
    | Refuse of error : UnixError
    /// Bind the new name `name` in `directory`, whose inode is `parent`.
    | Bind of directory : InodeNumber * name : DirectoryEntryName * parent : Inode

[<RequireQualifiedAccess>]
module internal NewNameRules =

    /// The checks a free name in a directory with a name of its own owes, in
    /// order: the trailing separator's ENOENT where `trailingSeparator` says
    /// so, `source`'s checks ahead of the write check, the write check's
    /// EACCES, `source`'s checks after it, and EILSEQ.
    let private unbound
        (trailingSeparator : FreeNameTrailingSeparator)
        (source : NewNameSource)
        (bindable : BindableEntryNames)
        (credentials : Credentials)
        (directory : InodeNumber)
        (name : DirectoryEntryName)
        (trailingSeparatorDemanded : bool)
        (vfs : VirtualFileSystem)
        : NewNameVerdict
        =
        let beforeWrite () : UnixError option =
            match source with
            | NewNameSource.Fresh -> None
            | NewNameSource.Linked (source, protection) ->
                if
                    VirtualFileSystem.mountedRootOf source vfs
                    <> VirtualFileSystem.mountedRootOf directory vfs
                then
                    Some UnixError.EXDEV
                elif
                    ProtectedFiles.refusesToLink
                        protection
                        credentials
                        (VirtualFileSystem.get "NewNameRules: the source" source vfs)
                then
                    Some UnixError.EPERM
                else
                    None
            | NewNameSource.Cloned source ->
                let cloned = VirtualFileSystem.get "NewNameRules: the source" source vfs

                match cloned.Content with
                | InodeContent.RegularFile (_, bits) ->
                    if PermissionBits.deniedTo (Standing.toward credentials cloned.Owner) AccessRequest.Read bits then
                        Some UnixError.EACCES
                    else
                        None
                | InodeContent.Directory _
                | InodeContent.Socket _
                | InodeContent.Fifo _
                | InodeContent.CharacterDevice _
                | InodeContent.Symlink _ ->
                    failwith
                        $"NewNameRules: the source of a clone, inode %O{source}, is not a regular file, but the clone's source phase admits only a regular file (this is a bug in this library)."

        let afterWrite () : UnixError option =
            match source with
            | NewNameSource.Fresh
            | NewNameSource.Cloned _ -> None
            | NewNameSource.Linked (source, _) ->
                match (VirtualFileSystem.get "NewNameRules: the source" source vfs).Content with
                | InodeContent.Directory _ -> Some UnixError.EPERM
                | InodeContent.RegularFile _
                | InodeContent.Symlink _
                | InodeContent.Socket _
                | InodeContent.Fifo _
                | InodeContent.CharacterDevice _ ->
                    // A source with no name left, which only Linux's
                    // `AT_EMPTY_PATH` reaches, is ENOENT only once every other
                    // check has passed (`link-empty-path.c`, UNLINKED).
                    if VirtualFileSystem.bindingCount source vfs = 0 then
                        Some UnixError.ENOENT
                    else
                        None

        match trailingSeparator with
        | FreeNameTrailingSeparator.NoSuchEntry when trailingSeparatorDemanded -> NewNameVerdict.Refuse UnixError.ENOENT
        | FreeNameTrailingSeparator.NoSuchEntry
        | FreeNameTrailingSeparator.Binds ->

        match beforeWrite () with
        | Some error -> NewNameVerdict.Refuse error
        | None ->

        let parent =
            VirtualFileSystem.get "NewNameRules: the directory to bind in" directory vfs

        // Write alone: the search half of the rule is the walk's, and a
        // resolution that reached here has already passed it.
        if
            PermissionBits.deniedTo
                (Standing.toward credentials parent.Owner)
                AccessRequest.Write
                (Inode.permissions parent)
        then
            NewNameVerdict.Refuse UnixError.EACCES
        else

        match afterWrite () with
        | Some error -> NewNameVerdict.Refuse error
        | None ->

        if not (BindableEntryNames.admits bindable name) then
            NewNameVerdict.Refuse UnixError.EILSEQ
        else
            NewNameVerdict.Bind (directory, name, parent)

    /// What a call that would bind the free name `name` in `directory` owes,
    /// in order, each beating those below it:
    ///
    ///  * nothing can be created in a directory whose last name has gone:
    ///    ENOENT;
    ///  * a trailing separator the walk demanded is ENOENT, unless
    ///    `trailingSeparator` says the call binds the name anyway;
    ///  * a `link(2)` source on another filesystem than `directory` is EXDEV,
    ///    and one its `protection` forbids the caller to link is EPERM; a
    ///    `clonefile(2)` source the caller may not read is EACCES;
    ///  * binding a name needs write on `directory`, in the triple the
    ///    caller's standing towards it selects: EACCES (root bypasses it);
    ///  * a `link(2)` source that is a directory is EPERM, and one with no
    ///    name left (which only Linux's `AT_EMPTY_PATH` names) ENOENT;
    ///  * a name `bindable` does not admit is EILSEQ.
    let freeName
        (trailingSeparator : FreeNameTrailingSeparator)
        (source : NewNameSource)
        (bindable : BindableEntryNames)
        (credentials : Credentials)
        (directory : InodeNumber)
        (name : DirectoryEntryName)
        (trailingSeparatorDemanded : bool)
        (vfs : VirtualFileSystem)
        : NewNameVerdict
        =
        // Measured on both flavours for every call that binds a name, at
        // 0o755 and at 0o555 alike, so the orphan's ENOENT beats the EACCES
        // below. Whether it comes before or after the trailing separator's is
        // unobservable: both are ENOENT.
        if VirtualFileSystem.isOrphanedDirectory directory vfs then
            NewNameVerdict.Refuse UnixError.ENOENT
        else
            unbound trailingSeparator source bindable credentials directory name trailingSeparatorDemanded vfs

    /// What a call that binds a new name owes, given how its path resolved,
    /// for a call that refuses every name already bound: a path that
    /// consumed no component ("/", ".", "..") is EEXIST; nothing can be
    /// created in a directory whose last name has gone (ENOENT); an existing
    /// final name is EEXIST, whatever it is; and a free one owes what
    /// `freeName` says.
    let verdict
        (trailingSeparator : FreeNameTrailingSeparator)
        (source : NewNameSource)
        (bindable : BindableEntryNames)
        (credentials : Credentials)
        (resolution : Resolution)
        (vfs : VirtualFileSystem)
        : NewNameVerdict
        =
        match resolution.Target with
        | ResolvedTarget.Directory _ -> NewNameVerdict.Refuse UnixError.EEXIST
        | ResolvedTarget.Entry (directory, name, existing) ->

        // Above the existing name's EEXIST because that is where a real kernel
        // puts it: the ENOENT comes from the lookup itself failing against a
        // dead parent. The ordering is not observable: an orphan is
        // necessarily empty, since `rmdir` refuses a populated directory and
        // this rule stops one ever gaining an entry.
        if VirtualFileSystem.isOrphanedDirectory directory vfs then
            NewNameVerdict.Refuse UnixError.ENOENT
        else

        match existing with
        | Some _ -> NewNameVerdict.Refuse UnixError.EEXIST
        | None ->
            unbound
                trailingSeparator
                source
                bindable
                credentials
                directory
                name
                resolution.TrailingSeparatorDemanded
                vfs
