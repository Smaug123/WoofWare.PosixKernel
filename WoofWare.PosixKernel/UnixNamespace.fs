namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// A bit of `open(2)`'s flag word that the simulated flavour defines and this
/// kernel does not model. `UnixNamespace.openPath` refuses a word holding any
/// of them rather than ignore what the caller
/// asked for.
[<RequireQualifiedAccess>]
type UnmodelledOpenFlag =
    /// `O_NOCTTY`, on both flavours.
    | NoControllingTerminal
    /// `O_APPEND`, on both flavours.
    | Append
    /// `O_NONBLOCK`, on both flavours.
    | NonBlocking
    /// `O_ASYNC` (Linux's `FASYNC`), on both flavours.
    | Asynchronous
    /// `O_DSYNC` without `O_SYNC`, on both flavours.
    | DataSynchronous
    /// Linux's `O_DIRECT`.
    | Direct
    /// Linux's `O_LARGEFILE`.
    | LargeFile
    /// Linux's `O_NOATIME`.
    | NoAccessTime
    /// Linux's `O_PATH`.
    | PathOnly
    /// Linux's `__O_TMPFILE`, the bit `O_TMPFILE` adds to `O_DIRECTORY`.
    | TemporaryFile
    /// Darwin's `O_SHLOCK`.
    | SharedLock
    /// Darwin's `O_EXLOCK`.
    | ExclusiveLock
    /// Darwin's `O_RESOLVE_BENEATH`.
    | ResolveBeneath
    /// Darwin's `O_UNIQUE`.
    | Unique
    /// Darwin's `O_EVTONLY`.
    | EventOnly
    /// Darwin's `O_SYMLINK`.
    | Symlink
    /// Darwin's `O_CLOFORK`.
    | CloseOnFork
    /// Darwin's `O_NOFOLLOW_ANY`.
    | NoFollowAny
    /// Darwin's `O_EXEC`, which with `O_DIRECTORY` is `O_SEARCH`.
    | Execute
    /// Darwin's `O_POPUP`.
    | Popup

[<RequireQualifiedAccess>]
module UnmodelledOpenFlag =
    /// The flag's name in the flavour's `<fcntl.h>`.
    let name (flag : UnmodelledOpenFlag) : string =
        match flag with
        | UnmodelledOpenFlag.NoControllingTerminal -> "O_NOCTTY"
        | UnmodelledOpenFlag.Append -> "O_APPEND"
        | UnmodelledOpenFlag.NonBlocking -> "O_NONBLOCK"
        | UnmodelledOpenFlag.Asynchronous -> "O_ASYNC"
        | UnmodelledOpenFlag.DataSynchronous -> "O_DSYNC"
        | UnmodelledOpenFlag.Direct -> "O_DIRECT"
        | UnmodelledOpenFlag.LargeFile -> "O_LARGEFILE"
        | UnmodelledOpenFlag.NoAccessTime -> "O_NOATIME"
        | UnmodelledOpenFlag.PathOnly -> "O_PATH"
        | UnmodelledOpenFlag.TemporaryFile -> "__O_TMPFILE"
        | UnmodelledOpenFlag.SharedLock -> "O_SHLOCK"
        | UnmodelledOpenFlag.ExclusiveLock -> "O_EXLOCK"
        | UnmodelledOpenFlag.ResolveBeneath -> "O_RESOLVE_BENEATH"
        | UnmodelledOpenFlag.Unique -> "O_UNIQUE"
        | UnmodelledOpenFlag.EventOnly -> "O_EVTONLY"
        | UnmodelledOpenFlag.Symlink -> "O_SYMLINK"
        | UnmodelledOpenFlag.CloseOnFork -> "O_CLOFORK"
        | UnmodelledOpenFlag.NoFollowAny -> "O_NOFOLLOW_ANY"
        | UnmodelledOpenFlag.Execute -> "O_EXEC"
        | UnmodelledOpenFlag.Popup -> "O_POPUP"

/// What a caller asked `open(2)` for, as facts about the open rather than as a
/// bit pattern: the flag word as `OpenFlagWord.decode` reads it for one
/// flavour.
///
/// Every field is a flag this kernel acts on, or (`CloseOnExec`,
/// `Synchronous`, `DataSynchronous`) one whose only effect here is what
/// `fcntl` reports. A word
/// holding any other bit its flavour defines never becomes one of these: the
/// decoder refuses it, so the kernel cannot guess at a flag it does not
/// model.
type internal OpenFlags =
    {
        /// `O_RDONLY`, `O_WRONLY` or `O_RDWR`, access modes 0, 1 and 2. The
        /// fourth, 3, never decodes to one of these: Darwin answers EINVAL
        /// for it, and Linux opens a descriptor that can neither read nor
        /// write, which this kernel refuses.
        Access : FileAccessMode
        /// `O_CREAT`: create the final component if nothing holds that name.
        Create : bool
        /// `O_EXCL`: fail EEXIST if the final component exists.
        ///
        /// Exactly as the word set it, **without** first ANDing it with
        /// `Create`. That it does nothing on its own is a measured kernel fact
        /// `UnixNamespace.openPathParsed` owns — `open(existing,
        /// O_WRONLY|O_EXCL)` succeeds and `open(missing, O_WRONLY|O_EXCL)` is
        /// ENOENT, exactly as without it.
        Exclusive : bool
        /// `O_TRUNC`: empty a regular file that is opened successfully.
        ///
        /// Not confined to a write access mode: measured on both,
        /// `open(f, O_RDONLY | O_TRUNC)` on a writable file succeeds and empties
        /// it. What it does instead is demand the write permission bit.
        Truncate : bool
        /// `O_NOFOLLOW`: do not follow a symbolic link in the final position,
        /// which makes opening one ELOOP.
        NoFollow : bool
        /// `O_CLOEXEC`: give the new descriptor `FD_CLOEXEC`.
        CloseOnExec : bool
        /// `O_SYNC` (on Linux, the `__O_SYNC` bit, which the kernel completes to
        /// `O_SYNC` whether or not `O_DSYNC` is beside it). It governs when a
        /// write reaches storage rather than whether it is visible, and this
        /// filesystem holds its bytes in memory, so every write is already as
        /// durable as the model gets; the description carries it for `fcntl`
        /// to report.
        Synchronous : bool
        /// `O_DSYNC`, as the description will carry it: on Linux whenever
        /// `Synchronous` is set, the kernel completing `__O_SYNC` with it; on
        /// Darwin when the word holds it, which the decoder admits only beside
        /// `O_SYNC`.
        DataSynchronous : bool
        /// `O_DIRECTORY`: fail ENOTDIR unless the path names a directory.
        ///
        /// Modelled only as `opendir(3)` uses it: with `O_RDONLY`, and without
        /// `O_TRUNC` or `O_NOFOLLOW` (`O_CREAT` with it is EINVAL). The decoder
        /// refuses every other combination, whose check order against those
        /// flags is unmodelled.
        Directory : bool
    }

/// Why this kernel will not answer a `readlink(2)`.
[<RequireQualifiedAccess>]
type internal ReadLinkRefusal =
    /// The destination buffer has no answer at the step the call reached.
    | Buffer of BufferRefusal
    /// This kernel will not resolve the path.
    | Path of PathRefusal
    /// Whether the caller may read the symbolic link at `inode` has not been
    /// measured for this caller.
    | UnmeasuredLinkRead of inode : InodeNumber * refusal : LinkReadRefusal

[<RequireQualifiedAccess>]
module internal ReadLinkRefusal =
    /// What this kernel knows about why it cannot answer. A client adds which
    /// entry point asked, and with which path.
    let describe (refusal : ReadLinkRefusal) : string =
        match refusal with
        | ReadLinkRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | ReadLinkRefusal.Path refusal -> PathRefusal.describe refusal
        | ReadLinkRefusal.UnmeasuredLinkRead (inode, refusal) ->
            $"reading inode %O{inode}: %s{LinkReadRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ReadLinkRefusal) : RefusalKind =
        match refusal with
        | ReadLinkRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | ReadLinkRefusal.Path inner -> PathRefusal.kind inner
        | ReadLinkRefusal.UnmeasuredLinkRead (_, inner) -> LinkReadRefusal.kind inner

/// What `readlink(2)` puts in the caller's buffer and what it returns.
[<RequireQualifiedAccess>]
type ReadLinkAnswer =
    /// Place these bytes in the caller's buffer; the entry point returns how
    /// many there are.
    ///
    /// **No terminator**, and truncated to the capacity rather than refused:
    /// `readlink` writes exactly the bytes it reports and reports success by a
    /// non-negative count, so a NUL would corrupt the byte after a target that
    /// exactly fits. Truncation is not an error path: `readlink(2)` truncates
    /// silently, so a result that fills the buffer is how a caller learns to
    /// retry with a larger one.
    | Reported of bytes : ImmutableArray<byte>
    /// The entry point returns -1 and the caller stores `error` wherever its
    /// libc keeps errno.
    | Failed of error : UnixError

/// What kind of object one directory entry names.
///
/// Not `InodeContent`, which carries the payload as well — a caller enumerating
/// a directory is owed the *type* of each entry and nothing else, and handing it
/// the bytes of every file in the directory would be a different API. Not
/// `fileTypeBits` either: that is the `S_IFMT` numbering `stat` reports, where
/// `readdir` has its own (`DT_REG` and friends), and the two are not the same
/// numbers. A client encodes whichever its own struct wants.
[<RequireQualifiedAccess>]
type DirectoryEntryKind =
    | RegularFile
    | Directory
    | Symlink
    | CharacterDevice
    /// `DT_SOCK`: an entry naming an `InodeContent.Socket`, which nothing in
    /// this version makes.
    | Socket
    /// `DT_FIFO`: an entry naming an `InodeContent.Fifo`, which nothing in
    /// this version makes.
    | Fifo

[<RequireQualifiedAccess>]
module DirectoryEntryKind =
    /// What kind of entry a directory binding onto this content is.
    let ofContent (content : InodeContent) : DirectoryEntryKind =
        match content with
        | InodeContent.RegularFile _ -> DirectoryEntryKind.RegularFile
        | InodeContent.Directory _ -> DirectoryEntryKind.Directory
        | InodeContent.Symlink _ -> DirectoryEntryKind.Symlink
        | InodeContent.CharacterDevice _ -> DirectoryEntryKind.CharacterDevice
        | InodeContent.Socket _ -> DirectoryEntryKind.Socket
        | InodeContent.Fifo _ -> DirectoryEntryKind.Fifo

/// One entry of a directory, as `getdents(2)` reports it: the facts in a
/// `struct linux_dirent64` or a Darwin `struct direntry`, without either's
/// layout.
type DirectoryRecord =
    {
        /// `d_ino`: the inode the entry names. For `.` that is the directory
        /// itself and for `..` its parent, as `stat` would report them.
        Inode : InodeNumber
        /// `d_name`.
        Name : PathComponent
        /// `d_type`. Never unknown: measured on tmpfs and APFS, every entry,
        /// the dots included, reports its kind.
        Kind : DirectoryEntryKind
    }

/// What reading the next entry of a directory descriptor answers.
[<RequireQualifiedAccess>]
type ReadDirectoryAnswer =
    /// The next entry. The description's position has moved past it.
    | Entry of record : DirectoryRecord
    /// There is nothing further: `getdents` returns 0.
    | EndOfDirectory
    /// `getdents` returns -1 with this errno.
    | Failed of error : UnixError

/// Why this kernel will not say what reading a directory descriptor yields.
[<RequireQualifiedAccess>]
type internal ReadDirectoryRefusal =
    /// `lseek` moved the description to a nonzero offset (see
    /// `DirectoryPosition.Unenumerable`), and what each filesystem yields from
    /// an offset it did not hand out is its own.
    | UnenumerablePosition of inode : InodeNumber * offset : int64
    /// The description is onto `inode`, a directory of the device filesystem.
    /// A real one lists a node for every device the machine has and this
    /// kernel's holds only the nodes of the devices it has drivers for, so a
    /// listing would leave out names a real one reports.
    | DeviceFileSystem of inode : InodeNumber

[<RequireQualifiedAccess>]
module internal ReadDirectoryRefusal =
    /// What this kernel knows about why it cannot answer, for a client composing
    /// a diagnostic.
    let describe (refusal : ReadDirectoryRefusal) : string =
        match refusal with
        | ReadDirectoryRefusal.UnenumerablePosition (inode, offset) ->
            $"the description onto directory %O{inode} is at offset %d{offset}, where lseek put it. Both kernels accept that offset, but what the next read yields from it is each filesystem's own (tmpfs resumes from the entry with the greatest offset at or below it; APFS skips that many entries, or answers EAGAIN, depending on the high word), and this kernel's position is a name rather than an offset. Only offset 0, which rewinds, is readable from."
        | ReadDirectoryRefusal.DeviceFileSystem inode ->
            $"the description is onto directory %O{inode}, on the device filesystem. A real one lists a node for every device the machine has, and this kernel's holds only the nodes of the devices it has drivers for, so its listing would leave out names a real one reports."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ReadDirectoryRefusal) : RefusalKind =
        match refusal with
        | ReadDirectoryRefusal.UnenumerablePosition _ -> RefusalKind.Unmodelled
        | ReadDirectoryRefusal.DeviceFileSystem _ -> RefusalKind.Unmodelled

/// How far `rename(2)` had got with its source when it stopped to copy its
/// *destination* pathname in — which is not the same point on the two flavours.
///
/// See `RenameWalkOrder`, whose two cases these mirror.
[<RequireQualifiedAccess>]
type internal RenameSourceProgress =
    /// The source's parent is walked and its final component not yet looked up:
    /// Linux, which walks both parents before either final lookup.
    | ParentWalked of parent : PausedResolution
    /// The source is finished, `RenameRules.sourceScreen` included: Darwin,
    /// which resolves the source to completion before touching the destination.
    | Resolved of resolution : Resolution

/// A `rename(2)` or `renameat(2)` that has run as far as the point where the
/// kernel copies its destination pathname in, and stopped there.
///
/// It stops rather than taking both pathnames up front because *reading* a
/// pathname out of a process's address space can fail — and on both flavours
/// there are calls that finish without ever reading the destination, where
/// failing to read it would answer about a pathname `rename(2)` never touched.
/// The caller supplies the bytes when handed one of these, and not before.
///
/// Opaque: the only thing to do with one is give it to
/// `UnixNamespace.renameWithDestination`.
[<NoEquality ; NoComparison>]
type PausedRename<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
            Rules : RenameRules
            SourceProgress : RenameSourceProgress
            /// Where a relative destination pathname starts, which is looked up
            /// only once that pathname has been copied in.
            Destination : AtDirectory
        }

/// Why this kernel will not answer a `rename(2)` or `renameat(2)`.
[<RequireQualifiedAccess>]
type internal RenameRefusal =
    /// A sticky directory whose rule Darwin has not been measured to apply to
    /// this caller.
    | Sticky of refusal : StickyRefusal
    /// This kernel will not resolve one of the paths.
    | Path of refusal : PathRefusal
    /// One of the paths names `mountRoot`, the root of a mounted filesystem,
    /// in a combination whose answer has not been measured.
    | MountPoint of mountRoot : InodeNumber
    /// The call would move `name` out of `directory`, on the device
    /// filesystem, which no name can be removed from here.
    | DeviceFileSystem of directory : InodeNumber * name : DirectoryEntryName

[<RequireQualifiedAccess>]
module internal RenameRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which paths.
    let describe (refusal : RenameRefusal) : string =
        match refusal with
        | RenameRefusal.Sticky refusal -> StickyRefusal.describe refusal
        | RenameRefusal.Path refusal -> PathRefusal.describe refusal
        | RenameRefusal.MountPoint mountRoot ->
            $"one of the paths names inode %O{mountRoot}, the root of a mounted filesystem. Measured on Linux, renaming it onto itself is 0, and to a free name in its own directory is EACCES without write on that directory and EBUSY with it. Any other rename involving it can depend on the covered directory's own owner and mode, which this kernel does not hold, and has not been measured."
        | RenameRefusal.DeviceFileSystem (directory, name) ->
            $"the call would move \"%s{DirectoryEntryName.toEscaped name}\" out of inode %O{directory}, on the device filesystem, which holds only the nodes of the devices this kernel has drivers for; it removes none of them, because it could not then say what a real one answers for the name."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : RenameRefusal) : RefusalKind =
        match refusal with
        | RenameRefusal.Sticky inner -> StickyRefusal.kind inner
        | RenameRefusal.Path inner -> PathRefusal.kind inner
        | RenameRefusal.MountPoint _ -> RefusalKind.Unmodelled
        | RenameRefusal.DeviceFileSystem _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer a `clonefile(2)`.
[<RequireQualifiedAccess>]
type internal CloneFileRefusal =
    /// This kernel is not Darwin-flavoured, and only Darwin has `clonefile`.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// The machine's mount is of this type, where whether a file can be cloned
    /// is unmeasured.
    | UnmeasuredFileSystem of fileSystem : EmulatedFileSystemType
    /// `flags` asks for `CLONE_NOFOLLOW`, `CLONE_NOFOLLOW_ANY` or
    /// `CLONE_RESOLVE_BENEATH`, which change how a pathname resolves in ways
    /// this kernel does not model.
    | UnmodelledFlags of flags : int
    /// The caller is privileged, which changes who owns the clone and which
    /// permission bits it keeps, unmeasured.
    | PrivilegedCaller
    /// The source is the directory at `inode`; cloning one copies its whole
    /// tree, which this kernel does not model.
    | DirectorySource of inode : InodeNumber
    /// The source at `inode` carries set-ID or sticky bits, and the caller
    /// stands towards it as `standing`: which of those bits a clone keeps has
    /// been measured only for an owner in the source's group, and for an
    /// owner outside it without `S_ISGID`.
    | UnmeasuredSpecialBits of inode : InodeNumber * standing : Standing * permissions : PermissionBits
    /// This kernel will not resolve one of the paths.
    | Path of PathRefusal

[<RequireQualifiedAccess>]
module internal CloneFileRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which paths.
    let describe (refusal : CloneFileRefusal) : string =
        match refusal with
        | CloneFileRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and clonefile exists on Darwin only."
        | CloneFileRefusal.UnmeasuredFileSystem fileSystem ->
            $"the machine's mount is %O{fileSystem}, where whether clonefile can share a file's blocks (or answers ENOTSUP or EXDEV) has not been measured."
        | CloneFileRefusal.UnmodelledFlags flags ->
            $"flags 0x%x{flags} ask for CLONE_NOFOLLOW (0x1), CLONE_NOFOLLOW_ANY (0x8) or CLONE_RESOLVE_BENEATH (0x10). Each changes how a pathname resolves, and cloning a symbolic link itself is not modelled."
        | CloneFileRefusal.PrivilegedCaller ->
            "the caller is privileged. A privileged clone keeps the source's owner unless CLONE_NOOWNERCOPY is given, and which permission bits it keeps has not been measured."
        | CloneFileRefusal.DirectorySource inode ->
            $"the source is directory %O{inode}. clonefile clones a directory's whole tree, which this kernel does not model."
        | CloneFileRefusal.UnmeasuredSpecialBits (inode, standing, permissions) ->
            $"the source, inode %O{inode}, has mode 0o%o{PermissionBits.toInt permissions}, and the caller stands towards it as %O{standing}. A clone drops both set-ID bits and keeps the sticky bit when an unprivileged owner in the source's group clones it, but which of these bits survive any other caller's clone has not been measured."
        | CloneFileRefusal.Path refusal -> PathRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : CloneFileRefusal) : RefusalKind =
        match refusal with
        | CloneFileRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | CloneFileRefusal.UnmeasuredFileSystem _ -> RefusalKind.Unmodelled
        | CloneFileRefusal.UnmodelledFlags _ -> RefusalKind.Unmodelled
        | CloneFileRefusal.PrivilegedCaller -> RefusalKind.Unmodelled
        | CloneFileRefusal.DirectorySource _ -> RefusalKind.Unmodelled
        | CloneFileRefusal.UnmeasuredSpecialBits _ -> RefusalKind.Unmodelled
        | CloneFileRefusal.Path inner -> PathRefusal.kind inner

/// A `clonefile(2)` whose flags have been screened, stopped at the point
/// where the kernel copies its source pathname in.
///
/// It stops there because reading a pathname out of a process's address space
/// can fail, and a call whose flags are refused never reads either pathname.
///
/// Opaque: the only thing to do with one is give it to
/// `UnixNamespace.cloneFileWithSource`.
[<NoEquality ; NoComparison>]
type PausedCloneFileSource<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
        }

/// A `clonefile(2)` that has resolved its source and stopped at the point
/// where the kernel copies its destination pathname in.
///
/// It stops rather than taking both pathnames up front because reading a
/// pathname out of a process's address space can fail, and a call whose
/// source fails never reads the destination.
///
/// Opaque: the only thing to do with one is give it to
/// `UnixNamespace.cloneFileWithDestination`.
[<NoEquality ; NoComparison>]
type PausedCloneFile<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
            Source : InodeNumber
        }

/// Why this kernel will not answer a `symlink(2)` or `symlinkat(2)`.
[<RequireQualifiedAccess>]
type internal SymlinkRefusal =
    /// This kernel will not resolve the link's pathname.
    | Path of refusal : PathRefusal
    /// The call would create a link whose target is empty, which Darwin does
    /// and this library does not represent: see `SymlinkTargetError.Empty`.
    /// Every check that would fail the call has already passed.
    | EmptyTarget

[<RequireQualifiedAccess>]
module internal SymlinkRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which pathnames.
    let describe (refusal : SymlinkRefusal) : string =
        match refusal with
        | SymlinkRefusal.Path refusal -> PathRefusal.describe refusal
        | SymlinkRefusal.EmptyTarget ->
            "the call would create a symbolic link with an empty target. Darwin creates one, which every walk through answers ENOENT; this library does not represent an empty target (SymlinkTargetError.Empty)."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SymlinkRefusal) : RefusalKind =
        match refusal with
        | SymlinkRefusal.Path inner -> PathRefusal.kind inner
        | SymlinkRefusal.EmptyTarget -> RefusalKind.Unmodelled

/// A `symlink(2)` or `symlinkat(2)` whose target this kernel has copied in,
/// paused at the point where it copies the link's own pathname in. Obtain one
/// from `UnixNamespace.symlinkat` or `symlink`, and finish it with
/// `UnixNamespace.symlinkWithPath`.
[<NoEquality ; NoComparison>]
type PausedSymlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
            Directory : AtDirectory
            /// `None` for an empty target, which only a flavour that accepts one
            /// gets this far with.
            Target : SymlinkTarget option
        }

/// Why this kernel will not answer a `link(2)` or `linkat(2)`.
[<RequireQualifiedAccess>]
type internal LinkRefusal =
    /// This kernel will not resolve one of the pathnames.
    | Path of refusal : PathRefusal
    /// The flag word carries flags the flavour accepts and this library does
    /// not model: Darwin's `AT_SYMLINK_NOFOLLOW_ANY` (0x800),
    /// `AT_RESOLVE_BENEATH` (0x2000) and `AT_UNIQUE` (0x8000).
    | UnmodelledFlags of UnmodelledAtFlags
    /// Linux's `AT_EMPTY_PATH`, from a caller that is not privileged, with a
    /// path (an empty one included) relative to a descriptor. Linux then
    /// answers `ENOENT` unless the descriptor was opened with the very
    /// credentials the caller now holds: compared by identity, so that a fork,
    /// or a change of credentials that keeps every ID, fails it. This library
    /// does not record the credentials a descriptor was opened with.
    | OpenTimeCredentials
    /// `AT_EMPTY_PATH` names `inode`, which has no name left and is not a
    /// regular file: which of the call's refusals such an inode meets first
    /// has not been measured.
    | NamelessSource of inode : InodeNumber
    /// The source is on a `fileSystem` whose rules for `link(2)`, its ceiling
    /// on a file's names among them, have not been measured.
    | UnmeasuredFileSystem of fileSystem : EmulatedFileSystemType

[<RequireQualifiedAccess>]
module internal LinkRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which pathnames.
    let describe (refusal : LinkRefusal) : string =
        match refusal with
        | LinkRefusal.Path refusal -> PathRefusal.describe refusal
        | LinkRefusal.UnmodelledFlags refused -> UnmodelledAtFlags.describe refused
        | LinkRefusal.OpenTimeCredentials ->
            "AT_EMPTY_PATH from a caller that is not privileged, with a path relative to a descriptor: Linux admits it only if the descriptor was opened with the caller's present credentials, and this library does not record the credentials a descriptor was opened with."
        | LinkRefusal.NamelessSource inode ->
            $"AT_EMPTY_PATH names inode %O{inode}, which has no name left and is not a regular file; which refusal such an inode meets first has not been measured."
        | LinkRefusal.UnmeasuredFileSystem fileSystem ->
            $"the source is on a %O{fileSystem} filesystem, whose rules for link(2) (its ceiling on a file's names among them) have not been measured."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : LinkRefusal) : RefusalKind =
        match refusal with
        | LinkRefusal.Path inner -> PathRefusal.kind inner
        | LinkRefusal.UnmodelledFlags _ -> RefusalKind.Unmodelled
        | LinkRefusal.OpenTimeCredentials -> RefusalKind.Unmodelled
        | LinkRefusal.NamelessSource _ -> RefusalKind.Unmodelled
        | LinkRefusal.UnmeasuredFileSystem _ -> RefusalKind.Unmodelled

/// A `link(2)` or `linkat(2)` whose source has resolved, paused at the point
/// where the kernel copies the new pathname in. Obtain one from
/// `UnixNamespace.linkat` or `link`, and finish it with
/// `UnixNamespace.linkWithDestination`.
[<NoEquality ; NoComparison>]
type PausedLink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            System : ProcessView<'Thread, 'Handler>
            Rules : LinkRules
            Source : InodeNumber
            Destination : AtDirectory
        }

/// Why this kernel will not answer an `open(2)`.
[<RequireQualifiedAccess>]
type internal OpenRefusal =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// An `O_TRUNC` open of the file at `inode`, whose effect on the file's
    /// set-ID bits has not been measured for this caller. Nothing was changed.
    | UnmeasuredSetIdChange of inode : InodeNumber * refusal : SetIdChangeRefusal
    /// The flag word `flags` holds bits the simulated flavour defines and this
    /// kernel does not model, named in `unmodelled` in ascending order of bit.
    /// Nothing was read or changed.
    | UnmodelledFlags of flags : int * unmodelled : UnmodelledOpenFlag list
    /// The flag word `flags` asks for Linux's access mode 3, which opens a
    /// descriptor that can neither read nor write and serves only `ioctl(2)`
    /// and the calls that need no access mode. This kernel's descriptions
    /// permit reading, writing or both. Nothing was read or changed.
    | IoctlOnlyAccessMode of flags : int
    /// The flag word `flags` asks for `O_DIRECTORY` with a write access mode,
    /// `O_TRUNC` or `O_NOFOLLOW`. This kernel models `O_DIRECTORY` only as
    /// `opendir(3)` uses it, alone with `O_RDONLY`. Nothing was read or
    /// changed.
    | UnmodelledDirectoryOpen of flags : int
    /// This kernel will not resolve the path. Nothing was read or changed.
    | Path of PathRefusal

[<RequireQualifiedAccess>]
module internal OpenRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which path.
    let describe (refusal : OpenRefusal) : string =
        match refusal with
        | OpenRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | OpenRefusal.UnmeasuredSetIdChange (inode, refusal) ->
            $"opening inode %O{inode} with O_TRUNC: %s{SetIdChangeRefusal.describe refusal}"
        | OpenRefusal.UnmodelledFlags (flags, unmodelled) ->
            let names = unmodelled |> List.map UnmodelledOpenFlag.name |> String.concat ", "

            $"flags 0x%x{flags} hold %s{names}, which this platform defines and this kernel does not model; model them before answering."
        | OpenRefusal.IoctlOnlyAccessMode flags ->
            $"flags 0x%x{flags} ask for access mode 3, which Linux opens (demanding the read and write permission bits) as a descriptor that can neither read nor write: read, write and flock answer EBADF, ftruncate EINVAL, and only ioctl and the calls that need no access mode succeed. This kernel's descriptions permit reading, writing or both; model the fourth before answering."
        | OpenRefusal.UnmodelledDirectoryOpen flags ->
            $"flags 0x%x{flags} ask for O_DIRECTORY with a write access mode, O_TRUNC or O_NOFOLLOW. Only O_DIRECTORY|O_RDONLY (what opendir(3) opens with) is modelled; where ENOTDIR falls among EISDIR, EACCES and ELOOP for any other combination is not."
        | OpenRefusal.Path refusal -> PathRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : OpenRefusal) : RefusalKind =
        match refusal with
        | OpenRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | OpenRefusal.UnmeasuredSetIdChange (_, inner) -> SetIdChangeRefusal.kind inner
        | OpenRefusal.UnmodelledFlags _ -> RefusalKind.Unmodelled
        | OpenRefusal.IoctlOnlyAccessMode _ -> RefusalKind.Unmodelled
        | OpenRefusal.UnmodelledDirectoryOpen _ -> RefusalKind.Unmodelled
        | OpenRefusal.Path inner -> PathRefusal.kind inner

/// `open(2)`'s flag word, in the simulated flavour's own `<fcntl.h>`
/// numbering, read as the kernel reads it.
[<RequireQualifiedAccess>]
module internal OpenFlagWord =

    /// What the flag word asks for, or how the call ends without reading the
    /// path.
    [<RequireQualifiedAccess>]
    type Decoding =
        /// The word is one this kernel models, asking for this.
        | Decoded of OpenFlags
        /// The kernel answers this errno before it copies the path in.
        | Fails of UnixError
        | Refused of OpenRefusal

    /// What one bit above the access mode asks for.
    [<RequireQualifiedAccess>]
    type private Meaning =
        | Create
        | Exclusive
        | Truncate
        | NoFollow
        | Directory
        | CloseOnExec
        | Synchronous
        /// `O_DSYNC`, which `O_SYNC` beside it subsumes.
        | DataSynchronous
        | Unmodelled of UnmodelledOpenFlag

    // Each flavour's numbering of every bit it defines above the access mode,
    // in ascending order of bit. Measured by open-flags.c on Linux 6.18.5
    // aarch64, Linux 6.12.111 x86-64 and Darwin 27.0 arm64: a single-bit row
    // differs from the bare access mode's for exactly these bits, bar those
    // that cannot act alone (O_EXCL; O_NOCTTY on a file that is not a
    // terminal; Linux's O_LARGEFILE, which a 64-bit kernel sets on every
    // description; Darwin's O_SYMLINK and O_POPUP). Every other bit is ignored
    // by both kernels, Darwin included, so it is ignored here too.
    //
    // Linux's O_SYNC is two bits, __O_SYNC and O_DSYNC, and the kernel reads
    // __O_SYNC alone as O_SYNC (F_GETFL reads both back).

    let private linuxBits (architecture : SimulatedUnixArchitecture) : (int * Meaning) list =
        // aarch64's <asm/fcntl.h> moves four bits; x86-64 keeps the generic
        // numbering.
        let directory = OpenFlagNumbering.linuxDirectory architecture
        let noFollow = OpenFlagNumbering.linuxNoFollow architecture
        let largeFile = OpenFlagNumbering.linuxLargeFile architecture

        let direct = OpenFlagNumbering.linuxDirect architecture

        [
            0x40, Meaning.Create
            OpenFlagNumbering.LinuxExclusive, Meaning.Exclusive
            0x100, Meaning.Unmodelled UnmodelledOpenFlag.NoControllingTerminal
            0x200, Meaning.Truncate
            OpenFlagNumbering.LinuxAppend, Meaning.Unmodelled UnmodelledOpenFlag.Append
            OpenFlagNumbering.LinuxNonBlock, Meaning.Unmodelled UnmodelledOpenFlag.NonBlocking
            OpenFlagNumbering.LinuxDataSynchronous, Meaning.DataSynchronous
            OpenFlagNumbering.LinuxAsynchronous, Meaning.Unmodelled UnmodelledOpenFlag.Asynchronous
            direct, Meaning.Unmodelled UnmodelledOpenFlag.Direct
            largeFile, Meaning.Unmodelled UnmodelledOpenFlag.LargeFile
            directory, Meaning.Directory
            noFollow, Meaning.NoFollow
            OpenFlagNumbering.LinuxNoAccessTime, Meaning.Unmodelled UnmodelledOpenFlag.NoAccessTime
            OpenFlagNumbering.LinuxCloseOnExec, Meaning.CloseOnExec
            OpenFlagNumbering.LinuxSynchronous, Meaning.Synchronous
            0x200000, Meaning.Unmodelled UnmodelledOpenFlag.PathOnly
            0x400000, Meaning.Unmodelled UnmodelledOpenFlag.TemporaryFile
        ]
        |> List.sortBy fst

    let private darwinBits : (int * Meaning) list =
        [
            OpenFlagNumbering.DarwinNonBlock, Meaning.Unmodelled UnmodelledOpenFlag.NonBlocking
            OpenFlagNumbering.DarwinAppend, Meaning.Unmodelled UnmodelledOpenFlag.Append
            0x10, Meaning.Unmodelled UnmodelledOpenFlag.SharedLock
            0x20, Meaning.Unmodelled UnmodelledOpenFlag.ExclusiveLock
            OpenFlagNumbering.DarwinAsynchronous, Meaning.Unmodelled UnmodelledOpenFlag.Asynchronous
            OpenFlagNumbering.DarwinSynchronous, Meaning.Synchronous
            0x100, Meaning.NoFollow
            0x200, Meaning.Create
            0x400, Meaning.Truncate
            0x800, Meaning.Exclusive
            0x1000, Meaning.Unmodelled UnmodelledOpenFlag.ResolveBeneath
            0x2000, Meaning.Unmodelled UnmodelledOpenFlag.Unique
            0x8000, Meaning.Unmodelled UnmodelledOpenFlag.EventOnly
            0x20000, Meaning.Unmodelled UnmodelledOpenFlag.NoControllingTerminal
            0x100000, Meaning.Directory
            0x200000, Meaning.Unmodelled UnmodelledOpenFlag.Symlink
            OpenFlagNumbering.DarwinDataSynchronous, Meaning.DataSynchronous
            OpenFlagNumbering.DarwinCloseOnExec, Meaning.CloseOnExec
            OpenFlagNumbering.DarwinCloseOnFork, Meaning.Unmodelled UnmodelledOpenFlag.CloseOnFork
            0x20000000, Meaning.Unmodelled UnmodelledOpenFlag.NoFollowAny
            0x40000000, Meaning.Unmodelled UnmodelledOpenFlag.Execute
            0x80000000, Meaning.Unmodelled UnmodelledOpenFlag.Popup
        ]

    /// Read `flags` as `platform`'s kernel does.
    let decode (platform : SimulatedUnixPlatform) (flags : int) : Decoding =
        let flavour = SimulatedUnixPlatform.flavour platform

        let meanings =
            match flavour with
            | SimulatedUnixFlavour.Linux -> linuxBits (SimulatedUnixPlatform.architecture platform)
            | SimulatedUnixFlavour.Darwin -> darwinBits
            |> List.filter (fun (bit, _) -> flags &&& bit <> 0)
            |> List.map snd

        let has (meaning : Meaning) : bool = List.contains meaning meanings

        let unmodelled =
            meanings
            |> List.choose (fun meaning ->
                match meaning with
                | Meaning.Unmodelled flag -> Some flag
                | Meaning.DataSynchronous when not (has Meaning.Synchronous) -> Some UnmodelledOpenFlag.DataSynchronous
                | Meaning.Create
                | Meaning.Exclusive
                | Meaning.Truncate
                | Meaning.NoFollow
                | Meaning.Directory
                | Meaning.CloseOnExec
                | Meaning.Synchronous
                | Meaning.DataSynchronous -> None
            )

        // Refused first: a flag this kernel does not model can lift a screen
        // below (Linux's O_PATH lifts O_CREAT|O_DIRECTORY's EINVAL), so no
        // answer is certain once one is present.
        if not unmodelled.IsEmpty then
            Decoding.Refused (OpenRefusal.UnmodelledFlags (flags, unmodelled))
        // Measured on both, for every word of modelled and undefined bits:
        // EINVAL, before the path is copied in. Linux has done so since 6.4.
        elif has Meaning.Create && has Meaning.Directory then
            Decoding.Fails UnixError.EINVAL
        else

        match flags &&& 3 with
        | 3 ->
            match flavour with
            // Measured for every word: EINVAL, before the path is copied in.
            | SimulatedUnixFlavour.Darwin -> Decoding.Fails UnixError.EINVAL
            | SimulatedUnixFlavour.Linux -> Decoding.Refused (OpenRefusal.IoctlOnlyAccessMode flags)
        | access ->

        let decoded : OpenFlags =
            {
                Access =
                    match access with
                    | 0 -> FileAccessMode.ReadOnly
                    | 1 -> FileAccessMode.WriteOnly
                    | _ -> FileAccessMode.ReadWrite
                Create = has Meaning.Create
                Exclusive = has Meaning.Exclusive
                Truncate = has Meaning.Truncate
                NoFollow = has Meaning.NoFollow
                CloseOnExec = has Meaning.CloseOnExec
                Synchronous = has Meaning.Synchronous
                DataSynchronous =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> has Meaning.Synchronous
                    | SimulatedUnixFlavour.Darwin -> has Meaning.DataSynchronous
                Directory = has Meaning.Directory
            }

        if
            decoded.Directory
            && (decoded.Access <> FileAccessMode.ReadOnly
                || decoded.Truncate
                || decoded.NoFollow)
        then
            Decoding.Refused (OpenRefusal.UnmodelledDirectoryOpen flags)
        else
            Decoding.Decoded decoded

[<RequireQualifiedAccess>]
module UnixNamespace =

    /// Who owns an inode the process is about to create in `directory`, which
    /// the caller's walk has just established is a directory.
    let private newInodeOwner<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (context : string)
        (directory : InodeNumber)
        (system : ProcessView<'Thread, 'Handler>)
        : InodeOwner
        =
        match VirtualFileSystem.tryGet directory system.Machine.FileSystem with
        | Some ({
                    Content = InodeContent.Directory parent
                } as entry) ->
            InodeOwner.ofNewInode
                (SimulatedUnixPlatform.newInodeGroupRule system.Machine.UnixPlatform)
                system.Process.Credentials
                entry.Owner
                parent.Permissions
        | Some _
        | None ->
            failwith
                $"%s{context}: about to create an inode in inode %O{directory}, which the walk had established was a directory, but it is now absent or not a directory (this is a bug in this library)."

    /// A new empty regular file bound as `name` in `directory`, which a walk
    /// has just found free, with the permission bits a creating `open(2)`
    /// gives `mode` and owned as any new inode there is: the file's inode, and
    /// the system holding it. `operation` names the caller in the failure a
    /// broken graph gives.
    let private createRegularFile<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (directory : InodeNumber)
        (name : DirectoryEntryName)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : InodeNumber * ProcessView<'Thread, 'Handler>
        =
        let parent = VirtualFileSystem.get operation directory system.Machine.FileSystem

        let parentPermissions =
            match parent.Content with
            | InodeContent.Directory content -> content.Permissions
            | InodeContent.RegularFile _
            | InodeContent.Symlink _
            | InodeContent.CharacterDevice _
            | InodeContent.Socket _
            | InodeContent.Fifo _ ->
                failwith
                    $"%s{operation}: about to create \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory}, which the walk had established was a directory, but it is not one now (this is a bug in this library)."

        let permissions =
            CreatingOpenRules.createdPermissions
                (SimulatedUnixPlatform.creatingOpenRules system.Machine.UnixPlatform)
                (Standing.toward system.Process.Credentials parent.Owner)
                parentPermissions
                system.Process.Umask
                mode

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match
            VirtualFileSystem.createFile
                directory
                name
                permissions
                (newInodeOwner operation directory system)
                now
                FileContents.empty
                system.Machine.FileSystem
        with
        | Error error ->
            // `createFile` refuses a name the directory already holds, and a
            // parent that is not a directory. The walk has just established
            // neither is the case, so either is a broken graph rather than
            // something the caller did.
            failwith
                $"%s{operation}: creating \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and does not hold that name (this is a bug in this library)."
        | Ok (inode, mutation) ->
            inode,
            { system with
                Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
            }

    /// `openat`, of a path this kernel has already copied in, starting from
    /// `directory` if it is relative.
    let internal openPathParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (flags : OpenFlags)
        (path : UnixPath)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, OpenRefusal>
        =
        // Measured (`openat-limit.c`): Linux's empty path is ENOENT even with
        // no descriptor left, since its copy-in refuses it; Darwin has
        // allocated the descriptor before it copies anything in (`openPath`).
        match
            (SimulatedUnixPlatform.startingPointRules system.Machine.UnixPlatform).EmptyPath, UnixPath.isEmpty path
        with
        | EmptyPathRule.NoSuchEntryBeforeDescriptor, true -> Ok (SyscallAnswer.Failed UnixError.ENOENT, system)
        | EmptyPathRule.NoSuchEntryBeforeDescriptor, false
        | EmptyPathRule.NoSuchEntryAfterDescriptor, _ ->

        // Measured (`fcntl-dup.c`'s LIMIT rows, and `openat-limit.c` for every
        // kind of dirfd): with no descriptor left below the limit, a missing
        // file is EMFILE rather than ENOENT, and so is a dirfd naming nothing
        // or no directory, on both: the descriptor comes before the walk, and
        // with it before `dirfd` is looked at.
        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal -> Error (OpenRefusal.DescriptorLimit refusal)
        | Ok () ->

        let rules = SimulatedUnixPlatform.creatingOpenRules system.Machine.UnixPlatform
        let credentials = system.Process.Credentials

        // `O_EXCL` on its own is neither an error nor a refusal: both kernels
        // ignore it entirely, measured. So it is read
        // only where `Create` is set, and that combining is done here rather than
        // by the caller -- it is the kernel's rule, and a caller that pre-ANDed
        // the two would leave it with nothing to be right or wrong about.
        let exclusive = flags.Create && flags.Exclusive

        /// Hand out a descriptor onto `inode`, which the walk reached
        /// `through`, for the access that was asked for, with the descriptor
        /// flag and the status flags the word asked for. `truncatedExisting` is
        /// whether this open's `O_TRUNC` truncated a file that was there before
        /// it.
        let opened
            (truncatedExisting : bool)
            (through : ReachedThrough)
            (inode : InodeNumber)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, OpenRefusal>
            =
            let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
            let descriptorFlags = DescriptorFlags.closingOnExec flavour flags.CloseOnExec

            let status =
                OpenFileStatus.opened flavour flags.Synchronous flags.DataSynchronous flags.Directory flags.NoFollow

            let status =
                if truncatedExisting then
                    OpenFileStatus.markWritten status
                else
                    status

            // A directory gets a description positioned in its entries rather
            // than at a byte offset. It can only be here for reading: every
            // writable or truncating open of one answered EISDIR before this.
            let fd, registry =
                match VirtualFileSystem.tryGetContent inode system.Machine.FileSystem with
                | Some (InodeContent.Directory _) ->
                    FileDescriptorRegistry.openDirectory
                        descriptorFlags
                        status
                        through
                        inode
                        (UnixSystemState.fileDescriptors system)
                | Some (InodeContent.CharacterDevice (device, _)) ->
                    FileDescriptorRegistry.openCharacterDevice
                        descriptorFlags
                        status
                        through
                        inode
                        device
                        flags.Access
                        (UnixSystemState.fileDescriptors system)
                | Some (InodeContent.Socket _) ->
                    failwith
                        $"UnixNamespace.openPath: inode %O{inode} is a socket. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."
                | Some (InodeContent.Fifo _) ->
                    failwith
                        $"UnixNamespace.openPath: inode %O{inode} is a FIFO. Nothing in this version makes one: InodeContent.Fifo is unreachable until FIFOs are modelled (this is a bug in this library)."
                | Some (InodeContent.RegularFile _)
                | Some (InodeContent.Symlink _)
                | None ->
                    FileDescriptorRegistry.openFile
                        descriptorFlags
                        status
                        through
                        inode
                        flags.Access
                        (UnixSystemState.fileDescriptors system)

            Ok (SyscallAnswer.Completed (int64 fd), UnixSystemState.withFileDescriptors registry system)

        if
            flags.Directory
            && (flags.Access <> FileAccessMode.ReadOnly
                || flags.Create
                || flags.Truncate
                || flags.NoFollow)
        then
            failwith
                $"UnixNamespace.openPath: O_DIRECTORY with %A{flags}, a combination OpenFlagWord.decode refuses or answers EINVAL before the path is read (this is a bug in this library)."

        if flags.Directory then
            // `opendir(3)` is exactly this open, and its rows are measured on
            // both kernels, which agree in every one: a final symlink is
            // followed, a trailing separator changes nothing, being a file beats
            // being unreadable, and it is the read bit rather than the search
            // bit that is demanded. `OpenDirRules` holds them.
            match
                UnixPathResolution.resolvePathFull
                    directory
                    SymlinkPolicy.Follow
                    TrailingSeparatorPolicy.Demand
                    path
                    system
            with
            | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
            | Error (PathFailure.Refused refusal) -> Error (OpenRefusal.Path refusal)
            | Ok resolution ->

            match OpenDirRules.verdict credentials resolution system.Machine.FileSystem with
            | OpenDirVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
            | OpenDirVerdict.Open inode ->
                opened false (ReachedThrough.ofResolved resolution.Target system.Machine.FileSystem) inode system
        else

        // `O_CREAT|O_EXCL` does not follow a final symlink -- measured
        // unanimously: an existing link is EEXIST whether it dangles, points at a
        // file, or points at itself, and nothing is created. Selecting `Follow`
        // here would create the *target* of a dangling link, and would answer
        // ELOOP for a cyclic one, where both kernels answer EEXIST.
        let policy =
            if flags.NoFollow || exclusive then
                SymlinkPolicy.NoFollowFinal
            else
                SymlinkPolicy.Follow

        let trailingSeparatorPolicy =
            if flags.Create then
                rules.TrailingSeparator
            else
                TrailingSeparatorPolicy.Demand

        match UnixPathResolution.resolvePathFull directory policy trailingSeparatorPolicy path system with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (OpenRefusal.Path refusal)
        | Ok resolution ->

        match
            CreatingOpenRules.verdict
                rules
                system.Machine.ProtectedFiles
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                credentials
                flags.Create
                exclusive
                resolution
                system.Machine.FileSystem
        with
        | CreatingOpenVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
        | CreatingOpenVerdict.Create (directory, name) ->
            let inode, system =
                createRegularFile "UnixNamespace.openPath" directory name mode system

            // A file this open created is not one it truncated, whatever
            // `O_TRUNC` asked: measured on Darwin (`fcntl-dup.c`, WRITTEN
            // rows), its description is not marked written.
            opened false (ReachedThrough.ofEntry directory name) inode system
        | CreatingOpenVerdict.OpenExisting inode ->

        let entry =
            VirtualFileSystem.get "UnixNamespace.openPath" inode system.Machine.FileSystem

        match entry.Content with
        | InodeContent.Symlink _ ->
            // Only reachable under `O_NOFOLLOW`, which is what `NoFollowFinal`
            // above selects: without it the resolver would have followed the link
            // (or failed ENOENT on a dangling one). ELOOP rather than anything
            // more specific is what both Unixes answer.
            Ok (SyscallAnswer.Failed UnixError.ELOOP, system)
        | InodeContent.Directory _ when FileAccessMode.permitsWrite flags.Access || flags.Truncate ->
            // Measured on both flavours, for `O_WRONLY` and `O_RDWR` alike, and
            // at uid 0 as well as uid 1000: a directory cannot be opened for
            // writing, and this beats the EACCES check below (a mode-0000
            // directory opened `O_WRONLY` is EISDIR, not EACCES).
            //
            // This is also what makes every writable descriptor name a regular
            // file, which `VirtualFileSystem.writeFile` relies on.
            //
            // `O_TRUNC` earns the same refusal whatever the access mode:
            // measured, `open(d, O_RDONLY | O_TRUNC)` is EISDIR on both, so this
            // is the one row where the arm fires for a *read-only* open. That
            // includes `O_CREAT | O_RDONLY | O_TRUNC` on the flavour whose
            // `RefusesExistingDirectory` is false, where the verdict is therefore
            // `OpenExisting` on the directory itself.
            Ok (SyscallAnswer.Failed UnixError.EISDIR, system)
        | InodeContent.Socket _ ->
            failwith
                $"UnixNamespace.openPath: resolution returned inode %O{inode}, which is a socket. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."
        | InodeContent.Fifo _ ->
            failwith
                $"UnixNamespace.openPath: resolution returned inode %O{inode}, which is a FIFO. Nothing in this version makes one: InodeContent.Fifo is unreachable until FIFOs are modelled (this is a bug in this library)."
        | InodeContent.RegularFile _
        | InodeContent.Directory _
        | InodeContent.CharacterDevice _ ->

        // A directory opens perfectly well for *reading*, measured on both. A
        // caller that wants to know what it opened asks `fstat`. So does a
        // device's node, for every access mode, its permission bits checked as
        // a file's are (`devices.c`, OPEN rows).
        let permissionBits = Inode.permissions entry

        // What `open(2)` itself checks: whether this process may open *this
        // object* for the access it asked for. Measured identically on macOS and
        // Linux, at uid 1000:
        //
        //   mode   O_RDONLY  O_WRONLY  O_RDWR
        //   0644   ok        ok        ok
        //   0444   ok        EACCES    EACCES
        //   0200   EACCES    ok        EACCES
        //   0000   EACCES    EACCES    EACCES
        //
        // The triple consulted is the one the caller's standing towards the
        // file selects (`PermissionBits.deniedTo`).
        //
        // `O_TRUNC` adds the write bit to whatever the access mode already asked
        // for, and adds nothing else. Measured at uid 1000 on both:
        //
        //   mode   flags               answer
        //   0444   RDONLY|TRUNC        EACCES
        //   0400   RDONLY|TRUNC        EACCES
        //   0200   RDONLY|TRUNC        EACCES   (the read bit is still owed)
        //   0600   RDONLY|TRUNC        ok
        //   0200   WRONLY|TRUNC        ok
        //   0400   WRONLY|TRUNC        EACCES
        // Both halves, where the mode asks for both: `O_RDWR` on a 0o400 file is
        // refused for want of the write bit even though the read bit is there,
        // which is what the disjunction says.
        let standing = Standing.toward credentials entry.Owner

        let denied =
            (FileAccessMode.permitsRead flags.Access
             && PermissionBits.deniedTo standing AccessRequest.Read permissionBits)
            || ((FileAccessMode.permitsWrite flags.Access || flags.Truncate)
                && PermissionBits.deniedTo standing AccessRequest.Write permissionBits)

        if denied then
            Ok (SyscallAnswer.Failed UnixError.EACCES, system)
        else

        // Only now, with every refusal discharged: measured, a refused open
        // leaves the bytes alone, and specifically `O_CREAT | O_EXCL | O_TRUNC`
        // on an existing file is EEXIST with its contents intact, while
        // `O_NOFOLLOW | O_TRUNC` on a symbolic link is ELOOP with its target
        // intact.
        //
        // Unconditional rather than skipped for an already-empty file: the
        // inode's timestamps move and its set-ID bits go regardless. Only a
        // regular file is truncated -- a directory cannot reach here at all (the
        // arm above refuses every truncating open of one), so the match is over
        // what the descriptor may still name rather than a filter. A device's
        // node is left alone: measured, `O_TRUNC` opens one without moving
        // anything `stat` reports (`devices.c`, OPEN rows).
        let through = ReachedThrough.ofResolved resolution.Target system.Machine.FileSystem

        let truncated =
            match entry.Content with
            | InodeContent.RegularFile _ when flags.Truncate ->
                match UnixDescriptor.truncateAt through inode 0L system with
                | Ok system -> Ok (true, system)
                | Error (TruncationRefusal.UnmeasuredSetIdChange (inode, refusal)) ->
                    Error (OpenRefusal.UnmeasuredSetIdChange (inode, refusal))
                // Truncating to zero cannot exceed a length limit.
                | Error (TruncationRefusal.ExceedsRepresentableLength _ as refusal) ->
                    failwith
                        $"UnixNamespace.openPath: truncating inode %O{inode} to zero was refused -- %s{TruncationRefusal.describe refusal} (this is a bug in this library)."
            | InodeContent.RegularFile _
            | InodeContent.Directory _
            | InodeContent.CharacterDevice _
            | InodeContent.Symlink _ -> Ok (false, system)
            | InodeContent.Socket _ ->
                failwith
                    $"UnixNamespace.openPath: inode %O{inode} is a socket. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."
            | InodeContent.Fifo _ ->
                failwith
                    $"UnixNamespace.openPath: inode %O{inode} is a FIFO. Nothing in this version makes one: InodeContent.Fifo is unreachable until FIFOs are modelled (this is a bug in this library)."

        truncated
        |> Result.bind (fun (truncatedExisting, system) -> opened truncatedExisting through inode system)

    let private openFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (flags : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, OpenRefusal>
        =
        // No open sleeps yet: nothing can make an object whose open waits.
        let answered
            (result : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, OpenRefusal>)
            : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, OpenRefusal>
            =
            result
            |> Result.map (fun (answer, system) -> SyscallOutcome.Answered answer, system)

        // Before the path is copied in: measured (`open-flags.c`), each
        // kernel screens the word whatever the path pointer is.
        // Measured (`fcntl-dup.c`, LIMIT rows): Darwin allocates the
        // descriptor before it reads the word or the path, so with none left
        // below the limit even its EINVAL and EFAULT are EMFILE; Linux reads
        // both first.
        let room =
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform, room with
        | SimulatedUnixFlavour.Darwin, Error refusal -> Error (OpenRefusal.DescriptorLimit refusal)
        | SimulatedUnixFlavour.Darwin, Ok ()
        | SimulatedUnixFlavour.Linux, _ ->

        match OpenFlagWord.decode system.Machine.UnixPlatform flags with
        | OpenFlagWord.Decoding.Refused refusal -> Error refusal
        | OpenFlagWord.Decoding.Fails error -> Ok (SyscallOutcome.Answered (SyscallAnswer.Failed error), system)
        | OpenFlagWord.Decoding.Decoded flags ->

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallOutcome.Answered (SyscallAnswer.Failed error), system)
        | Ok path -> openPathParsed directory flags path mode system |> answered

    /// `tryOpenPath` once `Entry` has admitted its caller.
    let private tryOpenPathIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (flags : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, OpenRefusal>
        =
        openFrom AtDirectory.CurrentDirectory flags path mode system

    /// `openPath`, with a refusal answered as the `Error` rather than raised.
    let internal tryOpenPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        Entry.call
            "UnixNamespace.openPath"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryOpenPathIn flags path mode)
            system

    /// `open(2)`, made by `caller`: resolve `path`, apply every check a kernel
    /// makes, and return a descriptor onto what it names. It is `openat` from
    /// `AT_FDCWD`.
    ///
    /// The answer is a `SyscallOutcome` because an open can sleep on a real
    /// kernel: a blocking open of one end of a FIFO waits until the other end
    /// is opened. Nothing in this version makes a FIFO, so every open is
    /// answered at once (`SyscallOutcome.Answered`), and never `WouldBlock` or
    /// `Interrupted`. `caller` must be one of the process's threads, and must not
    /// already be parked: a thread blocks in one syscall at a time.
    ///
    /// `flags` is raw, in the simulated flavour's own `<fcntl.h>` numbering,
    /// which differs between Linux's architectures as well as between
    /// flavours. A bit the flavour does not define is ignored, as both
    /// kernels ignore it. A bit it defines is either one this kernel models
    /// or a refusal naming it, never silently
    /// dropped.
    ///
    /// The word is screened before the path is copied in, so its EINVAL comes
    /// ahead of EFAULT, ENAMETOOLONG, EEXIST and EISDIR: on both flavours for
    /// `O_CREAT|O_DIRECTORY`, and on Darwin for access mode 3. Then `path` is
    /// the argument's bytes, copied in: EFAULT if they were unreadable,
    /// ENAMETOOLONG if they run past `PATH_MAX`.
    ///
    /// Named for the path it takes, `open` being an F# keyword. It opens
    /// directories too, for reading.
    ///
    /// `mode` is raw and **unvalidated**, and must stay that way:
    /// callers commonly pass 0666 even for a read-only open of an existing file,
    /// and a kernel accepts that, so refusing a nonzero mode without `O_CREAT`
    /// would refuse an ordinary read. It is read only when a file is actually created,
    /// and then masked rather than rejected: measured, `mode` 0o10777 creates
    /// 0o0755 on both flavours, so a bit above the permission word is dropped
    /// exactly as the platform's own mask drops it.
    ///
    /// Refused, before anything is read or changed, for a flag word this kernel
    /// does not model, for an `O_TRUNC` open whose effect
    /// on set-ID bits is unmeasured, and when no descriptor below the bound
    /// (`SimulatedUnixPlatform.descriptorBound`) is free: under Darwin ahead of
    /// every errno, and under Linux after the word's and the copy-in's (an
    /// empty path's ENOENT among them) and before the walk's. Every other
    /// outcome is a descriptor or an errno.
    let openPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryOpenPath caller flags path mode system
        |> Refusal.orRaise "UnixNamespace.openPath" OpenRefusal.kind OpenRefusal.describe

    /// `tryOpenat` once `Entry` has admitted its caller.
    let private tryOpenatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, OpenRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        openFrom (AtDirectory.decode flavour dirfd) flags path mode system

    /// `openat`, with a refusal answered as the `Error` rather than raised.
    let internal tryOpenat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        Entry.call
            "UnixNamespace.openat"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryOpenatIn dirfd path flags mode)
            system

    /// `openat(2)`, made by `caller`: `openPath` of `path`, starting from `dirfd`
    /// if it is relative; `openPath` is this from `AT_FDCWD`.
    ///
    /// `dirfd` is raw, in this platform's own numbering. Everything `openPath`
    /// says holds, with one more step: once the path is copied in, and once
    /// Linux has a descriptor to give, a relative path starts where `dirfd`
    /// says, as every `*at` call's does. So
    /// with no descriptor left below the bound the call is refused ahead of
    /// a `dirfd` that names nothing or no directory, on both flavours; and on
    /// Linux an unreadable, over-long or empty path is answered ahead of that
    /// refusal, while on Darwin the refusal comes first.
    let openat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryOpenat caller dirfd path flags mode system
        |> Refusal.orRaise "UnixNamespace.openat" OpenRefusal.kind OpenRefusal.describe

    /// `readlinkat`, of a path this kernel has already copied in, starting
    /// from `directory` if it is relative.
    let internal readlinkParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : UnixPath)
        (destination : UserBuffer)
        (capacity : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ReadLinkAnswer, ReadLinkRefusal>
        =
        let verdict =
            SimulatedUnixPlatform.readlinkCapacity system.Machine.UnixPlatform capacity

        match verdict with
        | ReadLinkCapacityVerdict.Refuse error -> Ok (ReadLinkAnswer.Failed error)
        | ReadLinkCapacityVerdict.ReportNothing
        | ReadLinkCapacityVerdict.Admit ->

        // The inode to read, and what the call answers if it is not a link.
        let (target : Result<Result<InodeNumber, UnixError>, ReadLinkRefusal>), (notALink : UnixError) =
            match
                AtPathTarget.classify
                    (SimulatedUnixPlatform.readlinkEmptyPath system.Machine.UnixPlatform)
                    directory
                    path
            with
            | AtPathTarget.Descriptor fd ->
                // Measured (`readlinkat-empty-path.c`, and `at-dirfd.c`'s
                // eventq rows): a pipe, a socket or an epoll instance is
                // ENOENT, as a file or directory that is not a link is.
                let named =
                    match FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system) with
                    | None -> Error UnixError.EBADF
                    | Some description ->

                    // An epoll or inotify instance is on an anonymous
                    // inode, which is no link either.
                    match OpenFileTable.inodeOf description.Target with
                    | Some inode -> Ok inode
                    | None -> Error UnixError.ENOENT

                Ok named, UnixError.ENOENT
            | AtPathTarget.CurrentDirectory
            | AtPathTarget.Walked ->
                // An empty path from AT_FDCWD names the current directory,
                // which is not a link, so it is ENOENT, as the walk answers it.
                //
                // `NoFollowFinal` is what makes this `readlink` rather than an
                // expensive way of asking about the target: a final symlink is
                // the thing being read, not something to step through. A
                // trailing separator still overrides that -- "lf/" demands
                // that `lf` be a directory -- and the resolver owns that rule,
                // answering ENOTDIR.
                let resolved =
                    match UnixPathResolution.resolvePath directory SymlinkPolicy.NoFollowFinal path system with
                    | Error (PathFailure.Errno error) -> Ok (Error error)
                    | Error (PathFailure.Refused refusal) -> Error (ReadLinkRefusal.Path refusal)
                    | Ok inode -> Ok (Ok inode)

                resolved, UnixError.EINVAL

        match target with
        | Error refusal -> Error refusal
        | Ok (Error error) -> Ok (ReadLinkAnswer.Failed error)
        | Ok (Ok inode) ->

        let record =
            VirtualFileSystem.get "UnixNamespace.readlink" inode system.Machine.FileSystem

        match record.Content with
        | InodeContent.Directory _
        | InodeContent.RegularFile _
        | InodeContent.Socket _
        | InodeContent.Fifo _
        | InodeContent.CharacterDevice _ ->
            // Not a link: EINVAL for a path, which is what distinguishes "not a
            // link" from a failure to read one, and ENOENT for an empty path
            // naming the starting point.
            // Decided before the destination is looked at, which is what a real
            // kernel does -- `vfs_readlink` refuses on the inode's operations
            // before it copies anything out. Measured on the host:
            // `readlink("f", (char*)8, 16)` is EINVAL, not EFAULT.
            Ok (ReadLinkAnswer.Failed notALink)
        | InodeContent.Symlink (target, bits) ->

        // The link's own mode, on a flavour that consults it, is judged once
        // the path is known to name a link and before the size or the buffer
        // is: measured on Darwin (`readlink-mode.c`'s ORDER rows), a link the
        // caller may not read is EACCES with a size of 0 and with a NULL or
        // unmapped buffer, while a negative size is EINVAL first and a
        // trailing separator ("ld/", "l/") follows the link whatever its mode.
        let standing = Standing.toward system.Process.Credentials record.Owner

        match
            PermissionBits.linkReadDenied (SimulatedUnixPlatform.linkReadRule system.Machine.UnixPlatform) standing bits
        with
        | Error refusal -> Error (ReadLinkRefusal.UnmeasuredLinkRead (inode, refusal))
        | Ok true -> Ok (ReadLinkAnswer.Failed UnixError.EACCES)
        | Ok false ->

        match verdict with
        | ReadLinkCapacityVerdict.Refuse _ ->
            failwith "UnixNamespace.readlink: a refused capacity was answered above (this is a bug in this library)."
        | ReadLinkCapacityVerdict.ReportNothing ->
            // Nothing is copied, so the destination is never looked at:
            // measured, a null buffer with a zero size answers 0.
            Ok (ReadLinkAnswer.Reported ImmutableArray<byte>.Empty)
        | ReadLinkCapacityVerdict.Admit ->

        // The destination is consulted only here, on the path that actually
        // writes through it. `readlink(2)` runs no up-front address check on
        // either flavour: the target is built in the kernel and handed over with
        // a single `copy_to_user`, so an unusable buffer is discovered at the
        // copy and every earlier refusal wins. Measured against a `PROT_READ`
        // page, both flavours answer EFAULT -- unlike `getcwd`, whose copy is a
        // user-space store on one of them.
        match destination with
        | UserBuffer.Unmapped _ -> Ok (ReadLinkAnswer.Failed UnixError.EFAULT)
        | UserBuffer.Opaque -> Error (ReadLinkRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
        | UserBuffer.Addressless -> Error (ReadLinkRefusal.Buffer BufferRefusal.AddresslessAtTransfer)
        | UserBuffer.Mapped ->

        let all = UnixByteString.toBytes (SymlinkTarget.toByteString target)

        // Truncated in *bytes*, not in characters: a symlink target is a byte
        // string, and truncating by character count would write two bytes where
        // the caller allowed one for any non-ASCII target.
        if all.Length <= capacity then
            Ok (ReadLinkAnswer.Reported all)
        else
            Ok (ReadLinkAnswer.Reported (ImmutableArray.CreateRange (Seq.truncate capacity all)))

    /// `tryReadlink` once `Entry` has admitted its caller.
    let private tryReadlinkIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ReadLinkAnswer, ReadLinkRefusal>
        =
        // The size is screened before the path is copied in, on both flavours:
        // measured (`path-copyin-order.c`), a size Linux refuses is EINVAL with a
        // NULL path, and so is a negative one on Darwin, whose size of zero goes on
        // to copy the path in.
        match SimulatedUnixPlatform.readlinkCapacity system.Machine.UnixPlatform capacity with
        | ReadLinkCapacityVerdict.Refuse error -> Ok (ReadLinkAnswer.Failed error)
        | ReadLinkCapacityVerdict.ReportNothing
        | ReadLinkCapacityVerdict.Admit ->

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (ReadLinkAnswer.Failed error)
        | Ok path -> readlinkParsed AtDirectory.CurrentDirectory path destination capacity system

    /// `readlink`, with a refusal answered as the `Error` rather than raised.
    let internal tryReadlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ReadLinkAnswer, ReadLinkRefusal>
        =
        Entry.call
            "UnixNamespace.readlink"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryReadlinkIn path destination capacity)
            system

    /// `readlink(2)`: report what the symbolic link at `path` points at. It is
    /// `readlinkat` from `AT_FDCWD`.
    ///
    /// Changes nothing and returns no system. POSIX lets a successful
    /// `readlink` mark the link's access time for update, but neither
    /// flavour's filesystem moves it as this kernel mounts it: APFS never
    /// does, and Linux's tmpfs is mounted `noatime`.
    ///
    /// `capacity` is the caller's buffer size. A size that is not positive is
    /// answered as this system's flavour answers it: EINVAL before the path is
    /// copied in on Linux and for a negative size on Darwin, and zero bytes
    /// from a resolved link on Darwin for a size of zero.
    ///
    /// The link's own mode is consulted as this system's flavour consults it
    /// (`SimulatedUnixPlatform.linkReadRule`): never on Linux, and on Darwin a
    /// caller whose standing selects a triple without the read bit gets
    /// EACCES, ahead of a size of zero and of the buffer. A privileged Darwin
    /// caller is refused an answer.
    ///
    /// `path` is the argument's bytes, copied in after that screen and before
    /// anything else: EFAULT if they were unreadable, ENAMETOOLONG if they run
    /// past `PATH_MAX`.
    let readlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : ReadLinkAnswer
        =
        tryReadlink caller path destination capacity system
        |> Refusal.orRaise "UnixNamespace.readlink" ReadLinkRefusal.kind ReadLinkRefusal.describe

    /// `tryReadlinkat` once `Entry` has admitted its caller.
    let private tryReadlinkatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ReadLinkAnswer, ReadLinkRefusal>
        =
        match SimulatedUnixPlatform.readlinkCapacity system.Machine.UnixPlatform capacity with
        | ReadLinkCapacityVerdict.Refuse error -> Ok (ReadLinkAnswer.Failed error)
        | ReadLinkCapacityVerdict.ReportNothing
        | ReadLinkCapacityVerdict.Admit ->

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (ReadLinkAnswer.Failed error)
        | Ok path ->
            let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
            readlinkParsed (AtDirectory.decode flavour dirfd) path destination capacity system

    /// `readlinkat`, with a refusal answered as the `Error` rather than raised.
    let internal tryReadlinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ReadLinkAnswer, ReadLinkRefusal>
        =
        Entry.call
            "UnixNamespace.readlinkat"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryReadlinkatIn dirfd path destination capacity)
            system

    /// `readlinkat(2)`: `readlink` of `path`, starting from `dirfd` if it is
    /// relative; `readlink` is this from `AT_FDCWD`.
    ///
    /// `dirfd` is raw, in this platform's own numbering. The size is screened
    /// as `readlink` screens it, before `path` is copied in, and a relative
    /// path then starts where `dirfd` says, as every `*at` call's does,
    /// except for the empty path on Linux: that names what `dirfd` names
    /// (`SimulatedUnixPlatform.readlinkEmptyPath`), which is EBADF if it
    /// names nothing and ENOENT if it is not a symbolic link. No descriptor
    /// here names a symbolic link, since this library models neither
    /// `O_PATH` nor `O_SYMLINK`.
    let readlinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (destination : UserBuffer)
        (capacity : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : ReadLinkAnswer
        =
        tryReadlinkat caller dirfd path destination capacity system
        |> Refusal.orRaise "UnixNamespace.readlinkat" ReadLinkRefusal.kind ReadLinkRefusal.describe

    /// `tryReadDirectoryEntry` once `Entry` has admitted its caller.
    let private tryReadDirectoryEntryIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ReadDirectoryAnswer * ProcessView<'Thread, 'Handler>, ReadDirectoryRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        match FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (ReadDirectoryAnswer.Failed UnixError.EBADF, system)
        | Some description ->

        // Not a directory. Measured on every descriptor kind this library
        // models (a regular file opened each way, both ends of a pipe, stream
        // and datagram sockets of both domains, an epoll instance or kqueue):
        //
        //   descriptor                       Linux     Darwin
        //   regular file, readable           ENOTDIR   EINVAL
        //   regular file, O_WRONLY           ENOTDIR   EBADF
        //   pipe, socket, epoll or kqueue    ENOTDIR   ENOTSUP
        //
        // Ahead of the buffer on both (a NULL buffer on a regular file answers
        // the same), which is why a caller need not screen one first.
        let notADirectory (readable : bool) (isVnode : bool) : UnixError =
            match flavour with
            | SimulatedUnixFlavour.Linux -> UnixError.ENOTDIR
            | SimulatedUnixFlavour.Darwin ->
                if not isVnode then UnixError.ENOTSUP
                elif not readable then UnixError.EBADF
                else UnixError.EINVAL

        match description.Target with
        | OpenFileTarget.File _
        // ENOTDIR measured on Linux (`devices-l2.c`, GETDENTS64 rows), the one
        // flavour that holds a device.
        | OpenFileTarget.CharacterDevice _ ->
            let readable = FileAccessMode.permitsRead description.AccessMode
            Ok (ReadDirectoryAnswer.Failed (notADirectory readable true), system)
        | OpenFileTarget.Pipe _
        | OpenFileTarget.Socket _
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _
        // Measured on Linux (`inotify-descriptor-probe.c` row D getdents64).
        | OpenFileTarget.Inotify _ -> Ok (ReadDirectoryAnswer.Failed (notADirectory true false), system)
        | OpenFileTarget.Fifo (inode, _) ->
            match flavour with
            // Every kind measured above is ENOTDIR on Linux, whose
            // `iterate_dir` answers it for any file without an `iterate_shared`.
            | SimulatedUnixFlavour.Linux -> Ok (ReadDirectoryAnswer.Failed UnixError.ENOTDIR, system)
            // Unmeasured: a Darwin FIFO is a vnode, so not the pipe's ENOTSUP.
            | SimulatedUnixFlavour.Darwin -> ReservedFifo.fail "UnixNamespace.getdents" inode
        | OpenFileTarget.Directory (inode, position) ->

        match VirtualFileSystem.mountedRootOf inode system.Machine.FileSystem with
        | Some _ -> Error (ReadDirectoryRefusal.DeviceFileSystem inode)
        | None ->

        let withPosition (position : DirectoryPosition) (system : ProcessView<'Thread, 'Handler>) =
            UnixSystemState.withFileDescriptors
                (FileDescriptorRegistry.setDirectoryPosition fd position (UnixSystemState.fileDescriptors system))
                system

        // A directory `rmdir` has removed yields nothing, from any position:
        // measured one call at a time, on a fresh description, after a partial
        // read, after a full one, after a rewind, and at offsets 5, 2^31-1 and
        // 2^62. Linux answers ENOENT and leaves the position alone. Darwin
        // answers 0 and moves the position to its end-of-directory value --
        // except at 2^62, where it answers EAGAIN, so a position `lseek` chose
        // stays refused there.
        let orphaned = VirtualFileSystem.isOrphanedDirectory inode system.Machine.FileSystem

        match flavour, orphaned, position with
        | SimulatedUnixFlavour.Linux, true, _ -> Ok (ReadDirectoryAnswer.Failed UnixError.ENOENT, system)
        | _, _, DirectoryPosition.Unenumerable offset ->
            Error (ReadDirectoryRefusal.UnenumerablePosition (inode, offset))
        | SimulatedUnixFlavour.Darwin, true, DirectoryPosition.Cursor _ ->
            Ok (
                ReadDirectoryAnswer.EndOfDirectory,
                withPosition (DirectoryPosition.Cursor DirectoryCursor.ReturnedDot) system
            )
        | _, false, DirectoryPosition.Cursor cursor ->

        match VirtualFileSystem.nextDirectoryEntry inode cursor system.Machine.FileSystem with
        | None -> Ok (ReadDirectoryAnswer.EndOfDirectory, system)
        | Some (name, target, next) ->

        let kind =
            (VirtualFileSystem.get "UnixNamespace.readDirectoryEntry" target system.Machine.FileSystem).Content
            |> DirectoryEntryKind.ofContent

        // A name a filesystem is mounted over reports the inode number of the
        // directory the mount covers, not the mounted root's: measured on both
        // flavours, `readdir("/")` reports `dev` as 14 and `stat("/dev")` as 1
        // on Linux (`mountpoint.c`).
        let reported =
            match name, VirtualFileSystem.mountOf target system.Machine.FileSystem with
            | PathComponent.Name _, Some mount -> mount.Covered
            | _, _ -> target

        let record : DirectoryRecord =
            {
                Inode = reported
                Name = name
                Kind = kind
            }

        // A call that returns an entry moves the directory's access time
        // where its filesystem's rule says, and one at the end does not
        // (measured, `docs/probes/atime`: getdents and getdents-eof).
        let read =
            { system with
                Machine =
                    UnixMachineState.afterRead
                        inode
                        (UnixMachineState.realtime system.Scheduling system.Machine)
                        system.Machine
            }

        Ok (ReadDirectoryAnswer.Entry record, withPosition (DirectoryPosition.Cursor next) read)

    /// `readDirectoryEntry`, with a refusal answered as the `Error` rather than raised.
    let internal tryReadDirectoryEntry<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ReadDirectoryAnswer * UnixSystem<'Thread, 'Handler>, ReadDirectoryRefusal>
        =
        Entry.call
            "UnixNamespace.readDirectoryEntry"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryReadDirectoryEntryIn fd)
            system

    /// Read the next entry of the directory `fd` names, and move its open file
    /// description's position past it: one record of `getdents(2)` (Linux) or
    /// `getdirentries(2)` (Darwin), without either's byte layout.
    ///
    /// The position is the description's, so every descriptor `dup(2)` made
    /// for it reads onward from the same place, and `lseek(fd, 0, SEEK_SET)`
    /// starts again from the first entry.
    ///
    /// The names come in this library's own order, which matches no real
    /// filesystem, followed by `..` and `.`, at the *end*, where ext4 has been
    /// seen to put them; `readdir(3)` fixes no position for either. A
    /// directory that `rmdir` has since removed yields nothing more.
    ///
    /// A call that yields an entry moves the directory's access time as
    /// `UnixReadWrite.read` moves a file's: it is a `getdents(2)` into a
    /// buffer with room for one record. A call at the end moves nothing.
    let readDirectoryEntry<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : ReadDirectoryAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryReadDirectoryEntry caller fd system
        |> Refusal.orRaise "UnixNamespace.readDirectoryEntry" ReadDirectoryRefusal.kind ReadDirectoryRefusal.describe

    /// `mkdirat`, of a path this kernel has already copied in, starting from
    /// `directory` if it is relative.
    let internal mkdirParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : UnixPath)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, PathRefusal>
        =
        let rules = SimulatedUnixPlatform.mkDirRules system.Machine.UnixPlatform

        // `NoFollowFinal` on both flavours: `mkdir` never dereferences the name
        // it is about to bind, so an existing link is EEXIST whether it dangles,
        // points at a file, or points at itself. The trailing separator is the
        // only thing that can reach past it, and only on Darwin — see
        // `SimulatedUnixPlatform.finalNameTrailingSeparator`.
        match
            UnixPathResolution.resolvePathFull
                directory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                path
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error refusal
        | Ok resolution ->

        match
            MkDirRules.verdict
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                system.Process.Credentials
                resolution
                system.Machine.FileSystem
        with
        | MkDirVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
        | MkDirVerdict.Create (directory, name, parentPermissions) ->

        let permissions =
            MkDirRules.createdPermissions rules parentPermissions system.Process.Umask mode

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        let owner = newInodeOwner "UnixNamespace.mkdir" directory system

        match VirtualFileSystem.createDirectory directory name permissions owner now system.Machine.FileSystem with
        | Error error ->
            // `createDirectory` refuses a name the directory already holds, and a
            // parent that is not a directory. The walk has just established
            // neither is the case, so either is a broken graph rather than
            // something the caller did.
            failwith
                $"UnixNamespace.mkdir: creating \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and does not hold that name (this is a bug in this library)."
        | Ok (_, mutation) ->

        Ok (
            SyscallAnswer.Completed 0L,
            { system with
                Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
            }
        )

    let private mkdirFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : PathArgumentBytes)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, PathRefusal>
        =
        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path -> mkdirParsed directory path mode system

    /// `tryMkdir` once `Entry` has admitted its caller.
    let private tryMkdirIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, PathRefusal>
        =
        mkdirFrom AtDirectory.CurrentDirectory path mode system

    /// `mkdir`, with a refusal answered as the `Error` rather than raised.
    let internal tryMkdir<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, PathRefusal>
        =
        Entry.call
            "UnixNamespace.mkdir"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryMkdirIn path mode)
            system

    /// `mkdir(2)`: bind a new directory at `path`. It is `mkdirat` from
    /// `AT_FDCWD`.
    ///
    /// `mode` is raw, exactly as the caller passed it, so what the created
    /// directory's permissions actually are depends on the umask and, on one
    /// flavour, on the parent's set-group-ID bit. `MkDirRules` holds that.
    ///
    /// Refuses only a path this kernel will not resolve:
    /// every other outcome is a success or an errno, the rules having been
    /// measured on both flavours.
    ///
    /// `path` is the argument's bytes, copied in before anything else: EFAULT
    /// if they were unreadable, ENAMETOOLONG if they run past `PATH_MAX`.
    let mkdir<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryMkdir caller path mode system
        |> Refusal.orRaise "UnixNamespace.mkdir" PathRefusal.kind PathRefusal.describe

    /// `tryMkdirat` once `Entry` has admitted its caller.
    let private tryMkdiratIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, PathRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        mkdirFrom (AtDirectory.decode flavour dirfd) path mode system

    /// `mkdirat`, with a refusal answered as the `Error` rather than raised.
    let internal tryMkdirat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, PathRefusal>
        =
        Entry.call
            "UnixNamespace.mkdirat"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryMkdiratIn dirfd path mode)
            system

    /// `mkdirat(2)`: `mkdir` of `path`, starting from `dirfd` if it is
    /// relative; `mkdir` is this from `AT_FDCWD`.
    ///
    /// `dirfd` is raw, in this platform's own numbering. Everything `mkdir`
    /// says holds, with one more step: once the path is copied in, a relative
    /// path starts where `dirfd` says, as every `*at` call's does. Nothing
    /// about `mode` is screened, so
    /// it never decides an answer ahead of the path or `dirfd`.
    let mkdirat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryMkdirat caller dirfd path mode system
        |> Refusal.orRaise "UnixNamespace.mkdirat" PathRefusal.kind PathRefusal.describe

    let private mknodFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, MkNodRefusal>
        =
        let platform = system.Machine.UnixPlatform
        let credentials = system.Process.Credentials

        match MkNodRules.screen (SimulatedUnixPlatform.mkNodRules platform) credentials mode dev with
        | MkNodScreen.Fails error -> Ok (SyscallAnswer.Failed error, system)
        | MkNodScreen.Refused refusal -> Error refusal
        | MkNodScreen.Walks node ->

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path ->

        // `NoFollowFinal`: like `mkdir` and `symlink`, `mknod` never
        // dereferences the name it is about to bind.
        match
            UnixPathResolution.resolvePathFull
                directory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator platform)
                path
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (MkNodRefusal.Path refusal)
        | Ok resolution ->

        let rules = SimulatedUnixPlatform.creatingOpenRules platform

        // Measured (`mknodat-rules.c`, PATH and MODE): past the walk, a
        // regular file is decided, and made, exactly as `open(O_CREAT|O_EXCL)`
        // decides and makes it.
        let creation =
            CreatingOpenRules.verdict
                rules
                system.Machine.ProtectedFiles
                (SimulatedUnixPlatform.bindableEntryNames platform)
                credentials
                true
                true
                resolution
                system.Machine.FileSystem

        match MkNodRules.verdict credentials node creation with
        | MkNodVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
        | MkNodVerdict.Refused refusal -> Error refusal
        | MkNodVerdict.CreateRegularFile (directory, name) ->
            let _, system = createRegularFile "UnixNamespace.mknod" directory name mode system
            Ok (SyscallAnswer.Completed 0L, system)

    /// `tryMknod` once `Entry` has admitted its caller.
    let private tryMknodIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, MkNodRefusal>
        =
        mknodFrom AtDirectory.CurrentDirectory path mode dev system

    /// `mknod`, with a refusal answered as the `Error` rather than raised.
    let internal tryMknod<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, MkNodRefusal>
        =
        Entry.call
            "UnixNamespace.mknod"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryMknodIn path mode dev)
            system

    /// `mknod(2)`: make a node of the type `mode` names at `path`. It is
    /// `mknodat` from `AT_FDCWD`; see there for what it answers and refuses.
    let mknod<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryMknod caller path mode dev system
        |> Refusal.orRaise "UnixNamespace.mknod" MkNodRefusal.kind MkNodRefusal.describe

    /// `tryMknodat` once `Entry` has admitted its caller.
    let private tryMknodatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, MkNodRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        mknodFrom (AtDirectory.decode flavour dirfd) path mode dev system

    /// `mknodat`, with a refusal answered as the `Error` rather than raised.
    let internal tryMknodat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, MkNodRefusal>
        =
        Entry.call
            "UnixNamespace.mknodat"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryMknodatIn dirfd path mode dev)
            system

    /// `mknodat(2)`: make a node of the type `mode` names at `path`, starting
    /// from `dirfd` if it is relative; `mknod` is this from `AT_FDCWD`.
    ///
    /// `dirfd`, `mode` and `dev` are raw, in this platform's own numbering.
    /// The type field of `mode` is read before anything else, as the flavour
    /// reads it: Linux answers a directory
    /// EPERM and a field naming no type it makes EINVAL, and Darwin answers
    /// any type but a FIFO EPERM to a caller without privilege, each before
    /// the path is copied in. Then `path` is copied in (EFAULT, ENAMETOOLONG),
    /// a relative path starts where `dirfd` says, as every `*at` call's does,
    /// and the walk never follows a final
    /// symbolic link. A regular file (`S_IFREG`, or a type field of 0) is
    /// then decided and made as `open(O_CREAT|O_EXCL)` decides and makes one:
    /// the same errnos in the same order, the same permission bits from
    /// `mode` under the umask and the parent's set-group-ID bit, the same
    /// owner, and the same timestamps. `dev` is not read for it. Only the
    /// walk differs: on Linux a trailing separator is resolved as `mkdir`
    /// resolves it, so `"f/"` is EEXIST where `open` answers EISDIR.
    ///
    /// Refuses, once every check that would fail the call has passed, to
    /// make a FIFO, a socket or a device node, none of which this library
    /// models, but answers Linux's EPERM to a caller without privilege who
    /// asks for a device. Refuses Darwin's FIFO, which is `mkfifo(2)`, and
    /// Darwin's privileged caller before the path is read.
    let mknodat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (mode : int)
        (dev : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryMknodat caller dirfd path mode dev system
        |> Refusal.orRaise "UnixNamespace.mknodat" MkNodRefusal.kind MkNodRefusal.describe

    /// `unlinkat` without `AT_REMOVEDIR`, of a path this kernel has already
    /// copied in, starting from `directory` if it is relative.
    let internal unlinkParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : UnixPath)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, RemovalRefusal>
        =
        // `NoFollowFinal` on both flavours — `unlink` removes the name it was
        // given, never what that name points at. The trailing separator is the
        // only thing that can reach past a final symlink, and only on Darwin;
        // see `SimulatedUnixPlatform.finalNameTrailingSeparator`.
        match
            UnixPathResolution.resolvePathFull
                directory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                path
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (RemovalRefusal.Path refusal)
        | Ok resolution ->

        // The covered directory, not the mounted root, is what a sticky
        // parent's rule consults; see `RemovalRefusal.MountPoint`.
        match RemovalChecks.mountPointInStickyDirectory resolution system.Machine.FileSystem with
        | Some mountRoot -> Error (RemovalRefusal.MountPoint mountRoot)
        | None ->

        match
            UnlinkRules.verdict
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                system.Process.Credentials
                resolution
                system.Machine.FileSystem
        with
        | Error refusal -> Error (RemovalRefusal.Sticky refusal)
        | Ok (UnlinkVerdict.Refuse error) -> Ok (SyscallAnswer.Failed error, system)
        | Ok (UnlinkVerdict.Remove (directory, name)) when
            (VirtualFileSystem.mountedRootOf directory system.Machine.FileSystem).IsSome
            ->
            Error (RemovalRefusal.DeviceFileSystem (directory, name))
        | Ok (UnlinkVerdict.Remove (directory, name)) ->

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match VirtualFileSystem.unbind UnbindTargetEffect.LostALink directory name now system.Machine.FileSystem with
        | Error error ->
            // `unbind` refuses a directory it does not hold and a name that
            // directory does not bind. The walk has just established both, so
            // either is a broken graph rather than something the caller did.
            failwith
                $"UnixNamespace.unlink: removing \"%s{DirectoryEntryName.toEscaped name}\" from inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and holds that name (this is a bug in this library)."
        | Ok (target, mutation) ->

        // The name is gone; whether the *inode* is depends on whether any other
        // name or any open descriptor still holds it. A real `unlink` of a file
        // something has open leaves it readable through that descriptor until the
        // last one closes.
        Ok (SyscallAnswer.Completed 0L, ObjectLifetime.commitRemoving target mutation system)

    /// `tryUnlink` once `Entry` has admitted its caller.
    let private tryUnlinkIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, RemovalRefusal>
        =
        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path -> unlinkParsed AtDirectory.CurrentDirectory path system

    /// `unlink`, with a refusal answered as the `Error` rather than raised.
    let internal tryUnlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RemovalRefusal>
        =
        Entry.call
            "UnixNamespace.unlink"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryUnlinkIn path)
            system

    /// `unlink(2)`: remove the name `path`, and the inode it named if nothing
    /// else holds it. It is `unlinkat` from `AT_FDCWD` with no flags.
    ///
    /// Every outcome is a success or an errno, except where Darwin's sticky
    /// rule has not been measured for this caller, where this kernel will not
    /// resolve the path, and where the name is on the device filesystem. A
    /// refusal changes nothing.
    ///
    /// `path` is the argument's bytes, copied in before anything else: EFAULT
    /// if they were unreadable, ENAMETOOLONG if they run past `PATH_MAX`.
    let unlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryUnlink caller path system
        |> Refusal.orRaise "UnixNamespace.unlink" RemovalRefusal.kind RemovalRefusal.describe

    /// `unlinkat` with `AT_REMOVEDIR`, of a path this kernel has already
    /// copied in, starting from `directory` if it is relative.
    let internal rmdirParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (path : UnixPath)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, RemovalRefusal>
        =
        let rules = SimulatedUnixPlatform.rmDirRules system.Machine.UnixPlatform

        // `NoFollowFinal` on both flavours. The trailing separator is what
        // reaches past a final symlink, and only on Darwin — which is how
        // `rmdir("ld/")` removes the *link's target* there and is ENOTDIR on
        // Linux. See `SimulatedUnixPlatform.finalNameTrailingSeparator`.
        match
            UnixPathResolution.resolvePathFull
                directory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                path
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (RemovalRefusal.Path refusal)
        | Ok resolution ->

        // The covered directory, not the mounted root, is what a sticky
        // parent's rule consults; see `RemovalRefusal.MountPoint`.
        match RemovalChecks.mountPointInStickyDirectory resolution system.Machine.FileSystem with
        | Some mountRoot -> Error (RemovalRefusal.MountPoint mountRoot)
        | None ->

        match
            RmDirRules.verdict
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                system.Process.Credentials
                resolution
                system.Machine.FileSystem
        with
        | Error refusal -> Error (RemovalRefusal.Sticky refusal)
        | Ok (RmDirVerdict.Refuse error) -> Ok (SyscallAnswer.Failed error, system)
        | Ok (RmDirVerdict.Remove (directory, name)) when
            (VirtualFileSystem.mountedRootOf directory system.Machine.FileSystem).IsSome
            ->
            Error (RemovalRefusal.DeviceFileSystem (directory, name))
        | Ok (RmDirVerdict.Remove (directory, name)) ->

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match VirtualFileSystem.unbind rules.RemovedDirectoryEffect directory name now system.Machine.FileSystem with
        | Error error ->
            failwith
                $"UnixNamespace.rmdir: removing \"%s{DirectoryEntryName.toEscaped name}\" from inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and holds that name (this is a bug in this library)."
        | Ok (target, mutation) ->

        // A directory has only ever had the one name, so this was the last — but
        // a descriptor or the current directory may still hold it, and a real
        // `rmdir` leaves such an orphan usable through what holds it.
        // `forgetIfUnheld` also collects the ancestors this directory's ".." was
        // keeping alive.
        Ok (SyscallAnswer.Completed 0L, ObjectLifetime.commitRemoving target mutation system)

    /// `tryRmdir` once `Entry` has admitted its caller.
    let private tryRmdirIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, RemovalRefusal>
        =
        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path -> rmdirParsed AtDirectory.CurrentDirectory path system

    /// `rmdir`, with a refusal answered as the `Error` rather than raised.
    let internal tryRmdir<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RemovalRefusal>
        =
        Entry.call
            "UnixNamespace.rmdir"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryRmdirIn path)
            system

    /// `rmdir(2)`: remove the empty directory `path` names. It is `unlinkat`
    /// from `AT_FDCWD` with `AT_REMOVEDIR`.
    ///
    /// Every outcome is a success or an errno, except where Darwin's sticky
    /// rule has not been measured for this caller, where this kernel will not
    /// resolve the path, and where the name is on the device filesystem. A
    /// refusal changes nothing.
    ///
    /// `path` is the argument's bytes, copied in before anything else: EFAULT
    /// if they were unreadable, ENAMETOOLONG if they run past `PATH_MAX`.
    let rmdir<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (path : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryRmdir caller path system
        |> Refusal.orRaise "UnixNamespace.rmdir" RemovalRefusal.kind RemovalRefusal.describe

    /// `tryUnlinkat` once `Entry` has admitted its caller.
    let private tryUnlinkatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, UnlinkAtRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        match UnlinkAtRules.screen flavour flags with
        | AtFlagScreen.Failed error -> Ok (SyscallAnswer.Failed error, system)
        | AtFlagScreen.Unmodelled refused -> Error (UnlinkAtRefusal.UnmodelledFlags refused)
        | AtFlagScreen.Screened kind ->

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path ->

        let directory = AtDirectory.decode flavour dirfd

        match kind with
        | RemovalKind.Unlink -> unlinkParsed directory path system
        | RemovalKind.RmDir -> rmdirParsed directory path system
        |> Result.mapError UnlinkAtRefusal.Removal

    /// `unlinkat`, with a refusal answered as the `Error` rather than raised.
    let internal tryUnlinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, UnlinkAtRefusal>
        =
        Entry.call
            "UnixNamespace.unlinkat"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryUnlinkatIn dirfd path flags)
            system

    /// `unlinkat(2)`: `unlink` of `path`, or with `AT_REMOVEDIR` `rmdir` of
    /// it, starting from `dirfd` if it is relative; `unlink` and `rmdir` are
    /// this from `AT_FDCWD`.
    ///
    /// `dirfd` and `flags` are raw, in this platform's own numbering. The flag
    /// word is screened first, ahead of the path and `dirfd`. Then everything
    /// `unlink` or `rmdir` says holds, with one more step: once the path is
    /// copied in, a relative path starts where `dirfd` says, as every `*at`
    /// call's does, and nothing else about the call changes.
    ///
    /// Refuses a flag word carrying flags the flavour accepts and this library
    /// does not model, and whatever `unlink` or `rmdir` refuses. A refusal
    /// changes nothing.
    let unlinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryUnlinkat caller dirfd path flags system
        |> Refusal.orRaise "UnixNamespace.unlinkat" UnlinkAtRefusal.kind UnlinkAtRefusal.describe

    let private renameStopped
        (system : ProcessView<'Thread, 'Handler>)
        (error : UnixError)
        : CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>
        =
        CallProgress.Answered (SyscallAnswer.Failed error, system)

    let private renameSourceFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (sourceDirectory : AtDirectory)
        (destinationDirectory : AtDirectory)
        (source : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              RenameRefusal
           >
        =
        let rules = SimulatedUnixPlatform.renameRules system.Machine.UnixPlatform

        let paused (progress : RenameSourceProgress) =
            CallProgress.NeedsCopyIn
                {
                    System = system
                    Rules = rules
                    SourceProgress = progress
                    Destination = destinationDirectory
                }
            |> Ok

        let stopped (error : UnixError) = renameStopped system error |> Ok

        match UnixPathResolution.copyIn source system with
        | Error error -> stopped error
        | Ok sourcePath ->

        // `NoFollowFinal` for both paths on both flavours — `rename` moves the
        // name it was given, never what that name points at. The trailing
        // separator is the only thing that reaches past a final symlink, and
        // only on Darwin; see `SimulatedUnixPlatform.finalNameTrailingSeparator`.
        //
        // Each side's starting directory is looked up as that side's walk
        // begins, after its own copy-in (`walkStart`), so a bad `newdirfd`
        // is answered only once the source has gone as far as this phase
        // takes it: measured by `at-dirfd.c` (ORDER2) and `renameat-rules.c`
        // (ORDER).
        match rules.WalkOrder with
        | RenameWalkOrder.ParentsThenFinals ->
            match
                UnixPathResolution.resolvePathParent
                    sourceDirectory
                    SymlinkPolicy.NoFollowFinal
                    (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                    sourcePath
                    system
            with
            | Error (PathFailure.Errno error) -> stopped error
            | Error (PathFailure.Refused refusal) -> Error (RenameRefusal.Path refusal)
            | Ok parent -> paused (RenameSourceProgress.ParentWalked parent)
        | RenameWalkOrder.SourceThenDestination ->

        match
            UnixPathResolution.resolvePathFull
                sourceDirectory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                sourcePath
                system
        with
        | Error (PathFailure.Errno error) -> stopped error
        | Error (PathFailure.Refused refusal) -> Error (RenameRefusal.Path refusal)
        | Ok sourceResolution ->

        // Darwin's source-side `namei` runs under rename semantics, so two of
        // the refusals the verdict would otherwise make are settled here —
        // before the destination's pathname has been read at all.
        match RenameRules.sourceScreen rules.WalkOrder sourceResolution with
        | Some error -> stopped error
        | None -> paused (RenameSourceProgress.Resolved sourceResolution)

    /// `tryRenameat` once `Entry` has admitted its caller.
    let private tryRenameatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              RenameRefusal
           >
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        renameSourceFrom (AtDirectory.decode flavour olddirfd) (AtDirectory.decode flavour newdirfd) oldpath system

    /// `renameat`, with a refusal answered as the `Error` rather than raised.
    let internal tryRenameat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>,
              RenameRefusal
           >
        =
        Entry.call
            "UnixNamespace.renameat"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryRenameatIn olddirfd oldpath newdirfd)
            system

    /// <summary>
    /// `renameat(2)`: move the name `oldpath`, relative to `olddirfd`, to a
    /// new name relative to `newdirfd`.
    /// </summary>
    /// <remarks>
    /// Everything the call does before it copies its destination pathname in
    /// comes first: on Linux the source's pathname and parent walk, on Darwin
    /// the whole source, including the two refusals Darwin's source-side
    /// lookup makes for itself under rename semantics. A call that ends there
    /// is `CallProgress.Answered`, and never reads the destination. Otherwise
    /// it stops where the kernel copies the destination in (`PausedRename`),
    /// and `renameWithDestination` finishes it.
    ///
    /// `olddirfd` and `newdirfd` are raw, in this platform's own numbering.
    /// Each side's starting directory is looked up where that side's walk
    /// begins, `newdirfd` only once the destination has been copied in, and
    /// nothing else about the call changes: `rename` is this from `AT_FDCWD`
    /// on both sides.
    /// </remarks>
    let renameat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryRenameat caller olddirfd oldpath newdirfd system
        |> Refusal.orRaise "UnixNamespace.renameat" RenameRefusal.kind RenameRefusal.describe

    /// `tryRename` once `Entry` has admitted its caller.
    let private tryRenameIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              RenameRefusal
           >
        =
        renameSourceFrom AtDirectory.CurrentDirectory AtDirectory.CurrentDirectory source system

    /// `rename`, with a refusal answered as the `Error` rather than raised.
    let internal tryRename<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (source : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>,
              RenameRefusal
           >
        =
        Entry.call
            "UnixNamespace.rename"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryRenameIn source)
            system

    /// `rename(2)`: `renameat` from `AT_FDCWD` on both sides.
    let rename<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (source : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedRename<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryRename caller source system
        |> Refusal.orRaise "UnixNamespace.rename" RenameRefusal.kind RenameRefusal.describe

    /// `tryRenameWithDestination`, before `Entry.resume` hands its answer back.
    let private tryRenameWithDestinationIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedRename<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, RenameRefusal>
        =
        CallProgress.requirePaused "UnixNamespace.renameWithDestination" "UnixNamespace.renameat or rename" paused

        let system = paused.System
        let rules = paused.Rules

        let resolved : Result<Resolution * Resolution, PathFailure> =
            match UnixPathResolution.copyIn destination system with
            | Error error -> Error (PathFailure.Errno error)
            | Ok destinationPath ->

            match paused.SourceProgress with
            | RenameSourceProgress.Resolved sourceResolution ->
                // Darwin: the source is already finished, so the destination is
                // resolved to completion and the verdict judges the pair.
                UnixPathResolution.resolvePathFull
                    paused.Destination
                    SymlinkPolicy.NoFollowFinal
                    (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                    destinationPath
                    system
                |> Result.map (fun destinationResolution -> sourceResolution, destinationResolution)
            | RenameSourceProgress.ParentWalked sourceParent ->

            // Linux: the destination's parent, then both final lookups.
            match
                UnixPathResolution.resolvePathParent
                    paused.Destination
                    SymlinkPolicy.NoFollowFinal
                    (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                    destinationPath
                    system
            with
            | Error failure -> Error failure
            | Ok destinationParent ->

            // Linux compares the two parents' mounts before it looks either
            // final name up: measured (`devices.c`, NS rows), a rename between
            // `/tmp` and `/dev` is EXDEV whether or not the source exists and
            // whether or not the caller may write either directory.
            if
                PathWalk.pausedMountedRoot sourceParent
                <> PathWalk.pausedMountedRoot destinationParent
            then
                Error (PathFailure.Errno UnixError.EXDEV)

            // Then either path naming no final component, "/", "." or "..", is
            // EBUSY, still before either final name is looked up: measured
            // (`renameat-rules.c`, ORDER), `rename("nx", ".")` and
            // `rename(<300 bytes>, "/")` are EBUSY, not the source's ENOENT
            // and ENAMETOOLONG.
            else if
                PathWalk.pausedNamesNoFinal sourceParent
                || PathWalk.pausedNamesNoFinal destinationParent
            then
                Error (PathFailure.Errno UnixError.EBUSY)
            else

            // Source before destination, and here the order *is* pinned: the
            // orphan check below sits between the two, so a 300-byte source name
            // is ENAMETOOLONG while a 300-byte destination name under the same
            // orphaned parent is ENOENT. Measured both ways.
            match PathWalk.completeResolution sourceParent with
            | Error failure -> Error failure
            | Ok sourceResolution ->

            // Linux's source screen runs here: after both parents and the
            // source's own final lookup, and before the destination's. Its
            // EBUSY arm has been settled above; its free-name ENOENT beats the
            // orphan check below and the destination's NAME_MAX, which is what
            // makes `rename("nope", <300-byte name>)` ENOENT.
            match RenameRules.sourceScreen rules.WalkOrder sourceResolution with
            | Some error -> Error (PathFailure.Errno error)
            | None ->

            // A destination parent that has lost its own last name — reachable
            // only as an `rmdir`'d current directory — is ENOENT here, *before*
            // the destination's final name is measured. Both verdicts also
            // refuse it, and on Darwin that is where it is caught, after the
            // whole destination has resolved: measured, the same call is
            // ENAMETOOLONG there. So this is the Linux position of a check both
            // flavours make, not a check only Linux makes.
            if PathWalk.pausedParentIsOrphaned destinationParent then
                Error (PathFailure.Errno UnixError.ENOENT)
            else

            PathWalk.completeResolution destinationParent
            |> Result.map (fun destinationResolution -> sourceResolution, destinationResolution)

        match resolved with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (RenameRefusal.Path refusal)
        | Ok (sourceResolution, destinationResolution) ->

        let vfs = system.Machine.FileSystem

        let mountRootNamed (resolution : Resolution) : InodeNumber option =
            match resolution.Target with
            | ResolvedTarget.Entry (_, _, Some target) when (VirtualFileSystem.mountOf target vfs).IsSome -> Some target
            | ResolvedTarget.Entry _
            | ResolvedTarget.Directory _ -> None

        let verdict =
            RenameRules.verdict
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                system.Process.Credentials
                sourceResolution
                destinationResolution
                vfs

        // A mount point's own rows. Linux checks the permissions first and the
        // mount after (`rename("/dev", "/devx")` is EACCES at uid 1000 and EBUSY
        // at uid 0), and a rename onto itself before either (`vfs_rename`
        // answers 0 when source and target are one inode: measured by
        // `mountpoint-self-rename.c`, as root and as uid 1000). Those, a mount
        // point renamed within its own directory, are all that has been
        // measured. They are also all that can be answered: the mount point's
        // own inode is the covered directory, whose owner a sticky parent
        // consults and whose write bit a move to another directory consults,
        // and this kernel holds only the mounted root.
        let sticky (resolution : Resolution) : bool =
            RemovalChecks.inStickyDirectory resolution vfs

        let verdict =
            match mountRootNamed sourceResolution, mountRootNamed destinationResolution, verdict with
            | None, None, verdict -> Ok verdict
            | Some source, Some destination, Ok RenameVerdict.NoOp when
                source = destination
                && SimulatedUnixPlatform.flavour system.Machine.UnixPlatform = SimulatedUnixFlavour.Linux
                ->
                Ok (Ok RenameVerdict.NoOp)
            | Some mountRoot, None, verdict when not (sticky sourceResolution) && not (sticky destinationResolution) ->
                match sourceResolution.Target, destinationResolution.Target, verdict with
                | ResolvedTarget.Entry (sourceDirectory, _, _),
                  ResolvedTarget.Entry (destinationDirectory, _, None),
                  Ok (RenameVerdict.Refuse UnixError.EACCES as refused) when sourceDirectory = destinationDirectory ->
                    Ok (Ok refused)
                | ResolvedTarget.Entry (sourceDirectory, _, _),
                  ResolvedTarget.Entry (destinationDirectory, _, None),
                  Ok (RenameVerdict.Move _) when sourceDirectory = destinationDirectory ->
                    Ok (Ok (RenameVerdict.Refuse UnixError.EBUSY))
                | _ -> Error (RenameRefusal.MountPoint mountRoot)
            | Some mountRoot, _, _
            | None, Some mountRoot, _ -> Error (RenameRefusal.MountPoint mountRoot)

        match verdict with
        | Error refusal -> Error refusal
        | Ok (Error refusal) -> Error (RenameRefusal.Sticky refusal)
        | Ok (Ok (RenameVerdict.Move (sourceDirectory, sourceName, _, _))) when
            (VirtualFileSystem.mountedRootOf sourceDirectory vfs).IsSome
            ->
            Error (RenameRefusal.DeviceFileSystem (sourceDirectory, sourceName))
        | Ok (Ok (RenameVerdict.Refuse error)) -> Ok (SyscallAnswer.Failed error, system)
        // Both paths name one inode: a success that changes nothing at all, not
        // a binding and not a timestamp. Deliberately not routed through
        // `VirtualFileSystem.rename`, which refuses it — the graph primitive
        // would have to invent a no-op stamp to express it.
        | Ok (Ok RenameVerdict.NoOp) -> Ok (SyscallAnswer.Completed 0L, system)
        | Ok (Ok (RenameVerdict.Move (sourceDirectory, sourceName, destinationDirectory, destinationName))) ->

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match
            VirtualFileSystem.rename
                sourceDirectory
                sourceName
                destinationDirectory
                destinationName
                now
                system.Machine.FileSystem
        with
        | Error error ->
            // `rename` refuses a directory it does not hold, a source name that
            // directory does not bind, and the four conditions that would leave
            // a graph no kernel could produce — the two paths naming one inode,
            // a populated destination directory, a destination inside the
            // source's own subtree, and an orphaned destination directory. The
            // verdict owes an errno for every one of those, so reaching here
            // means the verdict let something through rather than that the
            // caller did anything unusual.
            failwith
                $"UnixNamespace.rename: moving \"%s{DirectoryEntryName.toEscaped sourceName}\" from inode %O{sourceDirectory} to \"%s{DirectoryEntryName.toEscaped destinationName}\" in inode %O{destinationDirectory} was refused with %O{error}, but the verdict had just approved it (this is a bug in this library)."
        | Ok (outcome, mutation) ->

        // A rename is the one syscall that can change the *path* of a directory
        // the process is already in, without changing its inode: moving any
        // ancestor of the current directory moves the current directory with it.
        // Nothing here has to notice. Relative paths resolve from the inode,
        // which has not moved, and `getcwd` derives the path from the graph this
        // rename has just rewritten — so it reports the new path however many
        // levels up the move was, and reports nothing if this rename displaced
        // the current directory itself.
        //
        // The destination name may have been the displaced inode's last, and
        // whether the inode goes with it depends on the descriptor table, which
        // the filesystem cannot see. When the displaced thing was a directory
        // this also collects the ancestors its ".." was keeping alive.
        Ok (
            SyscallAnswer.Completed 0L,
            match outcome.Displaced with
            | None ->
                { system with
                    Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
                }
            | Some displaced -> ObjectLifetime.commitRemoving displaced mutation system
        )

    /// `renameWithDestination`, with a refusal answered as the `Error` rather than raised.
    let internal tryRenameWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedRename<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RenameRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryRenameWithDestinationIn destination paused)

    /// The rest of `rename(2)` or `renameat(2)`, given the destination
    /// pathname the kernel has just reached the point of copying in. A
    /// relative destination starts where the paused call's `newdirfd` says.
    ///
    /// Every outcome is a success or an errno, except where Darwin's sticky
    /// rule has not been measured for this caller, where this kernel will not
    /// resolve a path, where a path names a mount point in an unmeasured way,
    /// and where the source is on the device filesystem. A refusal changes
    /// nothing.
    let renameWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedRename<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryRenameWithDestination destination paused
        |> Refusal.orRaise "UnixNamespace.renameWithDestination" RenameRefusal.kind RenameRefusal.describe

    /// `tryCloneFile` once `Entry` has admitted its caller.
    let private tryCloneFileIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedCloneFileSource<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              CloneFileRefusal
           >
        =
        // Measured on Darwin 27.0 at uid 501 (`clonefile-rules.c`, APFS): bits
        // 0 to 4 alone are accepted and every higher bit alone is EINVAL, and
        // EINVAL beats an absent source and an existing destination.
        let cloneNoFollow = 0x1
        let cloneNoFollowAny = 0x8
        let cloneResolveBeneath = 0x10
        let known = 0x1F

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux -> Error (CloneFileRefusal.UnmodelledFlavour SimulatedUnixFlavour.Linux)
        | SimulatedUnixFlavour.Darwin ->

        match EmulatedMount.fileSystemType system.Machine.Mount with
        | EmulatedFileSystemType.Tmpfs
        | EmulatedFileSystemType.Nfs as fileSystem -> Error (CloneFileRefusal.UnmeasuredFileSystem fileSystem)
        | EmulatedFileSystemType.Apfs ->

        if flags &&& ~~~known <> 0 then
            Ok (CallProgress.Answered (SyscallAnswer.Failed UnixError.EINVAL, system))
        elif flags &&& (cloneNoFollow ||| cloneNoFollowAny ||| cloneResolveBeneath) <> 0 then
            Error (CloneFileRefusal.UnmodelledFlags flags)
        elif Credentials.privilege system.Process.Credentials = CallerPrivilege.Privileged then
            Error CloneFileRefusal.PrivilegedCaller
        else
            Ok (
                CallProgress.NeedsCopyIn
                    {
                        System = system
                    }
            )

    /// `cloneFile`, with a refusal answered as the `Error` rather than raised.
    let internal tryCloneFile<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedCloneFileSource<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>,
              CloneFileRefusal
           >
        =
        Entry.call
            "UnixNamespace.cloneFile"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryCloneFileIn flags)
            system

    /// <summary>
    /// `clonefile(source, destination, flags)`: make `destination` a copy of
    /// the regular file `source` names.
    ///
    /// `flags` is raw, and screened before either pathname is read: any bit
    /// above `CLONE_RESOLVE_BENEATH` (0x10) is EINVAL, answered as
    /// `CallProgress.Answered`. `CLONE_ACL` (0x4) and `CLONE_NOOWNERCOPY` (0x2)
    /// change nothing for an unprivileged caller of a filesystem without
    /// access control lists, which is what this kernel models. Otherwise the
    /// call stops where the kernel copies the source pathname in
    /// (`PausedCloneFileSource`), which `cloneFileWithSource` takes, and then
    /// where it copies the destination's, which `cloneFileWithDestination`
    /// takes.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has `clonefile`.</exception>
    let cloneFile<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedCloneFileSource<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryCloneFile caller flags system
        |> Refusal.orRaise "UnixNamespace.cloneFile" CloneFileRefusal.kind CloneFileRefusal.describe

    /// `tryCloneFileWithSource`, before `Entry.resume` hands its answer back.
    let private tryCloneFileWithSourceIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (paused : PausedCloneFileSource<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedCloneFile<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              CloneFileRefusal
           >
        =
        // Measured on Darwin 27.0 at uid 501 (`clonefile-rules.c`, APFS): the
        // source is resolved before anything about the destination: an absent
        // source is ENOENT whether the destination exists or its parent is
        // unwritable, and a source in an unsearchable directory is EACCES with
        // an existing destination. "f/" and "f/x" for a regular `f` are
        // ENOTDIR, a link to a file clones the file, and a dangling or cyclic
        // link is ENOENT or ELOOP.
        CallProgress.requirePaused "UnixNamespace.cloneFileWithSource" "UnixNamespace.cloneFile" paused

        let system = paused.System

        match UnixPathResolution.copyIn source system with
        | Error error -> Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))
        | Ok sourcePath ->

        match UnixPathResolution.resolvePath AtDirectory.CurrentDirectory SymlinkPolicy.Follow sourcePath system with
        | Error (PathFailure.Errno error) -> Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))
        | Error (PathFailure.Refused refusal) -> Error (CloneFileRefusal.Path refusal)
        | Ok inode ->

        match VirtualFileSystem.tryGetContent inode system.Machine.FileSystem with
        | Some (InodeContent.Directory _) -> Error (CloneFileRefusal.DirectorySource inode)
        | Some (InodeContent.RegularFile _) ->
            Ok (
                CallProgress.NeedsCopyIn
                    {
                        System = system
                        Source = inode
                    }
            )
        | Some (InodeContent.CharacterDevice _) ->
            failwith
                $"UnixNamespace.cloneFileWithSource: the source resolved to inode %O{inode}, a character device; clonefile(2) is Darwin's, and this kernel holds no device on Darwin (this is a bug in this library)."
        | Some (InodeContent.Socket _) ->
            failwith
                $"UnixNamespace.cloneFileWithSource: the source resolved to inode %O{inode}, which is a socket. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."
        | Some (InodeContent.Fifo _) ->
            failwith
                $"UnixNamespace.cloneFileWithSource: the source resolved to inode %O{inode}, which is a FIFO. Nothing in this version makes one: InodeContent.Fifo is unreachable until FIFOs are modelled (this is a bug in this library)."
        | Some (InodeContent.Symlink _)
        | None ->
            failwith
                $"UnixNamespace.cloneFileWithSource: following every link, the source resolved to inode %O{inode}, which is a symbolic link or absent (this is a bug in this library)."

    /// `cloneFileWithSource`, with a refusal answered as the `Error` rather than raised.
    let internal tryCloneFileWithSource<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (paused : PausedCloneFileSource<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedCloneFile<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>,
              CloneFileRefusal
           >
        =
        Entry.resume (Shape.result (Shape.progress Shape.withSystem)) (tryCloneFileWithSourceIn source paused)

    /// <summary>
    /// The next part of `clonefile(2)`, given the source pathname the kernel
    /// has just reached the point of copying in: it is resolved, following a
    /// final symbolic link, up to the point where the kernel copies the
    /// destination pathname in (`PausedCloneFile`), or answered there, never
    /// reading the destination.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has `clonefile`.</exception>
    let cloneFileWithSource<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (source : PathArgumentBytes)
        (paused : PausedCloneFileSource<'Thread, 'Handler>)
        : CallProgress<PausedCloneFile<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryCloneFileWithSource source paused
        |> Refusal.orRaise "UnixNamespace.cloneFileWithSource" CloneFileRefusal.kind CloneFileRefusal.describe

    /// `tryCloneFileWithDestination`, before `Entry.resume` hands its answer back.
    let private tryCloneFileWithDestinationIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedCloneFile<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, CloneFileRefusal>
        =
        // Measured on Darwin 27.0 at uid 501 (`clonefile-rules.c`, APFS). The
        // destination: an existing file, directory ("e" and "e/"), link to a
        // file or a directory, "/", "." and a hard link to the source are all
        // EEXIST, and so is an existing name in an unwritable directory; a
        // dangling link creates its target (and is EEXIST under
        // CLONE_NOFOLLOW); a cyclic link is ELOOP; "new/" and "nx/new" are
        // ENOENT, "f/new" ENOTDIR, a 299-byte name ENAMETOOLONG, an
        // unsearchable parent EACCES, and a removed current directory ENOENT.
        // Each of those beats an unreadable source, which beats an unwritable
        // parent (both EACCES) and a name that is not UTF-8 (EILSEQ, last).
        // The clone: over every mode an owner can give a source, in a
        // directory of its own group, the clone's mode is the source's less
        // both set-ID bits (0 mismatches over 2048 readable modes); in a wheel
        // directory, where S_ISGID cannot be set, likewise. A source the
        // caller cannot read (no owner read bit) is EACCES. uid is the
        // caller's and gid the directory's, either way round; the umask plays
        // no part; atime, mtime and birth time are the source's to the
        // nanosecond, ctime is now; the parent's mtime and ctime move and its
        // atime does not; the source's times do not move.
        CallProgress.requirePaused "UnixNamespace.cloneFileWithDestination" "UnixNamespace.cloneFileWithSource" paused

        let system = paused.System
        let failed (error : UnixError) = Ok (SyscallAnswer.Failed error, system)
        let rules = SimulatedUnixPlatform.creatingOpenRules system.Machine.UnixPlatform
        let credentials = system.Process.Credentials

        match UnixPathResolution.copyIn destination system with
        | Error error -> failed error
        | Ok destinationPath ->

        match
            UnixPathResolution.resolvePathFull
                AtDirectory.CurrentDirectory
                SymlinkPolicy.Follow
                rules.TrailingSeparator
                destinationPath
                system
        with
        | Error (PathFailure.Errno error) -> failed error
        | Error (PathFailure.Refused refusal) -> Error (CloneFileRefusal.Path refusal)
        | Ok resolution ->

        match
            NewNameRules.verdict
                FreeNameTrailingSeparator.NoSuchEntry
                (NewNameSource.Cloned paused.Source)
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                credentials
                resolution
                system.Machine.FileSystem
        with
        | NewNameVerdict.Refuse error -> failed error
        | NewNameVerdict.Bind (directory, name, _) ->

        // The verdict has found the source a readable regular file.
        let sourceBits, sourceStanding =
            match VirtualFileSystem.tryGet paused.Source system.Machine.FileSystem with
            | Some ({
                        Content = InodeContent.RegularFile (_, bits)
                    } as source) -> bits, Standing.toward credentials source.Owner
            | Some _
            | None ->
                failwith
                    $"UnixNamespace.cloneFileWithDestination: the source, inode %O{paused.Source}, is no longer a regular file in the filesystem, but nothing ran between resolving it and now (this is a bug in this library)."

        let raw = PermissionBits.toInt sourceBits

        let measured =
            raw
            &&& (PermissionBits.setUserId ||| PermissionBits.setGroupId ||| PermissionBits.sticky) = 0
            || (sourceStanding.Owns && sourceStanding.InGroup)
            || (sourceStanding.Owns && raw &&& PermissionBits.setGroupId = 0)

        if not measured then
            Error (CloneFileRefusal.UnmeasuredSpecialBits (paused.Source, sourceStanding, sourceBits))
        else

        let permissions =
            PermissionBits.parseOrFail
                "UnixNamespace.cloneFileWithDestination"
                (raw &&& ~~~(PermissionBits.setUserId ||| PermissionBits.setGroupId))

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match
            VirtualFileSystem.cloneFile
                paused.Source
                directory
                name
                permissions
                (newInodeOwner "UnixNamespace.cloneFileWithDestination" directory system)
                now
                system.Machine.FileSystem
        with
        | Error error ->
            failwith
                $"UnixNamespace.cloneFileWithDestination: binding \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and does not hold that name (this is a bug in this library)."
        | Ok (_, mutation) ->
            Ok (
                SyscallAnswer.Completed 0L,
                { system with
                    Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
                }
            )

    /// `cloneFileWithDestination`, with a refusal answered as the `Error` rather than raised.
    let internal tryCloneFileWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedCloneFile<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, CloneFileRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryCloneFileWithDestinationIn destination paused)

    /// <summary>
    /// The rest of `clonefile(2)`, given the destination pathname the kernel
    /// has just reached the point of copying in.
    ///
    /// The destination resolves as a creating `open(2)`'s does, following a
    /// final symbolic link, so a dangling link is replaced by a file at its
    /// target. Anything already there is EEXIST; then the source must be
    /// readable (EACCES), the destination's directory writable (EACCES), and
    /// its name one the filesystem admits (EILSEQ).
    ///
    /// The clone is a new regular file holding the source's bytes and its
    /// permission bits less both set-ID bits, owned as any new file in that
    /// directory is, with the source's access, modification and birth times;
    /// its status-change time is now, and the directory's modification and
    /// status-change times move. The source does not change.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has `clonefile`.</exception>
    let cloneFileWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : PathArgumentBytes)
        (paused : PausedCloneFile<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryCloneFileWithDestination destination paused
        |> Refusal.orRaise "UnixNamespace.cloneFileWithDestination" CloneFileRefusal.kind CloneFileRefusal.describe

    let private symlinkTargetFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (directory : AtDirectory)
        (target : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : CallProgress<PausedSymlink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>
        =
        // Measured by `link-symlink.c` (SYMORDER) on Linux 6.18.5 and Darwin
        // 27.0: the target is copied in before anything else, so an unreadable
        // or over-long one wins against every other argument, and Linux's
        // empty target is ENOENT before the link's pathname is read. Darwin
        // goes on, and fails the call at whatever else fails it.
        match UnixPathResolution.copyIn target system with
        | Error error -> CallProgress.Answered (SyscallAnswer.Failed error, system)
        | Ok target ->

        match SymlinkTarget.ofByteString (UnixPath.toByteString target) with
        | Ok target ->
            CallProgress.NeedsCopyIn
                {
                    System = system
                    Directory = directory
                    Target = Some target
                }
        | Error SymlinkTargetError.Empty ->
            match (SimulatedUnixPlatform.symlinkRules system.Machine.UnixPlatform).EmptyTarget with
            | EmptySymlinkTarget.NoSuchEntry -> CallProgress.Answered (SyscallAnswer.Failed UnixError.ENOENT, system)
            | EmptySymlinkTarget.Accepted ->
                CallProgress.NeedsCopyIn
                    {
                        System = system
                        Directory = directory
                        Target = None
                    }
        | Error (SymlinkTargetError.Text defect) ->
            failwith
                $"UnixNamespace.symlink: the copied-in target has a text defect (%A{defect}), which only a target parsed from a .NET string can have (this is a bug in this library)."

    /// `symlinkat` once `Entry` has admitted its caller.
    let private symlinkatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (target : PathArgumentBytes)
        (dirfd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : CallProgress<PausedSymlink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>
        =
        let directory =
            AtDirectory.decode (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform) dirfd

        symlinkTargetFrom directory target system

    /// `symlinkat(2)`: create, at a pathname relative to `dirfd`, a symbolic
    /// link whose target is `target`.
    ///
    /// `dirfd` is raw, in this platform's own numbering. `target` is the
    /// argument's bytes, copied in first: a target the kernel cannot copy in
    /// answers at once (`CallProgress.Answered`, changing nothing), and the
    /// link's own pathname is never read. Otherwise the call stops where the
    /// kernel copies that pathname in, and `symlinkWithPath` finishes it; see
    /// it for what the call answers and refuses.
    let symlinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (target : PathArgumentBytes)
        (dirfd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedSymlink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        Entry.call
            "UnixNamespace.symlinkat"
            CallerRequirement.Running
            caller
            (Shape.progress Shape.withSystem)
            (symlinkatIn target dirfd)
            system

    /// `symlink` once `Entry` has admitted its caller.
    let private symlinkIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (target : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : CallProgress<PausedSymlink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>
        =
        symlinkTargetFrom AtDirectory.CurrentDirectory target system

    /// `symlink(2)`: `symlinkat` from the current directory.
    let symlink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (target : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedSymlink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        Entry.call
            "UnixNamespace.symlink"
            CallerRequirement.Running
            caller
            (Shape.progress Shape.withSystem)
            (symlinkIn target)
            system

    /// `trySymlinkWithPath`, before `Entry.resume` hands its answer back.
    let private trySymlinkWithPathIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedSymlink<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, SymlinkRefusal>
        =
        CallProgress.requirePaused "UnixNamespace.symlinkWithPath" "UnixNamespace.symlinkat or symlink" paused

        let system = paused.System

        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok path ->

        match
            UnixPathResolution.resolvePathFull
                paused.Directory
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                path
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (SymlinkRefusal.Path refusal)
        | Ok resolution ->

        match
            SymlinkRules.verdict
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                system.Process.Credentials
                resolution
                system.Machine.FileSystem
        with
        | SymlinkVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
        | SymlinkVerdict.Create (directory, name) ->

        match paused.Target with
        | None -> Error SymlinkRefusal.EmptyTarget
        | Some target ->

        let permissions =
            SimulatedUnixPlatform.symlinkCreationPermissions system.Machine.UnixPlatform system.Process.Umask

        let owner = newInodeOwner "UnixNamespace.symlink" directory system
        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match VirtualFileSystem.createSymlink directory name permissions owner now target system.Machine.FileSystem with
        | Error error ->
            failwith
                $"UnixNamespace.symlink: creating \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory} was refused with %O{error}, but the walk had just established that the directory exists and does not hold that name (this is a bug in this library)."
        | Ok (_, mutation) ->

        Ok (
            SyscallAnswer.Completed 0L,
            { system with
                Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
            }
        )

    /// `symlinkWithPath`, with a refusal answered as the `Error` rather than raised.
    let internal trySymlinkWithPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedSymlink<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SymlinkRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (trySymlinkWithPathIn path paused)

    /// The second half of `symlink(2)` or `symlinkat(2)`: copy in `path`, the
    /// link's own pathname, and create the link the paused call describes.
    ///
    /// A relative `path` starts where the call's `dirfd` says. A final symbolic
    /// link is never followed, and a trailing separator reaches past the final
    /// name only as `SimulatedUnixPlatform.finalNameTrailingSeparator` says. The
    /// new link holds the target byte for byte, has the permission bits 0o777
    /// on Linux and 0o777 less the process's umask on Darwin, and is owned as
    /// any new inode in that directory is (see
    /// `SimulatedUnixPlatform.newInodeGroupRule`); the directory's modification and
    /// status-change times move.
    ///
    /// Refuses a pathname this kernel will not resolve, and a call that would
    /// create a link with an empty target, which this library does not
    /// represent.
    let symlinkWithPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (paused : PausedSymlink<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySymlinkWithPath path paused
        |> Refusal.orRaise "UnixNamespace.symlinkWithPath" SymlinkRefusal.kind SymlinkRefusal.describe

    let private linkSourceFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (arguments : AtFlagArguments)
        (source : AtDirectory)
        (destination : AtDirectory)
        (path : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              LinkRefusal
           >
        =
        let rules = SimulatedUnixPlatform.linkRules system.Machine.UnixPlatform
        let vfs = system.Machine.FileSystem

        // Measured by `link-rules.c` (ORDER, DESTORDER, EMPTY) and `at-dirfd.c`
        // (ORDER2) on Linux 6.18.5 and Darwin 27.0: the source is copied in and
        // resolved completely, its final lookup included, before the new
        // pathname is copied in, on both flavours.
        match UnixPathResolution.copyIn path system with
        | Error error -> Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))
        | Ok path ->

        let namesStartingPoint =
            UnixPath.isEmpty path
            && arguments.EmptyPath = EmptyPathMeaning.NamesStartingPoint

        // Measured by `link-empty-path.c` (CRED) on Linux 6.18.5: with
        // `AT_EMPTY_PATH`, a path relative to a descriptor, empty or not, is
        // checked against the descriptor's open-time credentials, unless the
        // caller is privileged. `AT_FDCWD` and a rooted path are not.
        let relativeToDescriptor =
            match source with
            | AtDirectory.Descriptor _ -> not (UnixPath.isRooted path)
            | AtDirectory.CurrentDirectory -> false

        let privileged =
            Credentials.privilege system.Process.Credentials = CallerPrivilege.Privileged

        if
            arguments.EmptyPath = EmptyPathMeaning.NamesStartingPoint
            && relativeToDescriptor
            && not privileged
        then
            Error LinkRefusal.OpenTimeCredentials
        else

        let resolved : Result<Result<InodeNumber, UnixError>, LinkRefusal> =
            if namesStartingPoint then
                match UnixPathResolution.startOf source arguments.EmptyPath path system with
                | Error (PathFailure.Errno error) -> Ok (Error error)
                | Error (PathFailure.Refused refusal) -> Error (LinkRefusal.Path refusal)
                | Ok (PathStart.StartingObject inode) ->
                    // An unlinked regular file goes on: `LinkRules.verdict`
                    // answers it once the destination has been looked at.
                    match (VirtualFileSystem.get "UnixNamespace.linkat" inode vfs).Content with
                    | InodeContent.Directory _ when VirtualFileSystem.isOrphanedDirectory inode vfs ->
                        Error (LinkRefusal.NamelessSource inode)
                    | _ -> Ok (Ok inode)
                | Ok (PathStart.Walk _) ->
                    failwith
                        "UnixNamespace.linkat: an empty path naming its starting point walked instead (this is a bug in this library)."
            else
                match
                    UnixPathResolution.resolvePathFull
                        source
                        arguments.FinalSymlink
                        TrailingSeparatorPolicy.Demand
                        path
                        system
                with
                | Error (PathFailure.Errno error) -> Ok (Error error)
                | Error (PathFailure.Refused refusal) -> Error (LinkRefusal.Path refusal)
                | Ok resolution -> Ok (PathWalk.existingOf resolution.Target)

        match resolved with
        | Error refusal -> Error refusal
        | Ok (Error error) -> Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))
        | Ok (Ok inode) ->

        match UnixMachineState.fileSystemTypeOf inode system.Machine with
        | EmulatedFileSystemType.Nfs -> Error (LinkRefusal.UnmeasuredFileSystem EmulatedFileSystemType.Nfs)
        | EmulatedFileSystemType.Tmpfs
        | EmulatedFileSystemType.Apfs ->

        let isDirectory =
            match VirtualFileSystem.tryGetContent inode vfs with
            | Some (InodeContent.Directory _) -> true
            | Some _
            | None -> false

        match rules.DirectorySource with
        | DirectorySourceRefusal.BeforeDestination when isDirectory ->
            Ok (CallProgress.Answered (SyscallAnswer.Failed UnixError.EPERM, system))
        | DirectorySourceRefusal.BeforeDestination
        | DirectorySourceRefusal.Last ->
            Ok (
                CallProgress.NeedsCopyIn
                    {
                        System = system
                        Rules = rules
                        Source = inode
                        Destination = destination
                    }
            )

    /// `tryLinkat` once `Entry` has admitted its caller.
    let private tryLinkatIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              LinkRefusal
           >
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        match AtFlags.screen flavour (AtFlagRules.linkat flavour) flags with
        | AtFlagScreen.Failed error -> Ok (CallProgress.Answered (SyscallAnswer.Failed error, system))
        | AtFlagScreen.Unmodelled refused -> Error (LinkRefusal.UnmodelledFlags refused)
        | AtFlagScreen.Screened arguments ->
            linkSourceFrom
                arguments
                (AtDirectory.decode flavour olddirfd)
                (AtDirectory.decode flavour newdirfd)
                oldpath
                system

    /// `linkat`, with a refusal answered as the `Error` rather than raised.
    let internal tryLinkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>, LinkRefusal>
        =
        Entry.call
            "UnixNamespace.linkat"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryLinkatIn olddirfd oldpath newdirfd flags)
            system

    /// <summary>
    /// `linkat(2)`: give the inode `oldpath` names, relative to `olddirfd`, a
    /// further name, relative to `newdirfd`.
    /// </summary>
    /// <remarks>
    /// `olddirfd`, `newdirfd` and `flags` are raw, in this platform's own
    /// numbering. The flag word is screened before either pathname is copied
    /// in: Linux answers EINVAL for any flag beyond `AT_SYMLINK_FOLLOW` (0x400)
    /// and `AT_EMPTY_PATH` (0x1000), and Darwin for any beyond
    /// `AT_SYMLINK_FOLLOW` (0x40) and the three it accepts and this library
    /// does not model, which are refused. Then the source is copied in and
    /// resolved. A call that ends there is `CallProgress.Answered`, changing
    /// nothing and never reading the new pathname. Otherwise it stops where
    /// the kernel copies the new pathname in (`PausedLink`), and
    /// `linkWithDestination` finishes it.
    ///
    /// Refuses a path this kernel will not resolve, Linux's `AT_EMPTY_PATH`
    /// where its answer turns on the credentials the descriptor was opened
    /// with, a nameless source, and a source on a filesystem whose rules for
    /// `link(2)` have not been measured.
    /// </remarks>
    let linkat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (olddirfd : int)
        (oldpath : PathArgumentBytes)
        (newdirfd : int)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryLinkat caller olddirfd oldpath newdirfd flags system
        |> Refusal.orRaise "UnixNamespace.linkat" LinkRefusal.kind LinkRefusal.describe

    /// `tryLink` once `Entry` has admitted its caller.
    let private tryLinkIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldpath : PathArgumentBytes)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * ProcessView<'Thread, 'Handler>>,
              LinkRefusal
           >
        =
        let rules = SimulatedUnixPlatform.linkRules system.Machine.UnixPlatform

        linkSourceFrom
            {
                FinalSymlink = rules.PlainLinkSource
                EmptyPath = EmptyPathMeaning.Walked
            }
            AtDirectory.CurrentDirectory
            AtDirectory.CurrentDirectory
            oldpath
            system

    /// `link`, with a refusal answered as the `Error` rather than raised.
    let internal tryLink<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldpath : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>, LinkRefusal>
        =
        Entry.call
            "UnixNamespace.link"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryLinkIn oldpath)
            system

    /// `link(2)`: `linkat` from the current directory on both sides,
    /// following a final symbolic link in the source on Darwin and not on
    /// Linux (`LinkRules.PlainLinkSource`).
    let link<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldpath : PathArgumentBytes)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedLink<'Thread, 'Handler>, SyscallAnswer * UnixSystem<'Thread, 'Handler>>
        =
        tryLink caller oldpath system
        |> Refusal.orRaise "UnixNamespace.link" LinkRefusal.kind LinkRefusal.describe

    /// `tryLinkWithDestination`, before `Entry.resume` hands its answer back.
    let private tryLinkWithDestinationIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (newpath : PathArgumentBytes)
        (paused : PausedLink<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, LinkRefusal>
        =
        CallProgress.requirePaused "UnixNamespace.linkWithDestination" "UnixNamespace.linkat or link" paused

        let system = paused.System

        match UnixPathResolution.copyIn newpath system with
        | Error error -> Ok (SyscallAnswer.Failed error, system)
        | Ok newpath ->

        match
            UnixPathResolution.resolvePathFull
                paused.Destination
                SymlinkPolicy.NoFollowFinal
                (SimulatedUnixPlatform.finalNameTrailingSeparator system.Machine.UnixPlatform)
                newpath
                system
        with
        | Error (PathFailure.Errno error) -> Ok (SyscallAnswer.Failed error, system)
        | Error (PathFailure.Refused refusal) -> Error (LinkRefusal.Path refusal)
        | Ok resolution ->

        match
            LinkRules.verdict
                paused.Rules
                system.Machine.ProtectedFiles.Hardlinks
                (SimulatedUnixPlatform.bindableEntryNames system.Machine.UnixPlatform)
                system.Process.Credentials
                paused.Source
                resolution
                system.Machine.FileSystem
        with
        | LinkVerdict.Refuse error -> Ok (SyscallAnswer.Failed error, system)
        | LinkVerdict.Create (directory, name) ->

        let now = UnixMachineState.realtime system.Scheduling system.Machine

        match VirtualFileSystem.hardLink directory name paused.Source now system.Machine.FileSystem with
        | Error error ->
            failwith
                $"UnixNamespace.link: binding inode %O{paused.Source} as \"%s{DirectoryEntryName.toEscaped name}\" in inode %O{directory} was refused with %O{error}, but the verdict had just established that it may be (this is a bug in this library)."
        | Ok mutation ->

        Ok (
            SyscallAnswer.Completed 0L,
            { system with
                Machine = UnixMachineState.commitFileSystem ChangeNotice.Names mutation system.Machine
            }
        )

    /// `linkWithDestination`, with a refusal answered as the `Error` rather than raised.
    let internal tryLinkWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (newpath : PathArgumentBytes)
        (paused : PausedLink<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, LinkRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryLinkWithDestinationIn newpath paused)

    /// The second half of `link(2)` or `linkat(2)`: copy in `newpath`, and give
    /// the paused call's source that name.
    ///
    /// A relative `newpath` starts where the call's new `dirfd` says; a final
    /// symbolic link is never followed, and a trailing separator reaches past
    /// the final name only as `SimulatedUnixPlatform.finalNameTrailingSeparator` says. On success
    /// the source gains a
    /// name, its status-change time moves, and so do the new name's
    /// directory's modification and status-change times.
    let linkWithDestination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (newpath : PathArgumentBytes)
        (paused : PausedLink<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryLinkWithDestination newpath paused
        |> Refusal.orRaise "UnixNamespace.linkWithDestination" LinkRefusal.kind LinkRefusal.describe
