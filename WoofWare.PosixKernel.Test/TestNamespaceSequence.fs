namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Random sequences of the path and namespace syscalls, made through their
/// public entry points by one process's leader: creating, linking, renaming
/// and removing names, opening and closing descriptors onto them, moving the
/// current directory, and reading and changing their attributes, with the
/// `*at` forms relative to the descriptors the sequence holds.
///
/// Each sequence starts from a seed holding nested directories, a sticky
/// root-owned directory holding another user's file and directory, and
/// symbolic links to a directory, to nothing and to the root, under three
/// configurations: Linux as an ordinary user, Linux as root, and Darwin. The
/// names the paths are made of include those, the dots, `dev` (the device
/// filesystem's mount point) and `null`.
///
/// After every call: no exception but `UnmodelledException` escaped it, and
/// every invariant holds: the system's own, its descriptor table's and its
/// filesystem's.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestNamespaceSequence =

    /// Who the sequence runs as, on which flavour.
    [<RequireQualifiedAccess>]
    type private Configuration =
        | LinuxUser
        | LinuxRoot
        | Darwin

    let private platformOf (configuration : Configuration) : SimulatedUnixPlatform =
        match configuration with
        | Configuration.LinuxUser
        | Configuration.LinuxRoot -> SimulatedUnixPlatform.linuxX64
        | Configuration.Darwin -> SimulatedUnixPlatform.macOsArm64

    /// A descriptor argument.
    [<RequireQualifiedAccess>]
    type private Fd =
        /// The descriptor the sequence holds in this slot. An empty slot is
        /// `AT_FDCWD` for a `dirfd`, and makes any other call a no-op.
        | Slot of slot : int
        | AtFdCwd

    /// The flag word of an `open(2)`.
    [<RequireQualifiedAccess>]
    type private OpenVariant =
        | ReadOnly
        /// `O_WRONLY | O_CREAT`.
        | Create
        /// `O_WRONLY | O_CREAT | O_EXCL`.
        | CreateExclusive
        /// `O_RDONLY | O_DIRECTORY`.
        | Directory
        /// `O_RDWR | O_TRUNC`.
        | Truncate
        /// `O_RDONLY | O_NOFOLLOW`.
        | NoFollow

    /// The owner a `chown(2)` asks for.
    [<RequireQualifiedAccess>]
    type private OwnerChoice =
        /// -1 for both IDs.
        | Unchanged
        /// The caller's own user and group.
        | Caller
        /// Another user's user and group.
        | Other
        /// Another user's group, the user unchanged.
        | OtherGroup

    /// One call. Every flag word is raw, in the configuration's flavour's
    /// numbering.
    [<RequireQualifiedAccess>]
    type private Op =
        | MkDir of path : string * mode : int
        | MkDirAt of dir : Fd * path : string * mode : int
        /// `mknod(2)` of a regular file.
        | MkNod of path : string
        | RmDir of path : string
        | Unlink of path : string
        | UnlinkAt of dir : Fd * path : string * flags : int
        | Rename of source : string * destination : string
        | RenameAt of sourceDir : Fd * source : string * destinationDir : Fd * destination : string
        | Link of source : string * destination : string
        | LinkAt of sourceDir : Fd * source : string * destinationDir : Fd * destination : string * flags : int
        | Symlink of target : string * path : string
        | SymlinkAt of target : string * dir : Fd * path : string
        /// Darwin's `clonefile(2)`.
        | CloneFile of source : string * destination : string * flags : int
        | ChDir of path : string
        /// An `open(2)`, whose descriptor goes in the first empty slot (and
        /// is closed again if there is none).
        | Open of path : string * flags : OpenVariant
        | OpenAt of dir : Fd * path : string * flags : OpenVariant
        /// A `dup(2)`, whose descriptor goes where `Open`'s does.
        | Dup of fd : Fd
        /// A `pipe(2)`, whose two descriptors go where `Open`'s does.
        | Pipe
        /// A `close(2)` of the slot's descriptor, which empties the slot.
        | Close of slot : int
        | Stat of path : string * follow : bool
        | FStat of fd : Fd
        | FStatAt of dir : Fd * path : string * flags : int
        /// A `getdents(2)` of one entry.
        | ReadDir of fd : Fd
        | Getcwd
        | Chmod of path : string * mode : int
        | FChmod of fd : Fd * mode : int
        | FChmodAt of dir : Fd * path : string * mode : int * flags : int
        | FChown of fd : Fd * owner : OwnerChoice
        | FChownAt of dir : Fd * path : string * owner : OwnerChoice * flags : int
        /// A `utimensat(2)` setting both times to now: of `path`, or of
        /// `dir` itself where `path` is the null pointer.
        | UTimensAt of dir : Fd * path : string option * flags : int
        | FAccessAt of dir : Fd * path : string * mode : int * flags : int

    let private slots : int = 6

    /// The name each kind of call is counted under.
    let private kindOf (op : Op) : string =
        match op with
        | Op.MkDir _ -> "mkdir"
        | Op.MkDirAt _ -> "mkdirat"
        | Op.MkNod _ -> "mknod"
        | Op.RmDir _ -> "rmdir"
        | Op.Unlink _ -> "unlink"
        | Op.UnlinkAt _ -> "unlinkat"
        | Op.Rename _ -> "rename"
        | Op.RenameAt _ -> "renameat"
        | Op.Link _ -> "link"
        | Op.LinkAt (_, source, _, _, _) when source = "" -> "linkat empty"
        | Op.LinkAt _ -> "linkat"
        | Op.Symlink _ -> "symlink"
        | Op.SymlinkAt _ -> "symlinkat"
        | Op.CloneFile _ -> "clonefile"
        | Op.ChDir _ -> "chdir"
        | Op.Open _ -> "open"
        | Op.OpenAt _ -> "openat"
        | Op.Dup _ -> "dup"
        | Op.Pipe -> "pipe"
        | Op.Close _ -> "close"
        | Op.Stat _ -> "stat"
        | Op.FStat _ -> "fstat"
        | Op.FStatAt (_, path, _) when path = "" -> "fstatat empty"
        | Op.FStatAt _ -> "fstatat"
        | Op.ReadDir _ -> "getdents"
        | Op.Getcwd -> "getcwd"
        | Op.Chmod _ -> "chmod"
        | Op.FChmod _ -> "fchmod"
        | Op.FChmodAt (_, path, _, _) when path = "" -> "fchmodat empty"
        | Op.FChmodAt _ -> "fchmodat"
        | Op.FChown _ -> "fchown"
        | Op.FChownAt (_, path, _, _) when path = "" -> "fchownat empty"
        | Op.FChownAt _ -> "fchownat"
        | Op.UTimensAt (_, None, _) -> "utimensat null"
        | Op.UTimensAt (_, Some "", _) -> "utimensat empty"
        | Op.UTimensAt _ -> "utimensat"
        | Op.FAccessAt _ -> "faccessat"

    /// What one call answered.
    [<RequireQualifiedAccess>]
    type private Outcome =
        | Answered of SyscallAnswer
        | Status of FileStatusAnswer
        | Directory of ReadDirectoryAnswer
        | WorkingDirectory of GetCwdAnswer
        /// The call threw `UnmodelledException`.
        | Unmodelled
        /// The call named an empty slot, and was not made.
        | Skipped

    /// What the property counts over its fixed sample.
    [<RequireQualifiedAccess>]
    type private Label =
        | Succeeded of call : string
        | Failed of call : string * error : UnixError
        | Unmodelled of call : string
        /// After the call, an inode no name reaches is still held: a
        /// directory or not.
        | OrphanHeld of directory : bool
        /// After the call, the current directory is one no name reaches.
        | CurrentDirectoryOrphaned
        /// After the call, a file other than a directory has two names or
        /// more.
        | HardLinked
        /// The call freed an inode, which the sequence had made or found.
        | Freed of call : string

    // `<fcntl.h>`'s AT_* bits, as each flavour numbers them.
    let private linuxAtSymlinkNoFollow : int = 0x100
    let private linuxAtRemoveDir : int = 0x200
    let private linuxAtSymlinkFollow : int = 0x400
    let private linuxAtEmptyPath : int = 0x1000
    let private darwinAtSymlinkNoFollow : int = 0x20
    let private darwinAtSymlinkFollow : int = 0x40
    let private darwinAtRemoveDir : int = 0x80

    let private atRemoveDir (configuration : Configuration) : int =
        match configuration with
        | Configuration.LinuxUser
        | Configuration.LinuxRoot -> linuxAtRemoveDir
        | Configuration.Darwin -> darwinAtRemoveDir

    let private atSymlinkFollow (configuration : Configuration) : int =
        match configuration with
        | Configuration.LinuxUser
        | Configuration.LinuxRoot -> linuxAtSymlinkFollow
        | Configuration.Darwin -> darwinAtSymlinkFollow

    let private atSymlinkNoFollow (configuration : Configuration) : int =
        match configuration with
        | Configuration.LinuxUser
        | Configuration.LinuxRoot -> linuxAtSymlinkNoFollow
        | Configuration.Darwin -> darwinAtSymlinkNoFollow

    /// Every bit an `*at` call's flag word is drawn from: each flavour's
    /// defined `AT_*` bits, the ones this library refuses as unmodelled among
    /// them, and a bit no flavour defines.
    let private atFlagBits (configuration : Configuration) : int list =
        match configuration with
        | Configuration.LinuxUser
        | Configuration.LinuxRoot ->
            // AT_SYMLINK_NOFOLLOW, AT_REMOVEDIR (AT_EACCESS), AT_SYMLINK_FOLLOW,
            // AT_NO_AUTOMOUNT, AT_EMPTY_PATH, AT_STATX_FORCE_SYNC,
            // AT_STATX_DONT_SYNC, AT_RECURSIVE.
            [ 0x100 ; 0x200 ; 0x400 ; 0x800 ; 0x1000 ; 0x2000 ; 0x4000 ; 0x8000 ; 0x1 ]
        | Configuration.Darwin ->
            // AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_SYMLINK_FOLLOW, AT_REMOVEDIR,
            // a bit the SDK does not name, AT_REALDEV, AT_FDONLY,
            // AT_SYMLINK_NOFOLLOW_ANY, another unnamed bit,
            // AT_RESOLVE_BENEATH, AT_NODELETEBUSY, AT_UNIQUE.
            [
                0x10
                0x20
                0x40
                0x80
                0x100
                0x200
                0x400
                0x800
                0x1000
                0x2000
                0x4000
                0x8000
                0x1
            ]

    /// An `*at` call's flag word: mostly none or `favoured`, sometimes one or
    /// two of any of the flavour's bits.
    let private atFlags (configuration : Configuration) (favoured : int list) : Gen<int> =
        let bits = atFlagBits configuration

        Gen.frequency
            [
                yield 4, Gen.constant 0
                if not favoured.IsEmpty then
                    yield 4, Gen.elements favoured
                yield 2, Gen.elements bits
                yield 1, Gen.map2 (|||) (Gen.elements bits) (Gen.elements bits)
            ]

    /// The names paths are made of, each weighted: most of what the seed
    /// holds, names it does not, the dots, and the device filesystem's.
    let private names : (int * string) list =
        [
            3, "a"
            2, "b"
            3, "c"
            3, "f"
            3, "x"
            2, "y"
            1, "la"
            1, "dang"
            1, "lroot"
            2, "t"
            2, "o"
            1, "dev"
            1, "null"
            1, "."
            1, ".."
        ]

    let private pathGen : Gen<string> =
        gen {
            let! rooted = Gen.frequency [ 1, Gen.constant true ; 4, Gen.constant false ]
            let! length = Gen.frequency [ 5, Gen.constant 1 ; 3, Gen.constant 2 ; 1, Gen.constant 3 ]

            let! components =
                Gen.listOfLength
                    length
                    (names
                     |> List.map (fun (weight, name) -> weight, Gen.constant name)
                     |> Gen.frequency)

            let! trailing = Gen.frequency [ 1, Gen.constant true ; 5, Gen.constant false ]
            let body = String.concat "/" components
            let body = if rooted then "/" + body else body
            return if trailing then body + "/" else body
        }

    /// A path that most often names something the seed or an opening binds.
    let private boundPathGen : Gen<string> =
        Gen.frequency
            [
                2, pathGen
                3,
                Gen.elements
                    [
                        "f"
                        "a/f"
                        "t/o"
                        "x"
                        "a/x"
                        "la"
                        "dang"
                        "a"
                        "c"
                        "a/b"
                        "t/b"
                        "/"
                        ".."
                        "/dev/null"
                    ]
            ]

    /// A path that most often names nothing yet, in a directory a sequence
    /// can usually write.
    let private freePathGen : Gen<string> =
        Gen.frequency
            [
                2, pathGen
                3, Gen.elements [ "x" ; "y" ; "a/x" ; "a/y" ; "c/x" ; "t/x" ; "la/y" ]
            ]

    /// A path for an `*at` call, which is sometimes empty.
    let private atPathGen : Gen<string> =
        Gen.frequency [ 6, pathGen ; 1, Gen.constant "" ]

    let private slotGen : Gen<int> = Gen.choose (0, slots - 1)

    /// A `dirfd`.
    let private fdGen : Gen<Fd> =
        Gen.frequency [ 3, Gen.map Fd.Slot slotGen ; 1, Gen.constant Fd.AtFdCwd ]

    let private openVariantGen : Gen<OpenVariant> =
        Gen.elements
            [
                OpenVariant.ReadOnly
                OpenVariant.Create
                OpenVariant.CreateExclusive
                OpenVariant.Directory
                OpenVariant.Truncate
                OpenVariant.NoFollow
            ]

    /// Modes that tell the owner, group and other classes apart, besides the
    /// usual ones.
    let private modeGen : Gen<int> =
        Gen.elements [ 0o755 ; 0o555 ; 0o1777 ; 0o700 ; 0o677 ; 0o500 ; 0o644 ; 0o000 ]

    let private ownerGen : Gen<OwnerChoice> =
        Gen.elements
            [
                OwnerChoice.Unchanged
                OwnerChoice.Caller
                OwnerChoice.Other
                OwnerChoice.OtherGroup
            ]

    let private opGen (configuration : Configuration) : Gen<Op> =
        let flags (favoured : int list) : Gen<int> = atFlags configuration favoured

        let noFollow = [ atSymlinkNoFollow configuration ]

        let emptyPath =
            match configuration with
            | Configuration.LinuxUser
            | Configuration.LinuxRoot -> [ linuxAtEmptyPath ; linuxAtEmptyPath ||| linuxAtSymlinkNoFollow ]
            | Configuration.Darwin -> []

        // A rename's or a link's destination: as often bound as free.
        let destinationGen = Gen.oneof [ boundPathGen ; freePathGen ]

        // Linux's `linkat(fd, "", AT_FDCWD, path, AT_EMPTY_PATH)`, giving what
        // a held descriptor names a new name, which the general `LinkAt`
        // seldom asks. Only root: an ordinary user's is refused, since its
        // answer turns on the credentials the descriptor was opened with.
        let linkDescriptor =
            match configuration with
            | Configuration.LinuxRoot ->
                [
                    2,
                    Gen.map2 (fun s d -> Op.LinkAt (Fd.Slot s, "", Fd.AtFdCwd, d, linuxAtEmptyPath)) slotGen freePathGen
                ]
            | Configuration.LinuxUser
            | Configuration.Darwin -> []

        let cloneFile =
            match configuration with
            | Configuration.Darwin ->
                // CLONE_NOFOLLOW (unmodelled), CLONE_NOOWNERCOPY, CLONE_ACL.
                [
                    2,
                    Gen.map3
                        (fun s d f -> Op.CloneFile (s, d, f))
                        boundPathGen
                        destinationGen
                        (Gen.elements [ 0 ; 0 ; 0 ; 0x2 ; 0x4 ; 0x1 ])
                ]
            | Configuration.LinuxUser
            | Configuration.LinuxRoot -> []

        Gen.frequency
            [
                yield 3, Gen.map2 (fun p m -> Op.MkDir (p, m)) freePathGen modeGen
                yield 2, Gen.map3 (fun d p m -> Op.MkDirAt (d, p, m)) fdGen freePathGen modeGen
                yield 1, Gen.map Op.MkNod freePathGen
                yield 3, Gen.map Op.RmDir boundPathGen
                yield 3, Gen.map Op.Unlink boundPathGen
                yield
                    3,
                    Gen.map3
                        (fun d p f -> Op.UnlinkAt (d, p, f))
                        fdGen
                        boundPathGen
                        (Gen.frequency
                            [
                                3, Gen.constant 0
                                3, Gen.constant (atRemoveDir configuration)
                                1, flags []
                            ])
                yield 4, Gen.map2 (fun s d -> Op.Rename (s, d)) boundPathGen destinationGen
                yield
                    3,
                    gen {
                        let! sourceDir = fdGen
                        let! source = boundPathGen
                        let! destinationDir = fdGen
                        let! destination = destinationGen
                        return Op.RenameAt (sourceDir, source, destinationDir, destination)
                    }
                yield 3, Gen.map2 (fun s d -> Op.Link (s, d)) boundPathGen destinationGen
                yield
                    3,
                    gen {
                        let! sourceDir = fdGen
                        let! source = Gen.frequency [ 4, boundPathGen ; 1, Gen.constant "" ]
                        let! destinationDir = fdGen
                        let! destination = destinationGen
                        let! flags = flags (atSymlinkFollow configuration :: emptyPath)
                        return Op.LinkAt (sourceDir, source, destinationDir, destination, flags)
                    }
                yield 2, Gen.map2 (fun t p -> Op.Symlink (t, p)) pathGen freePathGen
                yield 1, Gen.map3 (fun t d p -> Op.SymlinkAt (t, d, p)) pathGen fdGen freePathGen
                yield! linkDescriptor
                yield! cloneFile
                yield 3, Gen.map Op.ChDir boundPathGen
                yield 4, Gen.map2 (fun p v -> Op.Open (p, v)) boundPathGen openVariantGen
                yield 3, Gen.map3 (fun d p v -> Op.OpenAt (d, p, v)) fdGen pathGen openVariantGen
                yield 1, Gen.map (Fd.Slot >> Op.Dup) slotGen
                yield 1, Gen.constant Op.Pipe
                yield 3, Gen.map Op.Close slotGen
                yield 1, Gen.map2 (fun p f -> Op.Stat (p, f)) pathGen (Gen.elements [ true ; false ])
                yield 2, Gen.map (Fd.Slot >> Op.FStat) slotGen
                yield 2, Gen.map3 (fun d p f -> Op.FStatAt (d, p, f)) fdGen atPathGen (flags (noFollow @ emptyPath))
                yield 2, Gen.map (Fd.Slot >> Op.ReadDir) slotGen
                yield 1, Gen.constant Op.Getcwd
                yield 2, Gen.map2 (fun p m -> Op.Chmod (p, m)) pathGen modeGen
                yield 1, Gen.map2 (fun d m -> Op.FChmod (Fd.Slot d, m)) slotGen modeGen
                yield
                    2,
                    gen {
                        let! dir = fdGen
                        let! path = atPathGen
                        let! mode = modeGen
                        let! flags = flags (noFollow @ emptyPath)
                        return Op.FChmodAt (dir, path, mode, flags)
                    }
                yield 1, Gen.map2 (fun d o -> Op.FChown (Fd.Slot d, o)) slotGen ownerGen
                yield
                    2,
                    gen {
                        let! dir = fdGen
                        let! path = atPathGen
                        let! owner = ownerGen
                        let! flags = flags (noFollow @ emptyPath)
                        return Op.FChownAt (dir, path, owner, flags)
                    }
                yield
                    2,
                    Gen.map3
                        (fun d p f -> Op.UTimensAt (d, p, f))
                        fdGen
                        (Gen.frequency [ 1, Gen.constant None ; 6, Gen.map Some atPathGen ])
                        (flags (noFollow @ emptyPath))
                yield
                    1,
                    gen {
                        let! dir = fdGen
                        let! path = pathGen
                        // F_OK, R_OK, W_OK, X_OK, R_OK|W_OK.
                        let! mode = Gen.elements [ 0 ; 4 ; 2 ; 1 ; 6 ]
                        let! flags = flags noFollow
                        return Op.FAccessAt (dir, path, mode, flags)
                    }
            ]

    /// Beginnings that reach states a sequence of random calls seldom does,
    /// for the rest of the sequence to act in.
    let private openings (configuration : Configuration) : Op list list =
        // Root's `linkat(fd, "", AT_FDCWD, "y", AT_EMPTY_PATH)` of an open
        // file succeeds; the ordinary user's is refused, and Darwin has no
        // AT_EMPTY_PATH.
        let linkDescriptor =
            match configuration with
            | Configuration.LinuxRoot ->
                [
                    Op.Open ("f", OpenVariant.ReadOnly)
                    Op.LinkAt (Fd.Slot 3, "", Fd.AtFdCwd, "y", linuxAtEmptyPath)
                ]
            | Configuration.LinuxUser
            | Configuration.Darwin -> []

        [
            []
            // The current directory is one no name reaches.
            [ Op.MkDir ("x", 0o755) ; Op.ChDir "x" ; Op.RmDir "../x" ]
            // A descriptor holds a file no name reaches, and another a
            // directory no name reaches.
            [
                Op.Open ("a/f", OpenVariant.ReadOnly)
                Op.Unlink "a/f"
                Op.Open ("c", OpenVariant.Directory)
                Op.RmDir "c"
            ]
            // A descriptor holds a file no name reaches, and so the directory
            // its name was in, which no name reaches either.
            [ Op.Open ("c/x", OpenVariant.Create) ; Op.Unlink "c/x" ; Op.RmDir "c" ]
            // A file has two names, a descriptor holds the directory holding
            // one of them, and two more hold a pipe's ends.
            [ Op.Link ("f", "a/x") ; Op.Open ("a", OpenVariant.Directory) ; Op.Pipe ]
            @ linkDescriptor
        ]

    let private caseGen (configuration : Configuration) : Gen<Op list> =
        gen {
            let! opening = Gen.elements (openings configuration)
            let! length = Gen.choose (1, 60)
            let! ops = Gen.listOfLength length (opGen configuration)
            return opening @ ops
        }

    /// A list's one-shorter sublists, so that a failing sequence shrinks to
    /// the calls its failure needs.
    let private shrinkCase (ops : Op list) : Op list seq =
        Seq.init ops.Length (fun dropped -> List.removeAt dropped ops)

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail "TestNamespaceSequence" text

    let private otherUser : InodeOwner =
        {
            User = UserId.parseOrFail "TestNamespaceSequence" 4242u
            Group = GroupId.parseOrFail "TestNamespaceSequence" 4242u
        }

    let private rootGroup : GroupId = GroupId.parseOrFail "TestNamespaceSequence" 0u

    let private seed : Map<DirectoryEntryName, SeedEntry> =
        Map.ofList
            [
                name "a",
                SeedEntry.directory (
                    Map.ofList
                        [
                            name "b", SeedEntry.directory Map.empty
                            name "f", SeedEntry.file ImmutableArray<byte>.Empty
                        ]
                )
                name "c", SeedEntry.directory Map.empty
                name "f", SeedEntry.file ImmutableArray<byte>.Empty
                name "la", SeedEntry.Symlink (SymlinkTarget.parseOrFail "TestNamespaceSequence" "a", None)
                name "dang", SeedEntry.Symlink (SymlinkTarget.parseOrFail "TestNamespaceSequence" "nx", None)
                name "lroot", SeedEntry.Symlink (SymlinkTarget.parseOrFail "TestNamespaceSequence" "/", None)
                name "t",
                SeedEntry.Directory (
                    Map.ofList
                        [
                            name "o",
                            SeedEntry.File (
                                ImmutableArray<byte>.Empty,
                                PermissionBits.parseOrFail "TestNamespaceSequence" 0o666,
                                Some otherUser
                            )
                            name "b",
                            SeedEntry.Directory (
                                Map.empty,
                                PermissionBits.parseOrFail "TestNamespaceSequence" 0o777,
                                Some otherUser
                            )
                        ],
                    PermissionBits.parseOrFail "TestNamespaceSequence" 0o1777,
                    Some
                        {
                            User = UserId.root
                            Group = rootGroup
                        }
                )
            ]

    let private boot (configuration : Configuration) : UnixSystem<int, string> =
        let platform = platformOf configuration
        let flavour = SimulatedUnixPlatform.flavour platform

        let credentials (launch : ProcessLaunch<int>) : ProcessLaunch<int> =
            match configuration with
            | Configuration.LinuxRoot -> Launched.credentials (Credentials.ofIds UserId.root rootGroup []) launch
            | Configuration.LinuxUser
            | Configuration.Darwin -> launch

        UnixSystem.initial<int, string> platform
        |> Launched.fileSystem
            (UnixTimestamp.ofMillisecondsSinceEpoch 0L)
            {
                User = UnixSystem.defaultUserId flavour
                Group = UnixSystem.defaultGroupId flavour
            }
            seed
        |> Launched.bootWith credentials UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private openFlags (platform : SimulatedUnixPlatform) (variant : OpenVariant) : int =
        let bit (meaning : OpenFlagBit) : int = OpenFlagWords.bitOf platform meaning

        match variant with
        | OpenVariant.ReadOnly -> 0
        | OpenVariant.Create -> 1 ||| bit OpenFlagBit.Create
        | OpenVariant.CreateExclusive -> 1 ||| bit OpenFlagBit.Create ||| bit OpenFlagBit.Exclusive
        | OpenVariant.Directory -> bit OpenFlagBit.Directory
        | OpenVariant.Truncate -> 2 ||| bit OpenFlagBit.Truncate
        | OpenVariant.NoFollow -> bit OpenFlagBit.NoFollow

    /// The system a sequence has reached, and the descriptor it holds in each
    /// slot.
    type private World =
        {
            System : UnixSystem<int, string>
            Slots : Map<int, int>
        }

    let private arg : string -> PathArgumentBytes = PathArg.ofText

    /// Makes `op` in `world`, which `configuration` booted.
    let private apply (configuration : Configuration) (world : World) (op : Op) : Outcome * World =
        let system = world.System
        let platform = platformOf configuration
        let flavour = SimulatedUnixPlatform.flavour platform
        let atFdCwd = AtDirectory.atFdCwd flavour

        let dirfd (fd : Fd) : int =
            match fd with
            | Fd.Slot slot -> Map.tryFind slot world.Slots |> Option.defaultValue atFdCwd
            | Fd.AtFdCwd -> atFdCwd

        let descriptor (fd : Fd) : int option =
            match fd with
            | Fd.Slot slot -> Map.tryFind slot world.Slots
            | Fd.AtFdCwd -> Some atFdCwd

        let answered (answer : SyscallAnswer, after : UnixSystem<int, string>) : Outcome * World =
            Outcome.Answered answer,
            { world with
                System = after
            }

        let unchanged (outcome : Outcome) : Outcome * World = outcome, world

        let owner (choice : OwnerChoice) : UserId option * GroupId option =
            let credentials = (Lone.proc system).Credentials

            match choice with
            | OwnerChoice.Unchanged -> None, None
            | OwnerChoice.Caller -> Some credentials.EffectiveUser, Some credentials.EffectiveGroup
            | OwnerChoice.Other -> Some otherUser.User, Some otherUser.Group
            | OwnerChoice.OtherGroup -> None, Some otherUser.Group

        /// `world` holding `fd` in its first empty slot, or with `fd`
        /// closed again if there is none.
        let keep (world : World) (fd : int) : World =
            match
                Seq.init slots id
                |> Seq.tryFind (fun slot -> not (Map.containsKey slot world.Slots))
            with
            | Some slot ->
                { world with
                    Slots = Map.add slot fd world.Slots
                }
            | None ->
                { world with
                    System = UnixDescriptor.close (Callers.leader world.System) fd world.System |> snd
                }

        let opened (answer : SyscallAnswer) (after : UnixSystem<int, string>) : Outcome * World =
            let world =
                { world with
                    System = after
                }

            match answer with
            | SyscallAnswer.Failed _ -> Outcome.Answered answer, world
            | SyscallAnswer.Completed fd -> Outcome.Answered answer, keep world (int fd)

        let openOutcome (outcome : SyscallOutcome, after : UnixSystem<int, string>) : Outcome * World =
            match outcome with
            | SyscallOutcome.Answered answer -> opened answer after
            | SyscallOutcome.WouldBlock _
            | SyscallOutcome.Interrupted ->
                failwith $"%A{op} did not return, though the filesystem holds nothing an open can sleep on"

        match op with
        | Op.MkDir (path, mode) -> UnixNamespace.mkdir (Callers.leader system) (arg path) mode system |> answered
        | Op.MkDirAt (dir, path, mode) ->
            UnixNamespace.mkdirat (Callers.leader system) (dirfd dir) (arg path) mode system
            |> answered
        | Op.MkNod path ->
            UnixNamespace.mknod (Callers.leader system) (arg path) 0o100644 0u system
            |> answered
        | Op.RmDir path -> UnixNamespace.rmdir (Callers.leader system) (arg path) system |> answered
        | Op.Unlink path -> UnixNamespace.unlink (Callers.leader system) (arg path) system |> answered
        | Op.UnlinkAt (dir, path, flags) ->
            UnixNamespace.unlinkat (Callers.leader system) (dirfd dir) (arg path) flags system
            |> answered
        | Op.Rename (source, destination) ->
            match UnixNamespace.rename (Callers.leader system) (arg source) system with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused ->
                UnixNamespace.renameWithDestination (arg destination) paused |> answered
        | Op.RenameAt (sourceDir, source, destinationDir, destination) ->
            match
                UnixNamespace.renameat
                    (Callers.leader system)
                    (dirfd sourceDir)
                    (arg source)
                    (dirfd destinationDir)
                    system
            with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused ->
                UnixNamespace.renameWithDestination (arg destination) paused |> answered
        | Op.Link (source, destination) ->
            match UnixNamespace.link (Callers.leader system) (arg source) system with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused -> UnixNamespace.linkWithDestination (arg destination) paused |> answered
        | Op.LinkAt (sourceDir, source, destinationDir, destination, flags) ->
            match
                UnixNamespace.linkat
                    (Callers.leader system)
                    (dirfd sourceDir)
                    (arg source)
                    (dirfd destinationDir)
                    flags
                    system
            with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused -> UnixNamespace.linkWithDestination (arg destination) paused |> answered
        | Op.Symlink (target, path) ->
            match UnixNamespace.symlink (Callers.leader system) (arg target) system with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused -> UnixNamespace.symlinkWithPath (arg path) paused |> answered
        | Op.SymlinkAt (target, dir, path) ->
            match UnixNamespace.symlinkat (Callers.leader system) (arg target) (dirfd dir) system with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused -> UnixNamespace.symlinkWithPath (arg path) paused |> answered
        | Op.CloneFile (source, destination, flags) ->
            match UnixNamespace.cloneFile (Callers.leader system) flags system with
            | CallProgress.Answered answer -> answered answer
            | CallProgress.NeedsCopyIn paused ->
                match UnixNamespace.cloneFileWithSource (arg source) paused with
                | CallProgress.Answered answer -> answered answer
                | CallProgress.NeedsCopyIn paused ->
                    UnixNamespace.cloneFileWithDestination (arg destination) paused |> answered
        | Op.ChDir path -> UnixPathResolution.chdir (Callers.leader system) (arg path) system |> answered
        | Op.Open (path, variant) ->
            UnixNamespace.openPath (Callers.leader system) (openFlags platform variant) (arg path) 0o644 system
            |> openOutcome
        | Op.OpenAt (dir, path, variant) ->
            UnixNamespace.openat
                (Callers.leader system)
                (dirfd dir)
                (arg path)
                (openFlags platform variant)
                0o644
                system
            |> openOutcome
        | Op.Dup fd ->
            match descriptor fd with
            | None -> unchanged Outcome.Skipped
            | Some fd -> UnixDescriptor.dup (Callers.leader system) fd system ||> opened
        | Op.Pipe ->
            match UnixPipe.pipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
            | Pipe2Answer.Failed error, after ->
                Outcome.Answered (SyscallAnswer.Failed error),
                { world with
                    System = after
                }
            | Pipe2Answer.Created (readFd, writeFd), after ->
                let world =
                    { world with
                        System = after
                    }

                Outcome.Answered (SyscallAnswer.Completed 0L), keep (keep world readFd) writeFd
        | Op.Close slot ->
            match Map.tryFind slot world.Slots with
            | None -> unchanged Outcome.Skipped
            | Some fd ->
                let answer, after = UnixDescriptor.close (Callers.leader system) fd system

                Outcome.Answered answer,
                {
                    System = after
                    Slots = Map.remove slot world.Slots
                }
        | Op.Stat (path, follow) ->
            let policy =
                if follow then
                    SymlinkPolicy.Follow
                else
                    SymlinkPolicy.NoFollowFinal

            UnixPathResolution.stat (Callers.leader system) policy (arg path) system
            |> Outcome.Status
            |> unchanged
        | Op.FStat fd ->
            match descriptor fd with
            | None -> unchanged Outcome.Skipped
            | Some fd ->
                UnixPathResolution.fstat (Callers.leader system) fd system
                |> Outcome.Status
                |> unchanged
        | Op.FStatAt (dir, path, flags) ->
            UnixPathResolution.fstatat (Callers.leader system) (dirfd dir) (arg path) flags system
            |> Outcome.Status
            |> unchanged
        | Op.ReadDir fd ->
            match descriptor fd with
            | None -> unchanged Outcome.Skipped
            | Some fd ->
                let answer, after =
                    UnixNamespace.readDirectoryEntry (Callers.leader system) fd system

                Outcome.Directory answer,
                { world with
                    System = after
                }
        | Op.Getcwd ->
            UnixPathResolution.getcwd (Callers.leader system) UserBuffer.Mapped 4096UL system
            |> Outcome.WorkingDirectory
            |> unchanged
        | Op.Chmod (path, mode) ->
            UnixPathResolution.chmod (Callers.leader system) (arg path) mode system
            |> answered
        | Op.FChmod (fd, mode) ->
            match descriptor fd with
            | None -> unchanged Outcome.Skipped
            | Some fd -> UnixPathResolution.fchmod (Callers.leader system) fd mode system |> answered
        | Op.FChmodAt (dir, path, mode, flags) ->
            UnixPathResolution.fchmodat (Callers.leader system) (dirfd dir) (arg path) mode flags system
            |> answered
        | Op.FChown (fd, choice) ->
            match descriptor fd with
            | None -> unchanged Outcome.Skipped
            | Some fd ->
                let user, group = owner choice

                UnixPathResolution.fchown (Callers.leader system) fd user group system
                |> answered
        | Op.FChownAt (dir, path, choice, flags) ->
            let user, group = owner choice

            UnixPathResolution.fchownat (Callers.leader system) (dirfd dir) (arg path) user group flags system
            |> answered
        | Op.UTimensAt (dir, path, flags) ->
            let path =
                match path with
                | None -> NullablePathArgument.Null
                | Some path -> NullablePathArgument.NotNull (arg path)

            UnixPathResolution.utimensat (Callers.leader system) (dirfd dir) path TimesArgument.Null flags system
            |> answered
        | Op.FAccessAt (dir, path, mode, flags) ->
            match UnixPathResolution.faccessat (Callers.leader system) (dirfd dir) mode flags system with
            | CallProgress.Answered answer -> unchanged (Outcome.Answered answer)
            | CallProgress.NeedsCopyIn paused ->
                UnixPathResolution.accessWithPath (arg path) paused
                |> Outcome.Answered
                |> unchanged

    /// Every defect the system's, its descriptor table's and its
    /// filesystem's invariants find.
    let private defects (system : UnixSystem<int, string>) : string list =
        let fileSystem = system.Machine.FileSystem

        (UnixSystem.checkInvariants system |> List.map (sprintf "%A"))
        @ (FileDescriptorRegistry.checkInvariants (UnixSystem.fileDescriptors (Lone.pid system) system)
           |> List.map (sprintf "%A"))
        @ (VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes system) fileSystem
           |> List.map VirtualFileSystemDefect.describe)

    /// The labels `outcome` and the state after it reach.
    let private labels
        (op : Op)
        (outcome : Outcome)
        (before : UnixSystem<int, string>)
        (after : UnixSystem<int, string>)
        : Label list
        =
        let call = kindOf op

        let answer =
            let failedOrSucceeded (error : UnixError option) : Label option =
                match error with
                | Some error -> Some (Label.Failed (call, error))
                | None -> Some (Label.Succeeded call)

            match outcome with
            | Outcome.Answered (SyscallAnswer.Completed _) -> failedOrSucceeded None
            | Outcome.Answered (SyscallAnswer.Failed error) -> failedOrSucceeded (Some error)
            | Outcome.Status (FileStatusAnswer.Reported _) -> failedOrSucceeded None
            | Outcome.Status (FileStatusAnswer.Failed error) -> failedOrSucceeded (Some error)
            | Outcome.Directory (ReadDirectoryAnswer.Entry _)
            | Outcome.Directory ReadDirectoryAnswer.EndOfDirectory -> failedOrSucceeded None
            | Outcome.Directory (ReadDirectoryAnswer.Failed error) -> failedOrSucceeded (Some error)
            | Outcome.WorkingDirectory (GetCwdAnswer.Reported _) -> failedOrSucceeded None
            | Outcome.WorkingDirectory (GetCwdAnswer.Failed error) -> failedOrSucceeded (Some error)
            | Outcome.Unmodelled -> Some (Label.Unmodelled call)
            | Outcome.Skipped -> None

        let fileSystem = after.Machine.FileSystem
        let root = VirtualFileSystem.root fileSystem

        let state =
            VirtualFileSystem.inodes fileSystem
            |> Map.toSeq
            |> Seq.choose (fun (inode, contents) ->
                if inode = root then
                    None
                else

                let isDirectory =
                    match contents.Content with
                    | InodeContent.Directory _ -> true
                    | _ -> false

                match VirtualFileSystem.bindingCount inode fileSystem with
                | 0 -> Some (Label.OrphanHeld isDirectory)
                | 1 -> None
                | _ -> if isDirectory then None else Some Label.HardLinked
            )
            |> Seq.distinct
            |> List.ofSeq

        let cwd =
            if VirtualFileSystem.isOrphanedDirectory (Lone.proc after).CurrentDirectoryInode fileSystem then
                [ Label.CurrentDirectoryOrphaned ]
            else
                []

        let freed =
            let survivors = VirtualFileSystem.inodes fileSystem

            if
                VirtualFileSystem.inodes before.Machine.FileSystem
                |> Map.exists (fun inode _ -> not (Map.containsKey inode survivors))
            then
                [ Label.Freed call ]
            else
                []

        Option.toList answer @ state @ cwd @ freed

    let private run (configuration : Configuration) (cover : Label -> unit) (ops : Op list) : unit =
        let initial =
            {
                System = boot configuration
                Slots = Map.empty
            }

        match defects initial.System with
        | [] -> ()
        | found -> failwith $"the booted system has defects: %A{found}"

        ops
        |> List.mapi (fun index op -> index, op)
        |> List.fold
            (fun (world : World) (index, op) ->
                let made () : string =
                    $"after %A{List.take (index + 1) ops} on %A{configuration}"

                let outcome, after =
                    try
                        apply configuration world op
                    with
                    | :? UnmodelledException -> Outcome.Unmodelled, world
                    | e -> raise (Exception ($"%s{made ()}, %s{e.GetType().Name}: %s{e.Message}", e))

                for label in labels op outcome world.System after.System do
                    cover label

                match defects after.System with
                | [] -> ()
                | found -> failwith $"%s{made ()}: %A{found}"

                after
            )
            initial
        |> ignore

    /// How many sequences each configuration checks, over the fixed sample
    /// and again over fresh ones: `POSIXKERNEL_NAMESPACE_SEQUENCES`, or 200.
    let private sequences () : int =
        match Environment.GetEnvironmentVariable "POSIXKERNEL_NAMESPACE_SEQUENCES" with
        | null
        | "" -> 200
        | count -> int count

    let private check (configuration : Configuration) : Coverage<Label> =
        let arbitrary = Arb.fromGenShrink (caseGen configuration, shrinkCase)

        CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest (sequences ())) arbitrary (run configuration)

    /// Fails unless the fixed sample reached each label at least as often as
    /// its floor says, naming every label that fell short; and unless at most
    /// one call in ten was refused as unmodelled, since a refused call tests
    /// nothing.
    let private reaches (coverage : Coverage<Label>) (floors : (Label * int) list) : unit =
        let short =
            floors
            |> List.filter (fun (label, floor) -> coverage.Count label < floor)
            |> List.map (fun (label, floor) -> $"%A{label} %d{coverage.Count label} times, under %d{floor}")

        if not short.IsEmpty then
            let short = String.concat "; " short
            failwith $"the fixed sample reached %s{short}"

        let calls, unmodelled =
            coverage.Reached
            |> List.fold
                (fun (calls, unmodelled) (label, count) ->
                    match label with
                    | Label.Succeeded _
                    | Label.Failed _ -> calls + count, unmodelled
                    | Label.Unmodelled _ -> calls + count, unmodelled + count
                    | Label.OrphanHeld _
                    | Label.CurrentDirectoryOrphaned
                    | Label.HardLinked
                    | Label.Freed _ -> calls, unmodelled
                )
                (0, 0)

        unmodelled * 10 |> shouldBeSmallerThan calls

    /// The floors every configuration shares: a third of what the fixed
    /// sample reached when they were set.
    let private sharedFloors : (Label * int) list =
        [
            Label.Succeeded "mkdir", 45
            Label.Succeeded "mkdirat", 17
            Label.Succeeded "rmdir", 38
            Label.Succeeded "unlink", 26
            Label.Succeeded "unlinkat", 5
            Label.Succeeded "rename", 19
            Label.Succeeded "renameat", 4
            Label.Succeeded "link", 21
            Label.Succeeded "symlink", 23
            Label.Succeeded "symlinkat", 8
            Label.Succeeded "chdir", 40
            Label.Succeeded "open", 90
            Label.Succeeded "openat", 16
            Label.Succeeded "dup", 10
            Label.Succeeded "pipe", 47
            Label.Succeeded "close", 34
            Label.Succeeded "stat", 7
            Label.Succeeded "fstat", 20
            Label.Succeeded "fstatat", 7
            Label.Succeeded "getdents", 5
            Label.Succeeded "getcwd", 21
            Label.Succeeded "chmod", 13
            Label.Succeeded "fchmod", 5
            Label.Succeeded "fchmodat", 7
            Label.Succeeded "fchown", 3
            Label.Succeeded "fchownat", 2
            Label.Succeeded "utimensat", 7
            Label.Succeeded "faccessat", 4
            Label.Failed ("rmdir", UnixError.ENOTEMPTY), 5
            Label.Failed ("rmdir", UnixError.EBUSY), 5
            Label.Failed ("unlinkat", UnixError.ENOTEMPTY), 3
            Label.OrphanHeld true, 987
            Label.OrphanHeld false, 503
            Label.CurrentDirectoryOrphaned, 509
            Label.HardLinked, 637
            Label.Freed "close", 6
            Label.Freed "unlink", 7
            Label.Freed "unlinkat", 4
            Label.Freed "rmdir", 5
            Label.Freed "rename", 3
            Label.Freed "renameat", 1
            Label.Freed "chdir", 1
        ]

    [<Test>]
    let ``random namespace syscalls on Linux as an ordinary user keep every invariant`` () : unit =
        let coverage = check Configuration.LinuxUser

        reaches
            coverage
            (sharedFloors
             @ [
                 Label.Succeeded "mknod", 11
                 Label.Succeeded "fstatat empty", 2
                 Label.Succeeded "fchmodat empty", 2
                 Label.Succeeded "fchownat empty", 1
                 Label.Succeeded "utimensat empty", 2
                 // The sticky directory's rule, which the other user's
                 // entries in /t reach.
                 Label.Failed ("unlink", UnixError.EPERM), 7
                 Label.Failed ("unlinkat", UnixError.EPERM), 3
                 Label.Failed ("rmdir", UnixError.EPERM), 4
                 Label.Failed ("rename", UnixError.EPERM), 5
                 // The device filesystem's mount point.
                 Label.Failed ("rename", UnixError.EXDEV), 7
                 Label.Failed ("rename", UnixError.EBUSY), 13
                 Label.Failed ("link", UnixError.EXDEV), 1
             ])

    [<Test>]
    let ``random namespace syscalls on Linux as root keep every invariant`` () : unit =
        let coverage = check Configuration.LinuxRoot

        reaches
            coverage
            (sharedFloors
             @ [
                 Label.Succeeded "mknod", 8
                 Label.Succeeded "fstatat empty", 1
                 Label.Succeeded "fchmodat empty", 1
                 Label.Succeeded "fchownat empty", 4
                 Label.Succeeded "utimensat empty", 3
                 Label.Succeeded "linkat empty", 19
                 Label.Failed ("rename", UnixError.EXDEV), 6
                 Label.Failed ("rename", UnixError.EBUSY), 13
                 Label.Failed ("link", UnixError.EXDEV), 1
             ])

    [<Test>]
    let ``random namespace syscalls on Darwin keep every invariant`` () : unit =
        let coverage = check Configuration.Darwin

        reaches
            coverage
            (sharedFloors
             @ [
                 Label.Succeeded "clonefile", 2
                 Label.Failed ("unlink", UnixError.EPERM), 11
                 Label.Failed ("unlinkat", UnixError.EPERM), 6
                 Label.Failed ("unlink", UnixError.EBUSY), 5
                 Label.Failed ("link", UnixError.EPERM), 31
                 Label.Failed ("mknod", UnixError.EPERM), 30
             ])
