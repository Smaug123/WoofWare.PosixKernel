namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Darwin's devfs, which the kernel mounts over the root's `dev` at boot: what
/// `stat(2)`, `statfs(2)` and a listing report of it, when it moves a time,
/// and what each call that would change a name in it, or a mode or an owner,
/// answers.
///
/// The constants are the rows `docs/probes/devfs-darwin` measured on Darwin
/// 27.0 arm64 as uid 501, whose `/dev` held `monotonic`, a directory holding
/// the node `uncore`, and `console`, a node that uid owned.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDevfs =

    let private context : string = "TestDevfs"

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 200

    let private darwin : SimulatedUnixPlatform = SimulatedUnixPlatform.macOsArm64
    let private linux : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private bits (mode : int) : PermissionBits = PermissionBits.parseOrFail context mode

    let private owner (user : uint32) (group : uint32) : InodeOwner =
        {
            User = UserId.parseOrFail context user
            Group = GroupId.parseOrFail context group
        }

    let private rootOwner : InodeOwner = owner 0u 0u

    /// The probe's caller: uid 501, in group 20.
    let private user501 : Credentials =
        Credentials.ofIds (UserId.parseOrFail context 501u) (GroupId.parseOrFail context 20u) []

    let private rootCredentials : Credentials =
        Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []

    let private reading : OpenFlags =
        {
            Access = FileAccessMode.ReadOnly
            Create = false
            Exclusive = false
            Truncate = false
            NoFollow = false
            CloseOnExec = false
            Synchronous = false
            DataSynchronous = false
            NonBlocking = false
            Directory = false
        }

    let private node (major : uint32) (minor : uint32) (mode : int) (nodeOwner : InodeOwner option) : SeedEntry =
        SeedEntry.CharacterDevice (DeviceNumber (major, minor), bits mode, nodeOwner)

    /// A timestamp as the probe prints it: seconds, a point, nine digits.
    let private timestamp (text : string) : UnixTimestamp =
        let negative = text.StartsWith "-"
        let digits = if negative then text.Substring 1 else text

        match digits.Split '.' with
        | [| seconds ; nanoseconds |] when not negative ->
            UnixTimestamp.createOrFail context (int64 seconds) (int nanoseconds)
        | other -> failwith $"%s{context}: %A{other} is not a non-negative timestamp the probe printed"

    // ------------------------------------------------------- the probe rows

    /// Every row of `docs/probes/devfs-darwin`'s output, split on its tabs.
    let private probeRows : string[] list =
        use stream =
            System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream
                "WoofWare.PosixKernel.Test.devfs-darwin.txt"

        if isNull stream then
            failwith $"%s{context}: no embedded devfs-darwin probe output"

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split ('\n', System.StringSplitOptions.RemoveEmptyEntries)
        |> Array.filter (fun line -> not (line.StartsWith "#"))
        |> Array.map (fun line -> line.Split '\t')
        |> List.ofArray

    let private rowsOf (kind : string) : string[] list =
        probeRows |> List.filter (fun row -> row.[0] = kind)

    /// The `key=value` fields of a row's last column.
    let private fieldsOf (row : string[]) : Map<string, string> =
        row.[row.Length - 1].Split ' '
        |> Array.choose (fun field ->
            match field.IndexOf '=' with
            | -1 -> None
            | at -> Some (field.Substring (0, at), field.Substring (at + 1))
        )
        |> Map.ofArray

    /// The instant the probed machine booted at, from its BOOT row.
    let private bootTime : UnixTimestamp =
        match rowsOf "BOOT" with
        | [ row ] -> UnixTimestamp.createOrFail context (int64 row.[1]) (int row.[2] * 1000)
        | other -> failwith $"%s{context}: expected one BOOT row, got %A{other}"

    // ------------------------------------------------------- the machine

    /// The probed machine's devfs, as far as the probe's rows reach: the
    /// default nodes, `monotonic` holding `uncore` (19,0, group 88), and
    /// `console` (0,0, mode 0622), owned by the probe's caller.
    let private probedContents : Map<DirectoryEntryName, SeedEntry> =
        UnixSystem.defaultDevfsContents
        |> Map.add
            (name "monotonic")
            (SeedEntry.Directory (
                Map.ofList [ name "uncore", node 19u 0u 0o666 (Some (owner 0u 88u)) ],
                bits 0o555,
                None
            ))
        |> Map.add (name "console") (node 0u 0u 0o622 (Some (owner 501u 20u)))

    /// The probe's scratch directory, which it made with `mkdtemp` and calls
    /// `tmp`, at `/t`: a file `f`, a directory `sub`, a directory `ro` the
    /// caller may search but not write, and `nox`, which it may do neither to.
    let private probedSeed : Map<DirectoryEntryName, SeedEntry> =
        let mine = Some (owner 501u 20u)

        Map.ofList
            [
                name "t",
                SeedEntry.Directory (
                    Map.ofList
                        [
                            name "f", SeedEntry.File (ImmutableArray.Empty, bits 0o644, mine)
                            name "sub", SeedEntry.Directory (Map.empty, bits 0o755, mine)
                            name "ro", SeedEntry.Directory (Map.empty, bits 0o555, mine)
                            name "nox", SeedEntry.Directory (Map.empty, bits 0o600, mine)
                        ],
                    bits 0o700,
                    mine
                )
            ]

    /// A Darwin machine booted at the probed instant, whose root holds `seed`
    /// and whose devfs holds `contents`, its process running as `credentials`.
    let private bootedWith
        (credentials : Credentials)
        (seed : Map<DirectoryEntryName, SeedEntry>)
        (contents : Map<DirectoryEntryName, SeedEntry>)
        : UnixSystem<int, string>
        =
        UnixSystem.initial darwin
        |> UnixBootImage.withBootTime bootTime
        |> Launched.fileSystem bootTime rootOwner seed
        |> UnixBootImage.tryWithDeviceFileSystem contents
        |> Configured.expectOk DeviceFileSystemFault.describe
        |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// The probed machine, as uid 501.
    let private probed () : UnixSystem<int, string> =
        bootedWith user501 probedSeed probedContents

    /// `system` with its realtime clock moved on to `instant`.
    let private clockAt (instant : UnixTimestamp) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let now = UnixSystem.realtime system

        let nanoseconds =
            (UnixTimestamp.seconds instant - UnixTimestamp.seconds now) * 1_000_000_000L
            + int64 (UnixTimestamp.nanoseconds instant - UnixTimestamp.nanoseconds now)

        if nanoseconds < 0L then
            failwith $"%s{context}: the clock reads %O{now}, after %O{instant}"

        UnixSystem.advanceClock nanoseconds system

    let private lstat (path : string) (system : UnixSystem<int, string>) : Result<FileStatusAnswer, StatRefusal> =
        UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.NoFollowFinal (PathArg.ofText path) system

    let private reported (path : string) (system : UnixSystem<int, string>) : FileStatus =
        match lstat path system with
        | Ok (FileStatusAnswer.Reported status) -> status
        | other -> failwith $"lstat %s{path}: expected a status, got %A{other}"

    // ------------------------------------------------------------- stat

    [<Test>]
    let ``every node and directory reports the measured stat fields`` () : unit =
        let system = probed ()
        let bootSecond = UnixTimestamp.ofSeconds (UnixTimestamp.seconds bootTime)

        let rows = rowsOf "STAT"
        rows.Length |> shouldEqual 8

        for row in rows do
            let path = row.[1]

            match lstat path system with
            | Ok (FileStatusAnswer.Failed error) -> row.[2] |> shouldEqual $"-> %A{error}"
            | Ok (FileStatusAnswer.Reported status) ->
                let fields = fieldsOf row

                let fileType =
                    match fields.["type"] with
                    | "dir" -> 0o040000
                    | "chr" -> 0o020000
                    | other -> failwith $"%s{context}: a STAT row of type %s{other}"

                status.Mode
                |> shouldEqual (fileType ||| System.Convert.ToInt32 (fields.["mode"], 8))

                UserId.toUInt32 status.UserId |> shouldEqual (uint32 fields.["uid"])
                GroupId.toUInt32 status.GroupId |> shouldEqual (uint32 fields.["gid"])
                status.IoBlockSize |> shouldEqual (Some (int64 fields.["blksize"]))
                status.BirthTime |> shouldEqual (Some (timestamp fields.["birth"]))

                status.DeviceId
                |> shouldEqual (int64 (int32 (System.Convert.ToUInt32 (fields.["dev"], 16))))

                let rdev =
                    match fields.["rdev"].Split ',' with
                    | [| major ; minor |] -> (int64 major <<< 24) ||| int64 minor
                    | other -> failwith $"%s{context}: an rdev of %A{other}"

                status.SpecialFileDevice |> shouldEqual rdev

                // `/dev`'s own size, blocks and link count follow what the
                // machine holds, which the DENTS row and the next test check.
                if path <> "/dev" then
                    status.Size |> shouldEqual (int64 fields.["size"])
                    status.AllocatedBlocks |> shouldEqual (Some (int64 fields.["blocks"]))
                    status.LinkCount |> shouldEqual (int64 fields.["nlink"])

                // Every time no process moved is the boot's whole second.
                for time in [ "atime" ; "mtime" ; "ctime" ] do
                    if timestamp fields.[time] = bootSecond then
                        match time with
                        | "atime" -> status.AccessTime
                        | "mtime" -> status.ModificationTime
                        | _ -> status.StatusChangeTime
                        |> shouldEqual bootSecond
            | other -> failwith $"lstat %s{path}: %A{other}"

        // Every devfs time the model makes is the boot's whole second, and
        // the probe saw that second where nothing had moved a time.
        let zero = reported "/dev/zero" system

        [ zero.AccessTime ; zero.ModificationTime ; zero.StatusChangeTime ]
        |> shouldEqual [ bootSecond ; bootSecond ; bootSecond ]

        rows
        |> List.find (fun row -> row.[1] = "/dev/zero")
        |> fieldsOf
        |> fun fields -> timestamp fields.["mtime"]
        |> shouldEqual bootSecond

    [<Test>]
    let ``the directory's size is 8 bytes and its length per name, and its links 2 and its subdirectories`` () : unit =
        // The probe's own rows: the sum over `/dev`'s every name, against its
        // st_size and st_nlink.
        match rowsOf "DENTS" with
        | [ row ] ->
            let fields = fieldsOf row
            fields.["sum_namelen_plus_8"] |> shouldEqual fields.["size"]
            int fields.["nlink"] |> shouldEqual (2 + int fields.["subdirectories"])
        | other -> failwith $"%s{context}: expected one DENTS row, got %A{other}"

        let system = probed ()
        let status = reported "/dev" system

        let names =
            probedContents
            |> Map.keys
            |> Seq.map (fun entry -> (PathText.ofName entry).Length)

        status.Size
        |> shouldEqual (names |> Seq.sumBy (fun length -> int64 length + 8L))

        status.LinkCount |> shouldEqual 3L
        status.AllocatedBlocks |> shouldEqual (Some ((status.Size + 511L) / 512L))

    // ------------------------------------------------------------- listing

    [<Test>]
    let ``a listing's dots are the measured ones, and lists what the configuration holds`` () : unit =
        let system = probed ()
        let dev = (reported "/dev" system).Inode
        let monotonic = (reported "/dev/monotonic" system).Inode

        let listed (path : string) (system : UnixSystem<int, string>) =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail context path) system with
            | Ok fd, system -> DirectoryReading.drain fd system |> fst
            | Error error, _ -> failwith $"opening %s{path}: %O{error}"

        // Measured: `.` and `..` of `/dev` both carry `/dev`'s own inode, and
        // `..` of a directory inside it its parent's.
        let dents = rowsOf "DENT"

        let measured (path : string) (entry : string) : string =
            dents
            |> List.find (fun row -> row.[1] = path && row.[4] = entry)
            |> fun row -> row.[2]

        measured "/dev" "." |> shouldEqual (measured "/dev" "..")
        measured "/dev/monotonic" ".." |> shouldEqual (measured "/dev" ".")

        let records = listed "/dev" system

        records
        |> List.choose (fun record ->
            match record.Name with
            | PathComponent.Current
            | PathComponent.Parent -> Some record.Inode
            | PathComponent.Name _ -> None
        )
        |> shouldEqual [ dev ; dev ]

        records
        |> List.choose (fun record ->
            match record.Name with
            | PathComponent.Name entry -> Some (entry, record.Kind)
            | PathComponent.Current
            | PathComponent.Parent -> None
        )
        |> List.sort
        |> shouldEqual (
            probedContents
            |> Map.toList
            |> List.map (fun (entry, seed) ->
                entry,
                match seed with
                | SeedEntry.Directory _ -> DirectoryEntryKind.Directory
                | _ -> DirectoryEntryKind.CharacterDevice
            )
            |> List.sort
        )

        listed "/dev/monotonic" system
        |> List.filter (fun record -> record.Name = PathComponent.Parent)
        |> List.map (fun record -> record.Inode)
        |> shouldEqual [ dev ]

        ignore<InodeNumber> monotonic

    [<Test>]
    let ``a listing moves a directory's access time at every call, to the microsecond, and nothing else does``
        ()
        : unit
        =
        let rows = rowsOf "TIMES"

        for directory in [ "/dev" ; "/dev/monotonic" ] do
            let steps =
                rows
                |> List.filter (fun row -> row.[1] = directory)
                |> List.map (fun row -> row.[2], fieldsOf row)

            steps.Length |> shouldEqual 6

            let atimeOf (fields : Map<string, string>) = timestamp fields.["atime"]
            let clockOf (fields : Map<string, string>) = timestamp fields.["clock"]

            // The probe's own reading of which steps moved the time: a moved
            // atime is at or after the clock read just before the step, and
            // within a few milliseconds of it.
            let moved =
                steps
                |> List.pairwise
                |> List.map (fun ((_, before), (step, after)) ->
                    let movedHere = atimeOf after <> atimeOf before

                    if movedHere then
                        atimeOf after >= clockOf after |> shouldEqual true
                        UnixTimestamp.nanoseconds (atimeOf after) % 1000 |> shouldEqual 0

                    step, movedHere
                )

            moved |> List.map snd |> shouldEqual [ false ; false ; true ; true ; true ]

            // The model, at each step's clock: an open and a failed lookup
            // move nothing, and a call returning an entry and the call at the
            // end each move it to now, truncated to the microsecond.
            let system = probed ()

            let atime (system : UnixSystem<int, string>) = (reported directory system).AccessTime

            let clockFor (step : string) =
                steps |> List.find (fun (label, _) -> label = step) |> snd |> clockOf

            let system = clockAt (clockFor "after-open") system
            let before = atime system

            let fd, system =
                match DirectoryReading.openDirectory (UnixPath.parseOrFail context directory) system with
                | Ok fd, system -> fd, system
                | Error error, _ -> failwith $"opening %s{directory}: %O{error}"

            atime system |> shouldEqual before

            let system = clockAt (clockFor "after-failed-lookup") system

            lstat $"%s{directory}/nonexistent" system
            |> shouldEqual (Ok (FileStatusAnswer.Failed UnixError.ENOENT))

            atime system |> shouldEqual before

            let readOne (system : UnixSystem<int, string>) =
                match UnixNamespace.tryReadDirectoryEntry (Callers.leader system) fd system with
                | Ok (answer, system) -> answer, system
                | Error refusal -> failwith $"reading %s{directory}: %s{ReadDirectoryRefusal.describe refusal}"

            let stepped (step : string) (system : UnixSystem<int, string>) =
                let system = clockAt (clockFor step) system
                let answer, system = readOne system

                atime system
                |> shouldEqual (UnixTimestamp.truncateToMicroseconds (UnixSystem.realtime system))

                answer, system

            let first = steps |> List.item 3 |> fst
            let second = steps |> List.item 4 |> fst
            let answer, system = stepped first system

            match answer with
            | ReadDirectoryAnswer.Entry _ -> ()
            | other -> failwith $"the first read of %s{directory}: %A{other}"

            let _, system = stepped second system

            // Read on to the end, then the call there.
            let rec toEnd (system : UnixSystem<int, string>) =
                match readOne system with
                | ReadDirectoryAnswer.Entry _, system -> toEnd system
                | ReadDirectoryAnswer.EndOfDirectory, system -> system
                | ReadDirectoryAnswer.Failed error, _ -> failwith $"reading %s{directory}: %O{error}"

            let system = toEnd system

            match stepped (steps |> List.item 5 |> fst) system with
            | ReadDirectoryAnswer.EndOfDirectory, _ -> ()
            | other, _ -> failwith $"the call at the end of %s{directory}: %A{other}"

    // ------------------------------------------------------------- statfs

    [<Test>]
    let ``statfs of devfs is the measured row, through the root, a node and a subdirectory`` () : unit =
        let system = probed ()
        let rows = rowsOf "STATFS"
        rows.Length |> shouldEqual 3

        for row in rows do
            let fields = fieldsOf row

            match UnixPathResolution.tryStatfs (Callers.leader system) (PathArg.ofText row.[1]) system with
            | Ok (FileSystemStatisticsAnswer.Reported (FileSystemStatistics.Darwin statistics)) ->
                statistics.Type |> shouldEqual (uint32 fields.["type"])
                UnixByteString.toEscaped statistics.TypeName |> shouldEqual fields.["name"]
                statistics.Geometry.BlockSize |> shouldEqual (uint32 fields.["bsize"])
                statistics.Geometry.IoSize |> shouldEqual (int fields.["iosize"])

                let fsid =
                    match fields.["fsid"].Split ':' with
                    | [| first ; second |] ->
                        {
                            First = int32 (System.Convert.ToUInt32 (first, 16))
                            Second = int32 (System.Convert.ToUInt32 (second, 16))
                        }
                    | other -> failwith $"%s{context}: an fsid of %A{other}"

                statistics.FileSystemId |> shouldEqual fsid
                statistics.Mount.Owner |> shouldEqual (uint32 fields.["owner"])

                statistics.Mount.Flags
                |> shouldEqual (System.Convert.ToUInt32 (fields.["flags"].Substring 2, 16))

                statistics.Mount.ExtendedFlags
                |> shouldEqual (System.Convert.ToUInt32 (fields.["flags_ext"].Substring 2, 16))

                statistics.Mount.SubType |> shouldEqual (uint32 fields.["subtype"])
                UnixByteString.toEscaped statistics.Mount.MountedOn |> shouldEqual fields.["on"]

                UnixByteString.toEscaped statistics.Mount.MountedFrom
                |> shouldEqual fields.["from"]

                // The counts follow every node the machine's drivers made,
                // which the configuration does not describe.
                statistics.CapacityResult
                |> shouldEqual (Error CapacityRefusal.DeviceFileSystem)
            | other -> failwith $"statfs %s{row.[1]}: %A{other}"

    // ------------------------------------------------- a descriptor on /dev

    [<Test>]
    let ``a descriptor on devfs's root seeks over its size, reports devfs, and is refused a read`` () : unit =
        let fields = rowsOf "DIRFD" |> List.map (fun row -> row.[1], row.[2]) |> Map.ofList

        // Measured: SEEK_END lands on the size `stat` reports.
        let measuredSize =
            rowsOf "STAT"
            |> List.find (fun row -> row.[1] = "/dev")
            |> fieldsOf
            |> fun f -> f.["size"]

        fields.["lseek(0, SEEK_END)"] |> shouldEqual $"-> %s{measuredSize} "
        fields.["lseek(5, SEEK_SET)"] |> shouldEqual "-> 5 "
        fields.["lseek(-1, SEEK_SET)"] |> shouldEqual "-> -1 EINVAL"
        fields.["fstatfs"] |> shouldEqual "-> type=19 name=devfs"

        let system = probed ()

        let fd, system =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail context "/dev") system with
            | Ok fd, system -> fd, system
            | Error error, _ -> failwith $"opening /dev: %O{error}"

        let seek (offset : int64) (whence : int) =
            match UnixDescriptor.tryLseek (Callers.leader system) fd offset whence system with
            | Ok (answer, _) -> answer
            | Error refusal -> failwith $"lseek(%d{offset}, %d{whence}): %s{LSeekRefusal.describe refusal}"

        seek 0L 1 |> shouldEqual (SyscallAnswer.Completed 0L)
        seek 0L 2 |> shouldEqual (SyscallAnswer.Completed (reported "/dev" system).Size)
        seek 5L 0 |> shouldEqual (SyscallAnswer.Completed 5L)
        seek -1L 0 |> shouldEqual (SyscallAnswer.Failed UnixError.EINVAL)

        match UnixPathResolution.fstatfs (Callers.leader system) fd system with
        | FileSystemStatisticsAnswer.Reported (FileSystemStatistics.Darwin statistics) ->
            statistics.Type |> shouldEqual 19u
        | other -> failwith $"fstatfs: %A{other}"

        // Measured, a read returns bytes, which this kernel does not model.
        fields.["read(16)"] |> shouldEqual "-> ok"

        match UnixReadWrite.tryRead (Callers.leader system) fd UserBuffer.Mapped 16UL system with
        | Error (ReadRefusal.DevfsDirectory _) -> ()
        | other -> failwith $"read of /dev: expected a refusal, got %A{other}"

    // ------------------------------------------------- changing names, as uid 501

    /// What the model answers one NS row's call, rendered as the probe renders
    /// its answer ("ok" or the errno), or `None` for a call this library has
    /// no syscall for. A refusal renders as "refused: " and its description.
    let private answerOf (call : string) (system : UnixSystem<int, string>) : string option =
        let open' = call.IndexOf '('
        let syscall = call.Substring (0, open')
        let inside = call.Substring (open' + 1, call.Length - open' - 2)

        let path (text : string) : PathArgumentBytes =
            let text =
                if text.StartsWith "tmp/" then
                    $"/t/%s{text.Substring 4}"
                elif text.StartsWith "/dev/<" then
                    // `/dev/<N a>`: N bytes of 'a'.
                    let count = int (text.Substring(6).Split(' ').[0])
                    "/dev/" + System.String ('a', count)
                else
                    text

            PathArg.ofText text

        let args = inside.Split ", "

        let rendered (answer : SyscallAnswer) : string =
            match answer with
            | SyscallAnswer.Completed _ -> "ok"
            | SyscallAnswer.Failed error -> $"%A{error}"

        let ofResult
            (describe : 'refusal -> string)
            (result : Result<SyscallAnswer * UnixSystem<int, string>, 'refusal>)
            =
            match result with
            | Ok (answer, _) -> rendered answer
            | Error refusal -> $"refused: %s{describe refusal}"

        let caller = Callers.leader system

        match syscall with
        | "open" ->
            let flagNames = args.[1].Split '|' |> Set.ofArray

            let flags : OpenFlags =
                {
                    Access =
                        if flagNames.Contains "O_WRONLY" then
                            FileAccessMode.WriteOnly
                        else
                            FileAccessMode.ReadOnly
                    Create = flagNames.Contains "O_CREAT"
                    Exclusive = flagNames.Contains "O_EXCL"
                    Truncate = false
                    NoFollow = false
                    CloseOnExec = false
                    Synchronous = false
                    DataSynchronous = false
                    NonBlocking = false
                    Directory = false
                }

            match OpenFlagWords.openPath (path args.[0]) flags 0o644 system with
            | Ok (DescriptorAnswer.Returned _, _) -> Some "ok"
            | Ok (DescriptorAnswer.Failed error, _) -> Some $"%A{error}"
            | Error refusal -> Some $"refused: %s{OpenRefusal.describe refusal}"
        | "mkdir" ->
            UnixNamespace.tryMkdir caller (path args.[0]) 0o755 system
            |> ofResult PathRefusal.describe
            |> Some
        | "mkfifo" ->
            UnixNamespace.tryMknod caller (path args.[0]) 0o010644 0u system
            |> ofResult MkNodRefusal.describe
            |> Some
        | "mknod" ->
            let mode, dev =
                match args.[1] with
                | "S_IFCHR" -> 0o020644, 0x3000002u
                | "S_IFIFO" -> 0o010644, 0u
                | other -> failwith $"%s{context}: an NS row's mknod of %s{other}"

            UnixNamespace.tryMknod caller (path args.[0]) mode dev system
            |> ofResult MkNodRefusal.describe
            |> Some
        | "linkat"
        | "symlinkat" ->
            // A directory removed while a descriptor holds it, as the probe
            // made one.
            let removed, system =
                match UnixNamespace.tryMkdir caller (PathArg.ofText "/t/gone") 0o755 system with
                | Ok (SyscallAnswer.Completed _, system) ->
                    match DirectoryReading.openDirectory (UnixPath.parseOrFail context "/t/gone") system with
                    | Ok fd, system ->
                        match UnixNamespace.tryRmdir (Callers.leader system) (PathArg.ofText "/t/gone") system with
                        | Ok (SyscallAnswer.Completed _, system) -> fd, system
                        | other -> failwith $"%s{context}: removing /t/gone: %A{other}"
                    | Error error, _ -> failwith $"%s{context}: opening /t/gone: %O{error}"
                | other -> failwith $"%s{context}: making /t/gone: %A{other}"

            let atFdCwd = AtDirectory.atFdCwd SimulatedUnixFlavour.Darwin

            match syscall with
            | "linkat" ->
                Eager.tryLinkatAs
                    (Callers.leader system)
                    atFdCwd
                    (path args.[0])
                    removed
                    (PathArg.ofText args.[2])
                    0
                    system
                |> ofResult LinkRefusal.describe
            | _ ->
                Eager.trySymlinkatAs (Callers.leader system) (path args.[0]) removed (PathArg.ofText args.[2]) system
                |> ofResult SymlinkRefusal.describe
            |> Some
        | "symlink" ->
            Eager.trySymlink (path args.[0]) (path args.[1]) system
            |> ofResult SymlinkRefusal.describe
            |> Some
        | "link" ->
            Eager.tryLink (path args.[0]) (path args.[1]) system
            |> ofResult LinkRefusal.describe
            |> Some
        | "unlink" ->
            UnixNamespace.tryUnlink caller (path args.[0]) system
            |> ofResult RemovalRefusal.describe
            |> Some
        | "rmdir" ->
            UnixNamespace.tryRmdir caller (path args.[0]) system
            |> ofResult RemovalRefusal.describe
            |> Some
        | "rename" ->
            Eager.tryRename (path args.[0]) (path args.[1]) system
            |> ofResult RenameRefusal.describe
            |> Some
        | "clonefile" ->
            Eager.tryCloneFileAs caller (path args.[0]) (path args.[1]) 0 system
            |> ofResult CloneFileRefusal.describe
            |> Some
        | "chmod" ->
            UnixPathResolution.tryChmod caller (path args.[0]) (System.Convert.ToInt32 (args.[1], 8)) system
            |> ofResult ChModRefusal.describe
            |> Some
        | "chown" ->
            let user =
                match args.[1] with
                | "-1" -> None
                | "self" -> Some (UserId.parseOrFail context 501u)
                | other -> failwith $"%s{context}: an NS row's chown to %s{other}"

            UnixPathResolution.tryChown caller (path args.[0]) user None system
            |> ofResult ChOwnRefusal.describe
            |> Some
        | "access" ->
            let mode =
                args.[1].Split '|'
                |> Array.sumBy (fun bit ->
                    match bit with
                    | "R_OK" -> 4
                    | "W_OK" -> 2
                    | "X_OK" -> 1
                    | other -> failwith $"%s{context}: an access mode of %s{other}"
                )

            match Eager.tryAccess (path args.[0]) mode system with
            | Ok answer -> Some (rendered answer)
            | Error refusal -> Some $"refused: %s{AccessRefusal.describe refusal}"
        | "utimes"
        | "utimensat" ->
            let times =
                match syscall, args.[1..] with
                | _, [| "NULL" |] -> Some TimesArgument.Null
                | "utimensat", [| "explicit" |] ->
                    Some (
                        TimesArgument.Fields (
                            {
                                Seconds = 1_000_000_000L
                                Nanoseconds = 123_456_789L
                            },
                            {
                                Seconds = 1_000_000_000L
                                Nanoseconds = 987_654_321L
                            }
                        )
                    )
                | "utimensat", [| "NOW" ; second |] ->
                    let now = TimestampChangeRules.utimeNow SimulatedUnixFlavour.Darwin

                    let other =
                        if second = "NOW" then
                            now
                        else
                            TimestampChangeRules.utimeOmit SimulatedUnixFlavour.Darwin

                    Some (
                        TimesArgument.Fields (
                            {
                                Seconds = 0L
                                Nanoseconds = now
                            },
                            {
                                Seconds = 0L
                                Nanoseconds = other
                            }
                        )
                    )
                // Darwin's `utimes(2)` with times, which this library has no
                // syscall for: its `utimensat` is the libc's.
                | "utimes", _ -> None
                | _, other -> failwith $"%s{context}: an NS row's %s{syscall} with %A{other}"

            times
            |> Option.map (fun times ->
                UnixPathResolution.tryUtimensat
                    caller
                    (AtDirectory.atFdCwd SimulatedUnixFlavour.Darwin)
                    (NullablePathArgument.NotNull (path args.[0]))
                    times
                    0
                    system
                |> ofResult UTimensAtRefusal.describe
            )
        // `truncate(2)`, which this library has no syscall for.
        | "truncate" -> None
        | other -> failwith $"%s{context}: an NS row's call %s{other}"

    [<Test>]
    let ``every change of a name, a mode or an owner answers as measured, or is refused`` () : unit =
        let rows = rowsOf "NS"
        rows.Length |> shouldBeGreaterThan 150

        let navigationDestination (call : string) =
            call.StartsWith "rename("
            && (call.EndsWith "/dev/.)"
                || call.EndsWith "/.)" && call.Contains ", /dev"
                || call.EndsWith "/..)" && call.Contains ", /dev")

        [
            for row in rows do
                let call = row.[1]
                let probe = row.[2].Substring 3

                match answerOf call (probed ()) with
                | None -> ()
                | Some actual ->

                let expectedRefusal =
                    if call.Contains "<256 a>" then
                        Some "refused: the path looks up"
                    elif call.StartsWith "utime" && probe = "ok" then
                        Some "refused: the call would set the times"
                    // A missing source answers first, as measured.
                    elif navigationDestination call && not (call.StartsWith "rename(/dev/nope") then
                        Some "refused: the destination is inode"
                    // This library makes no FIFO on Darwin, anywhere.
                    elif call.StartsWith "mkfifo" || call.Contains "S_IFIFO" then
                        Some "refused: the call would make a FIFO"
                    else
                        None

                match expectedRefusal with
                | Some prefix ->
                    if not (actual.StartsWith prefix) then
                        yield $"%s{call}: expected a refusal starting %s{prefix}, got %s{actual}"
                | None ->
                    if actual <> probe then
                        yield $"%s{call}: the probe answered %s{probe}, this library %s{actual}"
        ]
        |> shouldEqual []

    [<Test>]
    let ``the owner of a node changes its mode and owner as measured, and sets its times only to now`` () : unit =
        let rows = rowsOf "CONSOLE"

        let row (prefix : string) =
            rows |> List.find (fun row -> row.[1].StartsWith prefix)

        // Measured: the owner's chmod is EPERM, to its own mode; naming its own
        // IDs succeeds; explicit times are stored to the microsecond.
        (row "chmod").[2].StartsWith "-> EPERM" |> shouldEqual true
        (row "chown").[2] |> shouldEqual "-> ok"

        (row "utimensat(1000000000.123456789").[2].StartsWith "-> ok"
        |> shouldEqual true

        let system = probed ()
        let caller = Callers.leader system

        match UnixPathResolution.tryChmod caller (PathArg.ofText "/dev/console") 0o622 system with
        | Ok (SyscallAnswer.Failed UnixError.EPERM, after) -> after |> shouldEqual system
        | other -> failwith $"chmod of the caller's own node: %A{other}"

        // The change time it then sets follows devfs's own lazy rule.
        let me = Some (UserId.parseOrFail context 501u)

        match UnixPathResolution.tryChown caller (PathArg.ofText "/dev/console") me None system with
        | Error (ChOwnRefusal.Devfs (DevfsAttributeRefusal.OwnerChange _)) -> ()
        | other -> failwith $"chown of the caller's own node to itself: %A{other}"

        match UnixPathResolution.tryChown caller (PathArg.ofText "/dev/console") None None system with
        | Ok (SyscallAnswer.Completed 0L, after) -> after |> shouldEqual system
        | other -> failwith $"chown(-1, -1) of the caller's own node: %A{other}"

        let explicit =
            TimesArgument.Fields (
                {
                    Seconds = 1_000_000_000L
                    Nanoseconds = 123_456_789L
                },
                {
                    Seconds = 1_000_000_001L
                    Nanoseconds = 987_654_321L
                }
            )

        match
            UnixPathResolution.tryUtimensat
                caller
                (AtDirectory.atFdCwd SimulatedUnixFlavour.Darwin)
                (NullablePathArgument.NotNull (PathArg.ofText "/dev/console"))
                explicit
                0
                system
        with
        | Error (UTimensAtRefusal.DevfsTimes _) -> ()
        | other -> failwith $"explicit times on the caller's own node: %A{other}"

    [<Test>]
    let ``setting a node's times is refused, its change time being devfs's own`` () : unit =
        let times = rowsOf "TIMES" |> List.filter (fun row -> row.[1] = "/dev/null")
        times.Length |> shouldEqual 3

        // The access and modification times are now, to the microsecond, but
        // the change time trails the clock by a second on some calls.
        let lags =
            [
                for row in times do
                    let fields = fieldsOf row
                    let clock = UnixTimestamp.truncateToMicroseconds (timestamp fields.["clock"])

                    for time in [ "atime" ; "mtime" ] do
                        timestamp fields.[time] >= clock |> shouldEqual true

                    yield UnixTimestamp.seconds (timestamp fields.["ctime"]) < UnixTimestamp.seconds clock
            ]

        lags |> List.contains true |> shouldEqual true

        let system = probed ()

        for times in
            [
                TimesArgument.Null
                TimesArgument.Fields (
                    {
                        Seconds = 0L
                        Nanoseconds = TimestampChangeRules.utimeNow SimulatedUnixFlavour.Darwin
                    },
                    {
                        Seconds = 0L
                        Nanoseconds = TimestampChangeRules.utimeNow SimulatedUnixFlavour.Darwin
                    }
                )
            ] do
            match
                UnixPathResolution.tryUtimensat
                    (Callers.leader system)
                    (AtDirectory.atFdCwd SimulatedUnixFlavour.Darwin)
                    (NullablePathArgument.NotNull (PathArg.ofText "/dev/null"))
                    times
                    0
                    system
            with
            | Error (UTimensAtRefusal.DevfsTimes _) -> ()
            | other -> failwith $"utimensat of /dev/null to now: %A{other}"

    // ------------------------------------------------------------- root

    [<Test>]
    let ``root's changes on devfs are refused, once its walks have answered`` () : unit =
        let system = bootedWith rootCredentials probedSeed probedContents
        let caller = Callers.leader system

        let privileged (refusal : PathRefusal) : unit =
            match refusal with
            | PathRefusal.DevfsPrivilegedCaller _ -> ()
            | other -> failwith $"expected devfs's refusal of root, got %A{other}"

        match
            OpenFlagWords.openPath
                (PathArg.ofText "/dev/n")
                { reading with
                    Create = true
                }
                0o644
                system
        with
        | Error (OpenRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"open(O_CREAT) as root: %A{other}"

        match UnixNamespace.tryMkdir caller (PathArg.ofText "/dev/null") 0o755 system with
        | Error refusal -> privileged refusal
        | other -> failwith $"mkdir as root: %A{other}"

        match UnixNamespace.tryMknod caller (PathArg.ofText "/dev/n") 0o010644 0u system with
        | Error (MkNodRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"mkfifo as root: %A{other}"

        match Eager.trySymlink (PathArg.ofText "x") (PathArg.ofText "/dev/null") system with
        | Error (SymlinkRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"symlink as root: %A{other}"

        // A link out of devfs is refused too, though its new name is not there.
        match Eager.tryLink (PathArg.ofText "/dev/null") (PathArg.ofText "/t/n") system with
        | Error (LinkRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"link from devfs as root: %A{other}"

        match UnixNamespace.tryUnlink caller (PathArg.ofText "/dev/null") system with
        | Error (RemovalRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"unlink as root: %A{other}"

        match UnixNamespace.tryRmdir caller (PathArg.ofText "/dev/monotonic") system with
        | Error (RemovalRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"rmdir as root: %A{other}"

        match Eager.tryRename (PathArg.ofText "/dev/null") (PathArg.ofText "/dev/zero") system with
        | Error (RenameRefusal.Path refusal) -> privileged refusal
        | other -> failwith $"rename as root: %A{other}"

        match UnixPathResolution.tryChmod caller (PathArg.ofText "/dev/null") 0o600 system with
        | Error (ChModRefusal.Devfs (DevfsAttributeRefusal.PrivilegedCaller _)) -> ()
        | other -> failwith $"chmod as root: %A{other}"

        match UnixPathResolution.tryChown caller (PathArg.ofText "/dev/null") (Some UserId.root) None system with
        | Error (ChOwnRefusal.Devfs (DevfsAttributeRefusal.OwnerChange _)) -> ()
        | other -> failwith $"chown as root: %A{other}"

        // The walks answer first: a missing directory is ENOENT, and a path
        // through a node ENOTDIR.
        match UnixNamespace.tryMkdir caller (PathArg.ofText "/dev/nope/x") 0o755 system with
        | Ok (SyscallAnswer.Failed UnixError.ENOENT, _) -> ()
        | other -> failwith $"mkdir under a missing directory as root: %A{other}"

        match UnixNamespace.tryUnlink caller (PathArg.ofText "/dev/null/x") system with
        | Ok (SyscallAnswer.Failed UnixError.ENOTDIR, _) -> ()
        | other -> failwith $"unlink through a node as root: %A{other}"

    // ------------------------------------------------------- long names

    [<Test>]
    let ``a name past NAME_MAX in devfs is refused, where every other filesystem answers ENAMETOOLONG`` () : unit =
        let system = probed ()
        let long = System.String ('a', 256)

        for path in [ $"/dev/%s{long}" ; $"/dev/%s{long}/x" ; $"/dev/monotonic/%s{long}" ] do
            match lstat path system with
            | Error (StatRefusal.Path (PathRefusal.DevfsNameTooLong (_, refused))) ->
                PathText.ofName refused |> shouldEqual long
            | other -> failwith $"lstat %s{path}: expected a refusal, got %A{other}"

        // 255 bytes is within NAME_MAX, and devfs holds no such name.
        lstat ("/dev/" + System.String ('a', 255)) system
        |> shouldEqual (Ok (FileStatusAnswer.Failed UnixError.ENOENT))

        lstat $"/t/%s{long}" system
        |> shouldEqual (Ok (FileStatusAnswer.Failed UnixError.ENAMETOOLONG))

    // -------------------------------------------------- configuration

    /// A Darwin devfs's contents: nodes holding any number its `dev_t`
    /// encodes, with any mode and owner, and the 0555 root directories
    /// holding them, `depth` deep at most.
    let rec private devfsContentsGen (depth : int) : Gen<Map<DirectoryEntryName, SeedEntry>> =
        let nameGen =
            gen {
                let! length = Gen.choose (1, 31)

                let! characters =
                    Gen.elements ([ 'a' .. 'z' ] @ [ '0' .. '9' ] @ [ '-' ; '_' ; '.' ])
                    |> Gen.listOfLength length

                return System.String (Array.ofList characters)
            }
            |> Gen.filter (fun text -> text <> "." && text <> "..")
            |> Gen.map name

        let ownerGen =
            Gen.map2
                (fun (user : int) (group : int) -> owner (uint32 user) (uint32 group))
                (Gen.choose (0, 600))
                (Gen.choose (0, 600))

        let nodeGen =
            gen {
                let! major = Gen.choose (0, 255)
                let! minor = Gen.oneof [ Gen.choose (0, 300) ; Gen.choose (0, 0xFFFFFF) ]
                let! mode = Gen.choose (0, 0o7777)
                let! nodeOwner = Gen.optionOf ownerGen
                return node (uint32 major) (uint32 minor) mode nodeOwner
            }

        let entry =
            if depth <= 0 then
                nodeGen
            else
                Gen.frequency
                    [
                        3, nodeGen
                        1,
                        devfsContentsGen (depth - 1)
                        |> Gen.map (fun children -> SeedEntry.Directory (children, bits 0o555, None))
                    ]

        Gen.zip nameGen entry |> Gen.listOf |> Gen.map (List.truncate 8 >> Map.ofList)

    [<Test>]
    let ``find /dev lists and reports exactly what the devfs was configured with`` () : unit =
        let property (contents : Map<DirectoryEntryName, SeedEntry>) =
            let system = bootedWith user501 Map.empty contents
            let bootSecond = UnixTimestamp.ofSeconds (UnixTimestamp.seconds bootTime)
            let dev = (reported "/dev" system).Inode

            UnixSystem.checkInvariants system |> shouldEqual []

            VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes system) (UnixSystem.fileSystem system)
            |> shouldEqual []

            let rec visit (path : string) (parent : InodeNumber) (entries : Map<DirectoryEntryName, SeedEntry>) =
                let status = reported path system

                // devfs's own rules: 8 bytes and its length per name, 2 links
                // and one per subdirectory, 512-byte blocks.
                status.Mode |> shouldEqual (0o040000 ||| 0o555)

                (UserId.toUInt32 status.UserId, GroupId.toUInt32 status.GroupId)
                |> shouldEqual (0u, 0u)

                status.Size
                |> shouldEqual (
                    entries
                    |> Map.toSeq
                    |> Seq.sumBy (fun (entry, _) -> int64 (PathText.ofName entry).Length + 8L)
                )

                status.LinkCount
                |> shouldEqual (
                    2L
                    + int64 (
                        entries
                        |> Map.filter (fun _ child ->
                            (match child with
                             | SeedEntry.Directory _ -> true
                             | _ -> false)
                        )
                        |> Map.count
                    )
                )

                status.AllocatedBlocks |> shouldEqual (Some ((status.Size + 511L) / 512L))
                status.IoBlockSize |> shouldEqual (Some 512L)

                let fd, system =
                    match DirectoryReading.openDirectory (UnixPath.parseOrFail context path) system with
                    | Ok fd, system -> fd, system
                    | Error error, _ -> failwith $"opening %s{path}: %O{error}"

                let records, _ = DirectoryReading.drain fd system

                for record in records do
                    match record.Name with
                    | PathComponent.Current -> record.Inode |> shouldEqual status.Inode
                    | PathComponent.Parent -> record.Inode |> shouldEqual parent
                    | PathComponent.Name _ -> ()

                records
                |> List.choose (fun record ->
                    match record.Name with
                    | PathComponent.Name entry -> Some entry
                    | _ -> None
                )
                |> List.sort
                |> shouldEqual (entries |> Map.keys |> List.ofSeq |> List.sort)

                for KeyValue (entry, seed) in entries do
                    let child = $"%s{path}/%s{PathText.ofName entry}"

                    match seed with
                    | SeedEntry.Directory (children, _, _) -> visit child status.Inode children
                    | SeedEntry.CharacterDevice (number, mode, nodeOwner) ->
                        let nodeStatus = reported child system
                        let nodeOwner = defaultArg nodeOwner rootOwner
                        nodeStatus.Mode |> shouldEqual (0o020000 ||| PermissionBits.toInt mode)

                        (nodeStatus.UserId, nodeStatus.GroupId)
                        |> shouldEqual (nodeOwner.User, nodeOwner.Group)

                        nodeStatus.SpecialFileDevice
                        |> shouldEqual (DeviceNumber.specialFileDevice SimulatedUnixFlavour.Darwin number)

                        nodeStatus.LinkCount |> shouldEqual 1L
                        nodeStatus.Size |> shouldEqual 0L
                        nodeStatus.IoBlockSize |> shouldEqual (Some 65536L)
                        nodeStatus.AllocatedBlocks |> shouldEqual (Some 0L)
                        nodeStatus.DeviceId |> shouldEqual DevfsMount.defaults.DeviceId
                        nodeStatus.BirthTime |> shouldEqual (Some UnixTimestamp.epoch)
                        nodeStatus.ModificationTime |> shouldEqual bootSecond

                        // No Darwin driver yet: opening a node is refused.
                        // A node whose mode denies uid 501 the read is EACCES
                        // first, as anywhere.
                        match OpenFlagWords.openPath (PathArg.ofText child) reading 0 system with
                        | Error (OpenRefusal.UndrivenDevice _) -> ()
                        | Ok (DescriptorAnswer.Failed UnixError.EACCES, _) when
                            PermissionBits.deniedTo (Standing.toward user501 nodeOwner) AccessRequest.Read mode
                            ->
                            ()
                        | other -> failwith $"opening %s{child}: %A{other}"
                    | other -> failwith $"%s{context}: a generated devfs holding %A{other}"

                // Every directory is devfs's: uid 501 may bind nothing there.
                // The name is outside the generator's alphabet, so it is free.
                match UnixNamespace.tryMkdir (Callers.leader system) (PathArg.ofText $"%s{path}/New") 0o755 system with
                | Ok (SyscallAnswer.Failed UnixError.EPERM, _) -> ()
                | other -> failwith $"mkdir %s{path}/New: %A{other}"

            visit "/dev" dev contents

        Check.One (config, Prop.forAll (Arb.fromGen (devfsContentsGen 2)) property)

    [<Test>]
    let ``devfs contents a Darwin kernel could not hold are refused`` () : unit =
        let image : UnixBootImage<int, string> = UnixSystem.initial darwin

        let refused (contents : Map<DirectoryEntryName, SeedEntry>) =
            UnixBootImage.tryWithDeviceFileSystem contents image |> Result.map ignore

        let long = name (System.String ('a', 32))

        refused (Map.ofList [ long, node 3u 2u 0o666 None ])
        |> shouldEqual (Error (DeviceFileSystemFault.NameTooLong (long, 31)))

        refused (Map.ofList [ name (System.String ('a', 31)), node 3u 2u 0o666 None ])
        |> shouldEqual (Ok ())

        refused (Map.ofList [ name "f", SeedEntry.file ImmutableArray.Empty ])
        |> shouldEqual (Error (DeviceFileSystemFault.NotMadeByDeviceFileSystem (name "f")))

        refused (Map.ofList [ name "d", SeedEntry.Directory (Map.empty, bits 0o755, None) ])
        |> shouldEqual (Error (DeviceFileSystemFault.DirectoryNotAsDevfsMakesIt (name "d", bits 0o755, rootOwner)))

        refused (Map.ofList [ name "d", SeedEntry.Directory (Map.empty, bits 0o555, Some (owner 501u 20u)) ])
        |> shouldEqual (Error (DeviceFileSystemFault.DirectoryNotAsDevfsMakesIt (name "d", bits 0o555, owner 501u 20u)))

        for number in [ DeviceNumber (256u, 0u) ; DeviceNumber (0u, 0x1000000u) ] do
            refused (Map.ofList [ name "n", SeedEntry.CharacterDevice (number, bits 0o666, None) ])
            |> shouldEqual (Error (DeviceFileSystemFault.NumberNotEncodable (name "n", number)))

        // Two spellings of one name, as APFS would compare them.
        let precomposed = name "é"
        let decomposed = name "é"

        match refused (Map.ofList [ precomposed, node 3u 2u 0o666 None ; decomposed, node 3u 3u 0o666 None ]) with
        | Error (DeviceFileSystemFault.NamesPossiblyEquivalent _) -> ()
        | other -> failwith $"possibly equivalent names: %A{other}"

        // On Linux, a devtmpfs takes 255 bytes and any number.
        UnixBootImage.tryWithDeviceFileSystem
            (Map.ofList [ long, SeedEntry.CharacterDevice (DeviceNumber (256u, 0u), bits 0o666, None) ])
            (UnixSystem.initial<int, string> linux)
        |> Result.isOk
        |> shouldEqual true

    [<Test>]
    let ``the boot time, the root filesystem and devfs may be set in any order`` () : unit =
        let property (contents : Map<DirectoryEntryName, SeedEntry>, seconds : int64, order : int) =
            let boot = UnixTimestamp.ofSeconds seconds

            let steps : (UnixBootImage<int, string> -> UnixBootImage<int, string>) list =
                [
                    UnixBootImage.withBootTime boot
                    Launched.fileSystem boot rootOwner probedSeed
                    fun image ->
                        UnixBootImage.tryWithDeviceFileSystem contents image
                        |> Configured.expectOk DeviceFileSystemFault.describe
                ]

            let permutations =
                [
                    [ 0 ; 1 ; 2 ]
                    [ 0 ; 2 ; 1 ]
                    [ 1 ; 0 ; 2 ]
                    [ 1 ; 2 ; 0 ]
                    [ 2 ; 0 ; 1 ]
                    [ 2 ; 1 ; 0 ]
                ]

            let build (permutation : int list) =
                permutation
                |> List.fold (fun image step -> steps.[step] image) (UnixSystem.initial darwin)
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
                |> UnixSystem.fileSystem

            build permutations.[order] |> shouldEqual (build [ 0 ; 1 ; 2 ])

        Check.One (
            config,
            Prop.forAll
                (Arb.fromGen (Gen.zip3 (devfsContentsGen 1) (Gen.choose64 (0L, 4_000_000_000L)) (Gen.choose (0, 5))))
                property
        )

    // ------------------------------------------------ the reviewer's walk

    [<Test>]
    let ``ls -l and find over the whole tree answer on both flavours`` () : unit =
        for platform in [ darwin ; linux ] do
            let system =
                UnixSystem.initial platform
                |> Launched.fileSystem bootTime rootOwner probedSeed
                |> Launched.bootWith (Launched.credentials rootCredentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let rec find (path : string) (system : UnixSystem<int, string>) : int =
                let fd, system =
                    match DirectoryReading.openDirectory (UnixPath.parseOrFail context path) system with
                    | Ok fd, system -> fd, system
                    | Error error, _ -> failwith $"%O{platform}: opening %s{path}: %O{error}"

                let records, system = DirectoryReading.drain fd system

                records
                |> List.sumBy (fun record ->
                    match record.Name with
                    | PathComponent.Name entry ->
                        let child =
                            if path = "/" then
                                $"/%s{PathText.ofName entry}"
                            else
                                $"%s{path}/%s{PathText.ofName entry}"

                        match lstat child system with
                        | Ok (FileStatusAnswer.Reported _) -> ()
                        | other -> failwith $"%O{platform}: lstat %s{child}: %A{other}"

                        match record.Kind with
                        | DirectoryEntryKind.Directory -> 1 + find child system
                        | _ -> 1
                    | _ -> 0
                )

            find "/" system |> shouldBeGreaterThan 8
