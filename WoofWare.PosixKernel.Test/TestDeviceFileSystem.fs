namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The device filesystem the kernel mounts over the root's `dev` at boot: a
/// devtmpfs holding `/dev/null` and `/dev/urandom` on Linux, and Darwin's devfs,
/// which is not modelled and so refuses every path that reaches it.
///
/// The constants are the rows `devices.c` and `mountpoint.c` measured on Linux
/// 6.18.5 (a devtmpfs at `/dev`, as root and as uid 1000) and Darwin 27.0 (uid
/// 501), in `docs/plans/2026-08-23-posix-kernel-extraction/`.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDeviceFileSystem =

    let private context : string = "TestDeviceFileSystem"

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 200

    let private linux : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64
    let private darwin : SimulatedUnixPlatform = SimulatedUnixPlatform.macOsArm64

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private rootOwner : InodeOwner =
        {
            User = UserId.root
            Group = GroupId.parseOrFail context 0u
        }

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

    let private creating : OpenFlags =
        { reading with
            Access = FileAccessMode.WriteOnly
            Create = true
        }

    /// A machine booted at `bootTime` with its first process as `configure` configures it,
    /// whose root, owned by root as a real one is, holds a file `f` and a
    /// directory `d`.
    let private bootedAtWith
        (configure : ProcessLaunch<int> -> ProcessLaunch<int>)
        (platform : SimulatedUnixPlatform)
        (bootTime : UnixTimestamp)
        : UnixSystem<int, string>
        =
        let seed =
            Map.ofList
                [
                    name "f", SeedEntry.File (ImmutableArray.Empty, PermissionBits.parseOrFail context 0o666, None)
                    name "d", SeedEntry.Directory (Map.empty, PermissionBits.parseOrFail context 0o777, None)
                ]

        let image : UnixBootImage<int, string> = UnixSystem.initial platform

        match UnixBootImage.tryWithFileSystem bootTime rootOwner seed image with
        | Ok image -> Launched.bootWith configure UnixSystem.pipedStandardStreams 0 (CpuId 0) image
        | Error fault -> failwith $"booting failed: %A{fault}"

    /// A machine booted at `bootTime` whose root, owned by root as a real one
    /// is, holds a file `f` and a directory `d`, and whose process is the
    /// flavour's default unprivileged user.
    let private bootedAt (platform : SimulatedUnixPlatform) (bootTime : UnixTimestamp) : UnixSystem<int, string> =
        bootedAtWith id platform bootTime

    let private booted (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        bootedAt platform (UnixTimestamp.ofSeconds 1_700_000_000L)

    /// `booted`, with the process root rather than the default user.
    let private bootedAsRoot (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        bootedAtWith
            (Launched.credentials (Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []))
            platform
            (UnixTimestamp.ofSeconds 1_700_000_000L)

    let private stat (path : string) (system : UnixSystem<int, string>) : Result<FileStatusAnswer, StatRefusal> =
        UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.Follow (PathArg.ofText path) system

    let private reported (path : string) (system : UnixSystem<int, string>) : FileStatus =
        match stat path system with
        | Ok (FileStatusAnswer.Reported status) -> status
        | other -> failwith $"stat %s{path}: expected a status, got %A{other}"

    let private failed (answer : SyscallAnswer * UnixSystem<int, string>) : UnixError option =
        match fst answer with
        | SyscallAnswer.Failed error -> Some error
        | SyscallAnswer.Completed _ -> None

    let private openFailed (answer : DescriptorAnswer * UnixSystem<int, string>) : UnixError option =
        match fst answer with
        | DescriptorAnswer.Failed error -> Some error
        | DescriptorAnswer.Returned _ -> None

    /// A name that is no device's: generated, so that no particular unlisted
    /// name is all that is checked.
    let private unknownNameGen : Gen<string> =
        gen {
            let! length = Gen.choose (1, 20)

            let! characters =
                Gen.elements ([ 'a' .. 'z' ] @ [ '0' .. '9' ] @ [ '.' ; '-' ; '_' ])
                |> Gen.listOfLength length

            return System.String (Array.ofList characters)
        }
        |> Gen.filter (fun text -> text <> "." && text <> ".." && text <> "null" && text <> "urandom")

    // ------------------------------------------------------------------ stat

    [<Test>]
    let ``every device's name, mode and Linux st_rdev are the measured ones, whether or not it has a driver``
        ()
        : unit
        =
        // Measured on Linux 6.18.5 and Darwin 27.0.0: mode 020666 for every
        // node (`devices.c` and `darwin-devfs.c`, STAT rows); Linux's mem
        // driver's 1,3, 1,5, 1,8 and 1,9, and `/dev/tty`'s 5,0, encoded by
        // glibc's `makedev`.
        let measured (device : CharacterDevice) : string * int * int64 =
            match device with
            | CharacterDevice.Null -> "null", 0o666, 0x103L
            | CharacterDevice.URandom -> "urandom", 0o666, 0x109L
            | CharacterDevice.Zero -> "zero", 0o666, 0x105L
            | CharacterDevice.Random -> "random", 0o666, 0x108L
            | CharacterDevice.Tty -> "tty", 0o666, 0x500L

        let everyDevice =
            Microsoft.FSharp.Reflection.FSharpType.GetUnionCases typeof<CharacterDevice>
            |> Array.map (fun case ->
                Microsoft.FSharp.Reflection.FSharpValue.MakeUnion (case, [||])
                |> unbox<CharacterDevice>
            )

        for device in everyDevice do
            let expectedName, expectedMode, expectedDevice = measured device
            CharacterDevice.name device |> shouldEqual (name expectedName)

            CharacterDevice.permissions device
            |> shouldEqual (PermissionBits.parseOrFail context expectedMode)

            CharacterDevice.number SimulatedUnixFlavour.Linux device
            |> DeviceNumber.specialFileDevice SimulatedUnixFlavour.Linux
            |> shouldEqual expectedDevice

    /// Any device number, weighted towards the small majors and minors real
    /// drivers register, so that the drivers' own numbers come up, and towards
    /// the edges of the bit fields an encoding splits each half into.
    let private deviceNumberGen : Gen<DeviceNumber> =
        // FsCheck's own `uint32` stays below its size, so it never reaches a
        // minor of 256, the first whose bits glibc's `makedev` moves.
        let anyUInt32 =
            Gen.map2
                (fun (high : int) (low : int) -> (uint32 high <<< 16) ||| uint32 low)
                (Gen.choose (0, 0xFFFF))
                (Gen.choose (0, 0xFFFF))

        let nearPowerOfTwo =
            gen {
                let! bit = Gen.choose (0, 31)
                let! offset = Gen.elements [ -1L ; 0L ; 1L ]
                return uint32 ((1L <<< bit) + offset)
            }

        let part =
            Gen.frequency [ 3, Gen.choose (0, 15) |> Gen.map uint32 ; 1, anyUInt32 ; 1, nearPowerOfTwo ]

        Gen.map2 (fun major minor -> DeviceNumber (major, minor)) part part

    [<Test>]
    let ``a number reaches a driver exactly when that driver is registered under it`` () : unit =
        let property (number : DeviceNumber) : unit =
            let registered =
                CharacterDevice.all
                |> List.filter (fun device -> CharacterDevice.number SimulatedUnixFlavour.Linux device = number)

            CharacterDevice.driverOf SimulatedUnixFlavour.Linux number
            |> shouldEqual (List.tryExactlyOne registered)

            // This kernel holds no device on Darwin.
            CharacterDevice.driverOf SimulatedUnixFlavour.Darwin number |> shouldEqual None

        Check.One (config, Prop.forAll (Arb.fromGen deviceNumberGen) property)

        // No two drivers share a number, and each driver's own reaches it.
        for device in CharacterDevice.all do
            CharacterDevice.number SimulatedUnixFlavour.Linux device
            |> CharacterDevice.driverOf SimulatedUnixFlavour.Linux
            |> shouldEqual (Some device)

    [<Test>]
    let ``st_rdev is the pair as glibc's makedev packs it`` () : unit =
        // glibc's `gnu_dev_major` and `gnu_dev_minor`, which undo `makedev`.
        let major (raw : int64) : uint32 =
            uint32 (((raw >>> 8) &&& 0xFFFL) ||| ((raw >>> 32) &&& ~~~0xFFFL))

        let minor (raw : int64) : uint32 =
            uint32 ((raw &&& 0xFFL) ||| ((raw >>> 12) &&& ~~~0xFFL))

        let property (number : DeviceNumber) : unit =
            let raw = DeviceNumber.specialFileDevice SimulatedUnixFlavour.Linux number
            DeviceNumber (major raw, minor raw) |> shouldEqual number

        Check.One (config, Prop.forAll (Arb.fromGen deviceNumberGen) property)

    [<Test>]
    let ``each device node reports the measured stat fields`` () : unit =
        let property (seconds : int64) : unit =
            let createdAt = UnixTimestamp.ofSeconds (abs seconds % 2_000_000_000L)
            let system = bootedAt linux createdAt

            for path, rawDevice in [ "/dev/null", 259L ; "/dev/urandom", 265L ] do
                let status = reported path system
                status.Mode |> shouldEqual 0o020666
                status.LinkCount |> shouldEqual 1L
                status.UserId |> shouldEqual UserId.root
                status.GroupId |> shouldEqual (GroupId.parseOrFail context 0u)
                status.Size |> shouldEqual 0L
                status.SpecialFileDevice |> shouldEqual rawDevice
                // devtmpfs's own device, which is not the root filesystem's.
                status.DeviceId |> shouldEqual DevtmpfsMount.defaults.DeviceId
                status.DeviceId |> shouldNotEqual (reported "/f" system).DeviceId
                // Made before the realtime clock was set, whenever the root
                // filesystem was made, and moved by nothing since (see the
                // timestamp tests below).
                status.AccessTime |> shouldEqual UnixTimestamp.epoch
                status.ModificationTime |> shouldEqual UnixTimestamp.epoch
                status.StatusChangeTime |> shouldEqual UnixTimestamp.epoch
                status.BirthTime |> shouldEqual None
                status.FileFlags |> shouldEqual None

                UnixPathResolution.tryStat
                    (Callers.leader system)
                    SymlinkPolicy.NoFollowFinal
                    (PathArg.ofText path)
                    system
                |> shouldEqual (Ok (FileStatusAnswer.Reported status))

            (reported "/dev/null" system).Inode
            |> shouldNotEqual (reported "/dev/urandom" system).Inode

        Check.One (config, Prop.forAll (Arb.fromGen (Gen.choose (0, System.Int32.MaxValue) |> Gen.map int64)) property)

    // ------------------------------------------------------------ timestamps

    /// Which of `withFileSystem` and `withBootTime` an image is built with, and
    /// in which order.
    [<RequireQualifiedAccess>]
    type private SetterOrder =
        | SeedThenBootTime
        | BootTimeThenSeed
        | SeedOnly
        | BootTimeOnly
        | Neither

    let private setterOrderGen : Gen<SetterOrder> =
        Gen.elements
            [
                SetterOrder.SeedThenBootTime
                SetterOrder.BootTimeThenSeed
                SetterOrder.SeedOnly
                SetterOrder.BootTimeOnly
                SetterOrder.Neither
            ]

    let private seeded (order : SetterOrder) : bool =
        match order with
        | SetterOrder.SeedThenBootTime
        | SetterOrder.BootTimeThenSeed
        | SetterOrder.SeedOnly -> true
        | SetterOrder.BootTimeOnly
        | SetterOrder.Neither -> false

    /// A Linux machine booted from an image built as `order` says, with a seed
    /// made at `createdAt` (holding an empty `dev` if `emptyDev`) and a boot
    /// time of `bootTime`.
    let private bootedFrom
        (order : SetterOrder)
        (createdAt : UnixTimestamp)
        (bootTime : UnixTimestamp)
        (emptyDev : bool)
        : UnixSystem<int, string>
        =
        let seed =
            [
                yield name "f", SeedEntry.file ImmutableArray.Empty
                if emptyDev then
                    yield name "dev", SeedEntry.directory Map.empty
            ]
            |> Map.ofList

        let withSeed (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
            Launched.fileSystem createdAt rootOwner seed image

        let withBootTime (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
            UnixBootImage.tryWithBootTime bootTime image
            |> Configured.expectOk BootTimeRefusal.describe

        let image : UnixBootImage<int, string> = UnixSystem.initial linux

        let image =
            match order with
            | SetterOrder.SeedThenBootTime -> image |> withSeed |> withBootTime
            | SetterOrder.BootTimeThenSeed -> image |> withBootTime |> withSeed
            | SetterOrder.SeedOnly -> withSeed image
            | SetterOrder.BootTimeOnly -> withBootTime image
            | SetterOrder.Neither -> image

        Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0) image

    let private timesOf (inode : InodeNumber) (system : UnixSystem<int, string>) : InodeTimes =
        match VirtualFileSystem.tryGet inode (UnixSystem.fileSystem system) with
        | Some inode -> inode.Times
        | None -> failwith $"inode %O{inode} is not in the filesystem"

    let private deviceRoot (system : UnixSystem<int, string>) : InodeNumber =
        match stat "/dev" system with
        | Error (StatRefusal.DeviceFileSystemRoot root) -> root
        | other -> failwith $"stat /dev: expected the device root's refusal, got %A{other}"

    let private atEpoch : InodeTimes =
        {
            Access = UnixTimestamp.epoch
            Modification = UnixTimestamp.epoch
            StatusChange = UnixTimestamp.epoch
            Birth = UnixTimestamp.epoch
        }

    let private timestampGen : Gen<UnixTimestamp> =
        Gen.choose (0, System.Int32.MaxValue)
        |> Gen.map (fun seconds -> UnixTimestamp.ofSeconds (int64 seconds))

    let private buildGen (createdAtGen : Gen<UnixTimestamp>) : Gen<SetterOrder * UnixTimestamp * UnixTimestamp * bool> =
        gen {
            let! order = setterOrderGen
            let! createdAt = createdAtGen
            let! bootTime = timestampGen

            let! emptyDev =
                if seeded order then
                    Gen.elements [ false ; true ]
                else
                    Gen.constant false

            return order, createdAt, bootTime, emptyDev
        }

    /// Every inode of the device filesystem, its root and each node, has all
    /// four times at the epoch, whatever the root filesystem's creation time
    /// and the boot time are, and in whichever order they were set.
    [<Test>]
    let ``the device filesystem is stamped at the epoch, whatever the setters say and in any order`` () : unit =
        let property (order : SetterOrder, createdAt : UnixTimestamp, bootTime : UnixTimestamp, emptyDev : bool) =
            let system = bootedFrom order createdAt bootTime emptyDev

            timesOf (deviceRoot system) system |> shouldEqual atEpoch

            for path in [ "/dev/null" ; "/dev/urandom" ] do
                let status = reported path system
                timesOf status.Inode system |> shouldEqual atEpoch
                status.AccessTime |> shouldEqual UnixTimestamp.epoch
                status.ModificationTime |> shouldEqual UnixTimestamp.epoch
                status.StatusChangeTime |> shouldEqual UnixTimestamp.epoch

        Check.One (config, Prop.forAll (Arb.fromGen (buildGen timestampGen)) property)

    /// Mounting the device filesystem over `/dev` changes nothing about the
    /// root directory's times, as a real mount touches no directory of the
    /// filesystem it covers: they are when the seed made the root, or the
    /// epoch for the empty root `UnixSystem.initial` makes.
    [<Test>]
    let ``mounting the device filesystem leaves the root's times as the seed made them`` () : unit =
        let property (order : SetterOrder, createdAt : UnixTimestamp, bootTime : UnixTimestamp, emptyDev : bool) =
            let system = bootedFrom order createdAt bootTime emptyDev

            let expected = if seeded order then createdAt else UnixTimestamp.epoch

            let status = reported "/" system
            status.AccessTime |> shouldEqual expected
            status.ModificationTime |> shouldEqual expected
            status.StatusChangeTime |> shouldEqual expected

            timesOf (VirtualFileSystem.root (UnixSystem.fileSystem system)) system
            |> shouldEqual
                {
                    Access = expected
                    Modification = expected
                    StatusChange = expected
                    Birth = expected
                }

        // Never the epoch, so that a root restamped at the epoch shows.
        let createdAtGen = timestampGen |> Gen.filter (fun t -> t <> UnixTimestamp.epoch)

        Check.One (config, Prop.forAll (Arb.fromGen (buildGen createdAtGen)) property)

    /// `docs/probes/devtmpfs-times`, three boots of Linux 6.18.5 aarch64: each
    /// node's four times are the realtime clock when devtmpfs made it, before
    /// the clock was first set, so within a few milliseconds of the epoch; the
    /// device root's access and birth times likewise. No read or write moved
    /// any of them. The model states that instant as the epoch itself.
    [<Test>]
    let ``the device filesystem's times are the measured ones, to within a few milliseconds`` () : unit =
        use stream =
            System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream
                "WoofWare.PosixKernel.Test.devtmpfs-times.linux.txt"

        if isNull stream then
            failwith $"%s{context}: no embedded devtmpfs-times probe output"

        use reader = new System.IO.StreamReader (stream)

        let time (label : string) (field : string) : decimal =
            if not (field.StartsWith (label + "=")) then
                failwith $"%s{context}: expected %s{label}= in the probe's row, got %s{field}"

            System.Decimal.Parse (field.Substring (label.Length + 1), System.Globalization.CultureInfo.InvariantCulture)

        // Each row: its label, the path, and its access, modification,
        // status-change and birth times.
        let rows =
            reader.ReadToEnd().Split ('\n', System.StringSplitOptions.RemoveEmptyEntries)
            |> Array.filter (fun line -> not (line.StartsWith "#"))
            |> Array.map (fun line -> line.Split ' ')
            |> Array.filter (fun fields -> fields.Length = 7)
            |> Array.map (fun fields ->
                fields.[0],
                fields.[1],
                [
                    time "atime" fields.[3]
                    time "mtime" fields.[4]
                    time "ctime" fields.[5]
                    time "birth" fields.[6]
                ]
            )

        let nearEpoch (t : decimal) : bool = t >= 0m && t < 0.01m

        // Three boots, each with a row per path before anything ran, and after
        // each round of reads and writes.
        rows
        |> Array.filter (fun (label, _, _) -> label = "STAT")
        |> Array.length
        |> shouldEqual 9

        rows |> Array.length |> shouldEqual 36

        for label, path, times in rows do
            match path, times with
            | "/dev/null", _
            | "/dev/urandom", _ ->
                if not (List.forall nearEpoch times) then
                    failwith $"%s{label} %s{path}: the probe measured times far from the epoch: %A{times}"
            | "/dev", [ atime ; _ ; _ ; birth ] ->
                // The device root's mtime and ctime are when its entries last
                // changed, which the container's init does after boot; this
                // library's machine runs no such init.
                if not (nearEpoch atime && nearEpoch birth) then
                    failwith $"%s{label} %s{path}: the probe measured times far from the epoch: %A{times}"
            | other, _ -> failwith $"%s{context}: the probe has no row for %s{other}"

        let system = booted linux

        for path in [ "/dev/null" ; "/dev/urandom" ] do
            timesOf (reported path system).Inode system |> shouldEqual atEpoch

        let rootTimes = timesOf (deviceRoot system) system
        rootTimes.Access |> shouldEqual UnixTimestamp.epoch
        rootTimes.Birth |> shouldEqual UnixTimestamp.epoch

    [<Test>]
    let ``the device filesystem's root is refused, for its size and link count`` () : unit =
        let system = booted linux

        for path in [ "/dev" ; "/dev/" ; "/dev/." ; "/d/../dev" ] do
            match stat path system with
            | Error (StatRefusal.DeviceFileSystemRoot _) -> ()
            | other -> failwith $"stat %s{path}: expected the device root's refusal, got %A{other}"

    [<Test>]
    let ``a name the device filesystem does not hold is refused, final or not`` () : unit =
        let system = booted linux

        let property (unknown : string) : unit =
            for path in [ $"/dev/%s{unknown}" ; $"/dev/%s{unknown}/x" ; $"/d/../dev/%s{unknown}" ] do
                match stat path system with
                | Error (StatRefusal.Path (PathRefusal.UnmodelledDeviceName (_, refused))) ->
                    refused |> shouldEqual (name unknown)
                | other -> failwith $"stat %s{path}: expected a refusal, got %A{other}"

            match OpenFlagWords.openPath (PathArg.ofText $"/dev/%s{unknown}") creating 0o644 system with
            | Error (OpenRefusal.Path (PathRefusal.UnmodelledDeviceName _)) -> ()
            | other -> failwith $"open(O_CREAT) /dev/%s{unknown}: expected a refusal, got %A{other}"

            match UnixNamespace.tryMkdir (Callers.leader system) (PathArg.ofText $"/dev/%s{unknown}") 0o755 system with
            | Error (PathRefusal.UnmodelledDeviceName _) -> ()
            | other -> failwith $"mkdir /dev/%s{unknown}: expected a refusal, got %A{other}"

        Check.One (config, Prop.forAll (Arb.fromGen unknownNameGen) property)

    [<Test>]
    let ``a path that continues through a device is ENOTDIR`` () : unit =
        let system = booted linux

        for path in [ "/dev/null/x" ; "/dev/null/" ; "/dev/urandom/." ] do
            stat path system |> shouldEqual (Ok (FileStatusAnswer.Failed UnixError.ENOTDIR))

    [<Test>]
    let ``dot-dot from the device filesystem's root is the root filesystem's root`` () : unit =
        let system = booted linux

        (reported "/dev/../dev/null" system)
        |> shouldEqual (reported "/dev/null" system)

        (reported "/dev/.." system) |> shouldEqual (reported "/" system)

        let _, system =
            Answered.chdir (Callers.leader system) (PathArg.ofText "/dev") system

        UnixPathResolution.currentDirectoryPath (Lone.pid system) system
        |> shouldEqual (Some (AbsoluteUnixPath.parseOrFail context "/dev"))

        (reported "null" system) |> shouldEqual (reported "/dev/null" system)

        let _, system = Answered.chdir (Callers.leader system) (PathArg.ofText "..") system

        UnixPathResolution.currentDirectoryPath (Lone.pid system) system
        |> shouldEqual (Some AbsoluteUnixPath.root)

    // ------------------------------------------------------------------ statfs

    [<Test>]
    let ``statfs of the device filesystem is devtmpfs's, through a node and through its root`` () : unit =
        let system = booted linux

        let expected =
            FileSystemStatisticsAnswer.Reported (
                FileSystemStatistics.Linux
                    {
                        TypeValue = 0x01021994L
                        GeometryResult =
                            Ok
                                {
                                    BlockSize = 4096L
                                    FragmentSize = 4096L
                                    NameLengthLimit = 255L
                                }
                        CapacityResult = Error CapacityRefusal.DeviceFileSystem
                        FileSystemIdResult =
                            Ok
                                {
                                    First = int32 0x544366deu
                                    Second = int32 0xad9235deu
                                }
                        FlagsResult = Ok 0x1022L
                    }
            )

        for path in [ "/dev" ; "/dev/null" ; "/dev/urandom" ] do
            Answered.statfs (Callers.leader system) (PathArg.ofText path) system
            |> shouldEqual expected

        let fd, system =
            match Answered.openPath (UnixPath.parseOrFail context "/dev") DirectoryReading.flags 0 system with
            | DescriptorAnswer.Returned fd, system -> fd, system
            | other -> failwith $"opening /dev: %A{other}"

        UnixPathResolution.fstatfs (Callers.leader system) fd system
        |> shouldEqual expected

        // The root filesystem is not the device filesystem.
        Answered.statfs (Callers.leader system) (PathArg.ofText "/f") system
        |> shouldNotEqual expected

    // ------------------------------------------------------------- listing

    [<Test>]
    let ``a listing of the root reports dev with the inode it covers`` () : unit =
        for platform in [ linux ; darwin ] do
            let system = booted platform

            let fd, system =
                match DirectoryReading.openDirectory (UnixPath.ofAbsolute AbsoluteUnixPath.root) system with
                | Ok fd, system -> fd, system
                | Error error, _ -> failwith $"opening /: %O{error}"

            let records, _ = DirectoryReading.drain fd system

            let dev =
                records
                |> List.filter (fun record -> record.Name = PathComponent.Name (name "dev"))
                |> List.exactlyOne

            dev.Kind |> shouldEqual DirectoryEntryKind.Directory

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux ->
                // `stat("/dev")` names the mounted root, which is refused, but
                // the refusal names the inode it would have reported.
                match stat "/dev" system with
                | Error (StatRefusal.DeviceFileSystemRoot mountedRoot) -> dev.Inode |> shouldNotEqual mountedRoot
                | other -> failwith $"stat /dev: expected the device root's refusal, got %A{other}"
            | SimulatedUnixFlavour.Darwin -> ()

    [<Test>]
    let ``the device filesystem holds a node for each device CharacterDevice.all lists, and no other device has one``
        ()
        : unit
        =
        // Read from the inode graph, since a listing of `/dev` is refused on
        // both flavours.
        for platform, expected in [ linux, CharacterDevice.all ; darwin, [] ] do
            let vfs = UnixSystem.fileSystem (booted platform)

            let mountedRoot =
                match VirtualFileSystem.tryGetContent (VirtualFileSystem.root vfs) vfs with
                | Some (InodeContent.Directory root) -> root.Entries.[name "dev"]
                | other -> failwith $"the root is not a directory: %A{other}"

            let entries =
                match VirtualFileSystem.tryGetContent mountedRoot vfs with
                | Some (InodeContent.Directory dev) ->
                    dev.Entries
                    |> Map.toList
                    |> List.map (fun (entry, inode) -> entry, VirtualFileSystem.tryGetContent inode vfs)
                | other -> failwith $"/dev is not a directory: %A{other}"

            entries
            |> shouldEqual (
                expected
                |> List.map (fun device ->
                    CharacterDevice.name device,
                    Some (
                        InodeContent.CharacterDevice (
                            CharacterDevice.number SimulatedUnixFlavour.Linux device,
                            CharacterDevice.permissions device
                        )
                    )
                )
                |> List.sortBy fst
            )

            VirtualFileSystem.inodes vfs
            |> Map.toList
            |> List.choose (fun (_, inode) ->
                match inode.Content with
                | InodeContent.CharacterDevice (number, _) ->
                    CharacterDevice.driverOf SimulatedUnixFlavour.Linux number
                | InodeContent.RegularFile _
                | InodeContent.Directory _
                | InodeContent.Symlink _
                | InodeContent.Socket _
                | InodeContent.Fifo _ -> None
            )
            |> List.sort
            |> shouldEqual (List.sort expected)

    [<Test>]
    let ``a listing of the device filesystem is refused, and so is its status`` () : unit =
        let system = booted linux

        let fd, system =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail context "/dev") system with
            | Ok fd, system -> fd, system
            | Error error, _ -> failwith $"opening /dev: %O{error}"

        match UnixNamespace.tryReadDirectoryEntry (Callers.leader system) fd system with
        | Error (ReadDirectoryRefusal.DeviceFileSystem _) -> ()
        | other -> failwith $"reading /dev: expected a refusal, got %A{other}"

        match UnixPathResolution.tryFstat (Callers.leader system) fd system with
        | Error (FStatRefusal.DeviceFileSystemRoot _) -> ()
        | other -> failwith $"fstat of /dev: expected a refusal, got %A{other}"

    // ---------------------------------------------------- the mount boundary

    [<Test>]
    let ``a rename across the mount is EXDEV, before either final name is looked up`` () : unit =
        // Measured on Linux as uid 1000 and as root alike, whether or not the
        // source exists and whether or not the destination is a name a real
        // devtmpfs holds.
        for system in [ booted linux ; bootedAsRoot linux ] do
            let rename (source : string) (destination : string) =
                Eager.tryRename (PathArg.ofText source) (PathArg.ofText destination) system

            for source, destination in
                [
                    "/f", "/dev/x"
                    "/d", "/dev/x"
                    "/dev/null", "/d/x"
                    "/dev/null", "/f"
                    "/f", "/dev/null"
                    "/dev/nonexistent", "/d/x"
                    "/nonexistent", "/dev/new"
                ] do
                match rename source destination with
                | Ok answer -> failed answer |> shouldEqual (Some UnixError.EXDEV)
                | Error refusal ->
                    failwith $"rename %s{source} -> %s{destination} was refused: %s{RenameRefusal.describe refusal}"

    [<Test>]
    let ``the mount point itself follows the measured rows`` () : unit =
        // The root is root's, mode 0755: uid 1000 may not change its names.
        let unprivileged = booted linux
        let root = bootedAsRoot linux

        let removal (result : Result<SyscallAnswer * UnixSystem<int, string>, RemovalRefusal>) =
            match result with
            | Ok answer -> failed answer
            | Error refusal -> failwith $"refused: %s{RemovalRefusal.describe refusal}"

        let renamed (system : UnixSystem<int, string>) (destination : string) =
            match Eager.tryRename (PathArg.ofText "/dev") (PathArg.ofText destination) system with
            | Ok answer -> failed answer
            | Error refusal -> failwith $"refused: %s{RenameRefusal.describe refusal}"

        removal (UnixNamespace.tryRmdir (Callers.leader unprivileged) (PathArg.ofText "/dev") unprivileged)
        |> shouldEqual (Some UnixError.EACCES)

        removal (UnixNamespace.tryRmdir (Callers.leader root) (PathArg.ofText "/dev") root)
        |> shouldEqual (Some UnixError.EBUSY)

        removal (UnixNamespace.tryUnlink (Callers.leader unprivileged) (PathArg.ofText "/dev") unprivileged)
        |> shouldEqual (Some UnixError.EACCES)

        removal (UnixNamespace.tryUnlink (Callers.leader root) (PathArg.ofText "/dev") root)
        |> shouldEqual (Some UnixError.EISDIR)

        for system in [ unprivileged ; root ] do
            removal (UnixNamespace.tryRmdir (Callers.leader system) (PathArg.ofText "/dev/.") system)
            |> shouldEqual (Some UnixError.EINVAL)

        renamed unprivileged "/devx" |> shouldEqual (Some UnixError.EACCES)
        renamed root "/devx" |> shouldEqual (Some UnixError.EBUSY)

        // Unmeasured: the mount point as the thing displaced.
        match Eager.tryRename (PathArg.ofText "/d") (PathArg.ofText "/dev") root with
        | Error (RenameRefusal.MountPoint _) -> ()
        | other -> failwith $"rename /d -> /dev: expected a refusal, got %A{other}"

        UnixNamespace.tryMkdir (Callers.leader unprivileged) (PathArg.ofText "/dev") 0o755 unprivileged
        |> Result.map failed
        |> shouldEqual (Ok (Some UnixError.EEXIST))

    /// Measured by `docs/probes/rename/mountpoint-self-rename.c` on Linux
    /// 6.18.5 aarch64, in a container whose `/dev` is a devtmpfs mount: renaming
    /// the mount point onto itself, under either spelling, answers 0 and moves
    /// nothing, as root and as uid 1000, where renaming it to another name is
    /// EBUSY and EACCES.
    [<Test>]
    let ``renaming the mount point onto itself succeeds and changes nothing`` () : unit =
        for system in [ booted linux ; bootedAsRoot linux ] do
            for destination in [ "/dev" ; "//dev" ] do
                match Eager.tryRename (PathArg.ofText "/dev") (PathArg.ofText destination) system with
                | Ok (answer, after) ->
                    answer |> shouldEqual (SyscallAnswer.Completed 0L)
                    after |> shouldEqual system
                | Error refusal ->
                    failwith $"rename /dev -> %s{destination} was refused: %s{RenameRefusal.describe refusal}"

    [<Test>]
    let ``a path ending in a dot component is on the filesystem it was taken from`` () : unit =
        // Linux's parent walk stops before the last component, so "/dev/.." and
        // "/dev/." are on the device filesystem whatever they reach.
        for system in [ booted linux ; bootedAsRoot linux ] do
            for source in [ "/dev/.." ; "/dev/." ] do
                match Eager.tryRename (PathArg.ofText source) (PathArg.ofText "/d/x") system with
                | Ok answer -> failed answer |> shouldEqual (Some UnixError.EXDEV)
                | Error refusal -> failwith $"rename %s{source}: refused: %s{RenameRefusal.describe refusal}"

            // And "/d/.." is on the root filesystem though it reaches the root.
            match Eager.tryRename (PathArg.ofText "/d/..") (PathArg.ofText "/dev/x") system with
            | Ok answer -> failed answer |> shouldEqual (Some UnixError.EXDEV)
            | Error refusal -> failwith $"rename /d/..: refused: %s{RenameRefusal.describe refusal}"

    [<Test>]
    let ``what the covered directory's own inode would decide is refused`` () : unit =
        // A sticky root consults the covered directory's owner, and a move to
        // another directory its write bit; this kernel holds neither.
        let unprivileged = booted linux

        let sticky =
            let root = bootedAsRoot linux

            match UnixPathResolution.tryChmod (Callers.leader root) (PathArg.ofText "/") 0o1777 root with
            | Ok (SyscallAnswer.Completed 0L, system) -> system
            | other -> failwith $"chmod / as root: %A{other}"

        // Root then gives up its privilege for an ordinary user's IDs.
        let sticky =
            Become.fully
                (Credentials.ofIds (UserId.parseOrFail context 1000u) (GroupId.parseOrFail context 1000u) [])
                sticky

        for removal in [ UnixNamespace.tryRmdir ; UnixNamespace.tryUnlink ] do
            match removal (Callers.leader sticky) (PathArg.ofText "/dev") sticky with
            | Error (RemovalRefusal.MountPoint _) -> ()
            | other -> failwith $"removing /dev from a sticky root: expected a refusal, got %A{other}"

        match Eager.tryRename (PathArg.ofText "/dev") (PathArg.ofText "/devx") sticky with
        | Error (RenameRefusal.MountPoint _) -> ()
        | other -> failwith $"renaming /dev in a sticky root: expected a refusal, got %A{other}"

        match Eager.tryRename (PathArg.ofText "/dev") (PathArg.ofText "/d/dev") (bootedAsRoot linux) with
        | Error (RenameRefusal.MountPoint _) -> ()
        | other -> failwith $"moving /dev to another directory: expected a refusal, got %A{other}"

    [<Test>]
    let ``no name in the device filesystem is created, removed or moved`` () : unit =
        let unprivileged = booted linux
        let root = bootedAsRoot linux

        // Its root is root's, mode 0755: uid 1000 is refused by the bits.
        match UnixNamespace.tryUnlink (Callers.leader unprivileged) (PathArg.ofText "/dev/null") unprivileged with
        | Ok answer -> failed answer |> shouldEqual (Some UnixError.EACCES)
        | Error refusal -> failwith $"refused: %s{RemovalRefusal.describe refusal}"

        match UnixNamespace.tryUnlink (Callers.leader root) (PathArg.ofText "/dev/null") root with
        | Error (RemovalRefusal.DeviceFileSystem (_, removed)) -> removed |> shouldEqual (name "null")
        | other -> failwith $"unlink /dev/null as root: expected a refusal, got %A{other}"

        match Eager.tryRename (PathArg.ofText "/dev/null") (PathArg.ofText "/dev/urandom") root with
        | Error (RenameRefusal.DeviceFileSystem _) -> ()
        | other -> failwith $"rename within /dev as root: expected a refusal, got %A{other}"

        match Eager.tryRename (PathArg.ofText "/dev/null") (PathArg.ofText "/dev/urandom") unprivileged with
        | Ok answer -> failed answer |> shouldEqual (Some UnixError.EACCES)
        | Error refusal -> failwith $"refused: %s{RenameRefusal.describe refusal}"

        // A device's name is taken.
        match
            OpenFlagWords.openPath
                (PathArg.ofText "/dev/null")
                { creating with
                    Exclusive = true
                }
                0o644
                root
        with
        | Ok answer -> openFailed answer |> shouldEqual (Some UnixError.EEXIST)
        | Error refusal -> failwith $"refused: %s{OpenRefusal.describe refusal}"

    [<Test>]
    let ``FICLONE between the device filesystem and the root filesystem is EXDEV`` () : unit =
        // Linux compares the two descriptors' mounts first, then whether either
        // is a directory: a directory on /dev against a file on / is EXDEV, as
        // a pipe against a file is.
        let system = booted linux

        let dev, system =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail context "/dev") system with
            | Ok fd, system -> fd, system
            | Error error, _ -> failwith $"opening /dev: %O{error}"

        let directory, system =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail context "/d") system with
            | Ok fd, system -> fd, system
            | Error error, _ -> failwith $"opening /d: %O{error}"

        let file, system =
            match
                Answered.openPath
                    (UnixPath.parseOrFail context "/f")
                    { reading with
                        Access = FileAccessMode.ReadWrite
                    }
                    0
                    system
            with
            | DescriptorAnswer.Returned fd, system -> fd, system
            | other -> failwith $"opening /f: %A{other}"

        UnixDescriptor.tryFileClone (Callers.leader system) file dev system
        |> shouldEqual (Ok (SyscallAnswer.Failed UnixError.EXDEV, system))

        UnixDescriptor.tryFileClone (Callers.leader system) dev file system
        |> shouldEqual (Ok (SyscallAnswer.Failed UnixError.EXDEV, system))
        // On one filesystem, the directory is what answers.
        UnixDescriptor.tryFileClone (Callers.leader system) file directory system
        |> shouldEqual (Ok (SyscallAnswer.Failed UnixError.EISDIR, system))

    // ------------------------------------------------------- the node itself

    /// `system` with the node at `/dev/null` holding `number` and `permissions`
    /// in place of its own.
    let private withNullHolding
        (number : DeviceNumber)
        (permissions : PermissionBits)
        (system : UnixSystem<int, string>)
        : InodeNumber * UnixSystem<int, string>
        =
        let inode = (reported "/dev/null" system).Inode

        let fileSystem =
            VirtualFileSystem.Unchecked.setContent
                inode
                (InodeContent.CharacterDevice (number, permissions))
                system.Machine.FileSystem

        inode,
        { system with
            Machine =
                { system.Machine with
                    CommittedFileSystem = CommittedFileSystem.initial fileSystem
                }
        }

    [<Test>]
    let ``a node whose number has no driver reports it, and opening it is refused once every check has passed``
        ()
        : unit
        =
        // Excluded by the drivers' own numbers rather than by `driverOf`, which
        // is under test: a `driverOf` that found a driver for every number
        // would leave a filter on it nothing to generate.
        let driven =
            CharacterDevice.all
            |> List.map (CharacterDevice.number SimulatedUnixFlavour.Linux)
            |> Set.ofList

        let undriven =
            deviceNumberGen |> Gen.filter (fun number -> not (Set.contains number driven))

        let property (number : DeviceNumber) : unit =
            let inode, system =
                withNullHolding number (PermissionBits.parseOrFail context 0o666) (booted linux)

            // Such a node is a state a machine can be in.
            UnixSystem.checkInvariants system |> shouldEqual []

            (reported "/dev/null" system).SpecialFileDevice
            |> shouldEqual (DeviceNumber.specialFileDevice SimulatedUnixFlavour.Linux number)

            for access in
                [
                    FileAccessMode.ReadOnly
                    FileAccessMode.WriteOnly
                    FileAccessMode.ReadWrite
                ] do
                match
                    OpenFlagWords.openPath
                        (PathArg.ofText "/dev/null")
                        { reading with
                            Access = access
                        }
                        0
                        system
                with
                | Error (OpenRefusal.UndrivenDevice (refusedInode, refusedNumber)) ->
                    refusedInode |> shouldEqual inode
                    refusedNumber |> shouldEqual number
                | other -> failwith $"open /dev/null holding %O{number}: expected a refusal, got %A{other}"

            // The open's own checks come first, and answer as they do for any
            // node: a root-only node is EACCES to the default user.
            let _, private' =
                withNullHolding number (PermissionBits.parseOrFail context 0o600) (booted linux)

            match OpenFlagWords.openPath (PathArg.ofText "/dev/null") reading 0 private' with
            | Ok answer -> openFailed answer |> shouldEqual (Some UnixError.EACCES)
            | Error refusal -> failwith $"refused: %s{OpenRefusal.describe refusal}"

            match
                OpenFlagWords.openPath
                    (PathArg.ofText "/dev/null")
                    { reading with
                        Directory = true
                    }
                    0
                    system
            with
            | Ok answer -> openFailed answer |> shouldEqual (Some UnixError.ENOTDIR)
            | Error refusal -> failwith $"refused: %s{OpenRefusal.describe refusal}"

        Check.One (config, Prop.forAll (Arb.fromGen undriven) property)


    [<Test>]
    let ``a device node is a node, whatever asks`` () : unit =
        let system = booted linux

        match
            OpenFlagWords.openPath
                (PathArg.ofText "/dev/null")
                { reading with
                    Directory = true
                }
                0
                system
        with
        | Ok answer -> openFailed answer |> shouldEqual (Some UnixError.ENOTDIR)
        | Error refusal -> failwith $"refused: %s{OpenRefusal.describe refusal}"

        Eager.tryAccess (PathArg.ofText "/dev/urandom") 6 system
        |> shouldEqual (Ok (SyscallAnswer.Completed 0L))

        Eager.tryAccess (PathArg.ofText "/dev/urandom") 1 system
        |> shouldEqual (Ok (SyscallAnswer.Failed UnixError.EACCES))

        UnixNamespace.tryReadlink (Callers.leader system) (PathArg.ofText "/dev/null") UserBuffer.Mapped 16 system
        |> shouldEqual (Ok (ReadLinkAnswer.Failed UnixError.EINVAL))

        Answered.chdir (Callers.leader system) (PathArg.ofText "/dev/null") system
        |> failed
        |> shouldEqual (Some UnixError.ENOTDIR)

        // Only the owner may change the mode, and root owns it.
        match UnixPathResolution.tryChmod (Callers.leader system) (PathArg.ofText "/dev/null") 0o666 system with
        | Ok answer -> failed answer |> shouldEqual (Some UnixError.EPERM)
        | Error refusal -> failwith $"refused: %s{ChModRefusal.describe refusal}"

        let root = bootedAsRoot linux

        match UnixPathResolution.tryChmod (Callers.leader root) (PathArg.ofText "/dev/null") 0o600 root with
        | Ok (SyscallAnswer.Completed 0L, changed) -> (reported "/dev/null" changed).Mode |> shouldEqual 0o020600
        | other -> failwith $"chmod /dev/null as root: %A{other}"

    // --------------------------------------------------------------- boot

    [<Test>]
    let ``a booted system is sound`` () : unit =
        for platform in [ linux ; darwin ] do
            UnixSystem.checkInvariants (booted platform) |> shouldEqual []

            UnixSystem.checkInvariants (
                UnixSystem.initial<int, string> platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            )
            |> shouldEqual []

    [<Test>]
    let ``a seed's empty dev is the directory the mount covers, and a populated one is refused`` () : unit =
        let system : UnixBootImage<int, string> = UnixSystem.initial linux

        let epoch = UnixTimestamp.ofSeconds 0L

        let emptyDev = Map.ofList [ name "dev", SeedEntry.directory Map.empty ]

        match UnixBootImage.tryWithFileSystem epoch rootOwner emptyDev system with
        | Ok image ->
            let booted = Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0) image
            (reported "/dev/null" booted).Mode |> shouldEqual 0o020666
            UnixSystem.checkInvariants booted |> shouldEqual []
        | Error fault -> failwith $"an empty dev was refused: %A{fault}"

        for populated in
            [
                SeedEntry.directory (Map.ofList [ name "x", SeedEntry.file ImmutableArray.Empty ])
                SeedEntry.file ImmutableArray.Empty
            ] do
            UnixBootImage.tryWithFileSystem epoch rootOwner (Map.ofList [ name "dev", populated ]) system
            |> Result.map ignore
            |> shouldEqual (Error (FileSystemSeedFault.SeedCoversDeviceFileSystem (name "dev")))

    [<Test>]
    let ``checkInvariants reports each forged mount defect`` () : unit =
        let system = booted linux
        let vfs = UnixSystem.fileSystem system

        let mountedRoot =
            match stat "/dev" system with
            | Error (StatRefusal.DeviceFileSystemRoot root) -> root
            | other -> failwith $"stat /dev: %A{other}"

        let mount =
            match VirtualFileSystem.mountOf mountedRoot vfs with
            | Some mount -> mount
            | None -> failwith "/dev is not a mount"

        let null' = (reported "/dev/null" system).Inode
        let file = (reported "/f" system).Inode

        VirtualFileSystem.checkInvariants Set.empty vfs |> shouldEqual []

        // A node recorded as on the root filesystem.
        VirtualFileSystem.Unchecked.setMountMember null' None vfs
        |> VirtualFileSystem.checkInvariants Set.empty
        |> shouldEqual
            [
                VirtualFileSystemDefect.MountMembershipMismatch (
                    mountedRoot,
                    Set.ofList [ mountedRoot ; (reported "/dev/urandom" system).Inode ],
                    Set.ofList [ mountedRoot ; null' ; (reported "/dev/urandom" system).Inode ]
                )
            ]

        // A covered number that an inode has.
        VirtualFileSystem.Unchecked.setMount
            mountedRoot
            (Some
                { mount with
                    Covered = file
                })
            vfs
        |> VirtualFileSystem.checkInvariants Set.empty
        |> shouldEqual [ VirtualFileSystemDefect.CoveredInodeInUse (mountedRoot, file) ]

        // A covered number the counter has not handed out.
        let unissued = VirtualFileSystem.nextInode vfs

        VirtualFileSystem.Unchecked.setMount
            mountedRoot
            (Some
                { mount with
                    Covered = unissued
                })
            vfs
        |> VirtualFileSystem.checkInvariants Set.empty
        |> shouldEqual [ VirtualFileSystemDefect.NextInodeNotFresh (unissued, unissued) ]

        // A mount whose root is a regular file.
        VirtualFileSystem.Unchecked.setMount file (Some mount) vfs
        |> VirtualFileSystem.checkInvariants Set.empty
        |> List.contains (VirtualFileSystemDefect.MountRootNotDirectory file)
        |> shouldEqual true

    // -------------------------------------------------------------- Darwin

    [<Test>]
    let ``on Darwin every path that reaches dev is refused`` () : unit =
        let system = booted darwin

        for path in [ "/dev" ; "/dev/null" ; "/dev/urandom" ; "/dev/x/y" ; "/d/../dev" ] do
            match stat path system with
            | Error (StatRefusal.Path (PathRefusal.UnmodelledFileSystem (_, MountedFileSystem.Devfs))) -> ()
            | other -> failwith $"stat %s{path} on Darwin: expected a refusal, got %A{other}"

        match UnixPathResolution.tryChdir (Callers.leader system) (PathArg.ofText "/dev") system with
        | Error (PathRefusal.UnmodelledFileSystem _) -> ()
        | other -> failwith $"chdir /dev on Darwin: expected a refusal, got %A{other}"
