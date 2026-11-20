namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The struct that `stat`, `lstat`, `fstat`, `fstatat`, `statfs` and `fstatfs`
/// copy out, given as a `UserBuffer`: the rows `stat-fault.c` measured
/// (`docs/probes/stat-output-buffer`), replayed on both flavours, and a
/// property that over every situation the probe's directory offers, a
/// destination changes only a reported answer: to EFAULT for one naming no
/// storage, and to a refusal for one with no address the model can use.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestStatDestination =

    let private context : string = "TestStatDestination"
    let private epoch : UnixTimestamp = UnixTimestamp.ofMillisecondsSinceEpoch 0L

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform =
        match flavour with
        | SimulatedUnixFlavour.Linux -> SimulatedUnixPlatform.linuxArm64
        | SimulatedUnixFlavour.Darwin -> SimulatedUnixPlatform.macOsArm64

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    // ------------------------------------------------------- the probe's directory

    /// Who ran the probe: uid 65534 in the Linux container (the probe drops to
    /// it from root), uid 501 (group 20) on Darwin.
    let private credentialsOf (flavour : SimulatedUnixFlavour) : Credentials =
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            Credentials.ofIds (UserId.parseOrFail context 65534u) (GroupId.parseOrFail context 65534u) []
        | SimulatedUnixFlavour.Darwin ->
            Credentials.ofIds (UserId.parseOrFail context 501u) (GroupId.parseOrFail context 20u) []

    /// What the probe made in its directory: a regular file `f` holding
    /// "hello", a directory `d`, a directory `d0` of mode 0 holding `x`, a link
    /// `l -> f` and a link `loop` to itself.
    let private seed : Map<DirectoryEntryName, SeedEntry> =
        Map.ofList
            [
                name "f",
                SeedEntry.File (ImmutableArray.CreateRange "hello"B, PermissionBits.parseOrFail context 0o644, None)
                name "d", SeedEntry.Directory (Map.empty, PermissionBits.parseOrFail context 0o755, None)
                name "d0",
                SeedEntry.Directory (
                    Map.ofList
                        [
                            name "x",
                            SeedEntry.File (ImmutableArray.Empty, PermissionBits.parseOrFail context 0o644, None)
                        ],
                    PermissionBits.parseOrFail context 0,
                    None
                )
                name "l", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "f", None)
                name "loop", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "loop", None)
            ]

    /// The probe's process, standing in its directory, holding the
    /// descriptors it opened: `f` read-write, `d` read-only, the read end of a
    /// pipe, a TCP socket and an event queue (an epoll instance on Linux, a
    /// kqueue on Darwin). Its standard input is a pipe it was launched with.
    type private Probe =
        {
            System : UnixSystem<int, string>
            File : int
            Directory : int
            PipeReadEnd : int
            Socket : int
            EventQueue : int
        }

    let private probeOn (flavour : SimulatedUnixFlavour) : Probe =
        let credentials = credentialsOf flavour
        let image : UnixBootImage<int, string> = UnixSystem.initial (platformOf flavour)

        let system =
            match UnixBootImage.tryWithFileSystem epoch (InodeOwner.ofProcess credentials) seed image with
            | Ok image ->
                Launched.bootWith
                    (Launched.credentials credentials
                     >> ProcessLaunch.withCurrentDirectory (AbsoluteUnixPath.parseOrFail context "/"))
                    UnixSystem.pipedStandardStreams
                    0
                    (CpuId 0)
                    image
            | Error fault -> failwith $"could not build the probe's directory: %A{fault}"

        let flags (access : FileAccessMode) (directory : bool) : OpenFlags =
            {
                Access = access
                Create = false
                Exclusive = false
                Truncate = false
                NoFollow = false
                CloseOnExec = false
                Synchronous = false
                DataSynchronous = false
                NonBlocking = false
                Directory = directory
            }

        let opened (path : string) (openFlags : OpenFlags) (system : UnixSystem<int, string>) =
            match Answered.openPath (UnixPath.parseOrFail context path) openFlags 0 system with
            | DescriptorAnswer.Returned fd, system -> fd, system
            | DescriptorAnswer.Failed error, _ -> failwith $"open(%s{path}) answered %O{error}"

        let file, system = opened "f" (flags FileAccessMode.ReadWrite false) system
        let directory, system = opened "d" (flags FileAccessMode.ReadOnly true) system

        let readEnd, system =
            match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
            | Ok (Pipe2Answer.Created (readFd, _), system) -> readFd, system
            | other -> failwith $"pipe2 did not make a pipe: %A{other}"

        let socket, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Default system

        let queue, system =
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"epoll_create1 did not make an instance: %A{other}"
            | SimulatedUnixFlavour.Darwin ->
                match UnixKqueue.tryKqueue (Callers.leader system) system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"kqueue did not make a queue: %A{other}"

        {
            System = system
            File = file
            Directory = directory
            PipeReadEnd = readEnd
            Socket = socket
            EventQueue = queue
        }

    /// A descriptor the probe's process does not hold.
    let private closedFd : int = 999

    /// The probe's `BADFLAG`, which neither flavour's `fstatat` accepts.
    let private badFlag : int = 0x1

    let private symlinkNoFollow (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0x100
        | SimulatedUnixFlavour.Darwin -> 0x20

    let private linuxEmptyPath : int = 0x1000

    let private atFdCwd (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> -100
        | SimulatedUnixFlavour.Darwin -> -2

    // ----------------------------------------------------------- the calls

    /// What one of this library's six functions answered, reduced to what the
    /// process sees: `Ok None` for success, `Ok (Some errno)` for a failure,
    /// and `Error` for a refusal, described.
    type private Seen = Result<UnixError option, string>

    let private ofStatus (describe : 'refusal -> string) (answer : Result<FileStatusAnswer, 'refusal>) : Seen =
        match answer with
        | Ok (FileStatusAnswer.Reported _) -> Ok None
        | Ok (FileStatusAnswer.Failed error) -> Ok (Some error)
        | Error refusal -> Error (describe refusal)

    let private ofStatistics
        (describe : 'refusal -> string)
        (answer : Result<FileSystemStatisticsAnswer, 'refusal>)
        : Seen
        =
        match answer with
        | Ok (FileSystemStatisticsAnswer.Reported _) -> Ok None
        | Ok (FileSystemStatisticsAnswer.Failed error) -> Ok (Some error)
        | Error refusal -> Error (describe refusal)

    /// One call the probe made, without its destination.
    [<RequireQualifiedAccess>]
    type private Call =
        | Stat of policy : SymlinkPolicy * path : PathArgumentBytes
        | FStat of fd : int
        | FStatAt of dirfd : int * path : PathArgumentBytes * flags : int
        | StatFs of path : PathArgumentBytes
        | FStatFs of fd : int

    let private make (probe : Probe) (call : Call) (destination : UserBuffer) : Seen =
        let system = probe.System
        let caller = Callers.leader system

        match call with
        | Call.Stat (policy, path) ->
            UnixPathResolution.tryStat caller policy path destination system
            |> ofStatus StatRefusal.describe
        | Call.FStat fd ->
            UnixPathResolution.tryFstat caller fd destination system
            |> ofStatus FStatRefusal.describe
        | Call.FStatAt (dirfd, path, flags) ->
            UnixPathResolution.tryFstatat caller dirfd path destination flags system
            |> ofStatus FStatAtRefusal.describe
        | Call.StatFs path ->
            UnixPathResolution.tryStatfs caller path destination system
            |> ofStatistics StatFsRefusal.describe
        | Call.FStatFs fd ->
            UnixPathResolution.tryFstatfs caller fd destination system
            |> ofStatistics BufferRefusal.describe

    let private text (path : string) : PathArgumentBytes = PathArg.ofText path

    /// The call each of the probe's rows names, by its call and case columns.
    let private callNamed (flavour : SimulatedUnixFlavour) (probe : Probe) (call : string) (case : string) : Call =
        let longName = String.replicate 300 "n"

        let path (case : string) : PathArgumentBytes =
            match case with
            | "file"
            | "cwd-file" -> text "f"
            | "symlink-to-file"
            | "symlink" -> text "l"
            | "missing" -> text "missing"
            | "empty" -> text ""
            | "file-as-directory" -> text "f/x"
            | "unsearchable" -> text "d0/x"
            | "long-name" -> text longName
            | "loop" -> text "loop"
            | "unreadable-path" -> PathArgumentBytes.Unreadable
            | other -> failwith $"the probe's %s{call} has no case %s{other}"

        let fd (case : string) : int =
            match case with
            | "file" -> probe.File
            | "directory" -> probe.Directory
            | "pipe-read-end" -> probe.PipeReadEnd
            | "inherited-pipe" -> 0
            | "socket" -> probe.Socket
            | "event-queue" -> probe.EventQueue
            | "negative-fd" -> -1
            | "closed-fd" -> closedFd
            | other -> failwith $"the probe's %s{call} has no case %s{other}"

        match call, case with
        | "stat", case -> Call.Stat (SymlinkPolicy.Follow, path case)
        | "lstat", case -> Call.Stat (SymlinkPolicy.NoFollowFinal, path case)
        | "fstat", case -> Call.FStat (fd case)
        | "fstatat", "cwd-file" -> Call.FStatAt (atFdCwd flavour, text "f", 0)
        | "fstatat", "dirfd-missing" -> Call.FStatAt (probe.Directory, text "missing", 0)
        | "fstatat", "closed-dirfd" -> Call.FStatAt (closedFd, text "f", 0)
        | "fstatat", "file-as-dirfd" -> Call.FStatAt (probe.File, text "x", 0)
        | "fstatat", "pipe-as-dirfd" -> Call.FStatAt (probe.PipeReadEnd, text "x", 0)
        | "fstatat", "bad-flag" -> Call.FStatAt (atFdCwd flavour, text "f", badFlag)
        | "fstatat", "bad-flag-missing" -> Call.FStatAt (atFdCwd flavour, text "missing", badFlag)
        | "fstatat", "nofollow-loop" -> Call.FStatAt (atFdCwd flavour, text "loop", symlinkNoFollow flavour)
        | "fstatat", "unsearchable" -> Call.FStatAt (atFdCwd flavour, text "d0/x", 0)
        | "fstatat", "empty-path-file" -> Call.FStatAt (probe.File, text "", linuxEmptyPath)
        | "fstatat", "empty-path-closed" -> Call.FStatAt (closedFd, text "", linuxEmptyPath)
        | "fstatat", "empty-path-pipe" -> Call.FStatAt (probe.PipeReadEnd, text "", linuxEmptyPath)
        | "fstatat", "empty-path-socket" -> Call.FStatAt (probe.Socket, text "", linuxEmptyPath)
        | "fstatat", "empty-path-null-path"
        | "fstatat", "empty-path-unreadable-path" ->
            Call.FStatAt (probe.File, PathArgumentBytes.Unreadable, linuxEmptyPath)
        | "fstatat", "empty-path-closed-null-path"
        | "fstatat", "empty-path-closed-unreadable-path" ->
            Call.FStatAt (closedFd, PathArgumentBytes.Unreadable, linuxEmptyPath)
        | "statfs", case -> Call.StatFs (path case)
        | "fstatfs", case -> Call.FStatFs (fd case)
        | call, case -> failwith $"the probe made no call %s{call} %s{case}"

    /// The destination each of the probe's `dest` columns names. The probe's
    /// `PROT_NONE` page is at an address of its own on each run; any address
    /// naming no storage stands for it.
    let private destinationNamed (column : string) : UserBuffer =
        match column with
        | "ok" -> UserBuffer.Mapped
        | "null" -> UserBuffer.Unmapped 0UL
        | "prot_none" -> UserBuffer.Unmapped 0x1_0000_0000UL
        | "high" -> UserBuffer.Unmapped 0xFFFF_FFFF_FFFF_F000UL
        | other -> failwith $"the probe has no destination %s{other}"

    // ------------------------------------------------------- the measured rows

    /// One row of a `stat-fault.c` output.
    type private Row =
        {
            Call : string
            Case : string
            Destination : string
            Returned : int
            Errno : string
        }

    let private rowsOf (flavour : SimulatedUnixFlavour) : Row list =
        let resource =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.stat-output-buffer.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.stat-output-buffer.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"no embedded resource %s{resource}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.choose (fun line ->
            let m = Regex.Match (line, @"^(\S+)\s+(\S+)\s+dest=(\S+)\s*: r=(-?\d+) errno=(\S+)")

            if m.Success then
                Some
                    {
                        Call = m.Groups.[1].Value
                        Case = m.Groups.[2].Value
                        Destination = m.Groups.[3].Value
                        Returned = int m.Groups.[4].Value
                        Errno = m.Groups.[5].Value
                    }
            else
                None
        )
        |> List.ofArray

    /// What the row says the process saw.
    let private measured (row : Row) : Seen =
        match row.Returned, row.Errno with
        | 0, "0" -> Ok None
        | -1, errno ->
            match UnixError.all |> List.tryFind (fun error -> error.ToString () = errno) with
            | Some error -> Ok (Some error)
            | None -> failwith $"a row names errno %s{errno}, which UnixError does not have"
        | returned, errno -> failwith $"a row returned %d{returned} with errno %s{errno}"

    /// The cases whose descriptor this kernel holds no status for: through
    /// storage the call is refused where the kernel succeeded, and through no
    /// storage it answers EFAULT, as the kernel did.
    let private statusUnknown : Set<string> =
        set [ "inherited-pipe" ; "socket" ; "event-queue" ; "empty-path-socket" ]

    /// Pairs of cases that `PathArgumentBytes.Unreadable` cannot tell apart:
    /// a NULL pathname and an unreadable one, under Linux's `AT_EMPTY_PATH`.
    /// The model answers what the two agree on, and is refused where they
    /// differ.
    let private indistinguishable : Map<string, string> =
        Map.ofList
            [
                "empty-path-null-path", "empty-path-unreadable-path"
                "empty-path-unreadable-path", "empty-path-null-path"
                "empty-path-closed-null-path", "empty-path-closed-unreadable-path"
                "empty-path-closed-unreadable-path", "empty-path-closed-null-path"
            ]

    [<TestCaseSource(nameof flavours)>]
    let ``every measured row answers as the kernel did`` (flavour : SimulatedUnixFlavour) : unit =
        let probe = probeOn flavour
        let rows = rowsOf flavour

        // A struct straddling the end of the storage is not something a
        // `UserBuffer` can express: Linux writes the bytes before the fault
        // (`changed=8/8`) and Darwin none, and both answer EFAULT.
        let replayed, straddling =
            rows |> List.partition (fun row -> row.Destination <> "straddle")

        let mismatches =
            replayed
            |> List.choose (fun row ->
                let seen =
                    make probe (callNamed flavour probe row.Call row.Case) (destinationNamed row.Destination)

                let partner =
                    Map.tryFind row.Case indistinguishable
                    |> Option.map (fun partner ->
                        replayed
                        |> List.find (fun other ->
                            other.Call = row.Call
                            && other.Case = partner
                            && other.Destination = row.Destination
                        )
                    )

                let agrees =
                    match seen, partner with
                    | _, Some partner when measured partner <> measured row ->
                        match seen with
                        | Error _ -> true
                        | Ok _ -> false
                    | Error _, None when
                        row.Call.StartsWith "fstat"
                        && statusUnknown.Contains row.Case
                        && row.Destination = "ok"
                        && row.Call <> "fstatfs"
                        ->
                        measured row = Ok None
                    | _, _ -> seen = measured row

                if agrees then
                    None
                else
                    Some
                        $"%s{row.Call} %s{row.Case} dest=%s{row.Destination}: measured %A{measured row}, model %A{seen}"
            )

        mismatches |> shouldEqual []

        // Every row the probe printed was read: six calls, each case at four
        // destinations and the straddle.
        straddling.Length |> shouldEqual (replayed.Length / 4)

        let expectedCases =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 47
            | SimulatedUnixFlavour.Darwin -> 39

        straddling.Length |> shouldEqual expectedCases

        // The rows reach both sides of the copy: some EFAULT that only the
        // destination caused, and some errno that beat it.
        replayed
        |> List.exists (fun row -> row.Destination <> "ok" && row.Errno = "EFAULT" && row.Case <> "unreadable-path")
        |> shouldEqual true

        replayed
        |> List.exists (fun row -> row.Destination <> "ok" && row.Errno <> "EFAULT" && row.Errno <> "0")
        |> shouldEqual true

    // ------------------------------------------------------------ the property

    let private pathGen : Gen<PathArgumentBytes> =
        Gen.frequency
            [
                8,
                Gen.elements
                    [
                        "f"
                        "l"
                        "d"
                        "d0"
                        "d0/x"
                        "missing"
                        ""
                        "f/x"
                        "loop"
                        "."
                        "/"
                        "d/"
                        "l/"
                        String.replicate 300 "n"
                    ]
                |> Gen.map text
                1, Gen.constant PathArgumentBytes.Unreadable
            ]

    let private callGen (flavour : SimulatedUnixFlavour) (probe : Probe) : Gen<Call> =
        let fd =
            Gen.elements
                [
                    probe.File
                    probe.Directory
                    probe.PipeReadEnd
                    probe.Socket
                    probe.EventQueue
                    0
                    1
                    2
                    -1
                    closedFd
                ]

        let dirfd = Gen.oneof [ fd ; Gen.constant (atFdCwd flavour) ]

        let flags =
            Gen.elements
                [
                    0
                    badFlag
                    symlinkNoFollow flavour
                    linuxEmptyPath
                    linuxEmptyPath ||| 0x100
                ]

        Gen.oneof
            [
                Gen.map2
                    (fun policy path -> Call.Stat (policy, path))
                    (Gen.elements [ SymlinkPolicy.Follow ; SymlinkPolicy.NoFollowFinal ])
                    pathGen
                Gen.map Call.FStat fd
                Gen.map3 (fun dirfd path flags -> Call.FStatAt (dirfd, path, flags)) dirfd pathGen flags
                Gen.map Call.StatFs pathGen
                Gen.map Call.FStatFs fd
            ]

    let private destinationGen : Gen<UserBuffer> =
        Gen.oneof
            [
                Gen.elements [ 0UL ; 0x1000UL ; 0x1_0000_0000UL ; 0xFFFF_FFFF_FFFF_F000UL ; UInt64.MaxValue ]
                |> Gen.map UserBuffer.Unmapped
                Gen.constant UserBuffer.Opaque
                Gen.constant UserBuffer.Addressless
            ]

    /// Whether `call` is refused through storage only for want of something
    /// that a destination naming no storage makes moot, so that through one it
    /// answers EFAULT: `fstat` of a descriptor this kernel holds no status for,
    /// though a real kernel reports one (a pipe the process was launched with,
    /// a socket or an event queue), the same through Linux's `AT_EMPTY_PATH`,
    /// and an unreadable pathname under `AT_EMPTY_PATH` with a `dirfd` whose
    /// status would be copied out.
    let private moot (flavour : SimulatedUnixFlavour) (probe : Probe) (call : Call) : bool =
        let unstated (fd : int) : bool =
            fd = 0 || fd = 1 || fd = 2 || fd = probe.Socket || fd = probe.EventQueue

        match call with
        | Call.FStat fd -> unstated fd
        | Call.FStatAt (fd, path, flags) ->
            flavour = SimulatedUnixFlavour.Linux
            && flags &&& linuxEmptyPath <> 0
            && flags &&& ~~~(linuxEmptyPath ||| 0x100) = 0
            && (path = text "" && unstated fd
                || path = PathArgumentBytes.Unreadable && fd <> -1 && fd <> closedFd)
        | Call.Stat _
        | Call.StatFs _
        | Call.FStatFs _ -> false

    /// What a call answers through `destination`, by what it answered through
    /// storage: a reported struct is copied out last, so a destination naming
    /// no storage turns it into EFAULT and one the model has no address for is
    /// refused; anything else the call answers stands, whatever the
    /// destination. A refusal that no storage makes `moot` is EFAULT through
    /// no storage too.
    let private reference (moot : bool) (throughStorage : Seen) (destination : UserBuffer) : Seen =
        match throughStorage, destination with
        | Ok None, UserBuffer.Unmapped _ -> Ok (Some UnixError.EFAULT)
        | Ok None, UserBuffer.Opaque -> Error (BufferRefusal.describe BufferRefusal.OpaqueAtTransfer)
        | Ok None, UserBuffer.Addressless -> Error (BufferRefusal.describe BufferRefusal.AddresslessAtTransfer)
        | Ok None, UserBuffer.Mapped -> throughStorage
        | Error _, UserBuffer.Unmapped _ when moot -> Ok (Some UnixError.EFAULT)
        | Ok (Some _), _
        | Error _, _ -> throughStorage

    [<TestCaseSource(nameof flavours)>]
    let ``a destination changes only a reported answer`` (flavour : SimulatedUnixFlavour) : unit =
        let probe = probeOn flavour
        let mutable reported = 0
        let mutable failed = 0

        let property (call : Call) (destination : UserBuffer) : unit =
            let throughStorage = make probe call UserBuffer.Mapped

            match throughStorage with
            | Ok None -> reported <- reported + 1
            | Ok (Some _) -> failed <- failed + 1
            | Error _ -> ()

            let seen = make probe call destination

            seen
            |> shouldEqual (reference (moot flavour probe call) throughStorage destination)

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 2000,
            Prop.forAll
                (Arb.fromGen (Gen.zip (callGen flavour probe) destinationGen))
                (fun (call, destination) -> property call destination)
        )

        // Both sides of the copy are explored.
        reported |> shouldBeGreaterThan 200
        failed |> shouldBeGreaterThan 200
