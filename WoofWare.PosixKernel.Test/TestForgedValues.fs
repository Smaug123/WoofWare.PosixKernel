namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A value no constructor could have produced, such as one built with
/// `Unchecked.defaultof`, handed to a function that checks for one: each throws
/// `ArgumentException`, or `ArgumentNullException` for a null reference,
/// naming the parameter the client passed it as. And the throwing parsers,
/// which name the value they were handed.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestForgedValues =

    let private platform : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64

    let private launch : ProcessLaunch<int> =
        ProcessLaunch.create UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private image () : UnixBootImage<int, string> = UnixSystem.initial platform

    let private root : Credentials =
        Credentials.ofIds UserId.root (GroupId.parseOrFail "TestForgedValues" 0u) []

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail "TestForgedValues" text

    /// `f` throws exactly `'Exn`, naming `parameter`, with `operation` in its
    /// message.
    let private rejects<'Exn when 'Exn :> ArgumentException>
        (parameter : string)
        (operation : string)
        (f : unit -> unit)
        : unit
        =
        let exn = Assert.Throws<'Exn> (fun () -> f ())
        exn.ParamName |> shouldEqual parameter
        exn.Message |> shouldContainText operation

    [<Test>]
    let ``a null platform is the caller's mistake`` () : unit =
        let forged = Unchecked.defaultof<SimulatedUnixPlatform>

        rejects<ArgumentNullException>
            "platform"
            "UnixSystem.initial"
            (fun () -> UnixSystem.initial<int, string> forged |> ignore<UnixBootImage<int, string>>)

        rejects<ArgumentNullException>
            "platform"
            "ctx"
            (fun () -> SimulatedUnixPlatform.assertValid "ctx" forged |> ignore<SimulatedUnixPlatform>)

    [<Test>]
    let ``a forged launch setting is the caller's mistake`` () : unit =
        rejects<ArgumentException>
            "environment"
            "client config"
            (fun () ->
                ProcessLaunch.withEnvironment "client config" [ Unchecked.defaultof<UnixByteString> ] launch
                |> ignore<ProcessLaunch<int>>
            )

        rejects<ArgumentException>
            "path"
            "client config"
            (fun () ->
                ProcessLaunch.withProcessPath "client config" (Some Unchecked.defaultof<AbsoluteUnixPath>) launch
                |> ignore<ProcessLaunch<int>>
            )

        rejects<ArgumentException>
            "directory"
            "ProcessLaunch.withCurrentDirectory"
            (fun () ->
                ProcessLaunch.withCurrentDirectory Unchecked.defaultof<AbsoluteUnixPath> launch
                |> ignore<ProcessLaunch<int>>
            )

    [<Test>]
    let ``a forged boot setting is the caller's mistake`` () : unit =
        rejects<ArgumentException>
            "pid"
            "UnixBootImage.withProcessId"
            (fun () ->
                UnixBootImage.withProcessId Unchecked.defaultof<ProcessId> (image ())
                |> ignore<UnixBootImage<int, string>>
            )

        let forgedLink = SeedEntry.Symlink (Unchecked.defaultof<SymlinkTarget>, None)

        let seeds : Map<DirectoryEntryName, SeedEntry> list =
            [
                Map.ofList
                    [
                        Unchecked.defaultof<DirectoryEntryName>,
                        SeedEntry.File (ImmutableArray.Empty, PermissionBits.parseOrFail "TestForgedValues" 0o644, None)
                    ]
                Map.ofList [ name "link", forgedLink ]
                Map.ofList
                    [
                        name "d",
                        SeedEntry.Directory (
                            Map.ofList [ name "link", forgedLink ],
                            PermissionBits.parseOrFail "TestForgedValues" 0o755,
                            None
                        )
                    ]
            ]

        for seed in seeds do
            rejects<ArgumentException>
                "seed"
                "UnixBootImage.withFileSystem"
                (fun () ->
                    UnixBootImage.withFileSystem UnixTimestamp.epoch (InodeOwner.ofProcess root) seed (image ())
                    |> ignore<UnixBootImage<int, string>>
                )

    [<Test>]
    let ``forged path limits are the caller's mistake`` () : unit =
        let system = image () |> UnixBootImage.boot launch

        rejects<ArgumentException>
            "limits"
            "PathWalk.resolveExistingFromRoot"
            (fun () ->
                PathWalk.resolveExistingFromRoot
                    Unchecked.defaultof<PathLimits>
                    root
                    SymlinkProtection.Off
                    SymlinkPolicy.Follow
                    (UnixPath.parseOrFail "TestForgedValues" "/dev")
                    (UnixSystem.fileSystem system)
                |> ignore<Result<InodeNumber, UnixError>>
            )

        rejects<ArgumentException>
            "limits"
            "ctx"
            (fun () ->
                PathLimits.assertValid "ctx" Unchecked.defaultof<PathLimits>
                |> ignore<PathLimits>
            )

    [<Test>]
    let ``a forged byte string is the caller's mistake`` () : unit =
        let forged = Unchecked.defaultof<UnixByteString>

        rejects<ArgumentException>
            "bytes"
            "UnixPath.ofByteString"
            (fun () -> UnixPath.ofByteString forged |> ignore<UnixPath>)

        rejects<ArgumentException>
            "candidate"
            "AbsoluteUnixPath.ofByteString"
            (fun () ->
                AbsoluteUnixPath.ofByteString forged
                |> ignore<Result<AbsoluteUnixPath, AbsoluteUnixPathError>>
            )

        rejects<ArgumentException>
            "candidate"
            "DirectoryEntryName.ofByteString"
            (fun () ->
                DirectoryEntryName.ofByteString forged
                |> ignore<Result<DirectoryEntryName, FileNameError>>
            )

        rejects<ArgumentException>
            "candidate"
            "SymlinkTarget.ofByteString"
            (fun () ->
                SymlinkTarget.ofByteString forged
                |> ignore<Result<SymlinkTarget, SymlinkTargetError>>
            )

        rejects<ArgumentException>
            "s"
            "ctx"
            (fun () -> UnixByteString.assertValid "ctx" forged |> ignore<UnixByteString>)

    [<Test>]
    let ``assertValid names its own parameter`` () : unit =
        rejects<ArgumentException>
            "pid"
            "ctx"
            (fun () -> ProcessId.assertValid "ctx" Unchecked.defaultof<ProcessId> |> ignore<ProcessId>)

        rejects<ArgumentException>
            "name"
            "ctx"
            (fun () ->
                DirectoryEntryName.assertValid "ctx" Unchecked.defaultof<DirectoryEntryName>
                |> ignore<DirectoryEntryName>
            )

        rejects<ArgumentException>
            "path"
            "ctx"
            (fun () ->
                AbsoluteUnixPath.assertValid "ctx" Unchecked.defaultof<AbsoluteUnixPath>
                |> ignore<AbsoluteUnixPath>
            )

        rejects<ArgumentException>
            "target"
            "ctx"
            (fun () ->
                SymlinkTarget.assertValid "ctx" Unchecked.defaultof<SymlinkTarget>
                |> ignore<SymlinkTarget>
            )

    [<Test>]
    let ``parseOrFail and createOrFail name the value they were handed`` () : unit =
        rejects<ArgumentOutOfRangeException>
            "candidate"
            "ctx"
            (fun () -> ProcessId.parseOrFail "ctx" 0 |> ignore<ProcessId>)

        rejects<ArgumentException>
            "candidate"
            "ctx"
            (fun () -> UserId.parseOrFail "ctx" UInt32.MaxValue |> ignore<UserId>)

        rejects<ArgumentException>
            "candidate"
            "ctx"
            (fun () -> GroupId.parseOrFail "ctx" UInt32.MaxValue |> ignore<GroupId>)

        for candidate in [ -1 ; 0o10000 ] do
            rejects<ArgumentOutOfRangeException>
                "candidate"
                "ctx"
                (fun () -> PermissionBits.parseOrFail "ctx" candidate |> ignore<PermissionBits>)

        for nanoseconds in [ -1 ; 1_000_000_000 ] do
            rejects<ArgumentOutOfRangeException>
                "nanoseconds"
                "ctx"
                (fun () -> UnixTimestamp.createOrFail "ctx" 0L nanoseconds |> ignore<UnixTimestamp>)

        for candidate in [ "" ; "a/b" ; ".." ; "a\000b" ] do
            rejects<ArgumentException>
                "candidate"
                "ctx"
                (fun () -> DirectoryEntryName.parseOrFail "ctx" candidate |> ignore<DirectoryEntryName>)

        rejects<ArgumentException> "candidate" "ctx" (fun () -> UnixPath.parseOrFail "ctx" "a\000b" |> ignore<UnixPath>)

        for candidate in [ "" ; "relative" ] do
            rejects<ArgumentException>
                "candidate"
                "ctx"
                (fun () -> AbsoluteUnixPath.parseOrFail "ctx" candidate |> ignore<AbsoluteUnixPath>)

        rejects<ArgumentException>
            "candidate"
            "ctx"
            (fun () -> SymlinkTarget.parseOrFail "ctx" "" |> ignore<SymlinkTarget>)

    [<Test>]
    let ``PathLimits.create names the limit no Unix has`` () : unit =
        let bytes = NameLengthLimit.Bytes 255

        let create (traversals : int) (pathMax : int) (nameMax : NameLengthLimit) () : unit =
            PathLimits.create traversals pathMax nameMax SpliceLengthRecheck.NoRecheck
            |> ignore<PathLimits>

        rejects<ArgumentOutOfRangeException> "maxSymlinkTraversals" "PathLimits.create" (create 0 4096 bytes)
        rejects<ArgumentOutOfRangeException> "maxSymlinkTraversals" "PathLimits.create" (create 1024 32 bytes)
        rejects<ArgumentOutOfRangeException> "pathMaxBytes" "PathLimits.create" (create 40 255 bytes)
        rejects<ArgumentOutOfRangeException> "nameMax" "PathLimits.create" (create 40 4096 (NameLengthLimit.Bytes 0))

        rejects<ArgumentOutOfRangeException>
            "nameMax"
            "PathLimits.create"
            (create 40 4096 (NameLengthLimit.Utf16CodeUnitsOrBytes (0, 765)))

        rejects<ArgumentOutOfRangeException>
            "nameMax"
            "PathLimits.create"
            (create 40 4096 (NameLengthLimit.Utf16CodeUnitsOrBytes (255, 0)))

    [<Test>]
    let ``SimulatedUnixPlatform.createOrFail names the release, and refuses an unmeasured kernel`` () : unit =
        let linux = SimulatedUnixPlatform.kernel SimulatedUnixPlatform.linuxX64

        rejects<ArgumentException>
            "release"
            "ctx"
            (fun () ->
                SimulatedUnixPlatform.createOrFail
                    "ctx"
                    linux
                    SimulatedUnixArchitecture.X64
                    SimulatedPageSize.FourKiB
                    "6.8.0\u0000bad"
                |> ignore<SimulatedUnixPlatform>
            )

        let exn =
            Assert.Throws<UnmodelledException> (fun () ->
                SimulatedUnixPlatform.createOrFail
                    "ctx"
                    linux
                    SimulatedUnixArchitecture.Arm64
                    SimulatedPageSize.SixtyFourKiB
                    "6.18.5"
                |> ignore<SimulatedUnixPlatform>
            )

        exn.Message |> shouldContainText "ctx"

    [<Test>]
    let ``reading a forged byte string's bytes is the caller's mistake`` () : unit =
        let forged = Unchecked.defaultof<UnixByteString>

        for read in
            [
                fun () -> UnixByteString.length forged |> ignore<int>
                fun () -> UnixByteString.toBytes forged |> ignore<ImmutableArray<byte>>
                fun () -> UnixByteString.toEscaped forged |> ignore<string>
            ] do
            let exn = Assert.Throws<ArgumentException> (fun () -> read ())
            exn.Message |> shouldContainText "Unchecked.defaultof"
