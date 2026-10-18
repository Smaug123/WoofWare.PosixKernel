namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// How long a symbolic link's target `UnixBootImage.withFileSystem` admits in
/// a seed: exactly what `symlink(2)` on the same machine would store, held to
/// `docs/probes/symlink-target-length`'s rows (on tmpfs and ext4 under Linux,
/// on APFS and HFS+ under Darwin) and to the syscall itself under every mount
/// the flavour can report.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSeedSymlinkTarget =

    let private context : string = "TestSeedSymlinkTarget"

    let private createdAt : UnixTimestamp =
        UnixTimestamp.createOrFail context 1_700_000_000L 0

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private targetOfLength (length : int) : SymlinkTarget =
        SymlinkTarget.parseOrFail context (String ('a', length))

    let private flavours : (SimulatedUnixPlatform * SimulatedUnixFlavour) list =
        [
            SimulatedUnixPlatform.linuxX64, SimulatedUnixFlavour.Linux
            SimulatedUnixPlatform.linuxArm64, SimulatedUnixFlavour.Linux
            SimulatedUnixPlatform.macOsArm64, SimulatedUnixFlavour.Darwin
        ]

    /// Every mount a machine of `flavour` may claim, by `withMount`.
    let private mountsOf (flavour : SimulatedUnixFlavour) : EmulatedMount list =
        [
            EmulatedFileSystemType.Tmpfs
            EmulatedFileSystemType.Apfs
            EmulatedFileSystemType.Nfs
        ]
        |> List.filter (EmulatedFileSystemType.isReportableUnder flavour)
        |> List.map EmulatedMount.defaultOf

    let private image (platform : SimulatedUnixPlatform) (mount : EmulatedMount) : UnixBootImage<int, string> =
        UnixSystem.initial<int, string> platform
        |> UnixBootImage.tryWithMount (Some mount)
        |> Configured.expectOk MountRefusal.describe

    let private trySeed
        (entries : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<int, string>)
        : Result<UnixBootImage<int, string>, FileSystemSeedFault>
        =
        UnixBootImage.tryWithFileSystem createdAt Owners.linuxDefault entries image

    /// Whether the seed holding just `/l` with a target of `length` bytes is
    /// admitted, as "ok", or the fault it is refused with.
    let private seedAnswer (length : int) (image : UnixBootImage<int, string>) : string =
        match trySeed (Map.ofList [ name "l", SeedEntry.Symlink (targetOfLength length, None) ]) image with
        | Ok _ -> "ok"
        | Error fault -> $"%A{fault}"

    /// What the `symlink(2)` or `symlinkat(2)` (from `AT_FDCWD`) of a target
    /// of `length` bytes at `/l` answers on a booted machine, as the probe
    /// prints it: "ok" with the link's `readlink` and `st_size`, or the errno.
    /// On NFS, where `lstat` refuses, the `st_size` reads "refused".
    let private syscallAnswer (at : bool) (length : int) (image : UnixBootImage<int, string>) : string =
        let system = Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0) image

        let target = PathArg.ofText (String ('a', length))
        let path = PathArg.ofText "/l"

        let answer =
            if at then
                let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
                Eager.trySymlinkatAs (Callers.leader system) target (AtDirectory.atFdCwd flavour) path system
            else
                Eager.trySymlink target path system

        match answer with
        | Error refusal -> $"refused: %s{SymlinkRefusal.describe refusal}"
        | Ok (SyscallAnswer.Failed error, _) -> $"%A{error}"
        | Ok (SyscallAnswer.Completed _, after) ->
            let readlink =
                match UnixNamespace.tryReadlink (Callers.leader after) path UserBuffer.Mapped 8192 after with
                | Ok (ReadLinkAnswer.Reported reported) ->
                    if Seq.forall ((=) (byte 'a')) reported then
                        $"%d{Seq.length reported}(same bytes)"
                    else
                        $"%d{Seq.length reported}(DIFFERENT BYTES)"
                | other -> $"%A{other}"

            let size =
                match UnixPathResolution.tryStat (Callers.leader after) SymlinkPolicy.NoFollowFinal path after with
                | Ok (FileStatusAnswer.Reported status) -> $"%d{status.Size}"
                | Error (StatRefusal.OnNfsMount _) -> "refused"
                | other -> $"%A{other}"

            $"ok readlink=%s{readlink} st_size=%s{size}"

    // ------------------------------------------------------------ the probe's output

    /// The probe's rows for one flavour: the filesystem each was measured on,
    /// whether it was `symlinkat`, the target's length, and the answer.
    let private probeRows (resource : string) : (string * bool * int * string) list =
        use stream = Assembly.GetExecutingAssembly().GetManifestResourceStream resource

        if isNull stream then
            failwith $"%s{context}: no embedded resource %s{resource}"

        use reader = new StreamReader (stream)

        let lines =
            reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> List.ofArray

        let rec go (fileSystem : string) (lines : string list) : (string * bool * int * string) list =
            match lines with
            | [] -> []
            | line :: rest when line.StartsWith "dir=" -> go (line.Split(' ').[1]) rest
            | line :: rest when line.StartsWith "symlink" ->
                let call, afterCall = line.Split(' ', 2).[0], line.Split(' ', 2).[1].TrimStart ()
                let colon = afterCall.IndexOf ':'
                let length = Int32.Parse (afterCall.Substring(0, colon).Replace ("len=", ""))
                let answer = afterCall.Substring(colon + 1).Trim ()
                (fileSystem, (call = "symlinkat"), length, answer) :: go fileSystem rest
            | _ :: rest -> go fileSystem rest

        go "" lines

    let private replay (resource : string) (flavour : SimulatedUnixFlavour) : unit =
        let rows = probeRows resource

        // The probe measured both sides of the boundary, on more than one
        // filesystem, or this replay proves nothing about the boundary.
        rows
        |> List.map (fun (fs, _, _, _) -> fs)
        |> List.distinct
        |> List.length
        |> shouldBeGreaterThan 1

        rows
        |> List.exists (fun (_, _, _, answer) -> answer.StartsWith "ok")
        |> shouldEqual true

        rows
        |> List.exists (fun (_, _, _, answer) -> answer = "ENAMETOOLONG")
        |> shouldEqual true

        let mismatches =
            [
                for platform, f in flavours do
                    if f = flavour then
                        for mount in mountsOf flavour do
                            let image = image platform mount

                            for fileSystem, at, length, measured in rows do
                                let call = if at then "symlinkat" else "symlink"

                                let label =
                                    $"%O{platform} %A{mount} (measured on %s{fileSystem}) %s{call} len=%d{length}"

                                let modelled = syscallAnswer at length image

                                // The probe measured no NFS mount, and `lstat`
                                // refuses on one: only its `st_size` differs.
                                let measured =
                                    match EmulatedMount.fileSystemType mount with
                                    | EmulatedFileSystemType.Nfs when measured.StartsWith "ok" ->
                                        measured.Substring (0, measured.IndexOf " st_size=") + " st_size=refused"
                                    | _ -> measured

                                if modelled <> measured then
                                    yield $"%s{label}: measured %s{measured}, the syscall answered %s{modelled}"

                                let expectedSeed =
                                    if measured.StartsWith "ok" then
                                        "ok"
                                    else
                                        let fault = FileSystemSeedFault.SeedSymlinkTargetTooLong (name "l", flavour)
                                        $"%A{fault}"

                                let seeded = seedAnswer length image

                                if seeded <> expectedSeed then
                                    yield $"%s{label}: measured %s{measured}, the seed answered %s{seeded}"
            ]

        mismatches |> shouldEqual []

    [<Test>]
    let ``every Linux row the probe measured is answered as measured, by the syscall and the seed`` () : unit =
        replay "WoofWare.PosixKernel.Test.symlink-target-length.linux.txt" SimulatedUnixFlavour.Linux

    [<Test>]
    let ``every Darwin row the probe measured is answered as measured, by the syscall and the seed`` () : unit =
        replay "WoofWare.PosixKernel.Test.symlink-target-length.darwin.txt" SimulatedUnixFlavour.Darwin

    // ------------------------------------------------------------ against the syscall

    /// The seed admits a target exactly when `symlink(2)` on the same machine,
    /// under the same mount, would create a link holding it; and a seeded link
    /// reports its target's length as its `st_size`, as a created one does.
    [<Test>]
    let ``a seed admits a link target exactly when symlink would store it`` () : unit =
        let gen =
            gen {
                let! platform, flavour = Gen.elements flavours
                let! mount = Gen.elements (mountsOf flavour)
                // Weighted to the two flavours' boundaries.
                let! length =
                    Gen.frequency
                        [
                            1, Gen.choose (1, 9000)
                            2, Gen.choose (1020, 1028)
                            2, Gen.choose (4092, 4100)
                        ]

                return platform, flavour, mount, length
            }

        let property (platform : SimulatedUnixPlatform, flavour : SimulatedUnixFlavour, mount, length : int) =
            let image = image platform mount
            let created = syscallAnswer false length image

            match trySeed (Map.ofList [ name "l", SeedEntry.Symlink (targetOfLength length, None) ]) image with
            | Ok seeded ->
                if not (created.StartsWith "ok") then
                    failwith $"the seed admitted a target of %d{length} bytes, but symlink answered %s{created}"

                let system = Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0) seeded

                match
                    UnixPathResolution.tryStat
                        (Callers.leader system)
                        SymlinkPolicy.NoFollowFinal
                        (PathArg.ofText "/l")
                        system
                with
                | Ok (FileStatusAnswer.Reported status) -> status.Size |> shouldEqual (int64 length)
                | Error (StatRefusal.OnNfsMount _) when EmulatedMount.fileSystemType mount = EmulatedFileSystemType.Nfs ->
                    ()
                | other -> failwith $"lstat of a seeded link answered %A{other}"
            | Error fault ->
                created |> shouldEqual "ENAMETOOLONG"

                fault
                |> shouldEqual (FileSystemSeedFault.SeedSymlinkTargetTooLong (name "l", flavour))

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen gen) (fun row -> property row))

    [<Test>]
    let ``a target past the flavour's limit is refused wherever the link sits`` () : unit =
        let nested (length : int) : Map<DirectoryEntryName, SeedEntry> =
            Map.ofList
                [
                    name "outer",
                    SeedEntry.directory (
                        Map.ofList
                            [
                                name "inner",
                                SeedEntry.directory (
                                    Map.ofList [ name "deep", SeedEntry.Symlink (targetOfLength length, None) ]
                                )
                            ]
                    )
                ]

        for platform, flavour in flavours do
            let image = UnixSystem.initial<int, string> platform
            let pathMax = PathLimits.pathMaxBytes (SimulatedUnixPlatform.pathLimits platform)

            trySeed (nested pathMax) image
            |> Result.map ignore
            |> shouldEqual (Error (FileSystemSeedFault.SeedSymlinkTargetTooLong (name "deep", flavour)))

            match trySeed (nested (pathMax - 1)) image with
            | Ok _ -> ()
            | Error fault -> failwith $"%O{platform}: a target of PATH_MAX - 1 bytes is admitted, but got %A{fault}"
