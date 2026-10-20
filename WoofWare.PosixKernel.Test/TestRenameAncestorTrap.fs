namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `rename(2)` whose destination is the source's own parent or an ancestor of
/// it, held to every row of every recording of `docs/probes/rename/ancestor-trap.py`.
///
/// Linux refuses that with ENOTEMPTY, and where that refusal sits against the
/// ENOTDIR a trailing separator over a non-directory earns moved in 6.19: up to
/// 6.18 the ENOTDIR wins, and from 6.19 the ENOTEMPTY does. So each Linux
/// recording is replayed at its own kernel's version, which is what selects the
/// ordering. Darwin has no such refusal, and its recording is replayed too.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestRenameAncestorTrap =

    /// One recording: its embedded resource, and the platform and caller it was
    /// measured on. The header line of each recording is checked against these.
    type private Recording =
        {
            Resource : string
            Platform : SimulatedUnixPlatform
            UserId : uint32
        }

    let private linux
        (major : uint32)
        (minor : uint32)
        (patch : uint32)
        (architecture : SimulatedUnixArchitecture)
        (release : string)
        : SimulatedUnixPlatform
        =
        SimulatedUnixPlatform.createOrFail
            "TestRenameAncestorTrap"
            (SimulatedUnixKernel.Linux
                {
                    Major = major
                    Minor = minor
                    Patch = patch
                })
            architecture
            SimulatedPageSize.FourKiB
            release

    /// Each recording, by the name its resource carries.
    let private recording (name : string) : Recording =
        let platform, userId =
            match name with
            | "linux-6.17-uid1001" -> SimulatedUnixPlatform.linuxX64, 1001u
            | "linux-6.17-uid0" -> SimulatedUnixPlatform.linuxX64, 0u
            | "linux-6.18-uid1000" -> linux 6u 18u 5u SimulatedUnixArchitecture.Arm64 "6.18.5", 1000u
            | "linux-6.18-uid0" -> linux 6u 18u 5u SimulatedUnixArchitecture.Arm64 "6.18.5", 0u
            | "linux-7.0-uid1001" -> linux 7u 0u 0u SimulatedUnixArchitecture.X64 "7.0.0-1017-azure", 1001u
            | "linux-7.0-uid0" -> linux 7u 0u 0u SimulatedUnixArchitecture.X64 "7.0.0-1017-azure", 0u
            | "darwin-uid501" -> SimulatedUnixPlatform.macOsArm64, 501u
            | _ -> failwith $"no recording is named %s{name}"

        {
            Resource = $"WoofWare.PosixKernel.Test.ancestor-trap.%s{name}.txt"
            Platform = platform
            UserId = userId
        }

    /// What one recording says: the header line, and each row's label with its
    /// answer (`OK` or an errno's name).
    let private read (resource : string) : string * (string * string) list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"embedded resource %s{resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        match
            reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> Array.toList
        with
        | [] -> failwith $"%s{resource} is empty"
        | header :: rows ->
            let rows =
                rows
                |> List.map (fun row ->
                    match row.LastIndexOf ':' with
                    | -1 -> failwith $"%s{resource}: unrecognised row: %s{row}"
                    | colon -> row.Substring(0, colon).TrimEnd (), row.Substring(colon + 1).Trim ()
                )

            header, rows

    /// One step of a row's tree, as the probe takes it: a directory, a file or a
    /// symlink at a path under the root, made the way `os.makedirs`,
    /// `open(..., "w")` and `os.symlink` make them (owned by the caller, at the
    /// modes a umask of 022 gives), or an `os.chmod` of one.
    type private Make =
        | Dir of path : string
        | File of path : string
        | Link of path : string * target : string
        | Mode of path : string * mode : int

    /// Each row's label, as the probe prints it, with the tree the probe builds
    /// for it (its `s1` to `s12`) and the two paths it renames.
    let private rows : (string * Make list * string * string) list =
        let s1 = [ Dir "a" ; File "a/f" ]
        let s2 = [ Dir "a" ; Dir "a/sub" ; Mode ("a", 0o555) ]
        let s3 = [ Dir "a" ; Dir "a/b" ; Dir "a/b/c" ; Mode ("a/b", 0o555) ]
        let s4 = [ Dir "a" ; Dir "a/sub" ]
        let s5 = [ Dir "a" ; Dir "a/b" ; Dir "a/b/c" ]
        let s7 = [ Dir "a" ; Link ("a/l", "x") ]
        let s8 = [ Dir "a" ; Dir "a/b" ; File "a/b/f" ; Mode ("a/b", 0o555) ]
        let s10 = [ Dir "a" ; Dir "a/b" ; File "a/b/f" ]
        let s12 = [ Dir "a" ; Dir "z" ; File "a/f" ]

        [
            "rename(a/f, a) f file", s1, "a/f", "a"
            "rename(a/sub, a) a 0555", s2, "a/sub", "a"
            "rename(a/b/c, a) a/b 0555", s3, "a/b/c", "a"
            "rename(a/sub, a) a 0755", s4, "a/sub", "a"
            "rename(a/b/c, a/b) parent", s5, "a/b/c", "a/b"
            "rename(a/b/c, a/b) parent 0555", s3, "a/b/c", "a/b"
            "rename(a/l, a) l symlink", s7, "a/l", "a"
            "rename(a/b/f, a) a/b 0555, f file", s8, "a/b/f", "a"
            "rename(a/f/, a) f file", s1, "a/f/", "a"
            "rename(a/f, a/) f file", s1, "a/f", "a/"
            "rename(a/f/, a/) f file", s1, "a/f/", "a/"
            "rename(a/l/, a) l symlink", s7, "a/l/", "a"
            "rename(a/b/f, a/) f file", s10, "a/b/f", "a/"
            "rename(a/b/f/, a) a/b 0555", s8, "a/b/f/", "a"
            "rename(a/sub/, a/) sub dir", s4, "a/sub/", "a/"
            "rename(a/f, z/) not an ancestor", s12, "a/f", "z/"
        ]

    let private buildTime : UnixTimestamp =
        UnixTimestamp.createOrFail "TestRenameAncestorTrap" 1_700_000_000L 0

    /// `makes` built into an empty filesystem on `platform`, every inode owned
    /// by `owner`.
    let private tree (platform : SimulatedUnixPlatform) (owner : InodeOwner) (makes : Make list) : VirtualFileSystem =
        let ok (result : Result<'a, UnixError>) : 'a =
            match result with
            | Ok value -> value
            | Error error -> failwith $"could not build the tree: %O{error}"

        let empty = VirtualFileSystem.empty EntryNameMatching.Bytes buildTime owner

        // Every inode made so far, by the path that made it; "" is the root.
        let parentAndName (made : Map<string, InodeNumber>) (path : string) : InodeNumber * DirectoryEntryName =
            let parent, name =
                match path.LastIndexOf '/' with
                | -1 -> "", path
                | slash -> path.Substring (0, slash), path.Substring (slash + 1)

            Map.find parent made, DirectoryEntryName.parseOrFail "TestRenameAncestorTrap" name

        makes
        |> List.fold
            (fun (made : Map<string, InodeNumber>, vfs : VirtualFileSystem) make ->
                match make with
                | Make.Dir path ->
                    let parent, name = parentAndName made path

                    let inode, vfs =
                        GraphMutators.createDirectory
                            parent
                            name
                            SeedEntry.defaultPermsForDirectory
                            owner
                            buildTime
                            vfs
                        |> ok

                    Map.add path inode made, vfs
                | Make.File path ->
                    let parent, name = parentAndName made path

                    let inode, vfs =
                        GraphMutators.createFile
                            parent
                            name
                            SeedEntry.defaultPermsForRegularFile
                            owner
                            buildTime
                            ImmutableArray<byte>.Empty
                            vfs
                        |> ok

                    Map.add path inode made, vfs
                | Make.Link (path, target) ->
                    let parent, name = parentAndName made path

                    let inode, vfs =
                        GraphMutators.createSymlink
                            parent
                            name
                            (SymlinkModes.at022 platform)
                            owner
                            buildTime
                            (SymlinkTarget.parseOrFail "TestRenameAncestorTrap" target)
                            vfs
                        |> ok

                    Map.add path inode made, vfs
                | Make.Mode (path, mode) ->
                    let bits = PermissionBits.parseOrFail "TestRenameAncestorTrap" mode
                    made, GraphMutators.setPermissions (Map.find path made) bits buildTime vfs
            )
            (Map.ofList [ "", VirtualFileSystem.root empty ], empty)
        |> snd

    /// A system on `platform` holding `vfs`, its process running with
    /// `credentials` from the root.
    let private system
        (platform : SimulatedUnixPlatform)
        (credentials : Credentials)
        (vfs : VirtualFileSystem)
        : UnixSystem<int, string>
        =
        let system : UnixSystem<int, string> =
            UnixSystem.initial platform
            |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

        Kernel.mapMachine
            (fun machine ->
                { machine with
                    CommittedFileSystem = CommittedFileSystem.initial vfs
                }
            )
            system
        |> Lone.mapProc (fun proc ->
            { proc with
                CurrentDirectoryInode = VirtualFileSystem.root vfs
            }
        )
        |> Lone.restand

    /// What the model answers for one row: `OK` or an errno's name.
    let private modelled (recording : Recording) (makes : Make list) (source : string) (destination : string) : string =
        let credentials =
            Credentials.ofIds
                (UserId.parseOrFail "TestRenameAncestorTrap" recording.UserId)
                (GroupId.parseOrFail "TestRenameAncestorTrap" recording.UserId)
                []

        let system =
            system recording.Platform credentials (tree recording.Platform (InodeOwner.ofProcess credentials) makes)

        match Eager.tryRename (PathArg.ofText source) (PathArg.ofText destination) system with
        | Ok (SyscallAnswer.Completed 0L, _) -> "OK"
        | Ok (SyscallAnswer.Failed error, _) -> string<UnixError> error
        | other -> failwith $"rename(%s{source}, %s{destination}): the model answered %A{other}"

    [<TestCase "linux-6.17-uid1001">]
    [<TestCase "linux-6.17-uid0">]
    [<TestCase "linux-6.18-uid1000">]
    [<TestCase "linux-6.18-uid0">]
    [<TestCase "linux-7.0-uid1001">]
    [<TestCase "linux-7.0-uid0">]
    [<TestCase "darwin-uid501">]
    let ``the model answers every row as the recording does`` (name : string) : unit =
        let recording = recording name
        let header, recorded = read recording.Resource

        let kernel =
            match SimulatedUnixPlatform.kernel recording.Platform with
            | SimulatedUnixKernel.Linux _ -> "Linux"
            | SimulatedUnixKernel.Darwin _ -> "Darwin"

        header
        |> shouldEqual $"%s{kernel} %s{SimulatedUnixPlatform.unixRelease recording.Platform} uid %d{recording.UserId}"

        // The probe and this table name the same rows, so neither can gain one
        // the other does not replay.
        recorded
        |> List.map fst
        |> shouldEqual (rows |> List.map (fun (label, _, _, _) -> label))

        let mismatches =
            List.zip recorded rows
            |> List.choose (fun ((label, answer), (_, makes, source, destination)) ->
                let model = modelled recording makes source destination

                if model = answer then
                    None
                else
                    Some $"%s{label}: measured %s{answer}, the model said %s{model}"
            )

        if not (List.isEmpty mismatches) then
            failwith (String.concat "\n" mismatches)
