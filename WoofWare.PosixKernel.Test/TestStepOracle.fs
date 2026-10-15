namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Text
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSystem.step` of each call it makes is that call made through its own
/// function: the same answer in the same `SteppedCall` case, the same refusal,
/// or the same exception. `reference` makes each call as a client holding
/// every argument would, through the call's function and then each
/// resumption, and each property generates calls of one case, by any thread,
/// on worlds a few generated calls have moved.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestStepOracle =

    let private context : string = "TestStepOracle"

    /// Each call the way a client makes it through the call's own function,
    /// and its resumptions, as the `SteppedCall` case `step` answers.
    let private reference
        (caller : Caller<int>)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Result<SteppedCall<int, string>, SyscallRefusal<int>>
        =
        match call with
        | Syscall.Dup fd ->
            UnixDescriptor.tryDup caller fd system
            |> Result.map SteppedCall.Dup
            |> Result.mapError SyscallRefusal.Dup
        | Syscall.Dup2 (oldFd, newFd) ->
            UnixDescriptor.tryDup2 caller oldFd newFd system
            |> Result.map SteppedCall.Dup2
            |> Result.mapError SyscallRefusal.Dup2
        | Syscall.Dup3 (oldFd, newFd, flags) ->
            UnixDescriptor.tryDup3 caller oldFd newFd flags system
            |> Result.map SteppedCall.Dup3
            |> Result.mapError SyscallRefusal.Dup3
        | Syscall.Fcntl (fd, command, argument) ->
            UnixDescriptor.tryFcntl caller fd command argument system
            |> Result.map SteppedCall.Fcntl
            |> Result.mapError SyscallRefusal.Fcntl
        | Syscall.LSeek (fd, offset, whence) ->
            UnixDescriptor.tryLseek caller fd offset whence system
            |> Result.map SteppedCall.LSeek
            |> Result.mapError SyscallRefusal.LSeek
        | Syscall.FLock (fd, operation) ->
            UnixDescriptor.tryFlock caller fd operation system
            |> Result.map SteppedCall.FLock
            |> Result.mapError SyscallRefusal.FLock
        | Syscall.FTruncate (fd, length) ->
            UnixDescriptor.tryFtruncate caller fd length system
            |> Result.map SteppedCall.FTruncate
            |> Result.mapError SyscallRefusal.FTruncate
        | Syscall.Close fd ->
            UnixDescriptor.tryClose caller fd system
            |> Result.map SteppedCall.Close
            |> Result.mapError SyscallRefusal.Close
        | Syscall.FileClone (destination, source) ->
            UnixDescriptor.tryFileClone caller destination source system
            |> Result.map SteppedCall.FileClone
            |> Result.mapError SyscallRefusal.FileClone
        | Syscall.GetEffectiveUserId ->
            Ok (SteppedCall.GetEffectiveUserId (UnixDescriptor.effectiveUserId caller system))
        | Syscall.GetEffectiveGroupId ->
            Ok (SteppedCall.GetEffectiveGroupId (UnixDescriptor.effectiveGroupId caller system))
        | Syscall.FChMod (fd, mode) ->
            UnixPathResolution.tryFchmod caller fd mode system
            |> Result.map SteppedCall.FChMod
            |> Result.mapError SyscallRefusal.FChMod
        | Syscall.FChModAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFchmodat caller dirfd path mode flags system
            |> Result.map SteppedCall.FChModAt
            |> Result.mapError SyscallRefusal.FChModAt
        | Syscall.FChOwn (fd, user, group) ->
            UnixPathResolution.tryFchown caller fd user group system
            |> Result.map SteppedCall.FChOwn
            |> Result.mapError SyscallRefusal.FChOwn
        | Syscall.FChOwnAt (dirfd, path, user, group, flags) ->
            UnixPathResolution.tryFchownat caller dirfd path user group flags system
            |> Result.map SteppedCall.FChOwnAt
            |> Result.mapError SyscallRefusal.FChOwnAt
        | Syscall.UTimensAt (dirfd, path, times, flags) ->
            UnixPathResolution.tryUtimensat caller dirfd path times flags system
            |> Result.map SteppedCall.UTimensAt
            |> Result.mapError SyscallRefusal.UTimensAt
        | Syscall.ChDir path ->
            UnixPathResolution.tryChdir caller path system
            |> Result.map SteppedCall.ChDir
            |> Result.mapError SyscallRefusal.ChDir
        | Syscall.FAccessAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFaccessat caller dirfd mode flags system
            |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)
            |> Result.map SteppedCall.FAccessAt
            |> Result.mapError SyscallRefusal.FAccessAt
        | Syscall.MkDirAt (dirfd, path, mode) ->
            UnixNamespace.tryMkdirat caller dirfd path mode system
            |> Result.map SteppedCall.MkDirAt
            |> Result.mapError SyscallRefusal.MkDirAt
        | Syscall.UnlinkAt (dirfd, path, flags) ->
            UnixNamespace.tryUnlinkat caller dirfd path flags system
            |> Result.map SteppedCall.UnlinkAt
            |> Result.mapError SyscallRefusal.UnlinkAt
        | Syscall.CloneFile (source, destination, flags) ->
            UnixNamespace.tryCloneFile caller flags system
            |> CallProgress.resumeWith (fun paused ->
                UnixNamespace.tryCloneFileWithSource source paused
                |> CallProgress.resumeWith (UnixNamespace.tryCloneFileWithDestination destination)
            )
            |> Result.map SteppedCall.CloneFile
            |> Result.mapError SyscallRefusal.CloneFile
        | Syscall.SymlinkAt (target, dirfd, path) ->
            Ok (UnixNamespace.symlinkat caller target dirfd system)
            |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)
            |> Result.map SteppedCall.SymlinkAt
            |> Result.mapError SyscallRefusal.SymlinkAt
        | Syscall.LinkAt (olddirfd, oldpath, newdirfd, newpath, flags) ->
            UnixNamespace.tryLinkat caller olddirfd oldpath newdirfd flags system
            |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)
            |> Result.map SteppedCall.LinkAt
            |> Result.mapError SyscallRefusal.LinkAt
        | Syscall.CopyFileRange (inFd, outFd, length, flags) ->
            UnixReadWrite.tryCopyFileRange caller inFd outFd length flags system
            |> Result.map SteppedCall.CopyFileRange
            |> Result.mapError SyscallRefusal.CopyFileRange
        | Syscall.InotifyInit1 flags ->
            UnixInotify.tryInotifyInit1 caller flags system
            |> Result.map SteppedCall.InotifyInit1
            |> Result.mapError SyscallRefusal.InotifyInit1
        | Syscall.InotifyRmWatch (fd, wd) ->
            UnixInotify.tryInotifyRmWatch caller fd wd system
            |> Result.map SteppedCall.InotifyRmWatch
            |> Result.mapError SyscallRefusal.InotifyRmWatch
        | Syscall.GetProcessId -> Ok (SteppedCall.GetProcessId (UnixSystem.processId caller system))
        | Syscall.UMask mask -> Ok (SteppedCall.UMask (UnixSystem.umask caller mask system))
        | Syscall.SetResUid (real, effective, saved) ->
            UnixCredentials.trySetresuid caller real effective saved system
            |> Result.map SteppedCall.SetResUid
            |> Result.mapError SyscallRefusal.SetResUid
        | Syscall.SetResGid (real, effective, saved) ->
            UnixCredentials.trySetresgid caller real effective saved system
            |> Result.map SteppedCall.SetResGid
            |> Result.mapError SyscallRefusal.SetResGid
        | Syscall.SetGroups (size, words) ->
            UnixCredentials.trySetgroups caller size words system
            |> Result.map SteppedCall.SetGroups
            |> Result.mapError SyscallRefusal.SetGroups
        | other -> failwith $"%s{UnionCaseName.ofValue other} is no call step makes yet"

    /// What a call answered, as values to compare: the `SteppedCall`'s case
    /// and fields, or the refusal, or the type and message of what it threw.
    let private observe
        (f : unit -> Result<SteppedCall<int, string>, SyscallRefusal<int>>)
        : Result<Result<string * obj list, SyscallRefusal<int>>, string * string>
        =
        try
            Ok (f () |> Result.map Stepped.view)
        with e ->
            Error (e.GetType().FullName, e.Message)

    /// The system a call left, if it answered without parking its thread.
    let private carriedOn (stepped : SteppedCall<int, string>) : UnixSystem<int, string> option =
        match stepped with
        | SteppedCall.FLock (SyscallOutcome.Answered _, system) -> Some system
        | SteppedCall.FLock _ -> None
        | SteppedCall.InotifyInit1 (Ok (_, system)) -> Some system
        | SteppedCall.InotifyInit1 (Error _) -> None
        | SteppedCall.UMask (_, system) -> Some system
        | stepped ->
            match Stepped.syscallAnswer stepped with
            | Some (_, system) -> system
            | None -> None

    // ------------------------------------------------------------- worlds

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private owner (id : uint32) : InodeOwner =
        {
            User = UserId.parseOrFail context id
            Group = GroupId.parseOrFail context id
        }

    let private bytes (text : string) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Encoding.ASCII.GetBytes text)

    /// `/f` and `/d/g` files, `/d/e` an empty directory, `/l` a link to `f`,
    /// `/dangling` a link to nothing, and `/theirs` and `/sticky/theirs` files
    /// another user owns, in a sticky directory for the second.
    let private seed : Map<DirectoryEntryName, SeedEntry> =
        let other = owner 1234u

        Map.ofList
            [
                name "f", SeedEntry.file (bytes "hello")
                name "d",
                SeedEntry.directory (
                    Map.ofList
                        [
                            name "g", SeedEntry.file (bytes "g")
                            name "e", SeedEntry.directory Map.empty
                        ]
                )
                name "l", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "f", None)
                name "dangling", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "nx", None)
                name "theirs", SeedEntry.File (bytes "t", PermissionBits.parseOrFail context 0o640, Some other)
                name "sticky",
                SeedEntry.Directory (
                    Map.ofList
                        [
                            name "theirs",
                            SeedEntry.File (bytes "t", PermissionBits.parseOrFail context 0o644, Some other)
                        ],
                    PermissionBits.parseOrFail context 0o1777,
                    None
                )
            ]

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    /// The calls of a world are made by thread 0, its leader, or thread 1.
    let private threads : int list = [ 0 ; 1 ]

    /// A booted process on `platform`, as root or as the flavour's default
    /// user, owning the seeded tree, with two threads, and with `/f` open
    /// read-write as 3, `/d` as 4, `/d/g` as 5 and `/f` again, read-only, as
    /// 6. Under Linux, 7 is an inotify instance watching `/d` as watch 1.
    let private world (platform : SimulatedUnixPlatform) (privileged : bool) : UnixSystem<int, string> =
        let flavour = SimulatedUnixPlatform.flavour platform
        let ordinary = UnixSystem.defaultCredentials flavour

        let credentials =
            if privileged then
                Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []
            else
                ordinary

        let opened (path : string) (flags : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixNamespace.openPath (Callers.leader system) flags (PathArg.ofText path) 0 system with
            | SyscallOutcome.Answered (SyscallAnswer.Completed _), system -> system
            | other -> failwith $"setting up, open(%s{path}): %A{other}"

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.fileSystem (UnixTimestamp.ofMillisecondsSinceEpoch 0L) (InodeOwner.ofProcess ordinary) seed
            |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure 1
            |> opened "/f" 2
            |> opened "/d" 0
            |> opened "/d/g" 0
            |> opened "/f" 0

        match flavour with
        | SimulatedUnixFlavour.Darwin -> system
        | SimulatedUnixFlavour.Linux ->
            match UnixInotify.inotifyInit1 (Callers.leader system) 0 system with
            | Ok (7, system) ->
                // IN_CREATE.
                match Eager.tryInotifyAddWatch 7 (PathArg.ofText "/d") 0x100u system with
                | Ok (SyscallAnswer.Completed 1L, system) -> system
                | other -> failwith $"setting up, inotify_add_watch: %A{other}"
            | other -> failwith $"setting up, inotify_init1: %A{other}"

    let private worlds : Lazy<Map<SimulatedUnixFlavour * bool, UnixSystem<int, string>>> =
        lazy
            Map.ofList
                [
                    for platform in platforms do
                        for privileged in [ true ; false ] do
                            yield (SimulatedUnixPlatform.flavour platform, privileged), world platform privileged
                ]

    // ------------------------------------------------------------- generators

    let private fdGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        Gen.frequency
            [
                8, Gen.choose (0, 8)
                1, Gen.elements [ -1 ; 99 ; 1023 ; 1024 ]
                2, Gen.constant (AtDirectory.atFdCwd flavour)
            ]

    let private pathTexts : string list =
        [
            "/f"
            "/d"
            "/d/g"
            "/d/e"
            "/d/e/"
            "/l"
            "/dangling"
            "/nx"
            "/nx/y"
            "f"
            "d"
            "g"
            "e"
            "new"
            "/d/new"
            "/new"
            "/f/"
            "."
            ".."
            "/theirs"
            "/sticky"
            "/sticky/theirs"
            "/sticky/new"
            ""
        ]

    let private pathGen : Gen<PathArgumentBytes> =
        Gen.frequency
            [
                12, Gen.elements pathTexts |> Gen.map PathArg.ofText
                1, Gen.constant PathArgumentBytes.Unreadable
            ]

    let private modeGen : Gen<int> =
        Gen.frequency
            [
                3, Gen.elements [ 0 ; 0o644 ; 0o700 ; 0o755 ; 0o777 ; 0o1777 ; 0o2755 ; 0o4755 ]
                1, Gen.choose (0, 0o7777)
                1, Gen.choose (Int32.MinValue, Int32.MaxValue)
            ]

    /// Flag words of both flavours' `*at` calls, and anything else.
    let private atFlagsGen : Gen<int> =
        Gen.frequency
            [
                4, Gen.constant 0
                3, Gen.elements [ 0x4 ; 0x10 ; 0x20 ; 0x40 ; 0x80 ; 0x100 ; 0x200 ; 0x400 ; 0x800 ; 0x1000 ]
                1, Gen.choose (0, 0xFFFF)
            ]

    let private userGen : Gen<UserId option> =
        Gen.elements [ None ; Some 0u ; Some 501u ; Some 1000u ; Some 1234u ]
        |> Gen.map (Option.map (UserId.parseOrFail context))

    let private groupGen : Gen<GroupId option> =
        Gen.elements [ None ; Some 0u ; Some 12u ; Some 20u ; Some 1000u ; Some 1234u ]
        |> Gen.map (Option.map (GroupId.parseOrFail context))

    let private offsetGen : Gen<int64> =
        Gen.frequency
            [
                4, Gen.choose (-3, 40) |> Gen.map int64
                1, Gen.elements [ Int64.MinValue ; -1L ; Int64.MaxValue ]
            ]

    let private timespecGen : Gen<TimespecFields> =
        Gen.map2
            (fun seconds nanoseconds ->
                {
                    Seconds = seconds
                    Nanoseconds = nanoseconds
                }
            )
            (Gen.elements [ -1L ; 0L ; 1L ; 1_000_000_000L ; Int64.MaxValue ])
            (Gen.elements
                [
                    -2L
                    -1L
                    0L
                    999_999_999L
                    1_000_000_000L
                    (1L <<< 30) - 2L
                    (1L <<< 30) - 1L
                ])

    /// A generator of calls of each case `step` makes, by the case's name.
    let private callGens (flavour : SimulatedUnixFlavour) : (string * Gen<Syscall<int, string>>) list =
        let fd = fdGen flavour

        [
            "Dup", fd |> Gen.map Syscall.Dup
            "Dup2", Gen.map2 (fun oldFd newFd -> Syscall.Dup2 (oldFd, newFd)) fd fd
            "Dup3",
            Gen.map3
                (fun oldFd newFd flags -> Syscall.Dup3 (oldFd, newFd, flags))
                fd
                fd
                (Gen.elements [ 0 ; 1 ; 0x800 ; 0x80000 ; -1 ])
            "Fcntl",
            Gen.map3
                (fun fd command argument -> Syscall.Fcntl (fd, command, argument))
                fd
                (Gen.frequency
                    [
                        4, Gen.choose (0, 12)
                        1, Gen.elements [ -1 ; 67 ; 1024 ; 1025 ; 1030 ; 1031 ; 1032 ; 1033 ; 1034 ]
                    ])
                (Gen.frequency
                    [
                        3, Gen.choose (-1, 10)
                        2, Gen.elements [ 0x4 ; 0x400 ; 0x800 ; 0x2000 ; 0x40000 ; 0x80000 ]
                        1, Gen.choose (Int32.MinValue, Int32.MaxValue)
                    ])
            "LSeek",
            Gen.map3 (fun fd offset whence -> Syscall.LSeek (fd, offset, whence)) fd offsetGen (Gen.choose (-1, 5))
            "FLock",
            Gen.map2
                (fun fd operation -> Syscall.FLock (fd, operation))
                fd
                (Gen.frequency [ 6, Gen.choose (0, 15) ; 1, Gen.elements [ -1 ; 16 ; 32 ] ])
            "FTruncate", Gen.map2 (fun fd length -> Syscall.FTruncate (fd, length)) fd offsetGen
            "Close", fd |> Gen.map Syscall.Close
            "FileClone", Gen.map2 (fun destination source -> Syscall.FileClone (destination, source)) fd fd
            "GetEffectiveUserId", Gen.constant Syscall.GetEffectiveUserId
            "GetEffectiveGroupId", Gen.constant Syscall.GetEffectiveGroupId
            "FChMod", Gen.map2 (fun fd mode -> Syscall.FChMod (fd, mode)) fd modeGen
            "FChModAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! mode = modeGen
                let! flags = atFlagsGen
                return Syscall.FChModAt (dirfd, path, mode, flags)
            }
            "FChOwn", Gen.map3 (fun fd user group -> Syscall.FChOwn (fd, user, group)) fd userGen groupGen
            "FChOwnAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! user = userGen
                let! group = groupGen
                let! flags = atFlagsGen
                return Syscall.FChOwnAt (dirfd, path, user, group, flags)
            }
            "UTimensAt",
            gen {
                let! dirfd = fd

                let! path =
                    Gen.frequency
                        [
                            1, Gen.constant NullablePathArgument.Null
                            6, pathGen |> Gen.map NullablePathArgument.NotNull
                        ]

                let! times =
                    Gen.frequency
                        [
                            1, Gen.constant TimesArgument.Null
                            1, Gen.constant TimesArgument.Unreadable
                            4,
                            Gen.map2
                                (fun access modification -> TimesArgument.Fields (access, modification))
                                timespecGen
                                timespecGen
                        ]

                let! flags = atFlagsGen
                return Syscall.UTimensAt (dirfd, path, times, flags)
            }
            "ChDir", pathGen |> Gen.map Syscall.ChDir
            "FAccessAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! mode = Gen.frequency [ 6, Gen.choose (0, 7) ; 1, Gen.elements [ -1 ; 8 ; 0x100 ] ]
                let! flags = atFlagsGen
                return Syscall.FAccessAt (dirfd, path, mode, flags)
            }
            "MkDirAt", Gen.map3 (fun dirfd path mode -> Syscall.MkDirAt (dirfd, path, mode)) fd pathGen modeGen
            "UnlinkAt", Gen.map3 (fun dirfd path flags -> Syscall.UnlinkAt (dirfd, path, flags)) fd pathGen atFlagsGen
            "CloneFile",
            Gen.map3
                (fun source destination flags -> Syscall.CloneFile (source, destination, flags))
                pathGen
                pathGen
                (Gen.elements [ 0 ; 1 ; 2 ; 4 ; 8 ; 0x10 ])
            "SymlinkAt", Gen.map3 (fun target dirfd path -> Syscall.SymlinkAt (target, dirfd, path)) pathGen fd pathGen
            "LinkAt",
            gen {
                let! olddirfd = fd
                let! oldpath = pathGen
                let! newdirfd = fd
                let! newpath = pathGen
                let! flags = atFlagsGen
                return Syscall.LinkAt (olddirfd, oldpath, newdirfd, newpath, flags)
            }
            "CopyFileRange",
            gen {
                let! inFd = fd
                let! outFd = fd
                let! length = Gen.elements [ 0UL ; 1UL ; 3UL ; 100UL ; UInt64.MaxValue ]
                let! flags = Gen.elements [ 0 ; 1 ]
                return Syscall.CopyFileRange (inFd, outFd, length, flags)
            }
            "InotifyInit1",
            Gen.elements [ 0 ; 1 ; 0x800 ; 0x4000 ; 0x80000 ; 0x80800 ]
            |> Gen.map Syscall.InotifyInit1
            "InotifyRmWatch", Gen.map2 (fun fd wd -> Syscall.InotifyRmWatch (fd, wd)) fd (Gen.choose (-1, 3))
            "GetProcessId", Gen.constant Syscall.GetProcessId
            "UMask",
            Gen.frequency [ 3, Gen.choose (0, 0o777) ; 1, Gen.choose (Int32.MinValue, Int32.MaxValue) ]
            |> Gen.map Syscall.UMask
            "SetResUid",
            Gen.map3 (fun real effective saved -> Syscall.SetResUid (real, effective, saved)) userGen userGen userGen
            "SetResGid",
            Gen.map3 (fun real effective saved -> Syscall.SetResGid (real, effective, saved)) groupGen groupGen groupGen
            "SetGroups",
            gen {
                let! words =
                    Gen.listOf (Gen.oneof [ Gen.elements [ 0u ; 20u ; UInt32.MaxValue ] ; CredentialsGen.rawId ])

                let! faults = Gen.elements [ true ; false ]

                return
                    if faults then
                        Syscall.SetGroups (List.length words + 1, GroupListWords.FaultsAfter words)
                    else
                        Syscall.SetGroups (List.length words, GroupListWords.Readable words)
            }
        ]

    [<Test>]
    let ``every case step makes has a generator here`` () : unit =
        for platform in platforms do
            callGens (SimulatedUnixPlatform.flavour platform)
            |> List.map fst
            |> shouldEqual TestSyscall.wired

    // ------------------------------------------------------------- the property

    let private agree (case : string) : unit =
        // How many of the samples' calls answered.
        let answered = ref 0

        let sample =
            gen {
                let! platform = Gen.elements platforms
                let! privileged = Gen.elements [ true ; false ]
                let flavour = SimulatedUnixPlatform.flavour platform
                let gens = callGens flavour
                let caseGen = gens |> List.find (fun (name, _) -> name = case) |> snd
                let! prefixLength = Gen.choose (0, 4)
                let! prefix = Gen.listOfLength prefixLength (Gen.oneof (List.map snd gens))
                let! caller = Gen.frequency [ 8, Gen.elements threads ; 1, Gen.constant 99 ]
                let! call = caseGen
                return platform, privileged, prefix, caller, call
            }

        let property
            (platform : SimulatedUnixPlatform, privileged : bool, prefix : Syscall<int, string> list, caller : int, call)
            : unit
            =
            let start =
                Map.find (SimulatedUnixPlatform.flavour platform, privileged) worlds.Value

            // The prefix moves the world through the calls' own functions,
            // made by the leader, keeping whatever answered without parking.
            let system =
                (start, prefix)
                ||> List.fold (fun system call ->
                    try
                        match reference (Callers.leader system) call system with
                        | Ok stepped -> carriedOn stepped |> Option.defaultValue system
                        | Error _ -> system
                    with _ ->
                        system
                )

            let caller = Callers.thread caller system
            let viaStep = observe (fun () -> UnixSystem.tryStep caller call system)
            let direct = observe (fun () -> reference caller call system)

            match viaStep with
            | Ok (Ok (stepped, _)) ->
                answered.Value <- answered.Value + 1
                stepped |> shouldEqual (UnionCaseName.ofValue call)
            | Ok (Error _)
            | Error _ -> ()

            if viaStep <> direct then
                failwith $"%A{call} by %O{caller}: step answered %A{viaStep}, and the call's own function %A{direct}"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen sample) property)

        // Not vacuous: the case answered, whatever else it did.
        answered.Value |> shouldBeGreaterThan 0

    let private wiredCases : string list = TestSyscall.wired

    [<TestCaseSource(nameof wiredCases)>]
    let ``step makes a call as its own function does`` (case : string) : unit = agree case
