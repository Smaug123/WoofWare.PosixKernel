namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open Microsoft.FSharp.Reflection
open NUnit.Framework
open WoofWare.PosixKernel

/// What a client learns, through the public API alone, of why
/// `UnixBootImage.tryBoot` or `UnixSystem.tryLaunch` refused a launch: which
/// `LaunchSetting` was at fault, so that it can name its own knob. And that
/// the raising `boot` and `launch` agree with them.
///
/// Each setting's own fixture (`TestCredentials`, `TestUmask`, `TestCpuRange`,
/// `TestDescriptorBound`, `TestWithFileSystemAndCurrentDirectory`, ...) holds
/// the rule that refuses it; this one holds the setting each refusal names.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestLaunchRefusals =

    let private context : string = "TestLaunchRefusals"

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 200

    let private name (s : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context s

    let private createdAt : UnixTimestamp =
        UnixTimestamp.createOrFail context 1_700_000_000L 0

    /// `/outer/inner/`, `/outer/file` and `/outer/lnk -> inner`.
    let private seed : Map<DirectoryEntryName, SeedEntry> =
        Map.ofList
            [
                name "outer",
                SeedEntry.directory (
                    Map.ofList
                        [
                            name "inner", SeedEntry.directory FileSystemSeed.empty
                            name "file", SeedEntry.file ImmutableArray<byte>.Empty
                            name "lnk", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "inner", None)
                        ]
                )
            ]

    /// Every launch setting a client can set, written as the test chooses it
    /// rather than as a `ProcessLaunch`, so that a failing case prints what it
    /// set. `None` leaves a setter unapplied.
    type private LaunchSpec =
        {
            Descriptors : Map<int, LaunchDescriptor>
            Cpu : int
            SetCredentials : Credentials option
            SetUmask : int option
            SetPendingSignalLimit : uint64 option
            SetCurrentDirectory : string option
            SetEnvironment : string list option
            SetProcessPath : string option option
            SetCoreDumps : CoreDumps option
        }

    let private toLaunch (spec : LaunchSpec) : ProcessLaunch<int> =
        let apply (setter : 'a -> ProcessLaunch<int> -> ProcessLaunch<int>) (value : 'a option) launch =
            match value with
            | None -> launch
            | Some value -> setter value launch

        ProcessLaunch.create spec.Descriptors 0 (CpuId spec.Cpu)
        |> apply ProcessLaunch.withCredentials spec.SetCredentials
        |> apply (fun bits -> ProcessLaunch.withUmask (PermissionBits.parseOrFail context bits)) spec.SetUmask
        |> apply ProcessLaunch.withPendingSignalLimit spec.SetPendingSignalLimit
        |> apply
            (fun dir -> ProcessLaunch.withCurrentDirectory (AbsoluteUnixPath.parseOrFail context dir))
            spec.SetCurrentDirectory
        |> apply
            (fun entries ->
                entries
                |> List.map (fun entry ->
                    match UnixByteString.ofString entry with
                    | Ok bytes -> bytes
                    | Error defect -> failwith $"test bug: %O{defect}"
                )
                |> ProcessLaunch.withEnvironment context
            )
            spec.SetEnvironment
        |> apply
            (fun path ->
                ProcessLaunch.withProcessPath context (path |> Option.map (AbsoluteUnixPath.parseOrFail context))
            )
            spec.SetProcessPath
        |> apply ProcessLaunch.withCoreDumps spec.SetCoreDumps

    /// A machine of `platform` with `count` logical processors and `seed` as
    /// its filesystem.
    let private imageOf (platform : SimulatedUnixPlatform) (count : int) : UnixBootImage<int, string> =
        UnixSystem.initial<int, string> platform
        |> UnixBootImage.withProcessorCount count
        |> UnixBootImage.withFileSystem createdAt Owners.linuxDefault seed

    let private descriptorsAvailable : LaunchDescriptor list =
        UnixSystem.pipedStandardStreams |> Map.toList |> List.map snd

    let private userId : Gen<UserId> =
        Gen.choose (0, 100_000) |> Gen.map (uint32 >> UserId.parseOrFail context)

    let private groupId : Gen<GroupId> =
        Gen.choose (0, 100_000) |> Gen.map (uint32 >> GroupId.parseOrFail context)

    /// Up to `limit` groups, usually few, and sometimes as many as `limit`.
    let private groupCount (limit : int) : Gen<int> =
        Gen.frequency [ 4, Gen.choose (0, min limit 8) ; 1, Gen.choose (max 0 (limit - 2), limit) ]

    let private groups (count : int) : Gen<GroupId list> = Gen.listOfLength count groupId

    let private credentialsOf
        (user : UserId * UserId * UserId)
        (group : GroupId * GroupId * GroupId)
        (supplementary : GroupId list)
        : Credentials
        =
        let realUser, effectiveUser, savedUser = user
        let realGroup, effectiveGroup, savedGroup = group

        {
            RealUser = realUser
            EffectiveUser = effectiveUser
            SavedUser = savedUser
            RealGroup = realGroup
            EffectiveGroup = effectiveGroup
            SavedGroup = savedGroup
            SupplementaryGroups = supplementary
        }

    /// Credentials `platform` admits: on Darwin with real, effective and saved
    /// IDs all the same.
    let private validCredentials (platform : SimulatedUnixPlatform) : Gen<Credentials> =
        gen {
            let! count = groupCount (SimulatedUnixPlatform.supplementaryGroupsHeld platform)
            let! supplementary = groups count

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux ->
                let! user = Gen.zip3 userId userId userId
                let! group = Gen.zip3 groupId groupId groupId
                return credentialsOf user group supplementary
            | SimulatedUnixFlavour.Darwin ->
                let! user = userId
                let! group = groupId
                return credentialsOf (user, user, user) (group, group, group) supplementary
        }

    let private validCurrentDirectories : string list =
        [ "/" ; "/outer" ; "/outer/inner" ; "/outer/lnk" ]

    /// A launch every setting of which `platform` admits on `imageOf platform
    /// count`, each setter applied or not at random.
    let private validSpec (platform : SimulatedUnixPlatform) (count : int) : Gen<LaunchSpec> =
        let flavour = SimulatedUnixPlatform.flavour platform
        let bound = SimulatedUnixPlatform.descriptorBound platform
        let stored = PermissionBits.toInt (SimulatedUnixPlatform.umaskStoredBits platform)

        let optional (g : Gen<'a>) : Gen<'a option> =
            Gen.frequency [ 1, Gen.constant None ; 2, Gen.map Some g ]

        gen {
            let! fds = Gen.listOf (Gen.choose (0, bound - 1))
            let! descriptors = Gen.listOfLength (List.length fds) (Gen.elements descriptorsAvailable)
            let! cpu = Gen.choose (0, count - 1)
            let! credentials = optional (validCredentials platform)
            let! umask = optional (Gen.choose (0, 0o7777) |> Gen.map (fun bits -> bits &&& stored))

            let! pendingSignalLimit =
                match flavour with
                | SimulatedUnixFlavour.Linux -> optional (ArbMap.defaults |> ArbMap.generate<uint64>)
                | SimulatedUnixFlavour.Darwin -> Gen.constant None

            let! currentDirectory = optional (Gen.elements validCurrentDirectories)

            let! environment =
                optional (Gen.listOf (Gen.elements [ "A=1" ; "PATH=/bin:/usr/bin" ; "no-equals" ; "" ; "A=2" ]))

            let! processPath = optional (Gen.elements [ None ; Some "/outer/prog" ; Some "/outer/file" ])
            let! coreDumps = optional (Gen.elements [ CoreDumps.Suppressed ; CoreDumps.Written ])

            return
                {
                    Descriptors = List.zip fds descriptors |> Map.ofList
                    Cpu = cpu
                    SetCredentials = credentials
                    SetUmask = umask
                    SetPendingSignalLimit = pendingSignalLimit
                    SetCurrentDirectory = currentDirectory
                    SetEnvironment = environment
                    SetProcessPath = processPath
                    SetCoreDumps = coreDumps
                }
        }

    /// How to make `setting` wrong in a launch onto `imageOf platform count`,
    /// leaving the rest of the launch as it was; `None` for a setting no value
    /// of which `platform` refuses, which `validSpec` then draws from in full.
    let private wrong
        (platform : SimulatedUnixPlatform)
        (count : int)
        (setting : LaunchSetting)
        : Gen<LaunchSpec -> LaunchSpec> option
        =
        let flavour = SimulatedUnixPlatform.flavour platform

        match setting with
        | LaunchSetting.Streams ->
            let bound = SimulatedUnixPlatform.descriptorBound platform

            gen {
                let! fd = Gen.frequency [ 1, Gen.constant bound ; 3, Gen.choose (bound, bound + 100_000) ]
                let! descriptor = Gen.elements descriptorsAvailable

                return
                    fun (spec : LaunchSpec) ->
                        { spec with
                            Descriptors = Map.add fd descriptor spec.Descriptors
                        }
            }
            |> Some
        | LaunchSetting.LeaderCpu ->
            gen {
                let! cpu = Gen.frequency [ 1, Gen.constant count ; 3, Gen.choose (count, count + 1000) ]

                return
                    fun (spec : LaunchSpec) ->
                        { spec with
                            Cpu = cpu
                        }
            }
            |> Some
        | LaunchSetting.Credentials ->
            let limit = SimulatedUnixPlatform.supplementaryGroupsHeld platform

            let tooManyGroups =
                gen {
                    let! credentials = validCredentials platform
                    let! extra = Gen.choose (1, 3)
                    let! supplementary = groups (limit + extra)

                    return
                        { credentials with
                            SupplementaryGroups = supplementary
                        }
                }

            // Real, effective and saved IDs not all the same, which Darwin
            // refuses as unmeasured.
            let idsDiffer =
                gen {
                    let! user = Gen.zip3 userId userId userId
                    let! group = Gen.zip3 groupId groupId groupId
                    let! supplementary = groups 0
                    return credentialsOf user group supplementary
                }
                |> Gen.filter (fun c ->
                    c.RealUser <> c.EffectiveUser
                    || c.SavedUser <> c.EffectiveUser
                    || c.RealGroup <> c.EffectiveGroup
                    || c.SavedGroup <> c.EffectiveGroup
                )

            let credentials =
                match flavour with
                | SimulatedUnixFlavour.Linux -> tooManyGroups
                | SimulatedUnixFlavour.Darwin -> Gen.oneof [ tooManyGroups ; idsDiffer ]

            credentials
            |> Gen.map (fun credentials (spec : LaunchSpec) ->
                { spec with
                    SetCredentials = Some credentials
                }
            )
            |> Some
        | LaunchSetting.Umask ->
            let stored = PermissionBits.toInt (SimulatedUnixPlatform.umaskStoredBits platform)
            let unstored = 0o7777 &&& ~~~stored

            if unstored = 0 then
                None
            else
                Gen.choose (0, 0o7777)
                |> Gen.filter (fun bits -> bits &&& unstored <> 0)
                |> Gen.map (fun bits (spec : LaunchSpec) ->
                    { spec with
                        SetUmask = Some bits
                    }
                )
                |> Some
        | LaunchSetting.PendingSignalLimit ->
            match flavour with
            | SimulatedUnixFlavour.Linux -> None
            | SimulatedUnixFlavour.Darwin ->
                ArbMap.defaults
                |> ArbMap.generate<uint64>
                |> Gen.map (fun limit (spec : LaunchSpec) ->
                    { spec with
                        SetPendingSignalLimit = Some limit
                    }
                )
                |> Some
        | LaunchSetting.CurrentDirectory ->
            [
                "/absent"
                "/outer/file"
                "/outer/file/inner"
                "/outer/absent/inner"
                "/outer/" + String.replicate 300 "a"
            ]
            |> Gen.elements
            |> Gen.map (fun dir (spec : LaunchSpec) ->
                { spec with
                    SetCurrentDirectory = Some dir
                }
            )
            |> Some
        | LaunchSetting.Environment
        | LaunchSetting.ProcessPath
        | LaunchSetting.CoreDumps -> None

    let private allSettings : LaunchSetting list =
        FSharpType.GetUnionCases typeof<LaunchSetting>
        |> Array.map (fun case -> FSharpValue.MakeUnion (case, [||]) :?> LaunchSetting)
        |> List.ofArray

    let private platformAndCount : Gen<SimulatedUnixPlatform * int> =
        Gen.zip (Gen.elements Machines.platforms) (Gen.choose (1, 8))

    /// A launch onto `imageOf platform count` with `setting` wrong and every
    /// other setting valid.
    let private specWrongIn (setting : LaunchSetting) : Gen<SimulatedUnixPlatform * int * LaunchSpec> option =
        let candidates =
            Machines.platforms
            |> List.filter (fun platform -> (wrong platform 1 setting).IsSome)

        if List.isEmpty candidates then
            None
        else
            gen {
                let! platform = Gen.elements candidates
                let! count = Gen.choose (1, 8)
                let! spec = validSpec platform count
                let! breakIt = (wrong platform count setting).Value
                return platform, count, breakIt spec
            }
            |> Some

    /// A launch whose settings are each valid or, where the platform refuses
    /// some value of it, as often wrong.
    let private anySpec : Gen<SimulatedUnixPlatform * int * LaunchSpec> =
        gen {
            let! platform, count = platformAndCount
            let! spec = validSpec platform count

            let breakers =
                allSettings |> List.choose (fun setting -> wrong platform count setting)

            let! chosen = Gen.subListOf breakers
            let! wrongs = Gen.sequenceToList chosen
            return platform, count, List.fold (fun spec breakIt -> breakIt spec) spec wrongs
        }

    /// The first process booted onto `imageOf platform count` as
    /// `ProcessLaunch.create` makes it.
    let private bootedOn (platform : SimulatedUnixPlatform) (count : int) : UnixSystem<int, string> =
        imageOf platform count |> UnixBootImage.boot (Machines.defaultLaunch ())

    [<Test>]
    let ``Every setting but the environment, the process path and core dumps is refusable on some flavour`` () : unit =
        allSettings
        |> List.filter (fun setting -> (specWrongIn setting).IsNone)
        |> shouldEqual
            [
                LaunchSetting.Environment
                LaunchSetting.ProcessPath
                LaunchSetting.CoreDumps
            ]

        let refusableOn (flavour : SimulatedUnixFlavour) : LaunchSetting list =
            let platform =
                Machines.platforms
                |> List.find (fun platform -> SimulatedUnixPlatform.flavour platform = flavour)

            allSettings |> List.filter (fun setting -> (wrong platform 1 setting).IsSome)

        refusableOn SimulatedUnixFlavour.Linux
        |> shouldEqual
            [
                LaunchSetting.Streams
                LaunchSetting.LeaderCpu
                LaunchSetting.Credentials
                LaunchSetting.Umask
                LaunchSetting.CurrentDirectory
            ]

        refusableOn SimulatedUnixFlavour.Darwin
        |> shouldEqual
            [
                LaunchSetting.Streams
                LaunchSetting.LeaderCpu
                LaunchSetting.Credentials
                LaunchSetting.PendingSignalLimit
                LaunchSetting.CurrentDirectory
            ]

    let private refusableSettings : LaunchSetting list =
        allSettings |> List.filter (fun setting -> (specWrongIn setting).IsSome)

    [<TestCaseSource(nameof refusableSettings)>]
    let ``tryBoot names exactly the one wrong setting`` (setting : LaunchSetting) : unit =
        let property (cover : SimulatedUnixFlavour -> unit) (platform : SimulatedUnixPlatform, count : int, spec) =
            cover (SimulatedUnixPlatform.flavour platform)

            match UnixBootImage.tryBoot (toLaunch spec) (imageOf platform count) with
            | Ok _ -> failwith $"%O{setting}: booted %A{spec}"
            | Error refusal ->
                match BootRefusal.launch refusal with
                | ValueNone -> failwith $"%O{setting}: refused the image: %s{BootRefusal.describe refusal}"
                | ValueSome launchRefusal -> LaunchRefusal.setting launchRefusal |> shouldEqual setting

        let coverage =
            CoverageSample.check config (Arb.fromGen (specWrongIn setting).Value) property

        for platform in Machines.platforms do
            if (wrong platform 1 setting).IsSome then
                coverage.Count (SimulatedUnixPlatform.flavour platform) |> shouldBeGreaterThan 0

    [<TestCaseSource(nameof refusableSettings)>]
    let ``tryLaunch names exactly the one wrong setting`` (setting : LaunchSetting) : unit =
        let property (cover : SimulatedUnixFlavour -> unit) (platform : SimulatedUnixPlatform, count : int, spec) =
            cover (SimulatedUnixPlatform.flavour platform)

            match UnixSystem.tryLaunch (toLaunch spec) (bootedOn platform count) with
            | Ok _ -> failwith $"%O{setting}: launched %A{spec}"
            | Error refusal ->
                match ProcessCreationRefusal.launch refusal with
                | ValueNone ->
                    failwith $"%O{setting}: refused for want of an ID: %s{ProcessCreationRefusal.describe refusal}"
                | ValueSome launchRefusal -> LaunchRefusal.setting launchRefusal |> shouldEqual setting

        let coverage =
            CoverageSample.check config (Arb.fromGen (specWrongIn setting).Value) property

        for platform in Machines.platforms do
            if (wrong platform 1 setting).IsSome then
                coverage.Count (SimulatedUnixPlatform.flavour platform) |> shouldBeGreaterThan 0

    [<Test>]
    let ``A launch whose every setting is valid is admitted by tryBoot and tryLaunch`` () : unit =
        let gen =
            gen {
                let! platform, count = platformAndCount
                let! spec = validSpec platform count
                return platform, count, spec
            }

        let property (platform : SimulatedUnixPlatform, count : int, spec : LaunchSpec) : unit =
            match UnixBootImage.tryBoot (toLaunch spec) (imageOf platform count) with
            | Error refusal -> failwith $"boot refused %A{spec}: %s{BootRefusal.describe refusal}"
            | Ok system -> UnixSystem.checkInvariants system |> shouldEqual []

            match UnixSystem.tryLaunch (toLaunch spec) (bootedOn platform count) with
            | Error refusal -> failwith $"launch refused %A{spec}: %s{ProcessCreationRefusal.describe refusal}"
            | Ok (_, system) -> UnixSystem.checkInvariants system |> shouldEqual []

        Check.One (config, Prop.forAll (Arb.fromGen gen) property)

    /// What `thrown` is, as the same function's `Error` would be raised:
    /// equal type, message and, for an `ArgumentException`, parameter name.
    let private shouldBeRaisedAs (expected : exn) (thrown : exn) : unit =
        thrown.GetType () |> shouldEqual (expected.GetType ())
        thrown.Message |> shouldEqual expected.Message

        match expected, thrown with
        | (:? System.ArgumentException as expected), (:? System.ArgumentException as thrown) ->
            thrown.ParamName |> shouldEqual expected.ParamName
        | _ -> ()

    [<RequireQualifiedAccess>]
    type private Outcome =
        | Admitted
        | Refused

    [<Test>]
    let ``boot answers what tryBoot answers, or raises its refusal`` () : unit =
        let property (cover : Outcome -> unit) (platform : SimulatedUnixPlatform, count : int, spec : LaunchSpec) =
            let launch = toLaunch spec
            let image = imageOf platform count

            let raised =
                try
                    Ok (UnixBootImage.boot launch image)
                with e ->
                    Error e

            match UnixBootImage.tryBoot launch image, raised with
            | Ok answered, Ok booted ->
                cover Outcome.Admitted
                booted |> shouldEqual answered
            | Error refusal, Error thrown ->
                cover Outcome.Refused

                thrown
                |> shouldBeRaisedAs (
                    Refusal.exceptionOf "UnixBootImage.boot" (BootRefusal.kind refusal) (BootRefusal.describe refusal)
                )
            | answered, raised -> failwith $"%A{spec}: tryBoot answered %A{answered}, boot %A{raised}"

        let coverage = CoverageSample.check config (Arb.fromGen anySpec) property
        coverage.Count Outcome.Admitted |> shouldBeGreaterThan 0
        coverage.Count Outcome.Refused |> shouldBeGreaterThan 0

    [<Test>]
    let ``launch answers what tryLaunch answers, or raises its refusal`` () : unit =
        let property (cover : Outcome -> unit) (platform : SimulatedUnixPlatform, count : int, spec : LaunchSpec) =
            let launch = toLaunch spec
            let system = bootedOn platform count

            let raised =
                try
                    Ok (UnixSystem.launch launch system)
                with e ->
                    Error e

            match UnixSystem.tryLaunch launch system, raised with
            | Ok answered, Ok launched ->
                cover Outcome.Admitted
                launched |> shouldEqual answered
            | Error refusal, Error thrown ->
                cover Outcome.Refused

                thrown
                |> shouldBeRaisedAs (
                    Refusal.exceptionOf
                        "UnixSystem.launch"
                        (ProcessCreationRefusal.kind refusal)
                        (ProcessCreationRefusal.describe refusal)
                )
            | answered, raised -> failwith $"%A{spec}: tryLaunch answered %A{answered}, launch %A{raised}"

        let coverage = CoverageSample.check config (Arb.fromGen anySpec) property
        coverage.Count Outcome.Admitted |> shouldBeGreaterThan 0
        coverage.Count Outcome.Refused |> shouldBeGreaterThan 0
