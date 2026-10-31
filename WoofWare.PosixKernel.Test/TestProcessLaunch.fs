namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestProcessLaunch =

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    let private create () : ProcessLaunch<int> =
        ProcessLaunch.create UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private mode (bits : int) : PermissionBits =
        PermissionBits.parseOrFail "TestProcessLaunch" bits

    let private launches
        (platform : SimulatedUnixPlatform)
        (launch : ProcessLaunch<int>)
        : (ProcessId * UnixSystem<int, string>) list
        =
        let image : UnixBootImage<int, string> = UnixSystem.initial platform
        let first = UnixBootImage.boot launch image
        [ Lone.pid first, first ; UnixSystem.launch launch first ]

    [<Test>]
    let ``one launch takes defaults from each machine at boot and at later launch`` () : unit =
        let launch = create ()

        for platform in platforms do
            let uid, gid, signalLimit =
                match SimulatedUnixPlatform.flavour platform with
                | SimulatedUnixFlavour.Linux -> 1000u, 1000u, ValueSome 4505UL
                | SimulatedUnixFlavour.Darwin -> 501u, 20u, ValueNone

            let credentials =
                Credentials.ofIds
                    (UserId.parseOrFail "TestProcessLaunch" uid)
                    (GroupId.parseOrFail "TestProcessLaunch" gid)
                    []

            for pid, system in launches platform launch do
                let proc = Proc.state pid system
                proc.Credentials |> shouldEqual credentials
                proc.Umask |> shouldEqual (mode 0o022)
                proc.PendingSignalLimit |> shouldEqual signalLimit
                UnixSystem.checkInvariants system |> shouldEqual []

    [<Test>]
    let ``explicit settings survive boot and later launch with the machine's rules`` () : unit =
        let gen =
            gen {
                let! user = CredentialsGen.userId
                let! group = CredentialsGen.groupId
                let! groups = Gen.listOfLength 3 CredentialsGen.groupId
                let! bits = Gen.choose (0, 0o777)
                let! limit = ArbMap.defaults |> ArbMap.generate<uint64>
                return Credentials.ofIds user group groups, mode bits, limit
            }

        let property (credentials : Credentials, mask : PermissionBits, limit : uint64) : unit =
            let launch =
                create ()
                |> ProcessLaunch.withCredentials credentials
                |> ProcessLaunch.withUmask mask

            for platform in platforms do
                let requested, expectedLimit =
                    match SimulatedUnixPlatform.flavour platform with
                    | SimulatedUnixFlavour.Linux -> ProcessLaunch.withPendingSignalLimit limit launch, ValueSome limit
                    | SimulatedUnixFlavour.Darwin -> launch, ValueNone

                for pid, system in launches platform requested do
                    let proc = Proc.state pid system
                    proc.Credentials |> shouldEqual credentials
                    proc.Umask |> shouldEqual mask
                    proc.PendingSignalLimit |> shouldEqual expectedLimit
                    UnixSystem.checkInvariants system |> shouldEqual []

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 100, Prop.forAll (Arb.fromGen gen) property)

    let private rejects<'Exn when 'Exn :> exn>
        (parameter : string option)
        (platform : SimulatedUnixPlatform)
        (launch : ProcessLaunch<int>)
        : unit
        =
        let image : UnixBootImage<int, string> = UnixSystem.initial platform
        let first = UnixBootImage.boot (create ()) image

        let operations : (string * (unit -> unit)) list =
            [
                "UnixBootImage.boot", (fun () -> UnixBootImage.boot launch image |> ignore)
                "UnixSystem.launch", (fun () -> UnixSystem.launch launch first |> ignore)
            ]

        for name, operation in operations do
            let error = Assert.Throws<'Exn> (fun () -> operation ())
            error.Message |> shouldContainText name

            match parameter with
            | Some parameter -> (error :> exn :?> ArgumentException).ParamName |> shouldEqual parameter
            | None -> ()

    [<Test>]
    let ``both launch entry points refuse settings the target cannot admit`` () : unit =
        for platform in platforms do
            let bound = SimulatedUnixPlatform.descriptorBound platform

            for fd in [ bound ; bound + 1 ; Int32.MaxValue ] do
                ProcessLaunch.create (Map.ofList [ fd, LaunchDescriptor.Drained ]) 0 (CpuId 0)
                |> rejects<UnmodelledException> None platform

            let count = SimulatedUnixPlatform.supplementaryGroupsHeld platform + 1

            let credentials =
                Credentials.ofIds
                    UserId.root
                    (GroupId.parseOrFail "TestProcessLaunch" 0u)
                    (List.replicate count (GroupId.parseOrFail "TestProcessLaunch" 1u))

            create ()
            |> ProcessLaunch.withCredentials credentials
            |> rejects<ArgumentException> (Some "launch") platform

        create ()
        |> ProcessLaunch.withUmask (mode 0o1022)
        |> rejects<ArgumentException> (Some "launch") SimulatedUnixPlatform.linuxX64

        let differing =
            { UnixSystem.defaultCredentials SimulatedUnixFlavour.Darwin with
                SavedUser = UserId.root
            }

        create ()
        |> ProcessLaunch.withCredentials differing
        |> rejects<UnmodelledException> None SimulatedUnixPlatform.macOsArm64

        for limit in [ 0UL ; 4505UL ; UInt64.MaxValue ] do
            create ()
            |> ProcessLaunch.withPendingSignalLimit limit
            |> rejects<PlatformNotSupportedException> None SimulatedUnixPlatform.macOsArm64
