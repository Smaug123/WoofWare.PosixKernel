namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `ParkedSyscall.Connect` and `WakePrimitive.AcceptQueueHasRoom`, which are
/// reserved: nothing parks a thread in a connect yet. What every reader of a
/// park already answers for it (the wake condition, the description it holds,
/// how a signal ends it), and the invariant that reports a thread parked in it,
/// which is what makes "nothing parks a thread in it" checked wherever a fuzzer
/// checks invariants.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestConnectPark =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private connectGen : Gen<ParkedConnect> =
        ArbMap.defaults
        |> ArbMap.generate<int64>
        |> Gen.map (fun socket ->
            {
                ParkedConnect.Socket = OpenFileDescriptionId socket
            }
        )

    [<Test>]
    let ``a connect waits for a signal alone while reserved, holds its socket, and restarts under SA_RESTART``
        ()
        : unit
        =
        let property (connect : ParkedConnect) : unit =
            let parked = ParkedSyscall.Connect connect

            WakeCondition.ofPark parked
            |> shouldEqual (WakeCondition.Primitive WakePrimitive.SignalDeliverable)

            WakeCondition.ofPark parked |> WakeCondition.deadlines |> shouldEqual []

            ParkedSyscall.descriptions parked |> shouldEqual [ connect.Socket ]

            // Measured (`docs/probes/connect-park`, rows T3 and U3): a Linux
            // connect asleep on a full listener, TCP or Unix-domain, returns
            // EINTR without SA_RESTART and sleeps on with it. A Darwin one never
            // sleeps.
            for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
                SyscallInterruption.ruleOf flavour parked
                |> shouldEqual SignalRestartRule.RestartsUnderSaRestart

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen connectGen) property)

    let private boot (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private thread : int = 1

    [<Test>]
    let ``a thread parked in a connect is a ReservedPark defect`` () : unit =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let awake = boot flavour |> Threads.ensure thread
            awake |> UnixSystem.checkInvariants |> shouldEqual []

            let socket =
                match FileDescriptorRegistry.tryFindId 0 (Lone.fileDescriptors awake) with
                | Some id -> id
                | None -> failwith "fd 0 names no description"

            let parked =
                ParkedSyscall.Connect
                    {
                        ParkedConnect.Socket = socket
                    }

            let asleep = Lone.Parking.park thread parked awake

            asleep
            |> UnixSystem.checkInvariants
            |> shouldEqual [ UnixSystemDefect.ReservedPark (Callers.ofDefault thread, parked) ]

            OpenFileTable.holdCount socket (UnixSystem.openFiles asleep)
            |> shouldEqual (Some 1)

            Lone.deadlines asleep |> shouldEqual []

            UnixWait.satisfied (Callers.thread thread asleep) asleep
            |> shouldEqual (Some Set.empty)

    [<Test>]
    let ``no park's condition waits for room in an accept queue yet`` () : unit =
        // `ofPark` is the only source of a condition, and the one park that will
        // wait for room is reserved and waits for a signal alone; so no
        // condition this library hands out contains the primitive.
        let rec primitives (condition : WakeCondition) : WakePrimitive list =
            match condition with
            | WakeCondition.Primitive primitive -> [ primitive ]
            | WakeCondition.AnyOf (first, rest) -> primitives first @ List.collect primitives rest

        let property (connect : ParkedConnect) : unit =
            WakeCondition.ofPark (ParkedSyscall.Connect connect)
            |> primitives
            |> List.exists (fun primitive ->
                match primitive with
                | WakePrimitive.AcceptQueueHasRoom _ -> true
                | _ -> false
            )
            |> shouldEqual false

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen connectGen) property)

        // And asking whether it holds fails loudly, naming it, rather than
        // guessing: a thread waits for it only if its park was recorded by hand.
        let awake = boot SimulatedUnixFlavour.Linux |> Threads.ensure thread

        let error =
            Assert.Throws<Exception> (fun () ->
                Lone.WakeCondition.satisfied
                    thread
                    (WakeCondition.Primitive (WakePrimitive.AcceptQueueHasRoom (SocketId 1L)))
                    awake
                |> ignore<Set<WakePrimitive>>
            )

        error.Message |> shouldContainText "AcceptQueueHasRoom"
