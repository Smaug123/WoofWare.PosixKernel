namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `ParkedSyscall.DatagramSend`, which is reserved: nothing parks a thread in
/// it yet. What every reader of a park already answers for it (the wake
/// condition, the description it holds, how a signal ends it), and the
/// invariant that reports a thread parked in one, which is what makes
/// "nothing parks a thread in it" checked wherever a fuzzer checks
/// invariants. `TestDatagramBlockingReceive` has the receive.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramPark =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private parkGen : Gen<ParkedSyscall> =
        gen {
            let! socket = ArbMap.defaults |> ArbMap.generate<int64> |> Gen.map OpenFileDescriptionId

            return
                ParkedSyscall.DatagramSend
                    {
                        ParkedDatagramSend.Socket = socket
                    }
        }

    let private socketOf (parked : ParkedSyscall) : OpenFileDescriptionId =
        match parked with
        | ParkedSyscall.DatagramSend send -> send.Socket
        | other -> failwith $"not a datagram send's park: %A{other}"

    [<Test>]
    let ``a datagram send waits for a signal alone while reserved, holds its socket, and restarts under SA_RESTART``
        ()
        : unit
        =
        let property (parked : ParkedSyscall) : unit =
            WakeCondition.ofPark parked
            |> shouldEqual (WakeCondition.Primitive WakePrimitive.SignalDeliverable)

            WakeCondition.ofPark parked |> WakeCondition.deadlines |> shouldEqual []

            // Measured (`docs/probes/datagram-park`, row R3): Linux's call keeps
            // the socket across a close of its descriptor.
            ParkedSyscall.descriptions parked |> shouldEqual [ socketOf parked ]

            // Measured (row S4): a Linux Unix-domain send restarts under
            // SA_RESTART. A Darwin send never sleeps.
            for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
                SyscallInterruption.ruleOf flavour parked
                |> shouldEqual SignalRestartRule.RestartsUnderSaRestart

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen parkGen) property)

    let private boot (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private thread : int = 1

    [<Test>]
    let ``a thread parked in a datagram send is a ReservedPark defect`` () : unit =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let awake = boot flavour |> Threads.ensure thread
            awake |> UnixSystem.checkInvariants |> shouldEqual []

            let socket =
                match FileDescriptorRegistry.tryFindId 0 (Lone.fileDescriptors awake) with
                | Some id -> id
                | None -> failwith "fd 0 names no description"

            for parked in
                [
                    ParkedSyscall.DatagramSend
                        {
                            ParkedDatagramSend.Socket = socket
                        }
                ] do
                let asleep = Lone.Parking.park thread parked awake

                asleep
                |> UnixSystem.checkInvariants
                |> shouldEqual [ UnixSystemDefect.ReservedPark (Callers.ofDefault thread, parked) ]

                // The park holds the description it names, once.
                OpenFileTable.holdCount socket (UnixSystem.openFiles awake)
                |> shouldEqual (Some 0)

                OpenFileTable.holdCount socket (UnixSystem.openFiles asleep)
                |> shouldEqual (Some 1)

                Lone.deadlines asleep |> shouldEqual []

                UnixWait.satisfied (Callers.thread thread asleep) asleep
                |> shouldEqual (Some Set.empty)
