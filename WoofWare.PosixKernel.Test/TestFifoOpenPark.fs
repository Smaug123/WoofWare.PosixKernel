namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `ParkedSyscall.FifoOpen` and `WakePrimitive.FifoPartnerOpened`, which are
/// reserved: nothing parks a thread in a FIFO open yet. What every reader of a
/// park already answers for it (its wake condition, the description it holds,
/// how a signal ends it), and the invariant that reports a thread parked in it,
/// which is what makes "nothing parks a thread in it" checked wherever a fuzzer
/// checks invariants.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFifoOpenPark =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private fifoOpenGen : Gen<ParkedFifoOpen> =
        gen {
            let! opener = ArbMap.defaults |> ArbMap.generate<int64>
            let! descriptor = ArbMap.defaults |> ArbMap.generate<int>
            let! partnerOpens = ArbMap.defaults |> ArbMap.generate<int64>

            return
                {
                    Opener = OpenFileDescriptionId opener
                    Descriptor = descriptor
                    PartnerOpens = partnerOpens
                }
        }

    [<Test>]
    let ``a FIFO open waits for a partner's open or a signal, holds its description, and restarts under SA_RESTART on Linux alone``
        ()
        : unit
        =
        let property (fifoOpen : ParkedFifoOpen) : unit =
            let parked = ParkedSyscall.FifoOpen fifoOpen

            WakeCondition.ofPark parked
            |> shouldEqual (
                WakeCondition.AnyOf (
                    WakeCondition.Primitive (WakePrimitive.FifoPartnerOpened (fifoOpen.Opener, fifoOpen.PartnerOpens)),
                    [ WakeCondition.Primitive WakePrimitive.SignalDeliverable ]
                )
            )

            WakeCondition.ofPark parked |> WakeCondition.deadlines |> shouldEqual []

            ParkedSyscall.descriptions parked |> shouldEqual [ fifoOpen.Opener ]

            // Measured: Linux restarts a FIFO open under SA_RESTART, and Darwin
            // answers EINTR with it as without.
            SyscallInterruption.ruleOf SimulatedUnixFlavour.Linux parked
            |> shouldEqual SignalRestartRule.RestartsUnderSaRestart

            SyscallInterruption.ruleOf SimulatedUnixFlavour.Darwin parked
            |> shouldEqual SignalRestartRule.FailsWithEintr

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen fifoOpenGen) property)

    let private boot (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private thread : int = 1

    [<Test>]
    let ``a thread parked in a FIFO open is a ReservedPark defect, and its description outlives its last descriptor``
        ()
        : unit
        =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let awake = boot flavour |> Threads.ensure thread
            awake |> UnixSystem.checkInvariants |> shouldEqual []

            // A real sleeping open holds a description no descriptor names. One
            // that a descriptor names, closed under the park, comes to the same.
            let opener =
                match FileDescriptorRegistry.tryFindId 0 (UnixSystemState.fileDescriptors awake) with
                | Some id -> id
                | None -> failwith "fd 0 names no description"

            let parked =
                ParkedSyscall.FifoOpen
                    {
                        Opener = opener
                        Descriptor = 3
                        PartnerOpens = 0L
                    }

            let asleep = UnixWait.park thread parked awake

            asleep
            |> UnixSystem.checkInvariants
            |> shouldEqual [ UnixSystemDefect.ReservedPark (thread, parked) ]

            let closed =
                match UnixDescriptor.tryClose 0 asleep with
                | Ok (SyscallAnswer.Completed 0L, closed) -> closed
                | other -> failwith $"closing fd 0 under %O{flavour}: %A{other}"

            OpenFileTable.holdCount opener closed.Machine.OpenFiles |> shouldEqual (Some 1)

            closed
            |> UnixSystem.checkInvariants
            |> shouldEqual [ UnixSystemDefect.ReservedPark (thread, parked) ]

            UnixWait.deadlines (Set.singleton thread) closed |> shouldEqual []

            // This library keeps no count of a FIFO's opens, so the primitive
            // cannot be evaluated, and asking fails loudly rather than guessing.
            let error =
                Assert.Throws<Exception> (fun () ->
                    UnixWait.satisfied thread closed |> ignore<Set<WakePrimitive> option>
                )

            error.Message |> shouldContainText "FifoOpen"
