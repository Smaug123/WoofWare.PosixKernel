namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `ParkedSyscall.Select`, which is reserved: nothing parks a thread in it yet.
/// What every reader of a park already answers for it (its wake condition, its
/// deadline, the descriptions it holds, how a signal ends it), and the
/// invariant that reports a thread parked in it, which is what makes "nothing
/// parks a thread in it" checked wherever a fuzzer checks invariants.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSelectPark =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private selectGen : Gen<ParkedSelect> =
        ArbMap.defaults
        |> ArbMap.generate<int64 option>
        |> Gen.map (fun deadline ->
            {
                ParkedSelect.Deadline = deadline
            }
        )

    [<Test>]
    let ``a select waits for its deadline or a signal, holds no description yet, and fails with EINTR under SA_RESTART``
        ()
        : unit
        =
        let property (select : ParkedSelect) : unit =
            let parked = ParkedSyscall.Select select
            let signal = WakeCondition.Primitive WakePrimitive.SignalDeliverable

            let expected =
                match select.Deadline with
                | None -> signal
                | Some deadline ->
                    WakeCondition.AnyOf (WakeCondition.Primitive (WakePrimitive.DeadlinePassed deadline), [ signal ])

            WakeCondition.ofPark parked |> shouldEqual expected

            WakeCondition.ofPark parked
            |> WakeCondition.deadlines
            |> shouldEqual (Option.toList select.Deadline)

            ParkedSyscall.descriptions parked |> shouldEqual []

            // Measured (`docs/probes/select-park`, row A3): EINTR under
            // SA_RESTART too, on both flavours.
            for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
                SyscallInterruption.ruleOf flavour parked
                |> shouldEqual SignalRestartRule.FailsWithEintr

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen selectGen) property)

    let private boot (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private thread : int = 1

    [<Test>]
    let ``a thread parked in a select is a ReservedPark defect, whose deadline the wait machinery reads`` () : unit =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let deadline = 1_000_000L

            let parked =
                ParkedSyscall.Select
                    {
                        ParkedSelect.Deadline = Some deadline
                    }

            let awake = boot flavour |> Threads.ensure thread
            awake |> UnixSystem.checkInvariants |> shouldEqual []

            let asleep = UnixWait.park thread parked awake

            asleep
            |> UnixSystem.checkInvariants
            |> shouldEqual [ UnixSystemDefect.ReservedPark (thread, parked) ]

            UnixWait.deadlines (Set.singleton thread) asleep |> shouldEqual [ deadline ]

            UnixWait.satisfied (Callers.thread thread asleep) asleep
            |> shouldEqual (Some Set.empty)

            let elapsed =
                { asleep with
                    Scheduling =
                        UnixSchedulingState.advanceClock
                            (deadline - asleep.Scheduling.NanosecondsSinceBoot)
                            asleep.Scheduling
                }

            UnixWait.satisfied (Callers.thread thread elapsed) elapsed
            |> shouldEqual (Some (Set.singleton (WakePrimitive.DeadlinePassed deadline)))
