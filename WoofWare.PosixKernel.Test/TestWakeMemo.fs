namespace WoofWare.PosixKernel.Test

open System
open System.Collections
open System.Collections.Generic
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixWait.wake` answers from the memo a system carries (`UnixSystem.Sweep`)
/// only while nothing a wake condition reads has changed, even where nothing
/// but that one input has. `TestMultiProcessFuzz` holds it to the reference
/// sweep over random interleavings; each test here changes one input of the
/// memo's alone, as no random interleaving does, in a system that carries the
/// memo, and checks that the memo does not answer.
///
/// The memo is no part of a system's value, so equality and hashing ignore it;
/// and a system asked again answers itself, allocating nothing but its answer.
///
/// In a Debug build, the memo also counts the answers it has given since its
/// sweep, which decide the ones it checks against a sweep
/// (`WakeMemo.crossChecks`).
///
/// Some of those states are forged: every syscall that changes a process's
/// thread table or the set of processes changes the machine state too, so only
/// a hand-made state changes one without the other. The memo must not rely on
/// that.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestWakeMemo =

    let private linux : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64

    /// `machine` remembering no sweep, so that `UnixWait.wake` sweeps it.
    let private forgetting (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
        { machine with
            Sweep = WakeMemo.none
        }

    /// Whether `machine` carries a memo of a sweep.
    let private remembers (machine : UnixSystem<int, string>) : bool = machine.Sweep.Remembered.IsSome

    /// `UnixWait.wake` of `machine`, which must answer what the reference sweep
    /// answers given the threads its parks hold asleep (`ReferenceWake`), and
    /// wake what a sweep of `machine` without its memo wakes; and the system it
    /// answers.
    let private waking
        (machine : UnixSystem<int, string>)
        : ((ProcessId * int) * Set<WakePrimitive>) list * UnixSystem<int, string>
        =
        let asleep =
            Machines.parkStates machine
            |> fst
            |> Set.map (fun (pid, thread) -> Caller.make pid thread)

        let reference = ReferenceWake.wakes asleep machine
        let woken, after = UnixWait.wake machine
        woken |> shouldEqual reference

        let _, swept = UnixWait.wake (forgetting machine)
        Machines.parkStates after |> shouldEqual (Machines.parkStates swept)

        woken
        |> List.map (fun (caller, fired) -> (Caller.processId caller, Caller.thread caller), fired),
        after

    /// `thread` of `pid` in a blocking `accept` on `listener`, which must sleep.
    let private parkInAccept
        (pid : ProcessId)
        (thread : int)
        (listener : int)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        Machines.doIn
            pid
            (fun view ->
                match UnixConnection.tryAccept (Caller.make pid thread) listener UserBuffer.Mapped 16u 0 view with
                | Ok (AcceptOutcome.WouldBlock _, view) -> view
                | other -> failwith $"accept by thread %d{thread}: %A{other}"
            )
            machine

    [<Test>]
    let ``a signal for a sleeping thread wakes it, though only the process's own state changed`` () : unit =
        let pids, machine = Machines.withThreads linux 1 2
        let pid = pids.[0]

        let listener, machine =
            Machines.inProcess
                pid
                (fun view ->
                    let view =
                        match
                            UnixSignal.sigaction
                                (Callers.leader view)
                                10
                                (Some (SignalDisposition.Catch (SignalCatch.ofHandler "h")))
                                view
                        with
                        | SigactionAnswer.Completed _, view -> view
                        | SigactionAnswer.Failed error, _ -> failwith $"sigaction: %O{error}"

                    KeventWorld.listenerAt 8080us view
                )
                machine

        let machine = parkInAccept pid 1 listener machine

        let woken, swept = waking machine
        woken |> shouldEqual []
        remembers swept |> shouldEqual true

        // Thread 0 sends SIGUSR1, which thread 1 catches, to thread 1.
        let signalled =
            Machines.doIn
                pid
                (fun view ->
                    match UnixSignal.tryPthreadKill (Callers.leader view) 1 10 view with
                    | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, view)) -> view
                    | other -> failwith $"pthread_kill: %A{other}"
                )
                swept

        LanguagePrimitives.PhysicalEquality (Kernel.machine signalled) (Kernel.machine swept)
        |> shouldEqual true

        LanguagePrimitives.PhysicalEquality
            (ProcessTable.find "test" (ProcessId.toInt32 pid) signalled.Processes).Threads
            (ProcessTable.find "test" (ProcessId.toInt32 pid) swept.Processes).Threads
        |> shouldEqual true

        // The call carried the memo into the system it answered.
        remembers signalled |> shouldEqual true

        waking signalled
        |> fst
        |> shouldEqual [ (pid, 1), Set.singleton WakePrimitive.SignalDeliverable ]

    /// One process whose threads 0 and 1 sleep in `accept` on its listener, which
    /// holds a connection; the sweep has woken thread 0, whose call has not yet
    /// finished, so thread 1 waits behind it. The process's ID, and the machine.
    let private behindAWokenAccepter () : ProcessId * UnixSystem<int, string> =
        let pids, machine = Machines.withThreads linux 1 3
        let pid = pids.[0]

        let listener, machine =
            Machines.inProcess pid (KeventWorld.listenerAtIn pid 8080us) machine

        let machine =
            machine
            |> parkInAccept pid 0 listener
            |> parkInAccept pid 1 listener
            // Thread 2 connects: threads 0 and 1 are asleep, and a thread asleep in
            // one call makes no other.
            |> Machines.doIn pid (fun view -> KeventWorld.clientAs (Caller.make pid 2) 8080us view |> snd)

        pid, Machines.waking [ pid, 0 ] machine

    /// `machine` with thread 0 of `pid` unparked in the thread table alone, as its
    /// finished `accept` leaves it: a forged state, whose open file table still
    /// counts the park's hold.
    let private finishedInThreadsAlone (pid : ProcessId) (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
        let slot = ProcessTable.find "test" (ProcessId.toInt32 pid) machine.Processes

        { machine with
            Processes =
                ProcessTable.add
                    (ProcessId.toInt32 pid)
                    { slot with
                        Threads = UnixThreadTable.unpark 0 slot.Threads
                    }
                    machine.Processes
        }

    [<Test>]
    let ``a woken accepter's finish lets the next one wake, though only the thread table changed`` () : unit =
        let pid, machine = behindAWokenAccepter ()

        let woken, swept = waking machine
        woken |> shouldEqual []

        let finished = finishedInThreadsAlone pid swept
        remembers finished |> shouldEqual true

        waking finished |> fst |> List.map fst |> shouldEqual [ pid, 1 ]

    [<Test>]
    let ``a process gone, or another in its place, is swept again, though nothing else changed`` () : unit =
        let pid, machine = behindAWokenAccepter ()
        let finished = finishedInThreadsAlone pid machine
        let other = ProcessId.parseOrFail "TestWakeMemo" 9999

        // A second process holding a copy of the first's threads, thread 0 among
        // them woken in its accept and not finished: thread 1 of the first
        // waits behind it.
        let withCopy =
            { finished with
                Processes =
                    ProcessTable.add
                        (ProcessId.toInt32 other)
                        (ProcessTable.find "test" (ProcessId.toInt32 pid) machine.Processes)
                        finished.Processes
            }

        let woken, swept = waking withCopy
        woken |> shouldEqual []
        remembers swept |> shouldEqual true

        // Without it, thread 1 wakes.
        let without =
            { swept with
                Processes = finished.Processes
            }

        remembers without |> shouldEqual true
        waking without |> fst |> List.map fst |> shouldEqual [ pid, 1 ]

        // With a process of no threads under another ID in its place, thread 1
        // wakes too.
        let replaced =
            { swept with
                Processes =
                    ProcessTable.add
                        9998
                        { ProcessTable.find "test" (ProcessId.toInt32 pid) machine.Processes with
                            Threads = UnixThreadTable.empty
                        }
                        finished.Processes
            }

        remembers replaced |> shouldEqual true
        waking replaced |> fst |> List.map fst |> shouldEqual [ pid, 1 ]

    /// One process whose threads 0 and 1 poll its idle listener, for 5 ms and
    /// for 10 ms; the process's ID, and the machine.
    let private twoPollers () : ProcessId * UnixSystem<int, string> =
        let pids, machine = Machines.withThreads linux 1 2
        let pid = pids.[0]

        let listener, machine =
            Machines.inProcess pid (KeventWorld.listenerAtIn pid 8080us) machine

        let pollFor (thread : int) (milliseconds : int) (machine : UnixSystem<int, string>) =
            Machines.doIn
                pid
                (fun view ->
                    let entry =
                        {
                            Fd = listener
                            Events = 0x0001s
                        }

                    match UnixPoll.tryPoll (Callers.thread thread view) [ entry ] milliseconds view with
                    | Ok (PollOutcome.WouldBlock _, view) -> view
                    | other -> failwith $"poll by thread %d{thread}: %A{other}"
                )
                machine

        pid, machine |> pollFor 0 5 |> pollFor 1 10

    [<Test>]
    let ``the earliest of several deadlines ends the memo's answer, not the latest`` () : unit =
        let pid, machine = twoPollers ()

        let woken, swept = waking machine
        woken |> shouldEqual []

        // Short of the earliest deadline, the memo answers the system itself.
        let sooner = UnixSystem.advanceClock 4_000_000L swept
        remembers sooner |> shouldEqual true
        let woken, after = waking sooner
        woken |> shouldEqual []
        obj.ReferenceEquals (after, sooner) |> shouldEqual true

        let later = UnixSystem.advanceClock 7_000_000L swept

        LanguagePrimitives.PhysicalEquality (Kernel.machine later) (Kernel.machine swept)
        |> shouldEqual true

        remembers later |> shouldEqual true

        match waking later |> fst with
        | [ (woke, fired) ] ->
            woke |> shouldEqual (pid, 0)

            fired
            |> Set.forall (fun primitive ->
                match primitive with
                | WakePrimitive.DeadlinePassed _ -> true
                | _ -> false
            )
            |> shouldEqual true
        | other -> failwith $"expected thread 0 alone to wake for its deadline, but %A{other} woke"

    [<Test>]
    let ``a sweep that wakes nobody answers an equal system that remembers it, and a sweep that wakes someone one that remembers nothing``
        ()
        : unit
        =
        let pid, machine = behindAWokenAccepter ()
        remembers machine |> shouldEqual false

        let woken, swept = waking machine
        woken |> shouldEqual []
        obj.ReferenceEquals (swept, machine) |> shouldEqual false
        swept |> shouldEqual machine

        obj.ReferenceEquals (Kernel.machine swept, Kernel.machine machine)
        |> shouldEqual true

        obj.ReferenceEquals (Kernel.scheduling swept, Kernel.scheduling machine)
        |> shouldEqual true

        obj.ReferenceEquals (swept.Processes, machine.Processes) |> shouldEqual true
        remembers swept |> shouldEqual true

        // Asked again, it answers the system itself.
        let woken, again = waking swept
        woken |> shouldEqual []
        obj.ReferenceEquals (again, swept) |> shouldEqual true

        // Thread 0 finishes its accept, and thread 1 wakes: the system that
        // answers remembers no sweep.
        let woken, after = waking (finishedInThreadsAlone pid swept)
        woken |> List.map fst |> shouldEqual [ pid, 1 ]
        remembers after |> shouldEqual false

    /// `a` and `b` are equal, through every way .NET and F# ask, and hash alike.
    let private equalEveryWay (a : UnixSystem<int, string>) (b : UnixSystem<int, string>) : unit =
        (a = b) |> shouldEqual true
        a.Equals (b :> obj) |> shouldEqual true
        (a :> IEquatable<UnixSystem<int, string>>).Equals b |> shouldEqual true

        EqualityComparer<UnixSystem<int, string>>.Default.Equals (a, b)
        |> shouldEqual true

        HashIdentity.Structural<UnixSystem<int, string>>.Equals (a, b)
        |> shouldEqual true

        (a :> IStructuralEquatable).Equals (b, StructuralComparisons.StructuralEqualityComparer)
        |> shouldEqual true

        hash a |> shouldEqual (hash b)
        a.GetHashCode () |> shouldEqual (b.GetHashCode ())

        (a :> IStructuralEquatable).GetHashCode StructuralComparisons.StructuralEqualityComparer
        |> shouldEqual ((b :> IStructuralEquatable).GetHashCode StructuralComparisons.StructuralEqualityComparer)

    [<Test>]
    let ``two systems that differ only in their memos are equal, and hash alike`` () : unit =
        let _, accepters = behindAWokenAccepter ()
        let _, pollers = twoPollers ()

        for machine, another in [ accepters, pollers ; pollers, accepters ] do
            let _, swept = UnixWait.wake (forgetting machine)
            let _, other = UnixWait.wake (forgetting another)

            // The same system remembering nothing, its own sweep, another system's
            // sweep, and its own sweep after the memo has answered.
            let answered = snd (UnixWait.wake swept)

            let variants =
                [
                    forgetting machine
                    swept
                    { machine with
                        Sweep = other.Sweep
                    }
                    answered
                ]

            remembers swept |> shouldEqual true
            remembers other |> shouldEqual true

            for a in variants do
                for b in variants do
                    equalEveryWay a b

            // And equality still reads everything else.
            (UnixSystem.advanceClock 1L swept = swept) |> shouldEqual false

    [<Test>]
    let ``a system has no comparison, so no comparison can read its memo`` () : unit =
        typeof<IComparable>.IsAssignableFrom typeof<UnixSystem<int, string>>
        |> shouldEqual false

        typeof<IStructuralComparable>.IsAssignableFrom typeof<UnixSystem<int, string>>
        |> shouldEqual false

    [<Test>]
    let ``asking wake again of the system it answered sweeps nothing, and allocates nothing but the answer`` () : unit =
        // A client asks `wake` before almost every instruction, and almost every
        // time nothing has changed. The answer is a tuple, a reference type, so
        // each call allocates that and nothing else: two references, a header
        // and a method table pointer.
        let tuple = 4L * int64 IntPtr.Size

        // In a Debug build the memo checks the first `CrossCheckedFirst` of its
        // answers, and one in every `CrossCheckedEvery` after, against a sweep;
        // the answers between are the ones measured.
        let unchecked = WakeMemo.CrossCheckedEvery - WakeMemo.CrossCheckedFirst

        /// The bytes allocated while `answers` answers after the checked ones
        /// were given, of a system that has been swept once; and whether each
        /// answered the system itself.
        let measure (answers : int) (machine : UnixSystem<int, string>) : int64 * bool =
            let woken, swept = UnixWait.wake (forgetting machine)
            woken |> shouldEqual []

            for _ in 1 .. WakeMemo.CrossCheckedFirst do
                UnixWait.wake swept |> ignore

            let mutable same = true
            let before = GC.GetAllocatedBytesForCurrentThread ()

            for _ in 1..answers do
                let woken, after = UnixWait.wake swept
                same <- same && woken.IsEmpty && obj.ReferenceEquals (after, swept)

            GC.GetAllocatedBytesForCurrentThread () - before, same

        let _, accepters = behindAWokenAccepter ()
        let _, pollers = twoPollers ()

        // Warm up, so that nothing the first calls do once is counted.
        measure unchecked accepters |> ignore

        // What measuring allocates besides the answers: nothing in a Debug
        // build, and one object of its own in an optimised one (measured).
        let around, _ = measure 0 accepters

        for machine in [ accepters ; pollers ] do
            let allocated, same = measure unchecked machine
            same |> shouldEqual true
            allocated - around |> shouldBeSmallerThan (tuple * int64 unchecked + 1L)

        // A sweep, which the memo spares, allocates far more than that.
        let before = GC.GetAllocatedBytesForCurrentThread ()
        UnixWait.wake (forgetting accepters) |> ignore

        GC.GetAllocatedBytesForCurrentThread () - before
        |> shouldBeGreaterThan (4L * tuple)

    [<Test>]
    let ``the cross-check takes every one of the first answers after a sweep, and at least one in every so many after``
        ()
        : unit
        =
        let hits = 100_000
        let checkedHits = [ 0 .. hits - 1 ] |> List.filter WakeMemo.crossChecks

        checkedHits
        |> List.take WakeMemo.CrossCheckedFirst
        |> shouldEqual [ 0 .. WakeMemo.CrossCheckedFirst - 1 ]

        // No run of `CrossCheckedEvery` answers in a row goes unchecked.
        (checkedHits @ [ hits ])
        |> List.pairwise
        |> List.forall (fun (before, after) -> after - before <= WakeMemo.CrossCheckedEvery)
        |> shouldEqual true

        // And no more are checked than that needs.
        checkedHits.Length
        |> shouldBeSmallerThan (WakeMemo.CrossCheckedFirst + hits / WakeMemo.CrossCheckedEvery + 2)

    [<Test>]
    let ``a memo counts the answers it has given since its sweep, from none after each sweep`` () : unit =
#if DEBUG
        let hits (machine : UnixSystem<int, string>) : int =
            machine.Sweep.Remembered.Value.HitsSinceSweep

        let pid, machine = behindAWokenAccepter ()

        let woken, swept = waking machine
        woken |> shouldEqual []
        hits swept |> shouldEqual 0

        for expected in 1..5 do
            let woken, after = waking swept
            woken |> shouldEqual []
            obj.ReferenceEquals (after, swept) |> shouldEqual true
            hits swept |> shouldEqual expected

        // The process's threads, the same threads in another map: the memo does not answer, and the
        // sweep wakes nobody, so the system it answers remembers it afresh.
        let slot = ProcessTable.find "test" (ProcessId.toInt32 pid) swept.Processes

        let copied =
            { swept with
                Processes =
                    ProcessTable.add
                        (ProcessId.toInt32 pid)
                        { slot with
                            Threads =
                                UnixThreadTable.ofMap (Map.ofList (Map.toList (UnixThreadTable.byName slot.Threads)))
                        }
                        swept.Processes
            }

        let woken, reswept = waking copied
        woken |> shouldEqual []
        obj.ReferenceEquals (reswept, copied) |> shouldEqual false
        hits reswept |> shouldEqual 0

        let woken, _ = waking reswept
        woken |> shouldEqual []
        hits reswept |> shouldEqual 1
#else
        Assert.Ignore "A memo counts its answers only in a Debug build, which cross-checks some of them."
#endif
