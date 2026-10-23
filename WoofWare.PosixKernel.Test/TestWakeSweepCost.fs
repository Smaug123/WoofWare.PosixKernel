namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A `UnixWait.wake` sweep that has to ask every sleeping thread costs time
/// linear in how many threads sleep, whatever each sleeps on: asking one
/// thread's wake condition must not walk every open file description on the
/// machine. Measured by the bytes a sweep allocates, which unlike time do not
/// move with the host's load: a sweep of four times the threads may allocate
/// about four times as much, and one that asks each thread about every
/// description allocates about sixteen times as much.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestWakeSweepCost =

    let private platform : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64

    let private booted : UnixSystem<int, unit> =
        let launch =
            ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

        UnixSystem.initial platform |> UnixBootImage.boot launch

    let private pid : ProcessId = Seq.exactlyOne (UnixSystem.processIds booted)

    let private leader : Caller<int> = Caller.make pid 0

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    /// A new pipe of the leader's: its read end, its write end, and the system.
    let private pipe (system : UnixSystem<int, unit>) : int * int * UnixSystem<int, unit> =
        match UnixPipe.pipe2 leader 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, resume leader system
        | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"

    let private spawn (thread : int) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixThreadLifecycle.spawn leader thread (CpuId 0) system with
        | SpawnAnswer.Spawned _, system -> resume leader system
        | answer, _ -> failwith $"expected thread %d{thread} to start: %A{answer}"

    /// How thread `thread` goes to sleep on the pipe `readFd`, `writeFd` that
    /// the leader has just made for it alone.
    type private Sleeper = int -> int -> int -> UnixSystem<int, unit> -> UnixSystem<int, unit>

    let private readsEmptyPipe : Sleeper =
        fun thread readFd _ system ->
            match UnixReadWrite.read (Caller.make pid thread) readFd UserBuffer.Mapped 64UL system with
            | ReadOutcome.WouldBlock _, system -> system
            | outcome, _ -> failwith $"expected thread %d{thread}'s read to sleep: %A{outcome}"

    let private pollsEmptyPipe : Sleeper =
        fun thread readFd _ system ->
            let entry : PollEntry =
                {
                    Fd = readFd
                    // `POLLIN`.
                    Events = 1s
                }

            match UnixPoll.poll (Caller.make pid thread) [ entry ] -1 system with
            | PollOutcome.WouldBlock _, system -> system
            | outcome, _ -> failwith $"expected thread %d{thread}'s poll to sleep: %A{outcome}"

    /// The leader locks the write end, and the thread waits to lock the read
    /// end: both ends of a pipe are one object to `flock`.
    let private waitsForFlock : Sleeper =
        fun thread readFd writeFd system ->
            // `LOCK_EX`.
            let exclusive = 2

            let locked =
                match UnixDescriptor.flock leader writeFd exclusive system with
                | SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system -> resume leader system
                | outcome, _ -> failwith $"expected the leader to take the lock: %A{outcome}"

            match UnixDescriptor.flock (Caller.make pid thread) readFd exclusive locked with
            | SyscallOutcome.WouldBlock _, system -> system
            | outcome, _ -> failwith $"expected thread %d{thread}'s flock to sleep: %A{outcome}"

    /// A system with `count` threads besides the leader, each asleep through
    /// `sleeper` on a pipe of its own; and then a pipe more, so that the next
    /// `UnixWait.wake` has to sweep and wakes nobody.
    let private sleeping (sleeper : Sleeper) (count : int) : UnixSystem<int, unit> =
        let asleep =
            (booted, [ 1..count ])
            ||> List.fold (fun system thread ->
                let readFd, writeFd, system = pipe system
                let system = spawn thread system |> sleeper thread readFd writeFd

                match UnixWait.wake system with
                | [], system -> system
                | woken, _ -> failwith $"expected thread %d{thread} to stay asleep: %A{woken}"
            )

        let _, _, changed = pipe asleep
        changed

    /// The fewest bytes one sweep of `system` allocates, of several.
    let private sweepBytes (system : UnixSystem<int, unit>) : int64 =
        let sweep () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match UnixWait.wake system with
            | [], _ -> ()
            | woken, _ -> failwith $"expected the sweep to wake nobody: %A{woken}"

            GC.GetAllocatedBytesForCurrentThread () - before

        sweep () |> ignore
        List.init 5 (fun _ -> sweep ()) |> List.min

    [<TestCase "read">]
    [<TestCase "poll">]
    [<TestCase "flock">]
    let ``a sweep of four times the sleeping threads allocates at most about four times as much``
        (call : string)
        : unit
        =
        let sleeper =
            match call with
            | "read" -> readsEmptyPipe
            | "poll" -> pollsEmptyPipe
            | "flock" -> waitsForFlock
            | call -> failwith $"no sleeper for %s{call}"

        // 4 × 100 pipes, two descriptors each, stay under the 1024 descriptors
        // a process may have.
        let fewer = sweepBytes (sleeping sleeper 100)
        let more = sweepBytes (sleeping sleeper 400)

        // Linear growth gives a ratio a little under 4, and asking each
        // thread about every description about 16.
        let ratio = float more / float fewer

        if ratio > 5.0 then
            failwith $"%d{fewer} bytes a sweep of 100 sleeping threads, and %d{more} of 400: %.1f{ratio} times as much"

    /// What a crowd that sleeps on nothing is made of: idle processes beside
    /// the leader's, or running threads in the leader's process.
    type private Crowd =
        | Processes
        | RunningThreads

    /// What is measured of a system with a few sleepers in a crowd.
    type private Measured =
        /// A sweep that wakes nobody.
        | SweepWakingNobody
        /// A sweep that wakes one of the sleepers.
        | SweepWakingOne
        /// The deadlines the sleepers wait for (`UnixWait.deadlines`).
        | Deadlines

    /// A system with a crowd of `count` that sleeps on nothing, and three
    /// threads of the leader's asleep, each reading a pipe of its own; then
    /// changed so that the next `UnixWait.wake` sweeps: the first sleeper's
    /// write end closed, which wakes it, if `wakeOne`, and otherwise a pipe
    /// more, which wakes nobody.
    let private crowded (crowd : Crowd) (count : int) (wakeOne : bool) : UnixSystem<int, unit> =
        let crowd =
            match crowd with
            | Crowd.Processes ->
                (booted, [ 1..count ])
                ||> List.fold (fun system _ ->
                    let launch =
                        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

                    UnixSystem.launch launch system |> snd
                )
            | Crowd.RunningThreads -> (booted, [ 1..count ]) ||> List.fold (fun system i -> spawn (1000 + i) system)

        let writeFds, asleep =
            (([], crowd), [ 1..3 ])
            ||> List.fold (fun (writeFds, system) thread ->
                let readFd, writeFd, system = pipe system
                let system = spawn thread system |> readsEmptyPipe thread readFd writeFd

                match UnixWait.wake system with
                | [], system -> writeFds @ [ writeFd ], system
                | woken, _ -> failwith $"expected thread %d{thread} to stay asleep: %A{woken}"
            )

        if wakeOne then
            match UnixDescriptor.close leader (List.head writeFds) asleep with
            | SyscallAnswer.Completed 0L, system -> resume leader system
            | answer, _ -> failwith $"expected the close to succeed: %A{answer}"
        else
            let _, _, changed = pipe asleep
            changed

    /// The fewest bytes of several that measuring `measured` of `system`
    /// allocates.
    let private measuredBytes (measured : Measured) (system : UnixSystem<int, unit>) : int64 =
        let once () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match measured with
            | Measured.SweepWakingNobody ->
                match UnixWait.wake system with
                | [], _ -> ()
                | woken, _ -> failwith $"expected the sweep to wake nobody: %A{woken}"
            | Measured.SweepWakingOne ->
                match UnixWait.wake system with
                | [ caller, _ ], _ when caller = Caller.make pid 1 -> ()
                | woken, _ -> failwith $"expected the sweep to wake thread 1 alone: %A{woken}"
            | Measured.Deadlines -> UnixWait.deadlines system |> shouldEqual []

            GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    [<TestCase("processes", "nobody")>]
    [<TestCase("processes", "one")>]
    [<TestCase("processes", "deadlines")>]
    [<TestCase("threads", "nobody")>]
    [<TestCase("threads", "one")>]
    [<TestCase("threads", "deadlines")>]
    let ``finding three sleepers among four times the crowd allocates about as much``
        (crowd : string)
        (measured : string)
        : unit
        =
        let crowd =
            match crowd with
            | "processes" -> Crowd.Processes
            | "threads" -> Crowd.RunningThreads
            | crowd -> failwith $"no crowd %s{crowd}"

        let measured, wakeOne =
            match measured with
            | "nobody" -> Measured.SweepWakingNobody, false
            | "one" -> Measured.SweepWakingOne, true
            | "deadlines" -> Measured.Deadlines, false
            | measured -> failwith $"nothing measured as %s{measured}"

        let fewer = measuredBytes measured (crowded crowd 100 wakeOne)
        let more = measuredBytes measured (crowded crowd 400 wakeOne)

        // Finding the sleepers in time of their own number gives a ratio near
        // 1, and visiting every process or thread of the crowd about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith $"%d{fewer} bytes among a crowd of 100, and %d{more} among 400: %.2f{ratio} times as much"
