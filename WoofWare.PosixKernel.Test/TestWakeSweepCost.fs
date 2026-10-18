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
