namespace WoofWare.PosixKernel.Test

open System
open NUnit.Framework
open WoofWare.PosixKernel

/// A `close` of a descriptor that no sleeping call refers to costs the same
/// however many of the process's threads sleep: the close must not visit them
/// to find that none needs it. Measured by the bytes a close allocates, which
/// unlike time do not move with the host's load: a close in a process with
/// four times the sleeping threads allocates about as much, and one that
/// visits each sleeping thread about four times as much.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCloseCost =

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    let private creating : OpenFlags =
        {
            Access = FileAccessMode.ReadWrite
            Create = true
            Exclusive = true
            Truncate = false
            NoFollow = false
            CloseOnExec = false
            Synchronous = false
            DataSynchronous = false
            Directory = false
        }

    /// A system on `platform` whose one process has `count` threads besides
    /// its leader, each asleep in `pause(2)`, and the descriptor the leader
    /// then opened onto a new `target`: "pipe" for a pipe's read end, "file"
    /// for a regular file.
    let private pausedThen
        (platform : SimulatedUnixPlatform)
        (target : string)
        (count : int)
        : Caller<int> * int * UnixSystem<int, unit>
        =
        let launch =
            ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let booted = UnixSystem.initial platform |> UnixBootImage.boot launch
        let pid = Seq.exactlyOne (UnixSystem.processIds booted)
        let leader = Caller.make pid 0

        let paused =
            (booted, [ 1..count ])
            ||> List.fold (fun system thread ->
                let system =
                    match UnixThreadLifecycle.spawn leader thread (CpuId 0) system with
                    | SpawnAnswer.Spawned _, system -> resume leader system
                    | answer, _ -> failwith $"expected thread %d{thread} to start: %A{answer}"

                match UnixSignal.pause (Caller.make pid thread) system with
                | SigsuspendOutcome.WouldBlock _, system -> system
                | outcome, _ -> failwith $"expected thread %d{thread}'s pause to sleep: %A{outcome}"
            )

        let fd, opened =
            match target with
            | "pipe" ->
                match UnixPipe.pipe2 leader 0 UserBuffer.Mapped paused with
                | Pipe2Answer.Created (readFd, _), system -> readFd, resume leader system
                | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"
            | "file" ->
                match OpenFlagWords.openPath (PathArg.ofText "/closed") creating 0o600 paused with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, resume leader system
                | other -> failwith $"expected the open to make a file: %A{other}"
            | target -> failwith $"no target %s{target}"

        match UnixWait.wake opened with
        | [], system -> leader, fd, system
        | woken, _ -> failwith $"expected every thread to stay asleep: %A{woken}"

    /// The fewest bytes a close of `fd` by `leader` in `system` allocates, of
    /// several.
    let private closeBytes (leader : Caller<int>) (fd : int) (system : UnixSystem<int, unit>) : int64 =
        let close () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match UnixDescriptor.close leader fd system with
            | SyscallAnswer.Completed 0L, _ -> ()
            | answer, _ -> failwith $"expected the close to succeed: %A{answer}"

            GC.GetAllocatedBytesForCurrentThread () - before

        close () |> ignore
        List.init 5 (fun _ -> close ()) |> List.min

    [<TestCase("linux", "pipe")>]
    [<TestCase("linux", "file")>]
    [<TestCase("darwin", "pipe")>]
    [<TestCase("darwin", "file")>]
    let ``a close no sleeping call refers to allocates about as much among four times the sleeping threads``
        (flavour : string, target : string)
        : unit
        =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | "darwin" -> SimulatedUnixPlatform.macOsArm64
            | flavour -> failwith $"no platform for %s{flavour}"

        let fewer =
            let leader, fd, system = pausedThen platform target 100
            closeBytes leader fd system

        let more =
            let leader, fd, system = pausedThen platform target 400
            closeBytes leader fd system

        // A cost independent of the sleeping threads gives a ratio near 1
        // (a lookup in a map of four times the threads may cost a little
        // more), and visiting each of them about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes a close among 100 sleeping threads, and %d{more} among 400: %.1f{ratio} times as much"
