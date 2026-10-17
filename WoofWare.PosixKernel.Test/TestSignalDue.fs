namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A thread owes its return to user mode from the moment a signal is
/// deliverable to it, whichever thread's call made it so, and until it has
/// returned, any call it makes throws `InvalidOperationException`. Each test
/// here makes a signal deliverable by one of the ways a kernel does, and finds
/// the thread it is deliverable to owing that return, and no other.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSignalDue =

    /// What `caller`'s thread owes before it makes another call.
    let private owed (caller : Caller<int>) (system : UnixSystem<int, string>) : OwedReturn option =
        UnixThreadTable.owedBy (Caller.thread caller) (Proc.threads (Caller.processId caller) system)

    /// `caller`'s return to user mode, at which it takes nothing.
    let private resumes (caller : Caller<int>) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"%O{caller}'s return to user mode: expected it to take nothing, got %A{other}"

    let private signo (system : UnixSystem<int, string>) (signal : Signal) : int =
        Signal.toRawSignoUnder (Lone.UnixSystemState.signalNumbering system) signal

    /// `sigaction(signal, disposition)` by `caller`, followed by its return to
    /// user mode.
    let private dispose
        (caller : Caller<int>)
        (signal : Signal)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction caller (signo system signal) (Some disposition) system with
        | Ok (_, system) -> resumes caller system
        | Error error -> failwith $"sigaction of %O{signal} by %O{caller}: %O{error}"

    let private caught : SignalDisposition<string> =
        SignalDisposition.Catch (SignalCatch.ofHandler "h")

    /// `pthread_kill(target, signal)` by `sender`, which runs on.
    let private send
        (sender : Caller<int>)
        (target : int)
        (signal : Signal)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.pthreadKill sender target (signo system signal) system with
        | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
        | other -> failwith $"pthread_kill of %d{target} with %O{signal} by %O{sender}: %A{other}"

    /// `kill(getpid(), signal)` by `sender`, which runs on.
    let private kill
        (sender : Caller<int>)
        (signal : Signal)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let pid = ProcessId.toInt32 (Caller.processId sender)

        match UnixSignal.kill sender pid (signo system signal) system with
        | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
        | other -> failwith $"kill of the process with %O{signal} by %O{sender}: %A{other}"

    /// `pthread_sigmask(SIG_SETMASK, signals)` by `caller`.
    let private setMask
        (caller : Caller<int>)
        (signals : Set<Signal>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let numbering = Lone.UnixSystemState.signalNumbering system

        let setMaskHow =
            match numbering with
            | SignalNumbering.Linux -> 2
            | SignalNumbering.Darwin -> 3

        match UnixSignal.pthreadSigmask caller setMaskHow (Some (SignalMask.ofSignals numbering signals)) system with
        | Ok (_, system) -> system
        | Error error -> failwith $"pthread_sigmask by %O{caller}: %O{error}"

    /// That `caller`'s next call throws, because it owes a return to user mode
    /// for a signal deliverable to it.
    let private refusesCalls (caller : Caller<int>) (system : UnixSystem<int, string>) : unit =
        let thrown =
            Assert.Throws<InvalidOperationException> (fun () -> UnixSystem.processId caller system |> ignore<ProcessId>)

        thrown.Message |> shouldContainText "a signal is deliverable to it"

    /// A process of `count` threads, 0 its leader, on `platform`.
    let private processOf (platform : SimulatedUnixPlatform) (count : int) : ProcessId * UnixSystem<int, string> =
        let pids, system = Machines.withThreads platform 1 count
        List.exactlyOne pids, system

    /// The sequence a signal's receiver could make were it not held to its
    /// return: thread 1 sends thread 0 a caught SIGUSR1; thread 0 calls
    /// `getpid`, which is answered with no system to mark it in, then ignores
    /// SIGUSR1, which discards it, so that its handler never runs. A real
    /// thread takes the signal before it runs more of its own code, so the
    /// `getpid` is refused.
    [<Test>]
    let ``a signal another thread sends holds its receiver to its return before the receiver's next call`` () : unit =
        for platform in Machines.platforms do
            let pids, system = Machines.withThreads platform 1 2
            let pid = List.exactlyOne pids
            let receiver = Caller.make pid 0
            let sender = Caller.make pid 1

            let usr1 =
                Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering platform) Signal.SIGUSR1

            let sent =
                let caught =
                    dispose receiver Signal.SIGUSR1 (SignalDisposition.Catch (SignalCatch.ofHandler "h")) system

                match UnixSignal.pthreadKill sender 0 usr1 caught with
                | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> resumes sender system
                | other -> failwith $"%O{platform}: pthread_kill of thread 0: %A{other}"

            let getpid =
                try
                    Ok (UnixSystem.processId receiver sent)
                with :? InvalidOperationException as e ->
                    Error e.Message

            match getpid with
            | Error message ->
                message |> shouldContainText "UnixSystem.processId: "
                message |> shouldContainText "a signal is deliverable to it"
            | Ok _ ->
                // What the client could go on to do: ignore the signal, so that
                // the handler it was sent to never runs.
                let ignored = dispose receiver Signal.SIGUSR1 SignalDisposition.Ignore sent

                failwith
                    $"%O{platform}: thread 0 made getpid with SIGUSR1 deliverable to it, then ignored SIGUSR1 and returned to user mode, and no handler ran; pending afterwards: %A{SignalState.pending (Lone.proc ignored).Signals}"

            // The return the receiver owes runs the handler.
            match UnixSignal.onReturnToUser receiver sent with
            | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), _) ->
                frame.Entry.Signal |> shouldEqual Signal.SIGUSR1
            | other -> failwith $"%O{platform}: thread 0's return to user mode: %A{other}"

    /// `pthread_kill` of the caller itself, which is `raise`: the caller owes.
    [<Test>]
    let ``a signal a thread sends itself holds it to its return`` () : unit =
        for platform in Machines.platforms do
            let pid, system = processOf platform 2
            let thread = Caller.make pid 1

            let system =
                dispose thread Signal.SIGUSR1 caught system |> send thread 1 Signal.SIGUSR1

            owed thread system |> shouldEqual (Some OwedReturn.SignalDue)
            owed (Caller.make pid 0) system |> shouldEqual None
            refusesCalls thread system

    /// `kill` of the process by a thread other than the leader: the leader
    /// takes the process's signals, and owes the return; the sender does not.
    [<Test>]
    let ``a signal sent to the process holds the leader to its return, and not the sender`` () : unit =
        for platform in Machines.platforms do
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let sender = Caller.make pid 1

            let system =
                dispose leader Signal.SIGUSR1 caught system |> kill sender Signal.SIGUSR1

            owed leader system |> shouldEqual (Some OwedReturn.SignalDue)
            owed sender system |> shouldEqual None
            refusesCalls leader system

    /// The `SIGPIPE` of a write into a pipe with no reader, by a thread other
    /// than the leader: Linux sends it to the writer, Darwin to the process,
    /// whose leader takes it.
    [<Test>]
    let ``a write's SIGPIPE holds the thread it is deliverable to to its return`` () : unit =
        for platform in Machines.platforms do
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let writer = Caller.make pid 1

            let system = dispose leader Signal.SIGPIPE caught system

            let writeFd, system =
                match UnixPipe.pipe2 leader 0 UserBuffer.Mapped system with
                | Pipe2Answer.Created (readFd, writeFd), system ->
                    let _, system = UnixDescriptor.close leader readFd system
                    writeFd, resumes leader system
                | other, _ -> failwith $"%O{platform}: pipe2: %A{other}"

            let written =
                match UnixReadWrite.write writer writeFd UserBuffer.Mapped 1UL system with
                | CallProgress.Answered (ProcessFate.Continues (WriteOutcome.ReturnsRaising _, system)) -> system
                | CallProgress.NeedsCopyIn paused ->
                    match UnixReadWrite.writeWithBytes (ImmutableArray.Create<byte> 0uy) paused with
                    | ProcessFate.Continues (WriteOutcome.ReturnsRaising _, system) -> system
                    | other -> failwith $"%O{platform}: the write: %A{other}"
                | other -> failwith $"%O{platform}: the write: %A{other}"

            let receiver, other =
                match SimulatedUnixPlatform.flavour platform with
                | SimulatedUnixFlavour.Linux -> writer, leader
                | SimulatedUnixFlavour.Darwin -> leader, writer

            owed receiver written |> shouldEqual (Some OwedReturn.SignalDue)
            owed other written |> shouldEqual None
            refusesCalls receiver written

    /// Under Darwin, a `close` of the descriptor a sleeping pipe write was made
    /// through ends the write and raises `SIGPIPE` for the process, whose
    /// leader takes it: here neither the closer nor the writer.
    [<Test>]
    let ``a close that ends a Darwin write holds the leader to its return for the SIGPIPE it raises`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64
        let pid, system = processOf platform 3
        let leader = Caller.make pid 0
        let writer = Caller.make pid 1
        let closer = Caller.make pid 2

        let system = dispose leader Signal.SIGPIPE caught system

        let writeFd, system =
            match UnixPipe.pipe2 leader 0 UserBuffer.Mapped system with
            | Pipe2Answer.Created (_, writeFd), system -> writeFd, resumes leader system
            | other, _ -> failwith $"pipe2: %A{other}"

        // More than the pipe holds, so the write sleeps for room.
        let count = 1 <<< 20

        let asleep =
            match UnixReadWrite.write writer writeFd UserBuffer.Mapped (uint64 count) system with
            | CallProgress.NeedsCopyIn paused ->
                let range = PausedWrite.copyRange paused

                match
                    UnixReadWrite.writeWithBytes
                        (ImmutableArray.Create<byte> (Array.zeroCreate<byte> range.ByteCount))
                        paused
                with
                | ProcessFate.Continues (WriteOutcome.WouldBlock _, system) -> system
                | other -> failwith $"the write: expected it to sleep, got %A{other}"
            | CallProgress.Answered other -> failwith $"the write: expected it to copy, got %A{other}"

        let closed =
            match UnixDescriptor.close closer writeFd asleep with
            | SyscallAnswer.Completed 0L, system -> system
            | other -> failwith $"the close: %A{other}"

        owed leader closed |> shouldEqual (Some OwedReturn.SignalDue)
        owed closer closed |> shouldEqual None
        refusesCalls leader closed

    /// A mask call that unblocks a signal pending for its caller: the caller
    /// owes, by each of the mask calls.
    [<Test>]
    let ``a mask call that unblocks a pending signal holds its caller to its return`` () : unit =
        for platform in Machines.platforms do
            let numbering = SimulatedUnixPlatform.signalNumbering platform
            let usr1 = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR1)

            let unblock (how : string) (caller : Caller<int>) (system : UnixSystem<int, string>) =
                let unblockHow =
                    match numbering with
                    | SignalNumbering.Linux -> 1
                    | SignalNumbering.Darwin -> 2

                match how with
                | "pthread_sigmask" -> UnixSignal.pthreadSigmask caller unblockHow (Some usr1) system
                | "sigprocmask" -> UnixSignal.sigprocmask caller unblockHow (Some usr1) system
                | "rt_sigprocmask" -> UnixSignal.rtSigprocmask caller unblockHow (Some usr1) 8UL system
                | other -> failwith $"unknown mask call %s{other}"
                |> function
                    | Ok (_, system) -> system
                    | Error error -> failwith $"%O{platform} %s{how}: %O{error}"

            let calls =
                match numbering with
                | SignalNumbering.Linux -> [ "pthread_sigmask" ; "sigprocmask" ; "rt_sigprocmask" ]
                | SignalNumbering.Darwin -> [ "pthread_sigmask" ; "sigprocmask" ]

            for how in calls do
                let pid, system = processOf platform 2
                let leader = Caller.make pid 0
                let blocker = Caller.make pid 1

                let blocked =
                    dispose leader Signal.SIGUSR1 caught system
                    |> setMask blocker (Set.singleton Signal.SIGUSR1)
                    |> setMask leader (Set.singleton Signal.SIGUSR1)
                    |> send leader 1 Signal.SIGUSR1

                // Blocked, it is deliverable to no one.
                owed blocker blocked |> shouldEqual None

                let unblocked = unblock how blocker blocked
                owed blocker unblocked |> shouldEqual (Some OwedReturn.SignalDue)
                owed leader unblocked |> shouldEqual None
                refusesCalls blocker unblocked

    /// A `sigreturn` that restores a mask letting through a signal sent while
    /// the handler blocked it: the thread owes.
    [<Test>]
    let ``a sigreturn that unblocks a pending signal holds its caller to its return`` () : unit =
        for platform in Machines.platforms do
            let numbering = SimulatedUnixPlatform.signalNumbering platform
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let handled = Caller.make pid 1

            let blocksUsr2 =
                SignalDisposition.Catch
                    { SignalCatch.ofHandler "h" with
                        Mask = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR2)
                    }

            let system =
                dispose leader Signal.SIGUSR1 blocksUsr2 system
                |> dispose leader Signal.SIGUSR2 caught
                |> send leader 1 Signal.SIGUSR1

            let frame, inHandler =
                match UnixSignal.onReturnToUser handled system with
                | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), system) -> frame, system
                | other -> failwith $"%O{platform}: thread 1's return: %A{other}"

            // Sent while the handler blocks it, it waits.
            let sent = send leader 1 Signal.SIGUSR2 inHandler
            owed handled sent |> shouldEqual None

            let returned = UnixSignal.sigreturn handled frame.Id sent
            owed handled returned |> shouldEqual (Some OwedReturn.SignalDue)
            refusesCalls handled returned

            match UnixSignal.onReturnToUser handled returned with
            | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), _) ->
                frame.Entry.Signal |> shouldEqual Signal.SIGUSR2
            | other -> failwith $"%O{platform}: thread 1's return after its sigreturn: %A{other}"

    /// A leader's return whose handler frames come to block a signal pending
    /// on the process, which Linux then hands to a thread that does not block
    /// it (`retarget_shared_pending`): that thread owes, and taking the signal
    /// there ends the process. Under Darwin, which put the signal in the
    /// leader's own set as it was sent, no other thread takes it.
    [<Test>]
    let ``a leader's return that blocks a signal of the process's holds the thread that takes it to its return``
        ()
        : unit
        =
        for platform in Machines.platforms do
            let numbering = SimulatedUnixPlatform.signalNumbering platform
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let other = Caller.make pid 1

            let blocksTerm =
                SignalDisposition.Catch
                    { SignalCatch.ofHandler "h" with
                        Mask = SignalMask.ofSignals numbering (Set.singleton Signal.SIGTERM)
                    }

            // SIGHUP comes before SIGTERM in the order the leader takes the
            // process's signals, on both flavours. SIGTERM is caught as it is
            // sent, so that it waits for the leader rather than ending the
            // process, and then reset to its default.
            let sent =
                dispose leader Signal.SIGHUP blocksTerm system
                |> dispose leader Signal.SIGTERM caught
                |> kill other Signal.SIGHUP
                |> kill other Signal.SIGTERM
                |> dispose other Signal.SIGTERM SignalDisposition.Default

            owed leader sent |> shouldEqual (Some OwedReturn.SignalDue)
            owed other sent |> shouldEqual None

            let returned =
                match UnixSignal.onReturnToUser leader sent with
                | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), system) ->
                    frame.Entry.Signal |> shouldEqual Signal.SIGHUP
                    system
                | other -> failwith $"%O{platform}: the leader's return: %A{other}"

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux ->
                owed other returned |> shouldEqual (Some OwedReturn.SignalDue)
                refusesCalls other returned

                match UnixSignal.onReturnToUser other returned with
                | ProcessFate.ProcessEnded (ended, _) ->
                    EndedProcess.termination ended
                    |> shouldEqual (ProcessTermination.Signaled (Signal.SIGTERM, false))
                | outcome -> failwith $"%O{platform}: thread 1's return: %A{outcome}"
            | SimulatedUnixFlavour.Darwin -> owed other returned |> shouldEqual None

    /// A return that stops at a default that stops the process, with another
    /// signal deliverable behind it: the return is not over, so the thread
    /// owes the rest of it, which takes that signal.
    [<Test>]
    let ``a return that stops the process with a signal still deliverable leaves the thread owing the rest`` () : unit =
        for platform in Machines.platforms do
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let stopped = Caller.make pid 1

            // SIGTSTP comes before SIGWINCH in the order a thread takes them,
            // on both flavours, and nothing pushes a frame before the stop.
            let both = Set.ofList [ Signal.SIGTSTP ; Signal.SIGWINCH ]

            let pending =
                dispose leader Signal.SIGWINCH caught system
                |> setMask stopped both
                |> send leader 1 Signal.SIGTSTP
                |> send leader 1 Signal.SIGWINCH

            let unblocked = setMask stopped Set.empty pending
            owed stopped unblocked |> shouldEqual (Some OwedReturn.SignalDue)

            let afterStop =
                match UnixSignal.onReturnToUser stopped unblocked with
                | ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped Signal.SIGTSTP, system) -> system
                | other -> failwith $"%O{platform}: thread 1's return: %A{other}"

            owed stopped afterStop |> shouldEqual (Some OwedReturn.SignalDue)
            refusesCalls stopped afterStop

            match UnixSignal.onReturnToUser stopped afterStop with
            | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), _) ->
                frame.Entry.Signal |> shouldEqual Signal.SIGWINCH
            | other -> failwith $"%O{platform}: thread 1's second return: %A{other}"

    /// A thread asleep takes no signal: one sent to it marks nothing, and a
    /// call that then finishes with its own answer, as Linux's pipe read
    /// answers the bytes before a pending signal, leaves the thread owing its
    /// return as it leaves the park.
    [<Test>]
    let ``a sleeping thread owes its return for a pending signal once its call answers`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let pid, system = processOf platform 2
        let leader = Caller.make pid 0
        let reader = Caller.make pid 1

        let readFd, writeFd, system =
            match UnixPipe.pipe2 leader 0 UserBuffer.Mapped (dispose leader Signal.SIGUSR1 caught system) with
            | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, resumes leader system
            | other, _ -> failwith $"pipe2: %A{other}"

        let asleep =
            match UnixReadWrite.read reader readFd UserBuffer.Mapped 4UL system with
            | ReadOutcome.WouldBlock _, system -> system
            | other -> failwith $"the read: expected it to sleep, got %A{other}"

        let written =
            match UnixReadWrite.write leader writeFd UserBuffer.Mapped 1UL asleep with
            | CallProgress.NeedsCopyIn paused ->
                match UnixReadWrite.writeWithBytes (ImmutableArray.Create<byte> 7uy) paused with
                | ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed 1L), system) -> system
                | other -> failwith $"the write: %A{other}"
            | CallProgress.Answered other -> failwith $"the write: %A{other}"
            |> resumes leader
            |> send leader 1 Signal.SIGUSR1

        // Asleep, the reader owes nothing.
        owed reader written |> shouldEqual None

        let finished =
            match UnixWait.wake written with
            | [ woken, _ ], woken' when woken = reader ->
                match UnixWait.finish reader woken' with
                | FinishedCall.PipeRead (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) ->
                    bytes.Length |> shouldEqual 1
                    system
                | other -> failwith $"the finish: %A{other}"
            | wakes, _ -> failwith $"expected the reader to wake: %A{wakes}"

        owed reader finished |> shouldEqual (Some OwedReturn.SignalDue)
        refusesCalls reader finished

    /// A new thread starts with its creator's mask, and its creator owes no
    /// return, so takes no signal: nor does the new thread, though under Linux
    /// a thread other than the leader takes a signal of the process's that the
    /// leader blocks.
    [<Test>]
    let ``a new thread owes no return, though a signal of the process's is pending`` () : unit =
        for platform in Machines.platforms do
            let pid, system = processOf platform 2
            let leader = Caller.make pid 0
            let creator = Caller.make pid 1
            let usr1 = Set.singleton Signal.SIGUSR1

            let pending =
                dispose leader Signal.SIGUSR1 caught system
                |> setMask leader usr1
                |> setMask creator usr1
                |> kill creator Signal.SIGUSR1

            let spawned =
                match UnixThreadLifecycle.spawn creator 2 (CpuId 0) pending with
                | SpawnAnswer.Spawned _, system -> system
                | other -> failwith $"%O{platform}: spawn: %A{other}"

            owed (Caller.make pid 2) spawned |> shouldEqual None
            UnixSystem.checkInvariants spawned |> shouldEqual []

    /// A thread returning from an interrupted `sigsuspend` with no handler to
    /// run, its signal ignored by another thread meanwhile, gets back the mask
    /// the call replaced; where that mask lets through a signal the call's
    /// mask kept pending, the return is refused, changing nothing.
    [<Test>]
    let ``a return from sigsuspend whose restored mask lets a signal through is refused`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let pid, system = processOf platform 2
        let leader = Caller.make pid 0
        let suspender = Caller.make pid 1

        let system =
            dispose leader Signal.SIGUSR1 caught system
            |> dispose leader Signal.SIGUSR2 caught

        let asleep =
            let usr2 = SignalMask.ofSignals SignalNumbering.Linux (Set.singleton Signal.SIGUSR2)

            match UnixSignal.sigsuspend suspender usr2 system with
            | SigsuspendOutcome.WouldBlock _, system -> system
            | other -> failwith $"the sigsuspend: expected it to sleep, got %A{other}"

        let signalled =
            asleep |> send leader 1 Signal.SIGUSR2 |> send leader 1 Signal.SIGUSR1

        let interrupted =
            match UnixWait.wake signalled with
            | [ woken, _ ], woken' when woken = suspender ->
                match UnixWait.finish suspender woken' with
                | FinishedCall.SigSuspend (SigsuspendOutcome.Interrupted, system) -> system
                | other -> failwith $"the finish: %A{other}"
            | wakes, _ -> failwith $"expected the suspender to wake: %A{wakes}"
            |> dispose leader Signal.SIGUSR1 SignalDisposition.Ignore

        match UnixSignal.tryOnReturnToUser suspender interrupted with
        | Error (ReturnToUserRefusal.RestoredMaskLetsThrough signal) -> signal |> shouldEqual Signal.SIGUSR2
        | other -> failwith $"expected the return to be refused, got %A{other}"

    /// One step of a client's run of a process of several threads, made by the
    /// thread each names.
    [<RequireQualifiedAccess>]
    type private Step =
        /// `call`, made by `thread` through `UnixSystem.tryStep`.
        | Call of thread : int * call : Syscall<int, string>
        | Return of thread : int
        /// The innermost handler the thread runs returns.
        | Sigreturn of thread : int
        /// `UnixWait.wake`, and every woken call finished.
        | Finish
        | Spawn of parent : int

    /// A step that left a thread owing a return to user mode it did not owe:
    /// which step, and whether the thread was the one making it.
    type private Marked =
        {
            Step : string
            Own : bool
        }

    let private pool : Signal list =
        [
            Signal.SIGHUP
            Signal.SIGUSR1
            Signal.SIGUSR2
            Signal.SIGPIPE
            Signal.SIGTERM
            Signal.SIGCHLD
        ]

    /// The most threads a run has, numbered from 0.
    let private mostThreads : int = 5

    /// The process a run's `kill` names: the one a boot makes.
    let private self : int = ProcessId.toInt32 UnixSystem.defaultProcessId

    /// The descriptors of the run's pipes, which its leader makes before the
    /// first step, after the three standard streams: the read and write ends
    /// of one, and the write end of another, whose read end it closes.
    let private readFd : int = 3
    let private writeFd : int = 4
    let private brokenFd : int = 6

    /// A `read` of the pipe, which sleeps while it is empty.
    let private read : Syscall<int, string> =
        Syscall.Read (readFd, UserBuffer.Mapped, 4UL)

    /// A `write` of two bytes through `fd`: into the pipe at `writeFd`, or into
    /// the one with no reader at `brokenFd`, which raises SIGPIPE.
    let private write (fd : int) : Syscall<int, string> =
        Syscall.Write (fd, CopiedArgument.Readable (ImmutableArray.Create<byte> (0uy, 0uy)), 2UL)

    /// The name a call of the run is counted under: its own, but that a write
    /// into the pipe with no reader is a "broken write".
    let private label (call : Syscall<int, string>) : string =
        match call with
        | Syscall.Kill _ -> "kill"
        | Syscall.PthreadKill _ -> "pthread_kill"
        | Syscall.PthreadSigMask _ -> "pthread_sigmask"
        | Syscall.SigProcMask _ -> "sigprocmask"
        | Syscall.SigAction _ -> "sigaction"
        | Syscall.SigSuspend _ -> "sigsuspend"
        | Syscall.Read _ -> "read"
        | Syscall.Write (fd, _, _) when fd = brokenFd -> "broken write"
        | Syscall.Write _ -> "write"
        | other -> failwith $"%s{UnionCaseName.ofValue other} is not generated by TestSignalDue's runs"

    /// The `how` of a mask call, as `numbering` numbers it: 0 blocks, 1
    /// unblocks, 2 sets the mask.
    let private howUnder (numbering : SignalNumbering) (how : int) : int =
        match numbering with
        | SignalNumbering.Linux -> how
        | SignalNumbering.Darwin -> how + 1

    /// `sigaction`'s new disposition: 0 the default, 1 ignored, 2 caught, 3
    /// caught by a handler that blocks every signal of the pool.
    let private dispositionUnder (numbering : SignalNumbering) (disposition : int) : SignalDisposition<string> =
        match disposition with
        | 0 -> SignalDisposition.Default
        | 1 -> SignalDisposition.Ignore
        | 2 -> SignalDisposition.Catch (SignalCatch.ofHandler "h")
        | _ ->
            SignalDisposition.Catch
                { SignalCatch.ofHandler "h" with
                    Mask = SignalMask.ofSignals numbering (Set.ofList pool)
                }

    let private stepGen (numbering : SignalNumbering) : Gen<Step> =
        let thread = Gen.choose (0, mostThreads - 1)
        let signal = Gen.elements pool
        let signals = Gen.subListOf pool |> Gen.map Set.ofList
        let how = Gen.choose (0, 2)
        let signo (signal : Signal) : int = Signal.toRawSignoUnder numbering signal
        let maskOf (signals : Set<Signal>) : SignalMask = SignalMask.ofSignals numbering signals

        Gen.frequency
            [
                4, Gen.map2 (fun s g -> Step.Call (s, Syscall.Kill (self, signo g))) thread signal
                6, Gen.map3 (fun s t g -> Step.Call (s, Syscall.PthreadKill (t, signo g))) thread thread signal
                5,
                Gen.map3
                    (fun t h m -> Step.Call (t, Syscall.PthreadSigMask (howUnder numbering h, Some (maskOf m))))
                    thread
                    how
                    signals
                5,
                Gen.map3
                    (fun t h m -> Step.Call (t, Syscall.SigProcMask (howUnder numbering h, Some (maskOf m))))
                    thread
                    how
                    signals
                3,
                Gen.map3
                    (fun t g d -> Step.Call (t, Syscall.SigAction (signo g, Some (dispositionUnder numbering d))))
                    thread
                    signal
                    (Gen.frequency [ 1, Gen.constant 0 ; 2, Gen.choose (1, 3) ])
                5, Gen.map Step.Return thread
                4, Gen.map Step.Sigreturn thread
                2, Gen.map2 (fun t m -> Step.Call (t, Syscall.SigSuspend (maskOf m))) thread signals
                6, Gen.map (fun t -> Step.Call (t, read)) thread
                5, Gen.map (fun t -> Step.Call (t, write writeFd)) thread
                2, Gen.map (fun t -> Step.Call (t, write brokenFd)) thread
                6, Gen.constant Step.Finish
                2, Gen.map Step.Spawn thread
            ]

    /// Every signal of the pool caught, but SIGCHLD, whose default discards
    /// it, and SIGUSR1's handler blocking the whole pool: so that most signals
    /// wait to be taken rather than end the process, and a handler's frame
    /// blocks what is pending behind it.
    let private opening (numbering : SignalNumbering) : Step list =
        let dispose (signal : Signal) (disposition : int) : Step =
            Step.Call (
                0,
                Syscall.SigAction (
                    Signal.toRawSignoUnder numbering signal,
                    Some (dispositionUnder numbering disposition)
                )
            )

        [
            dispose Signal.SIGHUP 2
            dispose Signal.SIGUSR1 3
            dispose Signal.SIGUSR2 2
            dispose Signal.SIGPIPE 2
            dispose Signal.SIGTERM 2
            Step.Spawn 0
            Step.Spawn 0
        ]

    /// Thread 1 asleep in a read that bytes and a signal reach before it is
    /// finished: Linux answers the bytes, and the thread leaves its sleep
    /// owing a return for the signal (Darwin refuses to say which came first).
    let private sleeperOpening (numbering : SignalNumbering) : Step list =
        [
            Step.Call (1, read)
            Step.Call (0, write writeFd)
            Step.Call (0, Syscall.PthreadKill (1, Signal.toRawSignoUnder numbering Signal.SIGUSR2))
            Step.Finish
        ]

    let private runGen : Gen<SimulatedUnixPlatform * Step list> =
        gen {
            let! platform = Gen.elements Machines.platforms
            let! sleeper = Gen.elements [ false ; true ]
            let numbering = SimulatedUnixPlatform.signalNumbering platform
            let! steps = Gen.listOf (stepGen numbering)

            let opening =
                if sleeper then
                    opening numbering @ sleeperOpening numbering
                else
                    opening numbering

            return platform, opening @ List.truncate 60 steps
        }

    /// What a call of the run left: the system the process runs on in, or the
    /// errno the call failed with, changing nothing; `None` where the call
    /// ended or stopped the process.
    let private left (stepped : SteppedCall<int, string>) : Result<UnixSystem<int, string>, UnixError> option =
        match stepped with
        | SteppedCall.Kill (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after)))
        | SteppedCall.PthreadKill (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after)))
        | SteppedCall.PthreadSigMask (Ok (_, after))
        | SteppedCall.SigProcMask (Ok (_, after))
        | SteppedCall.SigAction (Ok (_, after))
        | SteppedCall.SigSuspend (_, after)
        | SteppedCall.Read (_, after)
        | SteppedCall.Write (ProcessFate.Continues (_, after)) -> Some (Ok after)
        | SteppedCall.Kill (Ok (ProcessFate.Continues (KillOutcome.ProcessStopped _, _)))
        | SteppedCall.Kill (Ok (ProcessFate.ProcessEnded _))
        | SteppedCall.PthreadKill (Ok (ProcessFate.Continues (KillOutcome.ProcessStopped _, _)))
        | SteppedCall.PthreadKill (Ok (ProcessFate.ProcessEnded _))
        | SteppedCall.Write (ProcessFate.ProcessEnded _) -> None
        | SteppedCall.Kill (Error errno)
        | SteppedCall.PthreadKill (Error errno)
        | SteppedCall.PthreadSigMask (Error errno)
        | SteppedCall.SigProcMask (Error errno)
        | SteppedCall.SigAction (Error errno) -> Some (Error errno)
        | other -> failwith $"SteppedCall.%s{UnionCaseName.ofValue other} answers no call TestSignalDue's runs make"

    /// A client's run: before each step, the thread making it returns to user
    /// mode while it owes that return, as a real thread takes a signal before it
    /// runs more of its own code; a refused return, or a refused `kill`,
    /// `pthread_kill`, `sigprocmask`, `sigsuspend`, `read` or `write`, is
    /// skipped, as is a `pthread_kill` of a thread the process does not have,
    /// which no client makes; any other refusal fails the run, and a process
    /// stopped or ended ends it. After every call and return, the system breaks
    /// no rule: in particular, every thread in no syscall with a signal
    /// deliverable to it owes a return to user mode. `observe` is given each
    /// system the run takes after a call or return, with the run's process and
    /// what made that system.
    let private run
        (cover : Marked -> unit)
        (observe : string -> ProcessId -> UnixSystem<int, string> -> unit)
        (platform : SimulatedUnixPlatform, steps : Step list)
        : unit
        =
        let pid, booted = processOf platform 1
        let leader = Caller.make pid 0

        if ProcessId.toInt32 pid <> self then
            failwith $"%O{platform}: the run's kill names process %d{self}, but the process booted as %O{pid}"

        let mutable system = booted
        let mutable frames : Map<int, HandlerFrameId list> = Map.empty
        let mutable ended = false

        let threads () : Map<int, UnixThreadState> = Proc.threads pid system
        let live (thread : int) : bool = Map.containsKey thread (threads ())

        let owes (thread : int) : bool =
            (UnixThreadTable.owedBy thread (threads ())).IsSome

        let parked (thread : int) : bool =
            (UnixThreadTable.get thread (threads ())).Parked.IsSome

        // Takes `after` as the system, counting each thread it left owing a
        // return it did not owe, and holds it to every rule.
        let commit (step : string) (actor : int) (after : UnixSystem<int, string>) : unit =
            let before = threads ()

            for KeyValue (thread, state) in Proc.threads pid after do
                let owedBefore =
                    match Map.tryFind thread before with
                    | Some before -> before.Owes.IsSome
                    | None -> false

                if not owedBefore && state.Owes = Some OwedReturn.SignalDue then
                    cover
                        {
                            Step = step
                            Own = (thread = actor)
                        }

            system <- after

            let context = $"%O{platform}, after %s{step} by thread %d{actor}"

            match UnixSystem.checkInvariants system with
            | [] -> ()
            | defects -> failwith $"%s{context}: %A{defects}"

            observe context pid system

        let returnTo (thread : int) : unit =
            match UnixSignal.tryOnReturnToUser (Caller.make pid thread) system with
            | Error _ -> ()
            | Ok (ProcessFate.ProcessEnded _)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped _, _)) -> ended <- true
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes _, after))
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ContinueDiscarded _, after)) ->
                commit "return" thread after
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (pushed, _), after)) ->
                let ids = pushed |> List.map (fun frame -> frame.Id)
                let outer = Map.tryFind thread frames |> Option.defaultValue []
                frames <- Map.add thread (ids @ outer) frames
                commit "return" thread after

        // The thread returns while it owes a return, as a client returns it
        // before it runs more of its own code; `false` where it still owes,
        // its return refused.
        let returned (thread : int) : bool =
            let mutable tries = 0

            while not ended && owes thread && tries < 8 do
                returnTo thread
                tries <- tries + 1

            not ended && not (owes thread)

        let pipes =
            let piped (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
                match UnixPipe.pipe2 leader 0 UserBuffer.Mapped system with
                | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, system
                | other, _ -> failwith $"pipe2: %A{other}"

            let readFd, writeFd, piped' = piped system
            let brokenRead, brokenFd, piped' = piped piped'
            let _, closed = UnixDescriptor.close leader brokenRead piped'
            system <- closed
            readFd, writeFd, brokenFd

        if pipes <> (readFd, writeFd, brokenFd) then
            failwith
                $"%O{platform}: the run's pipes are at %A{pipes}, not at %A{(readFd, writeFd, brokenFd)}, which its calls name"

        let made (thread : int) (call : Syscall<int, string>) : unit =
            let step = label call

            match UnixSystem.tryStep (Caller.make pid thread) call system with
            | Error refusal ->
                match call with
                | Syscall.Kill _
                | Syscall.PthreadKill _
                | Syscall.SigProcMask _
                | Syscall.SigSuspend _
                | Syscall.Read _
                | Syscall.Write _ -> ()
                | _ -> failwith $"%O{platform}: %s{step} by %d{thread} was refused: %s{SyscallRefusal.describe refusal}"
            | Ok stepped ->
                match left stepped with
                | Some (Ok after) -> commit step thread after
                | Some (Error errno) -> failwith $"%O{platform}: %s{step} by %d{thread}: %O{errno}"
                | None -> ended <- true

        let finishAll () : unit =
            let woken, after = UnixWait.wake system
            commit "wake" 0 after

            for caller in List.map fst woken do
                let thread = Caller.thread caller

                if not ended && Caller.processId caller = pid then
                    match UnixWait.tryFinish caller system with
                    | Error _ -> ()
                    | Ok (FinishedCall.PipeRead (_, after))
                    | Ok (FinishedCall.SigSuspend (_, after)) -> commit "finish" thread after
                    | Ok other -> failwith $"%O{platform}: finished %A{other}, which no step parks"

        let make (step : Step) : unit =
            match step with
            | Step.Finish -> finishAll ()
            | Step.Spawn parent ->
                let child = (threads () |> Map.keys |> Seq.max) + 1

                if child < mostThreads && live parent && not (parked parent) && returned parent then
                    match UnixThreadLifecycle.trySpawn (Caller.make pid parent) child (CpuId 0) system with
                    | Ok (SpawnAnswer.Spawned _, after) -> commit "spawn" parent after
                    | other -> failwith $"%O{platform}: spawn: %A{other}"
            | Step.Return thread ->
                if live thread && not (parked thread) then
                    returnTo thread
            | Step.Sigreturn thread when live thread && not (parked thread) && returned thread ->
                match Map.tryFind thread frames with
                | Some (innermost :: outer) ->
                    let after = UnixSignal.sigreturn (Caller.make pid thread) innermost system
                    frames <- Map.add thread outer frames
                    commit "sigreturn" thread after
                | Some []
                | None -> ()
            | Step.Call (thread, call) when live thread && not (parked thread) && returned thread ->
                match call with
                | Syscall.PthreadKill (target, _) when not (live target) -> ()
                | _ -> made thread call
            | Step.Sigreturn _
            | Step.Call _ -> ()

        for step in steps do
            if not ended then
                make step

    /// Every way the run makes a signal deliverable marks the thread it is
    /// deliverable to: no state the run reaches holds a thread in no syscall
    /// with a signal deliverable to it that owes no return. The fixed sample
    /// reaches each way.
    [<Test>]
    let ``every way a client makes a signal deliverable leaves the thread it is deliverable to owing a return``
        ()
        : unit
        =
        let coverage =
            CoverageSample.check
                (Config.QuickThrowOnFailure.WithMaxTest 500)
                (Arb.fromGen runGen)
                (fun cover case -> run cover (fun _ _ _ -> ()) case)

        // Each about a third of what the fixed sample reaches. A leader's
        // return marks another thread only under Linux; a write's SIGPIPE
        // marks the writer under Linux and the leader under Darwin.
        for step, own, floor in
            [
                "kill", false, 30
                "pthread_kill", false, 35
                "pthread_kill", true, 18
                "pthread_sigmask", true, 2
                "sigprocmask", true, 2
                "sigreturn", true, 2
                "return", false, 2
                "finish", true, 45
                "broken write", true, 30
                "broken write", false, 6
            ] do
            (step,
             own,
             coverage.Count
                 {
                     Step = step
                     Own = own
                 })
            |> fun (step, own, count) -> (step, own, count > floor)
            |> shouldEqual (step, own, true)

    /// What `getpid`, a call that changes nothing, does when a thread makes
    /// it: admitted, or refused for the reason `Entry` gives.
    [<RequireQualifiedAccess>]
    type private CallAdmission =
        | Admitted
        /// The process has no thread by that name.
        | Absent
        | Parked
        /// The thread owes its return for a signal deliverable to it.
        | OwesSignal
        /// The thread owes the return that ends a call a signal interrupted.
        | OwesInterrupted

    /// What `UnixSystem.processId` by `caller` does in `system`, read from its
    /// refusal's message, which says why (`TestCallerChecks` holds each
    /// function's refusals to the same words).
    let private admission (caller : Caller<int>) (system : UnixSystem<int, string>) : CallAdmission =
        try
            UnixSystem.processId caller system |> ignore<ProcessId>
            CallAdmission.Admitted
        with :? InvalidOperationException as e ->
            if e.Message.Contains "is not one of the process's threads" then
                CallAdmission.Absent
            elif e.Message.Contains "and is making another call" then
                CallAdmission.Parked
            elif e.Message.Contains "a signal is deliverable to it" then
                CallAdmission.OwesSignal
            elif e.Message.Contains "interrupted its last call" then
                CallAdmission.OwesInterrupted
            else
                failwith $"getpid by %O{caller}: a refusal this test does not know: %s{e.Message}"

    /// `UnixSignal.owesReturn` answers `true` exactly when a call the thread
    /// made would be refused for the return to user mode it owes: asked of
    /// every name a run's threads have or may come to have, and of one no
    /// thread has, in every system the run reaches. The fixed sample reaches
    /// each kind of debt, threads parked, threads a call admits, and names
    /// that are no thread.
    [<Test>]
    let ``owesReturn answers true exactly when a call by the thread is refused for the return it owes`` () : unit =
        let agrees
            (cover : bool * CallAdmission -> unit)
            (context : string)
            (pid : ProcessId)
            (system : UnixSystem<int, string>)
            : unit
            =
            // No run spawns a thread named `mostThreads`.
            for thread in 0..mostThreads do
                let caller = Caller.make pid thread
                let owes = UnixSignal.owesReturn caller system
                let admission = admission caller system
                cover (owes, admission)

                let refusedForReturn =
                    match admission with
                    | CallAdmission.OwesSignal
                    | CallAdmission.OwesInterrupted -> true
                    | CallAdmission.Admitted
                    | CallAdmission.Absent
                    | CallAdmission.Parked -> false

                if owes <> refusedForReturn then
                    failwith
                        $"%s{context}: owesReturn of thread %d{thread} answered %b{owes}, and getpid by it was %A{admission}"

        let coverage =
            CoverageSample.check
                (Config.QuickThrowOnFailure.WithMaxTest 500)
                (Arb.fromGen runGen)
                (fun cover case -> run ignore (agrees cover) case)

        // Each about a third of what the fixed sample reaches.
        for label, floor in
            [
                (true, CallAdmission.OwesSignal), 600
                (true, CallAdmission.OwesInterrupted), 35
                (false, CallAdmission.Admitted), 7000
                (false, CallAdmission.Parked), 1900
                (false, CallAdmission.Absent), 11000
            ] do
            (label, coverage.Count label > floor) |> shouldEqual (label, true)
