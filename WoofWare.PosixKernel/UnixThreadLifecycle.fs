namespace WoofWare.PosixKernel

/// What a `kill(2)` or `pthread_kill(3)` the kernel answered did to the
/// calling process, if it did not end it (see `ProcessFate`).
[<RequireQualifiedAccess>]
type KillOutcome =
    /// The process runs on: the signal is pending, or was discarded, or there
    /// was no signal to send.
    | ProcessRuns
    /// The signal stops the whole process.
    | ProcessStopped of signal : Signal

/// Why this library will not answer a thread's exit: a case it does not
/// model, rather than an error a kernel would report, because the thread-exit
/// syscall cannot fail.
[<RequireQualifiedAccess>]
type internal ThreadExitRefusal<'Thread> =
    /// The thread is the process's leader, and other threads live. On both flavours
    /// the process carries on, with a leader that has gone (a zombie thread on
    /// Linux); this library keeps the leader until the process ends.
    | LeaderBeforeOthers of thread : 'Thread
    /// The thread is the last one on Darwin, where what its exit does has not
    /// been measured.
    | LastThreadOnDarwin of thread : 'Thread

[<RequireQualifiedAccess>]
module internal ThreadExitRefusal =

    /// A human-readable account of why the exit was refused.
    let describe<'Thread> (refusal : ThreadExitRefusal<'Thread>) : string =
        match refusal with
        | ThreadExitRefusal.LeaderBeforeOthers thread ->
            $"thread %O{thread} is the process's leader, and other threads are still running; this library does not model a process whose leader has exited before them"
        | ThreadExitRefusal.LastThreadOnDarwin thread ->
            $"thread %O{thread} is the process's last thread, and what Darwin does when the last thread makes the thread-exit syscall has not been measured"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ThreadExitRefusal<'Thread>) : RefusalKind =
        match refusal with
        | ThreadExitRefusal.LeaderBeforeOthers _ -> RefusalKind.Unmodelled
        | ThreadExitRefusal.LastThreadOnDarwin _ -> RefusalKind.Unmodelled

/// What `clone(2)` with `CLONE_THREAD` answered, for a request this library
/// could answer.
[<RequireQualifiedAccess>]
type SpawnAnswer =
    /// The new thread exists, and reports `threadId`.
    | Spawned of threadId : OsThreadId
    /// The call returned -1 with this errno. No thread was created, and no thread
    /// ID was handed out.
    | Failed of error : UnixError

/// Why this library will not answer a `clone(2)` with `CLONE_THREAD`: a case it
/// does not model or has not measured, rather than an error a kernel would
/// report.
[<RequireQualifiedAccess>]
type internal SpawnRefusal<'Thread> =
    /// Unmeasured. Darwin's 64-bit thread ID counter has reached the top of its
    /// range, and what Darwin does when a thread is created then has not been
    /// measured.
    | ThreadIdCounterExhausted

[<RequireQualifiedAccess>]
module internal SpawnRefusal =

    /// A human-readable account of why the thread's creation was refused.
    let describe<'Thread> (refusal : SpawnRefusal<'Thread>) : string =
        match refusal with
        | SpawnRefusal.ThreadIdCounterExhausted ->
            "Darwin's thread ID counter has reached the top of its 64-bit range, and what Darwin does when a thread is created then has not been measured"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SpawnRefusal<'Thread>) : RefusalKind =
        match refusal with
        | SpawnRefusal.ThreadIdCounterExhausted -> RefusalKind.Unmodelled

/// How threads join and leave a process, and how a process ends.
[<RequireQualifiedAccess>]
module UnixThreadLifecycle =

    /// `system` without `thread`, which is in no syscall: its thread ID is no
    /// longer live, the processor it was running on, if any, is idle, its
    /// signal mask and the signals pending on it alone are gone, and so is its
    /// entry in the table.
    let private leave<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        let state = UnixThreadTable.get thread system.Threads

        { system with
            Machine =
                { system.Machine with
                    ThreadIds = ThreadIdAllocator.release state.OsThreadId system.Machine.ThreadIds
                }
            Scheduling = UnixSchedulingState.vacate state.Cpu state.OsThreadId system.Scheduling
            Process =
                { system.Process with
                    Signals = SignalState.forgetThread thread system.Process.Signals
                }
            Threads = Map.remove thread system.Threads
        }

    /// End the process `system` is, as `termination` says: every thread goes, and
    /// with each everything the process and the machine held for that thread
    /// alone: its signal mask and the signals pending on it alone, its thread
    /// ID, the processor it was running on, and the holds its call in flight,
    /// if any, had. The machine lets go of the process's current directory and
    /// its process ID.
    let internal endProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (termination : ProcessTermination)
        (system : ProcessView<'Thread, 'Handler>)
        : EndedProcess<'Thread, 'Handler>
        =
        let gone =
            (system, Map.keys system.Threads)
            ||> Seq.fold (fun system thread -> system |> UnixParkState.unpark thread |> leave thread)

        let cwd = system.Process.CurrentDirectoryInode

        // A directory the process had removed while standing in it is free once
        // nothing else stands in it.
        let released =
            { gone with
                Machine =
                    { gone.Machine with
                        ProcessIds = ProcessIdTable.remove system.Process.ProcessId gone.Machine.ProcessIds
                    }
                    |> UnixMachineState.releaseCurrentDirectory cwd
            }
            |> ObjectLifetime.forgetIfUnheld cwd

        {
            Termination = termination
            Machine = released.Machine
            Scheduling = released.Scheduling
            FinalProcess =
                { system.Process with
                    Signals = gone.Process.Signals
                }
            EndedIn = system
        }

    /// `tryExitThread` once `Entry` has admitted its caller.
    let private tryExitThreadIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (status : int32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ProcessFate<unit, 'Thread, 'Handler>, ThreadExitRefusal<'Thread>>
        =
        // Measured on Linux 6.18.5 and Darwin 27.0.0 by
        // `docs/plans/2026-08-23-posix-kernel-extraction/leader-exits-first.c`: the
        // process carries on without its leader, which Linux keeps as a zombie
        // thread. Nothing here models a process in that state.
        if thread = system.Leader && system.Threads.Count > 1 then
            Error (ThreadExitRefusal.LeaderBeforeOthers thread)
        elif system.Threads.Count = 1 then
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux ->
                // The last thread's own status is the process's, whatever an earlier
                // thread exited with, and it is kept as `exit_group`'s is: measured on
                // Linux 6.18.5 (aarch64 and x86-64) by
                // `docs/plans/2026-08-23-posix-kernel-extraction/last-thread-exit-status.c`,
                // with the leader last, with a worker last, and with one thread.
                let termination =
                    ProcessTermination.Exited (ExitStatus.ofExitArgument SimulatedUnixFlavour.Linux status)

                Ok (ProcessFate.ProcessEnded (endProcess termination system))
            | SimulatedUnixFlavour.Darwin -> Error (ThreadExitRefusal.LastThreadOnDarwin thread)
        else

        Ok (ProcessFate.Continues ((), leave thread system))

    /// `exitThread`, with a refusal answered as the `Error` rather than raised.
    let internal tryExitThread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (status : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ProcessFate<unit, 'Thread, 'Handler>, ThreadExitRefusal<'Thread>>
        =
        Entry.call
            "UnixThreadLifecycle.exitThread"
            CallerRequirement.Running
            caller
            (Shape.result Shape.fate)
            (tryExitThreadIn (Caller.thread caller) status)
            system

    /// <summary>
    /// The thread-exit syscall: `thread` ends. This is `SYS_exit` on Linux, which is
    /// what `pthread_exit` and a thread's return from its start routine end in; it
    /// is not `exit(3)` or `exit_group(2)` (see `exitGroup`).
    ///
    /// Removes `thread` from the table, and with it everything the process holds for
    /// that thread alone: its signal mask, and the signals pending on it alone, which
    /// are discarded rather than passed on to another thread. Its thread ID is no
    /// longer live, so the machine may hand it out again, and the processor it
    /// was running on, if any, is idle. The process carries on
    /// unless `thread` was its last, in which case the process ends, on Linux, having
    /// exited with `status`. `status` is otherwise ignored.
    ///
    /// Refuses a thread that is parked in a syscall, the process's leader while any
    /// other thread lives, and the process's last thread on Darwin.
    ///
    /// Fails loudly if `thread` names no thread, which is a bug in the client.
    /// </summary>
    /// <exception cref="T:System.InvalidOperationException">The thread is blocked in a syscall, so it cannot be making another one.</exception>
    let exitThread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (status : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessFate<unit, 'Thread, 'Handler>
        =
        tryExitThread caller status system
        |> Refusal.orRaise "UnixThreadLifecycle.exitThread" ThreadExitRefusal.kind ThreadExitRefusal.describe

    /// `trySpawn` once `Entry` has admitted its caller.
    let private trySpawnIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (parent : 'Thread)
        (child : 'Thread)
        (cpu : CpuId)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SpawnAnswer * ProcessView<'Thread, 'Handler>, SpawnRefusal<'Thread>>
        =
        if Map.containsKey child system.Threads then
            failwith
                $"UnixThreadLifecycle.spawn: %O{child} already names a thread. A thread is created once, and creating it again would silently discard whatever the first creation recorded (this is a bug in the client)."

        if not (UnixMachineState.hasProcessor cpu system.Machine) then
            failwith
                $"UnixThreadLifecycle.spawn: %O{child} would be created on %O{cpu}, but the machine has %d{system.Machine.ProcessorCount} logical processors, numbered from 0 (this is a bug in the client)."

        match ThreadIdAllocator.allocate system.Machine.ThreadIds with
        | ThreadIdAllocation.Failed error -> Ok (SpawnAnswer.Failed error, system)
        | ThreadIdAllocation.DarwinCounterExhausted -> Error SpawnRefusal.ThreadIdCounterExhausted
        | ThreadIdAllocation.Issued (id, threadIds) ->

        Ok (
            SpawnAnswer.Spawned id,
            { system with
                Machine =
                    { system.Machine with
                        ThreadIds = threadIds
                    }
                // Measured on Linux 6.18.5 (aarch64 and x86-64) and Darwin
                // 27.0.0 by
                // `docs/plans/2026-08-23-posix-kernel-extraction/thread-spawn-mask.c`:
                // a new thread's mask is exactly its creator's current one, and
                // nothing pending on the creator alone is pending on it.
                Process =
                    { system.Process with
                        Signals = SignalState.inheritMask parent child system.Process.Signals
                    }
                Threads = UnixThreadTable.add child cpu id system.Threads
            }
        )

    /// `spawn`, with a refusal answered as the `Error` rather than raised.
    let internal trySpawn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (child : 'Thread)
        (cpu : CpuId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SpawnAnswer * UnixSystem<'Thread, 'Handler>, SpawnRefusal<'Thread>>
        =
        Entry.call
            "UnixThreadLifecycle.spawn"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (trySpawnIn (Caller.thread caller) child cpu)
            system

    /// `clone(2)` with `CLONE_THREAD`, made by `caller`: a new thread in the process,
    /// the thread `child`, running on the logical processor `cpu`. This is what
    /// `pthread_create(3)` ends in.
    ///
    /// Answers the thread ID the machine's allocator hands the new thread, one no
    /// live thread on the machine holds, which starts with a copy of the caller's
    /// signal mask and with no signal pending on it alone. On Linux, answers
    /// EAGAIN instead once every thread ID from 300 up to the machine's
    /// `pid_max` is in use, leaving the system as it was.
    ///
    /// Refuses a spawn on Darwin once the machine's thread ID counter has
    /// reached the top of its range, which has not been measured.
    ///
    /// Fails loudly if `caller` names no thread or is parked in a syscall, if
    /// `child` already names a thread, or if `cpu` is not one of the machine's
    /// processors (`UnixSystem.processorCount`): each is a bug in the client.
    let spawn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (child : 'Thread)
        (cpu : CpuId)
        (system : UnixSystem<'Thread, 'Handler>)
        : SpawnAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySpawn caller child cpu system
        |> Refusal.orRaise "UnixThreadLifecycle.spawn" SpawnRefusal.kind SpawnRefusal.describe

    /// `exitGroup` once `Entry` has admitted its caller.
    let private exitGroupIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (status : int32)
        (system : ProcessView<'Thread, 'Handler>)
        : EndedProcess<'Thread, 'Handler>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        endProcess (ProcessTermination.Exited (ExitStatus.ofExitArgument flavour status)) system

    /// `exit_group(2)`, made by `caller`: every thread ends at once, parked ones
    /// included, and the process exits with `status`. This is what `exit(3)` and
    /// `_exit(2)` end in; Darwin's `_exit(2)` is the same call under another name.
    ///
    /// Fails loudly if `caller` names no thread, or is parked in a syscall: a thread
    /// blocked in one is not making another, so either is a bug in the client.
    let exitGroup<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (status : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : EndedProcess<'Thread, 'Handler>
        =
        Entry.call
            "UnixThreadLifecycle.exitGroup"
            CallerRequirement.Running
            caller
            Shape.ended
            (exitGroupIn status)
            system

/// A signal the kernel generates for a process, as `kill(2)`, `pthread_kill(3)`
/// and a write that raises `SIGPIPE` do, and what it does to the process at once.
[<RequireQualifiedAccess>]
module internal ProcessSignal =

    /// Whether `system`'s process is process ID 1, an init process. From inside
    /// its own PID namespace an init process ignores every signal it has not
    /// installed a handler for, SIGKILL included, which this library does not
    /// model, so a call that would generate a signal for it refuses first.
    let isInit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        ProcessId.toInt32 system.Process.ProcessId = 1

    /// Generate `entry` for `system`'s process, as `SignalState.generate`
    /// decides, and apply what it decided: the process runs on, with the signal
    /// pending, coalesced or discarded; it stops (`KillOutcome.ProcessStopped`),
    /// with the signals the generation left; or the signal kills it, and the
    /// process ends as it stood before the signal.
    ///
    /// Fails loudly for an init process (`isInit`), which the caller refuses
    /// first.
    let generate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (entry : PendingSignal<'Thread>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ProcessFate<KillOutcome, 'Thread, 'Handler>, SignalReceiverRefusal>
        =
        if isInit system then
            failwith
                $"ProcessSignal.generate: %O{entry.Signal} would be generated for process 1, an init process, whose signals every caller refuses first (this is a bug in this library)."

        let generation =
            SignalState.generate
                (UnixSystemState.signalNumbering system)
                system.Process.CoreDumps
                system.Leader
                (system.Threads |> Map.keys |> Set.ofSeq)
                entry
                system.Process.Signals

        match generation with
        | Error refusal -> Error refusal
        | Ok (SignalGeneration.ProcessContinues signals) ->
            Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, UnixSystemState.withSignals signals system))
        | Ok (SignalGeneration.ProcessStopped (signal, signals)) ->
            Ok (ProcessFate.Continues (KillOutcome.ProcessStopped signal, UnixSystemState.withSignals signals system))
        | Ok (SignalGeneration.ProcessTerminated (signal, coreDumped)) ->
            Ok (
                ProcessFate.ProcessEnded (
                    UnixThreadLifecycle.endProcess (ProcessTermination.Signaled (signal, coreDumped)) system
                )
            )
