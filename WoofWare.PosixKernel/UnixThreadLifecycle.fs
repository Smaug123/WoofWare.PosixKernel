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

/// Why this library will not end a process: what closing its descriptors
/// would do has not been measured.
[<RequireQualifiedAccess>]
type internal ProcessEndRefusal =
    /// Closing the process's descriptors releases an open file description
    /// this library will not release (`DescriptionReleaseRefusal`): so far,
    /// the last reference to a connected socket whose `SO_LINGER` would make
    /// its close wait, or one of two Darwin closes whose outcome waits on a
    /// timer or on the peer's reads.
    | Release of DescriptionReleaseRefusal

[<RequireQualifiedAccess>]
module internal ProcessEndRefusal =
    /// What this library knows about why it will not end the process, for a
    /// client composing a diagnostic that names its own knob.
    let describe (refusal : ProcessEndRefusal) : string =
        match refusal with
        | ProcessEndRefusal.Release refusal ->
            $"the process's end closes its descriptors, and %s{DescriptionReleaseRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ProcessEndRefusal) : RefusalKind =
        match refusal with
        | ProcessEndRefusal.Release inner -> DescriptionReleaseRefusal.kind inner

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
    /// The thread is the last one, so its exit ends the process, and the
    /// process's end is refused.
    | ProcessEnd of ProcessEndRefusal

[<RequireQualifiedAccess>]
module internal ThreadExitRefusal =

    /// A human-readable account of why the exit was refused.
    let describe<'Thread> (refusal : ThreadExitRefusal<'Thread>) : string =
        match refusal with
        | ThreadExitRefusal.LeaderBeforeOthers thread ->
            $"thread %O{thread} is the process's leader, and other threads are still running; this library does not model a process whose leader has exited before them"
        | ThreadExitRefusal.LastThreadOnDarwin thread ->
            $"thread %O{thread} is the process's last thread, and what Darwin does when the last thread makes the thread-exit syscall has not been measured"
        | ThreadExitRefusal.ProcessEnd refusal ->
            $"the thread is the process's last, so its exit ends the process; %s{ProcessEndRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ThreadExitRefusal<'Thread>) : RefusalKind =
        match refusal with
        | ThreadExitRefusal.LeaderBeforeOthers _ -> RefusalKind.Unmodelled
        | ThreadExitRefusal.LastThreadOnDarwin _ -> RefusalKind.Unmodelled
        | ThreadExitRefusal.ProcessEnd inner -> ProcessEndRefusal.kind inner

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
            Threads = UnixThreadTable.remove thread system.Threads
        }

    /// `system` with every thread of its process gone, and with each everything
    /// the process and the machine held for that thread alone: its signal mask
    /// and the signals pending on it alone, its thread ID, the processor it was
    /// running on, and the holds its call in flight, if any, had. The machine
    /// lets go of the process's current directory and its process ID.
    let private leaveAll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        let gone =
            (system, Map.keys (UnixThreadTable.byName system.Threads))
            ||> Seq.fold (fun system thread -> system |> UnixParkState.unpark thread |> leave thread)

        let cwd = system.Process.CurrentDirectoryInode

        // A directory the process had removed while standing in it is free once
        // nothing else stands in it.
        { gone with
            Machine =
                { gone.Machine with
                    ProcessIds = ProcessIdTable.remove system.Process.ProcessId gone.Machine.ProcessIds
                }
                |> UnixMachineState.releaseCurrentDirectory cwd
        }
        |> ObjectLifetime.forgetIfUnheld cwd

    /// `dead`, a process with no thread left, with every descriptor closed, as
    /// a real kernel closes them at exit; or the refusal of a close.
    let private closeAll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dead : ProcessView<'Thread, 'Handler>)
        : Result<ProcessView<'Thread, 'Handler>, DescriptionReleaseRefusal>
        =
        let processId = dead.ProcessId

        // First what nothing references any more: what the process's calls in
        // flight held, whose holds went with its threads, and what the call that
        // ended the process let go of as it returned. These go as the calls
        // return when their threads die, before the process's files are closed;
        // the order between the two has not been measured. On a machine no
        // process's end has left so, no description is unreferenced.
        let unreferenced =
            OpenFileTable.descriptions dead.Machine.OpenFiles
            |> Map.keys
            |> Seq.filter (fun id ->
                OpenFileTable.descriptorCount id dead.Machine.OpenFiles = Some 0
                && OpenFileTable.holdCount id dead.Machine.OpenFiles = Some 0
            )
            |> Seq.toList

        let released =
            ((Ok dead : Result<ProcessView<'Thread, 'Handler>, DescriptionReleaseRefusal>), unreferenced)
            ||> List.fold (fun state id ->
                match state with
                | Error refusal -> Error refusal
                | Ok dead ->
                    match OpenFileTable.destroyIfUnreferenced id dead.Machine.OpenFiles with
                    | _, None ->
                        failwith
                            $"UnixThreadLifecycle: ending process %O{processId}, open file description %O{id} was unreferenced a moment ago, and destroying it destroyed nothing (this is a bug in this library)."
                    | openFiles, Some destroyed ->
                        UnixSystemState.mapOpenFiles (fun _ -> openFiles) dead
                        |> ObjectLifetime.releaseDestroyed destroyed
            )

        // Then every descriptor. Measured on Linux 6.18.5 and Darwin 27.0.0
        // (`exit-close-order.c`, sections O and D): Linux drops them lowest
        // first and releases each description the drop let go of only after
        // every drop, the last let go of first, as its deferred final `fput`s
        // run; Darwin drops them highest first, releasing each as it goes.
        let drop
            (fd : int)
            (dead : ProcessView<'Thread, 'Handler>)
            : ProcessView<'Thread, 'Handler> * DestroyedDescription option
            =
            match FileDescriptorRegistry.dropDescriptor processId fd (UnixSystemState.fileDescriptors dead) with
            | Error FileDescriptorCloseError.BadFd ->
                failwith
                    $"UnixThreadLifecycle: process %O{processId}'s table held descriptor %d{fd} a moment ago, and closing it at the process's end answered EBADF (this is a bug in this library)."
            | Ok (registry, destroyed) -> UnixSystemState.withFileDescriptors registry dead, destroyed

        match released with
        | Error refusal -> Error refusal
        | Ok dead ->

        let ascending =
            FileDescriptorRegistry.fds (UnixSystemState.fileDescriptors dead)
            |> Map.keys
            |> Seq.sort
            |> Seq.toList

        match SimulatedUnixPlatform.flavour dead.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux ->
            // A description the drops let go of is still a reference until its
            // deferred `fput` releases it, as Linux's file is: so each is held
            // while the drops run, and destroyed only as its turn comes.
            // Measured (`inotify-self-probe.c` section X): of two files held
            // through descriptors let go of in turn, the one whose name an
            // unreleased file still holds goes later.
            // Each description held, by the last of this process's descriptors
            // naming it.
            let dead, held =
                ((dead, Map.empty), ascending)
                ||> List.fold (fun (dead, held) fd ->
                    let id =
                        match FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors dead) with
                        | Some id -> id
                        | None ->
                            failwith
                                $"UnixThreadLifecycle: process %O{processId}'s table held descriptor %d{fd} a moment ago, and it names no description now (this is a bug in this library)."

                    let dead =
                        if Map.containsKey id held then
                            dead
                        else
                            UnixSystemState.mapOpenFiles (OpenFileTable.hold id) dead

                    match drop fd dead with
                    | dead, None -> dead, Map.add id fd held
                    | _, Some destroyed ->
                        failwith
                            $"UnixThreadLifecycle: closing descriptor %d{fd} at process %O{processId}'s end destroyed %A{destroyed.Description.Target}, which the end holds (this is a bug in this library)."
                )

            // The last let go of first.
            let released = held |> Map.toList |> List.sortByDescending snd |> List.map fst

            (Ok dead, released)
            ||> List.fold (fun state id ->
                match state with
                | Error refusal -> Error refusal
                | Ok dead ->

                let dead = UnixSystemState.mapOpenFiles (OpenFileTable.releaseHold id) dead

                match OpenFileTable.destroyIfUnreferenced id dead.Machine.OpenFiles with
                | _, None -> Ok dead
                | openFiles, Some destroyed ->
                    UnixSystemState.mapOpenFiles (fun _ -> openFiles) dead
                    |> ObjectLifetime.releaseDestroyed destroyed
            )
        | SimulatedUnixFlavour.Darwin ->
            (Ok dead, List.rev ascending)
            ||> List.fold (fun state fd ->
                match state with
                | Error refusal -> Error refusal
                | Ok dead ->

                match drop fd dead with
                | dead, None -> Ok dead
                | dead, Some destroyed -> ObjectLifetime.releaseDestroyed destroyed dead
            )

    /// End the process `system` is, as `termination` says, as a real kernel
    /// does at exit, where another process can see it: how it ended, and the
    /// view of it with no thread or descriptor left, which
    /// `ProcessView.unfocusWithout` takes out of the kernel.
    ///
    /// Every thread goes first (`leaveAll`), and with them the holds their
    /// calls in flight had; any description only those calls held, or that
    /// the call which ended the process let go of as it returned, is released
    /// then. Then every descriptor of the process is closed, in the order each
    /// flavour measurably closes them (`exit-close-order.c`, Linux 6.18.5 and
    /// Darwin 27.0.0, which a peer watching several connections sees as the
    /// order of their FINs): Linux drops the descriptors lowest first and then
    /// releases what that let go of, the last first; Darwin drops them highest
    /// first, releasing each as it goes. Each release does everything a
    /// `close(2)` of the last descriptor onto the description does.
    ///
    /// Refuses where a close would be refused.
    let internal tryEndProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (termination : ProcessTermination)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EndedProcess * ProcessView<'Thread, 'Handler>, ProcessEndRefusal>
        =
        match closeAll (leaveAll system) with
        | Error refusal -> Error (ProcessEndRefusal.Release refusal)
        | Ok dead ->
            let ended : EndedProcess =
                {
                    Termination = termination
                    ProcessId = system.ProcessId
                }

            Ok (ended, dead)

    /// `tryExitThread` once `Entry` has admitted its caller.
    let private tryExitThreadIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (status : int32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ViewFate<unit, ProcessView<'Thread, 'Handler>>, ThreadExitRefusal<'Thread>>
        =
        // Measured on Linux 6.18.5 and Darwin 27.0.0 by
        // `docs/plans/2026-08-23-posix-kernel-extraction/leader-exits-first.c`: the
        // process carries on without its leader, which Linux keeps as a zombie
        // thread. Nothing here models a process in that state.
        if thread = system.Leader && (UnixThreadTable.byName system.Threads).Count > 1 then
            Error (ThreadExitRefusal.LeaderBeforeOthers thread)
        elif (UnixThreadTable.byName system.Threads).Count = 1 then
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux ->
                // The last thread's own status is the process's, whatever an earlier
                // thread exited with, and it is kept as `exit_group`'s is: measured on
                // Linux 6.18.5 (aarch64 and x86-64) by
                // `docs/plans/2026-08-23-posix-kernel-extraction/last-thread-exit-status.c`,
                // with the leader last, with a worker last, and with one thread.
                let termination =
                    ProcessTermination.Exited (ExitStatus.ofExitArgument SimulatedUnixFlavour.Linux status)

                match tryEndProcess termination system with
                | Ok (ended, dead) -> Ok (ViewFate.ProcessEnded (ended, dead))
                | Error refusal -> Error (ThreadExitRefusal.ProcessEnd refusal)
            | SimulatedUnixFlavour.Darwin -> Error (ThreadExitRefusal.LastThreadOnDarwin thread)
        else

        Ok (ViewFate.Continues ((), leave thread system))

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
    /// exited with `status`, and is removed from the system at once, its
    /// descriptors closed as `exitGroup` closes them. `status` is otherwise ignored.
    ///
    /// Refuses a thread that is parked in a syscall, the process's leader while any
    /// other thread lives, the process's last thread on Darwin, and the last
    /// thread where closing the process's descriptors would be refused (see
    /// `exitGroup`).
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
        if UnixThreadTable.contains child system.Threads then
            raise (
                Refusal.exceptionOf
                    "UnixThreadLifecycle.spawn"
                    (RefusalKind.Contradictory "child")
                    $"%O{child} already names a thread. A thread is created once, and creating it again would silently discard whatever the first creation recorded (this is a bug in the client)."
            )

        if not (UnixMachineState.hasProcessor cpu system.Machine) then
            raise (
                Refusal.exceptionOf
                    "UnixThreadLifecycle.spawn"
                    (RefusalKind.OutOfRange "cpu")
                    $"%O{child} would be created on %O{cpu}, but the machine has %d{system.Machine.ProcessorCount} logical processors, numbered from 0 (this is a bug in the client)."
            )

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
    /// Throws `InvalidOperationException` if `caller` names no thread or is
    /// parked in a syscall, `ArgumentException` if `child` already names a
    /// thread, and `ArgumentOutOfRangeException` if `cpu` is not one of the
    /// machine's processors (`UnixSystem.processorCount`): each is a bug in the
    /// client.
    let spawn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (child : 'Thread)
        (cpu : CpuId)
        (system : UnixSystem<'Thread, 'Handler>)
        : SpawnAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySpawn caller child cpu system
        |> Refusal.orRaise "UnixThreadLifecycle.spawn" SpawnRefusal.kind SpawnRefusal.describe

    /// `tryExitGroup` once `Entry` has admitted its caller.
    let private tryExitGroupIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (status : int32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EndedProcess * ProcessView<'Thread, 'Handler>, ProcessEndRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        tryEndProcess (ProcessTermination.Exited (ExitStatus.ofExitArgument flavour status)) system

    /// `exitGroup`, with a refusal answered as the `Error` rather than raised.
    let internal tryExitGroup<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (status : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<EndedProcess * UnixSystem<'Thread, 'Handler>, ProcessEndRefusal>
        =
        Entry.call
            "UnixThreadLifecycle.exitGroup"
            CallerRequirement.Running
            caller
            (Shape.result Shape.ended)
            (tryExitGroupIn status)
            system

    /// `exit_group(2)`, made by `caller`: every thread ends at once, parked ones
    /// included, and the process exits with `status`. This is what `exit(3)` and
    /// `_exit(2)` end in; Darwin's `_exit(2)` is the same call under another name.
    ///
    /// Answers how the process ended, and the system without it, which holds
    /// every other process as the call left it: the process is gone at once, as
    /// it is for a parent that reaps it at once.
    ///
    /// The end is what a real kernel does at exit, where another process can
    /// see it. Every thread goes, and with them the holds their calls in
    /// flight had, and any description only those calls held is released.
    /// Then every descriptor of the process is closed, in the order each
    /// flavour measurably closes them at exit, which a peer watching several
    /// connections sees as the order of their FINs: Linux drops the
    /// descriptors lowest first and then releases what that let go of, the
    /// last first; Darwin drops them highest first, releasing each as it goes.
    /// Each release does everything a `close(2)` of the last descriptor onto
    /// the description does: a connected peer gets its FIN, or a reset where
    /// bytes were left unread, a lock is let go of, a pipe end closes, an epoll
    /// instance or a kqueue goes, a listener goes and resets each client still
    /// in its accept queue, whichever process holds it, and every registration
    /// made through the descriptor goes with it. The process ID, thread IDs and
    /// current directory are let go of with the threads.
    ///
    /// Every other call that ends the process ends it so: the last thread's
    /// `exitThread`, and a signal whose default action ends the process, from
    /// `UnixSignal.kill`, `UnixSignal.pthreadKill`, `UnixSignal.onReturnToUser`,
    /// or a write or `send` that raises SIGPIPE.
    ///
    /// Refuses where a close would be refused: so far, the last close of a
    /// connected socket whose `SO_LINGER` would make it wait, and two Darwin
    /// closes whose outcome waits on a timer or on the peer's reads.
    ///
    /// Fails loudly if `caller` names no thread, or is parked in a syscall: a thread
    /// blocked in one is not making another, so either is a bug in the client.
    let exitGroup<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (status : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : EndedProcess * UnixSystem<'Thread, 'Handler>
        =
        tryExitGroup caller status system
        |> Refusal.orRaise "UnixThreadLifecycle.exitGroup" ProcessEndRefusal.kind ProcessEndRefusal.describe

/// What a signal the kernel generates for a process does to it at once, as
/// `ProcessSignal.effect` answers it: the process runs on or stops, or the
/// signal kills it.
[<RequireQualifiedAccess>]
type internal SignalEffect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The process runs on, or stops, as `outcome` says, as `view`.
    | Applied of outcome : KillOutcome * view : ProcessView<'Thread, 'Handler>
    /// The signal kills the process, which ends as `termination` says, as it
    /// stood before the signal.
    | Kills of termination : ProcessTermination
    /// Nothing happened: a real-time signal sent by `tgkill(2)` past the
    /// receiving user's `RLIMIT_SIGPENDING`, which fails with `EAGAIN`.
    | QueueFull

/// What generating a signal for a process came to, as
/// `ProcessSignal.generate` answers it.
[<RequireQualifiedAccess>]
type internal SignalSent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The process runs on or stops, or the signal ended it.
    | Fate of ViewFate<KillOutcome, ProcessView<'Thread, 'Handler>>
    /// The signal kills the process, and its end is refused.
    | EndRefused of ProcessEndRefusal
    /// `SignalEffect.QueueFull`.
    | QueueFull

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

    /// What generating `entry` for `system`'s process does to it at once, as
    /// `SignalState.generate` decides: the process runs on, with the signal
    /// pending, coalesced or discarded; it stops (`KillOutcome.ProcessStopped`),
    /// with the signals the generation left; the signal kills it; or, a
    /// real-time signal sent by `tgkill(2)` past the limit, nothing happens.
    ///
    /// Under Linux the signal is counted against the process's
    /// `RLIMIT_SIGPENDING` as `sender` sent it: the instances queued for the
    /// process's real user, in it and in every other process on the machine.
    ///
    /// A signal left pending where its receiver does not block it is
    /// deliverable to that receiver, which then owes a return to user mode
    /// (`OwedReturns.markIfDue`): the thread it is sent to, or, for one sent
    /// to the process, the leader, which takes the process's signals.
    ///
    /// Fails loudly for an init process (`isInit`), which the caller refuses
    /// first.
    let effect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (sender : SignalSender)
        (entry : PendingSignal<'Thread>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SignalEffect<'Thread, 'Handler>, SignalReceiverRefusal>
        =
        if isInit system then
            failwith
                $"ProcessSignal.effect: %O{entry.Signal} would be generated for process 1, an init process, whose signals every caller refuses first (this is a bug in this library)."

        // A thread the client has dispatched and has not since parked, or one
        // woken from its park and dispatched to finish its call: Linux's
        // `task_curr`. A thread asleep in a call is not running wherever the
        // client last placed it.
        let leaderRunning =
            let leader = UnixThreadTable.get system.Leader system.Threads

            UnixSchedulingState.runs leader.Cpu leader.OsThreadId system.Scheduling
            && (
                match leader.Parked with
                | None -> true
                | Some park ->
                    match park.State with
                    | ParkState.Woken _ -> true
                    | ParkState.Asleep -> false
            )

        let queue =
            match system.Process.PendingSignalLimit with
            | ValueNone -> QueueAccount.Unbounded
            | ValueSome limit ->
                let user = system.Process.Credentials.RealUser

                let elsewhere =
                    ProcessTable.slots system.Others
                    |> Map.toSeq
                    |> Seq.sumBy (fun (_, slot) -> SignalState.chargedTo user slot.Process.Signals)

                QueueAccount.Limited (user, elsewhere, limit, sender)

        let generation =
            SignalState.generate
                (UnixSystemState.signalNumbering system)
                system.Process.CoreDumps
                queue
                system.Leader
                leaderRunning
                (UnixThreadTable.byName system.Threads |> Map.keys |> Set.ofSeq)
                entry
                system.Process.Signals

        // `SignalState.generate` leaves a signal sent to the process pending
        // only where the leader takes it or every thread blocks it; one that
        // only another thread could take is refused, or acts at once.
        let receiver =
            match entry.Target with
            | ValueSome target -> target
            | ValueNone -> system.Leader

        match generation with
        | Error refusal -> Error refusal
        | Ok (SignalGeneration.ProcessContinues signals) ->
            let applied =
                UnixSystemState.withSignals signals system |> OwedReturns.markIfDue receiver

            Ok (SignalEffect.Applied (KillOutcome.ProcessRuns, applied))
        // A stop leaves nothing pending that was not: it acts at once, and
        // discards any pending SIGCONT.
        | Ok (SignalGeneration.ProcessStopped (signal, signals)) ->
            Ok (SignalEffect.Applied (KillOutcome.ProcessStopped signal, UnixSystemState.withSignals signals system))
        | Ok (SignalGeneration.ProcessTerminated (signal, coreDumped)) ->
            Ok (SignalEffect.Kills (ProcessTermination.Signaled (signal, coreDumped)))
        | Ok SignalGeneration.QueueFull -> Ok SignalEffect.QueueFull

    /// Generate `entry`, sent as `sender` sent it, for `system`'s process, and
    /// apply what it does at once (`effect`): the process runs on or stops, or
    /// the signal kills it and the process ends as it stood before the signal
    /// (`UnixThreadLifecycle.tryEndProcess`), or that end is refused, or the
    /// receiving user's queue is full.
    ///
    /// Fails loudly for an init process (`isInit`), which the caller refuses
    /// first.
    let generate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (sender : SignalSender)
        (entry : PendingSignal<'Thread>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SignalSent<'Thread, 'Handler>, SignalReceiverRefusal>
        =
        match effect sender entry system with
        | Error refusal -> Error refusal
        | Ok (SignalEffect.Applied (outcome, view)) -> Ok (SignalSent.Fate (ViewFate.Continues (outcome, view)))
        | Ok SignalEffect.QueueFull -> Ok SignalSent.QueueFull
        | Ok (SignalEffect.Kills termination) ->
            match UnixThreadLifecycle.tryEndProcess termination system with
            | Ok (ended, dead) -> Ok (SignalSent.Fate (ViewFate.ProcessEnded (ended, dead)))
            | Error refusal -> Ok (SignalSent.EndRefused refusal)
