namespace WoofWare.PosixKernel

/// Where a process's view of a `SimulatedMachine` was taken from: the machine,
/// its scheduling state and the process's own state as they stood, which
/// `SimulatedMachine.unfocus` requires to be the machine's still, so that a
/// view whose copy of the machine is stale, or of another history of it, is
/// refused rather than written back over a change it never saw.
///
/// Compared by identity rather than by content, both by `unfocus` and as part
/// of a `UnixSystem`'s equality: two views are views of the same state when
/// they were taken from the same values. A system no machine has focused is
/// `NotFocused`, so equality between such systems is unaffected.
[<CustomEquality ; NoComparison>]
type internal FocusOrigin<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    | NotFocused
    | FocusedFrom of
        machine : UnixMachineState *
        scheduling : UnixSchedulingState *
        proc : UnixProcessState<'Thread, 'Handler> *
        threads : Map<'Thread, UnixThreadState>

    override this.Equals (other : obj) : bool =
        match other with
        | :? FocusOrigin<'Thread, 'Handler> as other ->
            match this, other with
            | NotFocused, NotFocused -> true
            | FocusedFrom (machine, scheduling, proc, threads), FocusedFrom (machine', scheduling', proc', threads') ->
                obj.ReferenceEquals (machine, machine')
                && obj.ReferenceEquals (scheduling, scheduling')
                && obj.ReferenceEquals (proc, proc')
                && obj.ReferenceEquals (threads, threads')
            | NotFocused, FocusedFrom _
            | FocusedFrom _, NotFocused -> false
        | _ -> false

    override this.GetHashCode () : int =
        match this with
        | NotFocused -> 0
        | FocusedFrom _ -> 1

/// Everything one simulated POSIX process is, as a syscall sees it: the machine
/// it runs on, its own per-process state, and its threads.
///
/// On a `SimulatedMachine` holding several processes, this is one process's
/// view of it (`SimulatedMachine.focus`): it holds no other process, so no
/// syscall can reach one.
///
/// Generic in what names a thread and what a signal handler is, for the same
/// reason `SignalState` is: those are the client's identities and this library
/// never learns them.
///
/// Opaque: a client reads it through the queries in the `UnixSystem` module
/// and changes it only through syscalls, `UnixSystem.advanceClock` and
/// `UnixSystem.writePidMaxSysctl`.
type UnixSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    internal
        {
            Machine : UnixMachineState
            /// How long the machine has been up, and which thread each of its
            /// processors runs: see `UnixSchedulingState`.
            Scheduling : UnixSchedulingState
            Process : UnixProcessState<'Thread, 'Handler>
            Threads : Map<'Thread, UnixThreadState>
            /// The process's first thread, which it started with: its thread-group
            /// leader.
            ///
            /// Always in `Threads`. It cannot exit while another thread lives
            /// (`UnixThreadLifecycle.exitThread` refuses that), so it is a thread for as
            /// long as the process is running. On Linux its thread ID is the process ID.
            Leader : 'Thread
            /// Where this view was taken from, if a `SimulatedMachine` focused
            /// it; see `FocusOrigin`.
            Origin : FocusOrigin<'Thread, 'Handler>
        }

/// Reading and writing a `UnixSystem`'s process's descriptor table together
/// with the machine's open file descriptions it names.
[<RequireQualifiedAccess>]
module internal UnixSystemState =
    /// Whether the process's descriptor table is every descriptor on the
    /// machine: whether no other process is on it.
    let census<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : DescriptorCensus
        =
        let others =
            Set.remove system.Process.ProcessId (ProcessIdTable.live system.Machine.ProcessIds)

        if Set.isEmpty others then
            DescriptorCensus.Complete
        else
            DescriptorCensus.OneProcessOf system.Process.ProcessId

    /// The process's descriptor table, read against the machine's open file
    /// descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        FileDescriptorRegistry.ofTables (census system) system.Process.FileDescriptors system.Machine.OpenFiles

    /// `system` with `registry`'s descriptor table as the process's, and its open
    /// file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Machine =
                { system.Machine with
                    OpenFiles = FileDescriptorRegistry.openFiles registry
                }
            Process =
                { system.Process with
                    FileDescriptors = FileDescriptorRegistry.descriptorTable registry
                }
        }

    /// `system` with its machine's open file descriptions rewritten by `f`.
    let mapOpenFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : OpenFileTable -> OpenFileTable)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Machine =
                { system.Machine with
                    OpenFiles = f system.Machine.OpenFiles
                }
        }

    /// The numbering `system`'s signals are read under: its machine's
    /// platform's.
    let signalNumbering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : SignalNumbering
        =
        SimulatedUnixPlatform.signalNumbering system.Machine.UnixPlatform

    /// `system` with `signals` as its process's signal state.
    let withSignals<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (signals : SignalState<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Process =
                { system.Process with
                    Signals = signals
                }
        }

/// Writing a thread's park, together with the holds it takes on open file
/// descriptions.
[<RequireQualifiedAccess>]
module internal UnixParkState =
    /// The machine's open file table with the holds of `released` let go of and
    /// those of `taken` taken: one per time a park names a description
    /// (`ParkedSyscall.descriptions`).
    let private moveHolds
        (released : ThreadPark option)
        (taken : ThreadPark option)
        (openFiles : OpenFileTable)
        : OpenFileTable
        =
        let descriptions (park : ThreadPark option) : OpenFileDescriptionId list =
            match park with
            | None -> []
            | Some park -> ParkedSyscall.descriptions park.Syscall

        let openFiles =
            (openFiles, descriptions released)
            ||> List.fold (fun openFiles id -> OpenFileTable.releaseHold id openFiles)

        (openFiles, descriptions taken)
        ||> List.fold (fun openFiles id -> OpenFileTable.hold id openFiles)

    /// The machine's sleeping Darwin polls' kqueues with the one `released`
    /// names destroyed, unless `taken` names it too: a Darwin poll's park holds
    /// its kqueue, and a re-park of the call keeps it.
    let private moveQueue
        (released : ThreadPark option)
        (taken : ThreadPark option)
        (queues : Map<PollQueueId, PollQueue>)
        : Map<PollQueueId, PollQueue>
        =
        let queueOf (park : ThreadPark option) : PollQueueId option =
            match park with
            | Some {
                       Syscall = ParkedSyscall.KqueuePoll poll
                   } -> Some poll.Queue
            | Some _
            | None -> None

        match queueOf released with
        | Some queue when queueOf taken <> Some queue -> Map.remove queue queues
        | Some _
        | None -> queues

    /// `system` with `thread` parked in `park`, which replaces any park it was in,
    /// and with the holds the machine records moved to match: the old park's
    /// let go of, and the new park's taken; and a Darwin poll's kqueue the old
    /// park held destroyed, unless the new one holds it too. Every write of a
    /// park goes through here or `unpark`, so the holds the open file table
    /// records are always those the parks name, and the machine holds the
    /// kqueue of exactly the Darwin polls asleep.
    ///
    /// Refuses to replace a park of one syscall with a park of another, as
    /// `UnixThreadTable.withPark` does. Writes `park` as it stands, ordinal and
    /// all: `UnixWait.park` is what mints a fresh ordinal.
    let setPark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (park : ThreadPark)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let previous = UnixThreadTable.parkOf thread system.Threads

        { system with
            Machine =
                { system.Machine with
                    OpenFiles = moveHolds previous (Some park) system.Machine.OpenFiles
                    PollQueues = moveQueue previous (Some park) system.Machine.PollQueues
                }
            Threads = UnixThreadTable.withPark thread park system.Threads
        }

    /// `system` with `thread` no longer parked, its call having returned or been
    /// ended, and the holds its park took let go of. Destroys no description: a
    /// description only the park held stays in the table until
    /// `ObjectLifetime.releaseUnreferenced` is asked about it. A Darwin poll's
    /// kqueue, which nothing but its park reaches, goes with the park.
    let unpark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let previous = UnixThreadTable.parkOf thread system.Threads

        { system with
            Machine =
                { system.Machine with
                    OpenFiles = moveHolds previous None system.Machine.OpenFiles
                    PollQueues = moveQueue previous None system.Machine.PollQueues
                }
            Threads = UnixThreadTable.unpark thread system.Threads
        }

/// A simulated machine before it has booted, with the ID its first process
/// will have: what `UnixSystem.initial` makes, which the setters in
/// `UnixBootImage` configure and `UnixBootImage.boot` turns, by launching that
/// first process (`ProcessLaunch`), into the `UnixSystem` that syscalls take.
///
/// Generic in the thread and handler types of the system it boots into.
///
/// Opaque, so that the only way to a system from it is `boot`, after which no
/// setter applies.
type UnixBootImage<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    internal
        {
            Machine : UnixMachineState
            /// The ID the first process gets. The machine's thread ID allocator
            /// already holds its leader's thread ID as its one live ID.
            ProcessId : ProcessId
        }

/// What the entry point returns, for a request this kernel could answer.
[<RequireQualifiedAccess>]
type SyscallAnswer =
    /// The entry point returns this.
    | Completed of answer : int64
    /// The entry point returns its failure sentinel, and the client stores
    /// `error` wherever its libc keeps errno.
    ///
    /// A failure still changes the system in general: `flock` advances the
    /// descriptor table before it can discover the conflict that fails it.
    | Failed of error : UnixError

/// A process that has ended, and how. Only a syscall that ends the process makes
/// one. `EndedProcess.termination` and `EndedProcess.processId` read it, and
/// `SimulatedMachine.endProcess` ends the process on its machine, closing its
/// descriptors (`SimulatedMachine.endLoneProcess` for a process alone on its
/// machine).
///
/// Not a `UnixSystem`: it has no threads, so nothing can make a syscall in it, no
/// function that answers one accepts it, and nothing hands one back from it.
type EndedProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    internal
        {
            /// How the process ended, which is what its parent's `wait` reads.
            Termination : ProcessTermination
            /// The machine the process ran on, as the process's end left it: its
            /// threads' thread IDs are no longer live, the holds its threads' calls
            /// in flight had on open file descriptions are let go of, so is the
            /// hold its current directory had on its inode, and its process ID is
            /// no live process's (no `wait` is modelled, so nothing keeps it).
            ///
            /// Its descriptors are not closed, so every description they name is
            /// still counted as named, and a description no descriptor named,
            /// which only a call held, is still in the table. On a
            /// `SimulatedMachine`, `SimulatedMachine.endProcess` closes them, as a
            /// real kernel does at exit, where another process can see it.
            Machine : UnixMachineState
            /// The machine's scheduling state as the process's end left it: no
            /// processor runs one of its threads.
            Scheduling : UnixSchedulingState
            /// The process's own state as it stood when it ended. It holds nothing for
            /// any thread: no signal mask, and no signal pending on one thread alone.
            FinalProcess : UnixProcessState<'Thread, 'Handler>
            /// The process as the call that ended it found it, threads and all: what
            /// `SimulatedMachine.endProcess` checks against the machine it ends the
            /// process on, as `SimulatedMachine.unfocus` checks a view, and reads
            /// the calls the process's threads had in flight from.
            EndedIn : UnixSystem<'Thread, 'Handler>
        }

[<RequireQualifiedAccess>]
module EndedProcess =

    /// How the process ended, which is what its parent's `wait` reads.
    let termination<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (ended : EndedProcess<'Thread, 'Handler>)
        : ProcessTermination
        =
        ended.Termination

    /// The ID of the process that ended. The machine no longer counts it as
    /// any live process's.
    let processId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (ended : EndedProcess<'Thread, 'Handler>)
        : ProcessId
        =
        ended.FinalProcess.ProcessId

/// What a syscall that can end the whole process did to it: the call's own
/// outcome and the system it left the process in, or the process ended.
///
/// `'Outcome` is what the call says besides, which never includes the process
/// ending: a `WriteOutcome` for a write, a `KillOutcome` for `kill(2)`, a
/// `ReturnToUserOutcome` for a return to user mode, and `unit` for a thread's
/// exit, which says nothing more.
[<RequireQualifiedAccess>]
type ProcessFate<'Outcome, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The process carries on, as `system`.
    | Continues of outcome : 'Outcome * system : UnixSystem<'Thread, 'Handler>
    /// The process has ended, and never returns from the call.
    | ProcessEnded of EndedProcess<'Thread, 'Handler>

/// What the thread making a call must be doing as it makes it, which `Entry`
/// checks before the call runs.
[<RequireQualifiedAccess>]
type internal CallerRequirement =
    /// Running its own code, so parked in no syscall: what a call requires of
    /// the thread making it.
    | Running
    /// Parked in a syscall: what a finishing function requires of the thread
    /// whose call it finishes.
    | Woken
    /// Parked in no syscall: what `UnixSignal.onReturnToUser` requires of the
    /// thread returning to user mode.
    | Returning
    /// Any thread of the process, parked or not.
    | Exists

/// The way into a call. Each function fails with `InvalidOperationException`
/// unless `caller` is a thread of the system's process that meets
/// `requirement`, and otherwise answers what `body` answers for the system:
/// `operation` names the function the client called. There is one function
/// for each shape of answer.
[<RequireQualifiedAccess>]
module internal Entry =

    let private require<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        if Caller.processId caller <> system.Process.ProcessId then
            invalidOp
                $"%s{operation}: the caller is %O{caller}, but the system holds process %O{system.Process.ProcessId} and no other, so the call cannot be made in it (this is a bug in the client)."

        let thread = Caller.thread caller

        match requirement with
        | CallerRequirement.Running -> UnixThreadTable.requireIssuer operation thread system.Threads
        | CallerRequirement.Woken ->
            UnixThreadTable.requireParked operation thread system.Threads
            |> ignore<ParkedSyscall>
        | CallerRequirement.Returning -> UnixThreadTable.requireReturning operation thread system.Threads
        | CallerRequirement.Exists ->
            UnixThreadTable.requireThread operation thread system.Threads
            |> ignore<UnixThreadState>

    /// A call whose answer holds no system.
    let answer<'Thread, 'Handler, 'Answer when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (body : UnixSystem<'Thread, 'Handler> -> 'Answer)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Answer
        =
        require operation requirement caller system
        body system

    /// A call that answers with the system it leaves.
    let withSystem<'Thread, 'Handler, 'Answer when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (body : UnixSystem<'Thread, 'Handler> -> 'Answer * UnixSystem<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Answer * UnixSystem<'Thread, 'Handler>
        =
        require operation requirement caller system
        body system

    /// A call that answers with the system it leaves, or with an error.
    let result<'Thread, 'Handler, 'Answer, 'Error when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (body : UnixSystem<'Thread, 'Handler> -> Result<'Answer * UnixSystem<'Thread, 'Handler>, 'Error>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<'Answer * UnixSystem<'Thread, 'Handler>, 'Error>
        =
        require operation requirement caller system
        body system

    /// A call that can end the process.
    let fate<'Thread, 'Handler, 'Outcome when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (body : UnixSystem<'Thread, 'Handler> -> ProcessFate<'Outcome, 'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessFate<'Outcome, 'Thread, 'Handler>
        =
        require operation requirement caller system
        body system

    /// A call that can stop where the kernel copies from the caller's memory,
    /// whose paused value holds the system.
    let progress<'Thread, 'Handler, 'Paused, 'Answer when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (body : UnixSystem<'Thread, 'Handler> -> CallProgress<'Paused, 'Answer>)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<'Paused, 'Answer>
        =
        require operation requirement caller system
        body system
