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

/// Where the systems sit in a call's answer, built from the `Shape` module's
/// functions, which nest as the answer's type does: `kill`'s
/// `Result<Result<ProcessFate<_, _, _>, UnixError>, KillRefusal>` is
/// `Shape.result (Shape.result Shape.fate)`.
///
/// `'InView` is the answer as a call's body gives it, each system in it a
/// `'View`, and `'InKernel` is that answer with each of those systems put back
/// as a `'Kernel`, which `Shape.map` does. `Entry` takes shapes whose `'View`
/// and `'Kernel` are both `UnixSystem`: the system a call's body runs over,
/// and the one the call hands back.
[<Struct>]
type internal Shape<'View, 'Kernel, 'InView, 'InKernel> =
    // `'View` and `'Kernel` are separate parameters, though `Entry` makes both
    // `UnixSystem`, so that a primitive generic in them has no way to make a
    // `'Kernel` but to put a `'View` back: the compiler rejects one that leaves
    // a system where it was, or puts one back twice.
    private | Shape of map : (('View -> 'Kernel) -> 'InView -> 'InKernel)

[<RequireQualifiedAccess>]
module internal Shape =

    /// `answer` with `put` applied once to each system in it, where `shape`
    /// says they sit, and nothing else in it changed.
    let map<'View, 'Kernel, 'InView, 'InKernel>
        (put : 'View -> 'Kernel)
        (shape : Shape<'View, 'Kernel, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel
        =
        match shape with
        | Shape map -> map put answer

    /// An answer holding no system, however it nests.
    let answer<'View, 'Kernel, 'Answer> : Shape<'View, 'Kernel, 'Answer, 'Answer> =
        Shape (fun (_ : 'View -> 'Kernel) (answer : 'Answer) -> answer)

    /// A system alone.
    let system<'View, 'Kernel> : Shape<'View, 'Kernel, 'View, 'Kernel> =
        Shape (fun (put : 'View -> 'Kernel) (view : 'View) -> put view)

    /// An answer holding no system, and the system the call left.
    let withSystem<'View, 'Kernel, 'Answer> : Shape<'View, 'Kernel, 'Answer * 'View, 'Answer * 'Kernel> =
        Shape (fun (put : 'View -> 'Kernel) ((answer : 'Answer), (view : 'View)) -> answer, put view)

    /// A `Result` whose `Ok` is shaped as `ok` says. Its `Error` holds no
    /// system.
    let result<'View, 'Kernel, 'InView, 'InKernel, 'Error>
        (ok : Shape<'View, 'Kernel, 'InView, 'InKernel>)
        : Shape<'View, 'Kernel, Result<'InView, 'Error>, Result<'InKernel, 'Error>>
        =
        Shape (fun (put : 'View -> 'Kernel) (result : Result<'InView, 'Error>) ->
            match result with
            | Ok answer -> Ok (map put ok answer)
            | Error error -> Error error
        )

    /// A `CallProgress` whose `Answered` is shaped as `answered` says. Its
    /// paused value is left as it is, holding the system the call paused in:
    /// the call's resumption answers from that system, and puts it back
    /// through `Entry.resume`.
    let progress<'View, 'Kernel, 'Paused, 'InView, 'InKernel>
        (answered : Shape<'View, 'Kernel, 'InView, 'InKernel>)
        : Shape<'View, 'Kernel, CallProgress<'Paused, 'InView>, CallProgress<'Paused, 'InKernel>>
        =
        Shape (fun (put : 'View -> 'Kernel) (progress : CallProgress<'Paused, 'InView>) ->
            match progress with
            | CallProgress.Answered answer -> CallProgress.Answered (map put answered answer)
            | CallProgress.NeedsCopyIn paused -> CallProgress.NeedsCopyIn paused
        )

    /// A process that ended. Nothing in it is a system a call can be made in,
    /// so it is left as it is.
    let ended<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Shape<
              UnixSystem<'Thread, 'Handler>,
              UnixSystem<'Thread, 'Handler>,
              EndedProcess<'Thread, 'Handler>,
              EndedProcess<'Thread, 'Handler>
           > =
        let leave
            (_ : UnixSystem<'Thread, 'Handler> -> UnixSystem<'Thread, 'Handler>)
            (ended : EndedProcess<'Thread, 'Handler>)
            : EndedProcess<'Thread, 'Handler>
            =
            ended

        Shape leave

    /// A `ProcessFate`: the system the process carries on as, or the process
    /// ended, shaped as `ended` says.
    let fate<'Outcome, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Shape<
              UnixSystem<'Thread, 'Handler>,
              UnixSystem<'Thread, 'Handler>,
              ProcessFate<'Outcome, 'Thread, 'Handler>,
              ProcessFate<'Outcome, 'Thread, 'Handler>
           > =
        let putBack
            (put : UnixSystem<'Thread, 'Handler> -> UnixSystem<'Thread, 'Handler>)
            (fate : ProcessFate<'Outcome, 'Thread, 'Handler>)
            : ProcessFate<'Outcome, 'Thread, 'Handler>
            =
            match fate with
            | ProcessFate.Continues (outcome, system) -> ProcessFate.Continues (outcome, put system)
            | ProcessFate.ProcessEnded ended' -> ProcessFate.ProcessEnded (map put ended ended')

        Shape putBack

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
    /// Any thread of the process, parked or not: what `UnixScheduling.dispatch`
    /// requires of the thread it reports running.
    | Exists

/// The way into a call, and out of one resumed after it paused to copy from
/// the caller's memory; and the way into a query about one process.
[<RequireQualifiedAccess>]
module internal Entry =

    /// The check `call` makes before its body runs: fails with
    /// `InvalidOperationException` unless `caller` is a thread of the system's
    /// process that meets `requirement`. `operation` names the function the
    /// client called.
    ///
    /// For a call that must allocate nothing, which the closures `call` takes
    /// would make it do: `UnixScheduling.dispatch`, which a client makes
    /// before every instruction.
    let admit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
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

    /// A call: fails with `InvalidOperationException` unless `caller` is a
    /// thread of the system's process that meets `requirement`, and otherwise
    /// answers what `body` answers for the system. `shape` says where the
    /// systems sit in that answer, and each is handed back as the body left
    /// it. `operation` names the function the client called.
    let call<'Thread, 'Handler, 'InView, 'InKernel when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (shape : Shape<UnixSystem<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>, 'InView, 'InKernel>)
        (body : UnixSystem<'Thread, 'Handler> -> 'InView)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'InKernel
        =
        admit operation requirement caller system
        // `id`: the body runs over the system the call hands back.
        Shape.map id shape (body system)

    /// A call resumed after it paused to copy from the caller's memory:
    /// `answer`, which the resumption gave from the system the paused value
    /// held. `shape` says where the systems sit in it, and each is handed back
    /// as the resumption left it.
    ///
    /// The caller is not checked again. It was checked as the call began, and
    /// the paused value holds the system, so nothing can have happened to the
    /// caller since.
    let resume<'Thread, 'Handler, 'InView, 'InKernel when 'Thread : comparison and 'Handler : equality>
        (shape : Shape<UnixSystem<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel
        =
        // `id`: the resumption runs over the system the call hands back.
        Shape.map id shape answer

    /// A question about the process `pid` that no thread of it asks, such as
    /// which threads it has: fails with `InvalidOperationException` unless
    /// `pid` is the system's process, and otherwise answers what `body`
    /// answers for the system. `operation` names the function the client
    /// called.
    ///
    /// The answer holds no system, so nothing is handed back.
    let query<'Thread, 'Handler, 'Answer when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (body : UnixSystem<'Thread, 'Handler> -> 'Answer)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Answer
        =
        if pid <> system.Process.ProcessId then
            invalidOp
                $"%s{operation}: the question is about process %O{pid}, but the system holds process %O{system.Process.ProcessId} and no other, so it cannot be asked of it (this is a bug in the client)."

        body system
