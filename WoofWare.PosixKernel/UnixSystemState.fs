namespace WoofWare.PosixKernel

/// One process of a `UnixSystem`: its own state, its threads, and its leader.
type internal ProcessSlot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    {
        Process : UnixProcessState<'Thread, 'Handler>
        /// The process's threads. A thread is named by the client, separately in
        /// each process: two processes may each have a thread the client calls
        /// by the same name.
        Threads : Map<'Thread, UnixThreadState>
        /// The process's first thread, which it started with: its thread-group
        /// leader.
        ///
        /// Always in `Threads`. It cannot exit while another thread lives
        /// (`UnixThreadLifecycle.exitThread` refuses that), so it is a thread for as
        /// long as the process is running. On Linux its thread ID is the process ID.
        Leader : 'Thread
    }

/// The whole simulated kernel: the machine, which thread each of its
/// processors runs, and every process on it, with its threads.
///
/// Generic in what names a thread and what a signal handler is, for the same
/// reason `SignalState` is: those are the client's identities and this library
/// never learns them.
///
/// Opaque: a client reads it through the queries in the `UnixSystem` module
/// and changes it only through syscalls, `UnixSystem.launch`,
/// `UnixSystem.endProcess`, `UnixSystem.advanceClock` and
/// `UnixSystem.writePidMaxSysctl`.
type UnixSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    internal
        {
            Machine : UnixMachineState
            /// How long the machine has been up, and which thread each of its
            /// processors runs: see `UnixSchedulingState`.
            Scheduling : UnixSchedulingState
            /// Every process on the machine, keyed by its process ID's
            /// `pid_t` (`ProcessId.toInt32`).
            Processes : Map<int32, ProcessSlot<'Thread, 'Handler>>
        }

// Keyed by the `pid_t` rather than by the `ProcessId`, a struct, because a
// `Map` compares a struct key through F#'s generic comparison, which boxes
// both keys at every comparison (measured: 48 bytes a lookup), and
// `UnixScheduling.dispatch`, which a client makes before every instruction,
// finds its caller's process here and must allocate nothing.

/// One process's view of a `UnixSystem`, which a call's body works on: the
/// machine, which thread each processor runs, the process with its threads,
/// and every other process, held apart from it.
///
/// `Entry` focuses the caller's process to make one (`ProcessView.ofSlot`) and
/// puts each view in the body's answer back into the kernel
/// (`ProcessView.unfocus`). A view holds the rest of the kernel, so a value
/// that holds a view, such as a call paused at a copy, holds everything its
/// resumption needs to answer a whole kernel.
type internal ProcessView<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    {
        Machine : UnixMachineState
        /// How long the machine has been up, and which thread each of its
        /// processors runs: see `UnixSchedulingState`.
        Scheduling : UnixSchedulingState
        /// The process this is the view of: the key its slot goes back under.
        ProcessId : ProcessId
        Process : UnixProcessState<'Thread, 'Handler>
        /// The process's threads: see `ProcessSlot.Threads`.
        Threads : Map<'Thread, UnixThreadState>
        /// The process's leader: see `ProcessSlot.Leader`.
        Leader : 'Thread
        /// Every process on the machine but this one, keyed as
        /// `UnixSystem.Processes` is.
        Others : Map<int32, ProcessSlot<'Thread, 'Handler>>
    }

/// Moving between a `UnixSystem` and the view of it from one of its
/// processes.
[<RequireQualifiedAccess>]
module internal ProcessView =

    /// The view of `system` from the process `pid`, whose slot is `slot`.
    let ofSlot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (slot : ProcessSlot<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        {
            Machine = system.Machine
            Scheduling = system.Scheduling
            ProcessId = pid
            Process = slot.Process
            Threads = slot.Threads
            Leader = slot.Leader
            Others = Map.remove (ProcessId.toInt32 pid) system.Processes
        }

    /// The view of `system` from the process `pid`, or `None` if `system`
    /// holds no process with that ID.
    let tryFocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler> option
        =
        match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
        | Some slot -> Some (ofSlot pid slot system)
        | None -> None

    /// The kernel `view` is a view of, as the view has it: its machine and
    /// scheduling, and its process back among the others, under its ID.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        {
            Machine = view.Machine
            Scheduling = view.Scheduling
            Processes =
                Map.add
                    (ProcessId.toInt32 view.ProcessId)
                    {
                        Process = view.Process
                        Threads = view.Threads
                        Leader = view.Leader
                    }
                    view.Others
        }

    /// Whether every part of `view` is the very value `focused` holds: the
    /// same objects, not merely equal ones, but for the leader, which is the
    /// client's value and is compared for equality.
    let internal unchangedFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (focused : ProcessView<'Thread, 'Handler>)
        (view : ProcessView<'Thread, 'Handler>)
        : bool
        =
        obj.ReferenceEquals (view.Machine, focused.Machine)
        && obj.ReferenceEquals (view.Scheduling, focused.Scheduling)
        && ProcessId.toInt32 view.ProcessId = ProcessId.toInt32 focused.ProcessId
        && obj.ReferenceEquals (view.Process, focused.Process)
        && obj.ReferenceEquals (view.Threads, focused.Threads)
        && obj.ReferenceEquals (view.Others, focused.Others)
        && System.Collections.Generic.EqualityComparer<'Thread>.Default.Equals (view.Leader, focused.Leader)

    /// `unfocus`, for a view derived from `focused`, the view of `origin` a
    /// call began with: `origin` itself, the same value, if `view` is
    /// unchanged from `focused` (`unchangedFrom`), so that a call that changed
    /// nothing answers the kernel it was given.
    let unfocusFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (origin : UnixSystem<'Thread, 'Handler>)
        (focused : ProcessView<'Thread, 'Handler>)
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        if unchangedFrom focused view then origin else unfocus view

/// Reading and writing a `ProcessView`'s process's descriptor table together
/// with the machine's open file descriptions it names.
[<RequireQualifiedAccess>]
module internal UnixSystemState =
    /// Whether the process's descriptor table is every descriptor on the
    /// machine: whether no other process is on it.
    let census<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
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
        (system : ProcessView<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        FileDescriptorRegistry.ofTables (census system) system.Process.FileDescriptors system.Machine.OpenFiles

    /// `system` with `registry`'s descriptor table as the process's, and its open
    /// file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (registry : FileDescriptorRegistry)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
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
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
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
        (system : ProcessView<'Thread, 'Handler>)
        : SignalNumbering
        =
        SimulatedUnixPlatform.signalNumbering system.Machine.UnixPlatform

    /// `system` with `signals` as its process's signal state.
    let withSignals<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (signals : SignalState<'Thread, 'Handler>)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
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
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
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
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
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
/// `UnixSystem.endProcess` ends the process in the kernel it ran in, closing its
/// descriptors and removing it.
///
/// Not a `UnixSystem`: nothing can make a syscall in it, no function that
/// answers one accepts it, and only `UnixSystem.endProcess` hands back a
/// kernel from it.
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
            /// which only a call held, is still in the table.
            /// `UnixSystem.endProcess` closes them, as a real kernel does at exit,
            /// where another process can see it.
            Machine : UnixMachineState
            /// The machine's scheduling state as the process's end left it: no
            /// processor runs one of its threads.
            Scheduling : UnixSchedulingState
            /// The process's own state as it stood when it ended. It holds nothing for
            /// any thread: no signal mask, and no signal pending on one thread alone.
            FinalProcess : UnixProcessState<'Thread, 'Handler>
            /// The view the call that ended the process ran in, as the call found
            /// it: its threads, and every other process on the machine, from which
            /// `UnixSystem.endProcess` makes the kernel without this process.
            EndedIn : ProcessView<'Thread, 'Handler>
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

/// What a call's body that can end the whole process did to it, before `Entry`
/// puts its view back: a `ProcessFate` whose process carries on as a
/// `ProcessView`. `Shape.fate` makes the `ProcessFate` of it.
[<RequireQualifiedAccess>]
type internal ViewFate<'Outcome, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The process carries on, as `view`.
    | Continues of outcome : 'Outcome * view : ProcessView<'Thread, 'Handler>
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
/// is `ProcessView`, the view of the caller's process a call's body runs
/// over, and whose `'Kernel` is `UnixSystem`, the kernel the call hands back.
[<Struct>]
type internal Shape<'View, 'Kernel, 'InView, 'InKernel> =
    // `'View` and `'Kernel` are separate parameters, and the primitives that
    // can be are generic in them, so that one has no way to make a `'Kernel`
    // but to put a `'View` back: the compiler rejects one that leaves a view
    // where it was, or puts one back twice.
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
    /// paused value is left as it is, holding the view the call paused in, and
    /// with it the rest of the kernel: the call's resumption answers from that
    /// view, and puts it back through `Entry.resume`.
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
    /// so it is left as it is: `UnixSystem.endProcess` makes a kernel of it.
    let ended<'View, 'Kernel, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Shape<'View, 'Kernel, EndedProcess<'Thread, 'Handler>, EndedProcess<'Thread, 'Handler>> =
        answer

    /// A body's `ViewFate` as the call's `ProcessFate`: the view the process
    /// carries on as put back, or the process ended, shaped as `ended` says.
    let fate<'Outcome, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Shape<
              ProcessView<'Thread, 'Handler>,
              UnixSystem<'Thread, 'Handler>,
              ViewFate<'Outcome, 'Thread, 'Handler>,
              ProcessFate<'Outcome, 'Thread, 'Handler>
           > =
        let putBack
            (put : ProcessView<'Thread, 'Handler> -> UnixSystem<'Thread, 'Handler>)
            (fate : ViewFate<'Outcome, 'Thread, 'Handler>)
            : ProcessFate<'Outcome, 'Thread, 'Handler>
            =
            match fate with
            | ViewFate.Continues (outcome, view) -> ProcessFate.Continues (outcome, put view)
            | ViewFate.ProcessEnded ended' -> ProcessFate.ProcessEnded (map put ended ended')

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

    /// The slot of the caller's process, once the check `call` makes before
    /// its body runs has passed: fails with `InvalidOperationException` unless
    /// `caller` is a thread of one of the kernel's processes that meets
    /// `requirement`. `operation` names the function the client called.
    ///
    /// Allocates nothing.
    let admitted<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessSlot<'Thread, 'Handler>
        =
        // `TryGetValue` rather than `Map.tryFind`, which would allocate an
        // option.
        let mutable slot = Unchecked.defaultof<ProcessSlot<'Thread, 'Handler>>

        if not (system.Processes.TryGetValue (ProcessId.toInt32 (Caller.processId caller), &slot)) then
            invalidOp
                $"%s{operation}: the caller is %O{caller}, but the system holds no process %O{Caller.processId caller}, so the call cannot be made in it (this is a bug in the client)."

        let thread = Caller.thread caller

        match requirement with
        | CallerRequirement.Running -> UnixThreadTable.requireIssuer operation thread slot.Threads
        | CallerRequirement.Woken ->
            UnixThreadTable.requireParked operation thread slot.Threads
            |> ignore<ParkedSyscall>
        | CallerRequirement.Returning -> UnixThreadTable.requireReturning operation thread slot.Threads
        | CallerRequirement.Exists ->
            UnixThreadTable.requireThread operation thread slot.Threads
            |> ignore<UnixThreadState>

        slot

    /// The check `call` makes before its body runs, as `admitted` makes it,
    /// for a call that must allocate nothing, which the closures `call` takes
    /// would make it do: `UnixScheduling.dispatch`, which a client makes
    /// before every instruction.
    let admit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        admitted operation requirement caller system
        |> ignore<ProcessSlot<'Thread, 'Handler>>

    /// A call: fails with `InvalidOperationException` unless `caller` is a
    /// thread of one of the kernel's processes that meets `requirement`, and
    /// otherwise answers what `body` answers for the view of the caller's
    /// process. `shape` says where the views sit in that answer, and each is
    /// put back into the kernel as the body left it; the kernel itself, if the
    /// body changed nothing (`ProcessView.unfocusFrom`). `operation` names the
    /// function the client called.
    let call<'Thread, 'Handler, 'InView, 'InKernel when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (requirement : CallerRequirement)
        (caller : Caller<'Thread>)
        (shape : Shape<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>, 'InView, 'InKernel>)
        (body : ProcessView<'Thread, 'Handler> -> 'InView)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'InKernel
        =
        let slot = admitted operation requirement caller system
        let focused = ProcessView.ofSlot (Caller.processId caller) slot system
        Shape.map (ProcessView.unfocusFrom system focused) shape (body focused)

    /// A call resumed after it paused to copy from the caller's memory:
    /// `answer`, which the resumption gave from the view the paused value
    /// held. `shape` says where the views sit in it, and each is put back into
    /// the kernel as the resumption left it.
    ///
    /// The caller is not checked again. It was checked as the call began, and
    /// the paused value holds the view, with the rest of the kernel, so nothing
    /// can have happened to the caller since.
    let resume<'Thread, 'Handler, 'InView, 'InKernel when 'Thread : comparison and 'Handler : equality>
        (shape : Shape<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel
        =
        Shape.map ProcessView.unfocus shape answer

    /// A question about the process `pid` that no thread of it asks, such as
    /// which threads it has: fails with `InvalidOperationException` unless
    /// the kernel holds a process `pid`, and otherwise answers what `body`
    /// answers for the view of it. `operation` names the function the client
    /// called.
    ///
    /// The answer holds no system, so nothing is handed back.
    let query<'Thread, 'Handler, 'Answer when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (body : ProcessView<'Thread, 'Handler> -> 'Answer)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Answer
        =
        match ProcessView.tryFocus pid system with
        | Some view -> body view
        | None ->
            invalidOp
                $"%s{operation}: the question is about process %O{pid}, but the system holds no process %O{pid}, so it cannot be asked of it (this is a bug in the client)."
