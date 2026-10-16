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

/// What a sweep of a kernel's sleeping threads that woke none of them read:
/// everything a wake condition is asked of but the clock, among it which
/// threads sleep, and the earliest deadline any of those threads waits for.
[<NoEquality ; NoComparison>]
type internal RememberedSweep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    {
        Machine : UnixMachineState
        /// Every process's state and threads, whose parks say which threads
        /// sleep.
        Processes : Map<int32, ProcessSlot<'Thread, 'Handler>>
        /// The earliest `WakePrimitive.DeadlinePassed` among the wake
        /// conditions of the threads asleep in `Processes`, if any has one.
        EarliestDeadline : int64 voption
#if DEBUG
        /// How many answers `UnixWait.wake` has given from this sweep, which
        /// decides the ones it checks against a sweep (`WakeMemo.crossChecks`).
        ///
        /// Mutable, and counted atomically, so that an answer from the memo
        /// answers the very kernel it was asked of, allocating nothing, and
        /// still counts itself. It decides only which answers are checked, never
        /// what any answer is.
        mutable HitsSinceSweep : int
#endif
    }

/// The wake memo a kernel carries (`UnixSystem.Sweep`): the last sweep of it
/// that woke no thread, if it remembers one, which lets `UnixWait.wake` answer
/// without asking any wake condition while nothing that sweep read has changed.
///
/// Equality ignores it: any two are equal and hash alike, so two kernels that
/// differ only in what their memos remember are equal. It has no comparison,
/// as `UnixSystem` has none.
[<Struct ; CustomEquality ; NoComparison>]
type internal WakeMemo<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    {
        Remembered : RememberedSweep<'Thread, 'Handler> voption
    }

    override this.Equals (other : obj) : bool = other :? WakeMemo<'Thread, 'Handler>

    override this.GetHashCode () : int = 0

    interface System.IEquatable<WakeMemo<'Thread, 'Handler>> with
        member this.Equals (_ : WakeMemo<'Thread, 'Handler>) : bool = true

/// The whole simulated kernel: the machine, which thread each of its
/// processors runs, and every process on it, with its threads.
///
/// Generic in what names a thread and what a signal handler is, for the same
/// reason `SignalState` is: those are the client's identities and this library
/// never learns them.
///
/// Opaque: a client reads it through the queries in the `UnixSystem` module
/// and changes it only through syscalls, `UnixSystem.launch`,
/// `UnixSystem.advanceClock` and `UnixSystem.writePidMaxSysctl`.
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
            /// The wake memo (`UnixWait.wake`), which equality ignores. Every
            /// change but a wake carries it into the kernel it makes: it
            /// compares what it read by reference, so it never answers for a
            /// kernel that differs from the one it read.
            Sweep : WakeMemo<'Thread, 'Handler>
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
/// (`ProcessView.unfocus`), or, for a process that ended, makes the kernel
/// without it (`ProcessView.unfocusWithout`). A view holds the rest of the
/// kernel, so a value that holds a view, such as a call paused at a copy,
/// holds everything its resumption needs to answer a whole kernel.
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
        /// The kernel's wake memo (`UnixSystem.Sweep`), which no call's body
        /// reads: held so that putting the view back puts it back too.
        Sweep : WakeMemo<'Thread, 'Handler>
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
            Sweep = system.Sweep
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
            Sweep = view.Sweep
        }

    /// The kernel `view` is a view of, as the view has it, without the view's
    /// process, which has ended: its machine and scheduling, and every other
    /// process.
    ///
    /// Fails loudly if the process still has a thread: only a process's end
    /// takes the process out of the kernel, and that ends every thread first.
    let unfocusWithout<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        if not view.Threads.IsEmpty then
            failwith
                $"ProcessView.unfocusWithout: process %O{view.ProcessId} still has the threads %A{Map.keys view.Threads |> List.ofSeq}, so it has not ended (this is a bug in this library)."

        {
            Machine = view.Machine
            Scheduling = view.Scheduling
            Processes = view.Others
            Sweep = view.Sweep
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
    /// The process's descriptor table, read against the machine's open file
    /// descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        FileDescriptorRegistry.ofTables system.Process.FileDescriptors system.Machine.OpenFiles

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

/// Recording that a thread must return to user mode before it makes another
/// call. A thread owes that return as soon as a signal is deliverable to it
/// (`SignalState.deliverable`) while it is in no syscall: every change that
/// can make a signal so marks the thread there, through `markIfDue`.
[<RequireQualifiedAccess>]
module internal OwedReturns =
    /// A signal deliverable to `thread` in `system`: see
    /// `SignalState.deliverable`.
    let deliverable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Signal voption
        =
        SignalState.deliverable (UnixSystemState.signalNumbering system) system.Leader thread system.Process.Signals

    /// `system` with `thread` owing a return to user mode if a signal is
    /// deliverable to it (`deliverable`), and otherwise `system` itself: a
    /// thread that has exited, is parked, or owes a return already, is left
    /// as it is. A parked thread takes its signals once it leaves the park
    /// (`UnixParkState.unpark`).
    let markIfDue<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        match Map.tryFind thread system.Threads with
        | Some {
                   Parked = None
                   Owes = None
               } when (deliverable thread system).IsSome ->
            { system with
                Threads = UnixThreadTable.owe thread OwedReturn.SignalDue system.Threads
            }
        | Some _
        | None -> system

    /// `system` with `thread` having returned to user mode, owing nothing.
    let settle<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        match UnixThreadTable.owedBy thread system.Threads with
        | None -> system
        | Some _ ->
            { system with
                Threads = UnixThreadTable.settle thread system.Threads
            }

    /// `system` with `thread`, whose return to user mode is not over, owing
    /// the rest of it.
    let returnGoesOn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        { system with
            Threads = UnixThreadTable.owe thread OwedReturn.SignalDue system.Threads
        }

    /// `system` with `thread`, whose call `interruption` interrupted and which
    /// is parked no longer, owing the return to user mode that decides how the
    /// call ends, in place of the `SignalDue` its leaving the park may have
    /// marked it with.
    let interrupt<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (interruption : Interruption)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        // The return that decides how the call ends takes the signal that
        // made the thread owe it too, so the one mark stands for both.
        let threads =
            match UnixThreadTable.owedBy thread system.Threads with
            | Some OwedReturn.SignalDue -> UnixThreadTable.settle thread system.Threads
            | Some (OwedReturn.Interrupted _)
            | None -> system.Threads

        { system with
            Threads = UnixThreadTable.owe thread (OwedReturn.Interrupted interruption) threads
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
    /// all: `Parking.park` is what mints a fresh ordinal.
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
    /// ended, and the holds its park took let go of; and with the thread owing
    /// a return to user mode if a signal is deliverable to it
    /// (`OwedReturns.markIfDue`), since it takes its signals once it has left
    /// the park. Destroys no description: a description only the park held
    /// stays in the table until `ObjectLifetime.releaseUnreferenced` is asked
    /// about it. A Darwin poll's kqueue, which nothing but its park reaches,
    /// goes with the park.
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
        |> OwedReturns.markIfDue thread

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

/// A process that has ended, and how. Only a syscall that ends the process
/// makes one, and answers it beside the system without the process
/// (`ProcessFate.ProcessEnded`, `UnixThreadLifecycle.exitGroup`).
/// `EndedProcess.termination` and `EndedProcess.processId` read it.
type EndedProcess =
    internal
        {
            /// How the process ended, which is what its parent's `wait` reads.
            Termination : ProcessTermination
            /// The ID the process had.
            ProcessId : ProcessId
        }

[<RequireQualifiedAccess>]
module EndedProcess =

    /// How the process ended, which is what its parent's `wait` reads.
    let termination (ended : EndedProcess) : ProcessTermination = ended.Termination

    /// The ID of the process that ended. No process on the machine has it now:
    /// no `wait` is modelled, so nothing keeps the process for a parent to
    /// reap.
    let processId (ended : EndedProcess) : ProcessId = ended.ProcessId

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
    /// The process has ended, and never returns from the call: how it ended,
    /// and `system`, the system without it, which holds every other process as
    /// the call left it. The process's descriptors are closed, as
    /// `UnixThreadLifecycle.exitGroup` closes them.
    | ProcessEnded of ended : EndedProcess * system : UnixSystem<'Thread, 'Handler>

/// What a call's body that can end the whole process did to it, before `Entry`
/// makes a kernel of its view: a `ProcessFate` whose systems are `'View`s.
/// `Shape.fate` makes the `ProcessFate` of it.
[<RequireQualifiedAccess>]
type internal ViewFate<'Outcome, 'View> =
    /// The process carries on, as `view`.
    | Continues of outcome : 'Outcome * view : 'View
    /// The process has ended, and never returns from the call: how it ended,
    /// and the view of it with no thread or descriptor left, which `Shape.fate`
    /// takes out of the kernel.
    | ProcessEnded of ended : EndedProcess * view : 'View

/// How `Shape.map` makes a kernel of each view in a call's answer: one whose
/// process carries on goes `Back` into the kernel, and one whose process has
/// ended leaves the kernel `Without` it.
[<Struct>]
type internal Unfocus<'View, 'Kernel> =
    {
        /// The kernel with the view's process as the view has it.
        Back : 'View -> 'Kernel
        /// The kernel without the view's process, which has ended.
        Without : 'View -> 'Kernel
    }

/// Where the systems sit in a call's answer, built from the `Shape` module's
/// functions, which nest as the answer's type does: `kill`'s
/// `Result<Result<ProcessFate<_, _, _>, UnixError>, KillRefusal>` is
/// `Shape.result (Shape.result Shape.fate)`.
///
/// `'InView` is the answer as a call's body gives it, each system in it a
/// `'View`, and `'InKernel` is that answer with a `'Kernel` made of each of
/// those systems, which `Shape.map` does. `Entry` takes shapes whose `'View`
/// is `ProcessView`, the view of the caller's process a call's body runs
/// over, and whose `'Kernel` is `UnixSystem`, the kernel the call hands back.
[<Struct>]
type internal Shape<'View, 'Kernel, 'InView, 'InKernel> =
    // `'View` and `'Kernel` are separate parameters, and the primitives that
    // can be are generic in them, so that one has no way to make a `'Kernel`
    // but of a `'View`, through the `Unfocus` it is given: the compiler
    // rejects one that leaves a view where it was, or that answers a process's
    // end without the view it ended in.
    private | Shape of map : (Unfocus<'View, 'Kernel> -> 'InView -> 'InKernel)

/// What `Shape.union` hands the code that makes a union's answer, in place of
/// the `Unfocus` the shape is given: a way to make a kernel of each view in a
/// part of the answer only as one of the `Shape` module's shapes says.
type internal ShapeMap<'View, 'Kernel> =
    /// `answer` with a kernel made of each view in it, where `shape` says they
    /// sit, as `Shape.map` makes it with the `Unfocus` the union's shape was
    /// given.
    abstract Map<'InView, 'InKernel> :
        shape : Shape<'View, 'Kernel, 'InView, 'InKernel> -> answer : 'InView -> 'InKernel

[<RequireQualifiedAccess>]
module internal Shape =

    /// `answer` with a kernel made of each system in it, where `shape` says
    /// they sit, and nothing else in it changed: `unfocus.Back` of each view
    /// whose process carries on, and `unfocus.Without` of each whose process
    /// has ended, once each.
    let map<'View, 'Kernel, 'InView, 'InKernel>
        (unfocus : Unfocus<'View, 'Kernel>)
        (shape : Shape<'View, 'Kernel, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel
        =
        match shape with
        | Shape map -> map unfocus answer

    /// An answer holding no system, however it nests.
    let answer<'View, 'Kernel, 'Answer> : Shape<'View, 'Kernel, 'Answer, 'Answer> =
        Shape (fun (_ : Unfocus<'View, 'Kernel>) (answer : 'Answer) -> answer)

    /// A system alone.
    let system<'View, 'Kernel> : Shape<'View, 'Kernel, 'View, 'Kernel> =
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) (view : 'View) -> unfocus.Back view)

    /// An answer holding no system, and the system the call left.
    let withSystem<'View, 'Kernel, 'Answer> : Shape<'View, 'Kernel, 'Answer * 'View, 'Answer * 'Kernel> =
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) ((answer : 'Answer), (view : 'View)) ->
            answer, unfocus.Back view
        )

    /// A `Result` whose `Ok` is shaped as `ok` says. Its `Error` holds no
    /// system.
    let result<'View, 'Kernel, 'InView, 'InKernel, 'Error>
        (ok : Shape<'View, 'Kernel, 'InView, 'InKernel>)
        : Shape<'View, 'Kernel, Result<'InView, 'Error>, Result<'InKernel, 'Error>>
        =
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) (result : Result<'InView, 'Error>) ->
            match result with
            | Ok answer -> Ok (map unfocus ok answer)
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
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) (progress : CallProgress<'Paused, 'InView>) ->
            match progress with
            | CallProgress.Answered answer -> CallProgress.Answered (map unfocus answered answer)
            | CallProgress.NeedsCopyIn paused -> CallProgress.NeedsCopyIn paused
        )

    /// A process that ended, and the view it ended in, of which the kernel
    /// without it is made.
    let ended<'View, 'Kernel> : Shape<'View, 'Kernel, EndedProcess * 'View, EndedProcess * 'Kernel> =
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) ((ended : EndedProcess), (view : 'View)) ->
            ended, unfocus.Without view
        )

    /// A body's `ViewFate` as the call's `ProcessFate`: the view the process
    /// carries on as put back, or the process ended, shaped as `ended` says.
    let fate<'View, 'Outcome, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Shape<
              'View,
              UnixSystem<'Thread, 'Handler>,
              ViewFate<'Outcome, 'View>,
              ProcessFate<'Outcome, 'Thread, 'Handler>
           > =
        Shape (fun (unfocus : Unfocus<'View, UnixSystem<'Thread, 'Handler>>) (fate : ViewFate<'Outcome, 'View>) ->
            match fate with
            | ViewFate.Continues (outcome, view) -> ProcessFate.Continues (outcome, unfocus.Back view)
            | ViewFate.ProcessEnded (ended', view) -> ProcessFate.ProcessEnded (map unfocus ended (ended', view))
        )

    /// A union whose cases hold their systems each where a shape of its own
    /// says: `cases` makes the answer of each case, putting back the views in
    /// it through the `ShapeMap` it is handed, which maps each part as the
    /// shape it is given says.
    ///
    /// `cases` is generic in the view, as every primitive is, so that the
    /// compiler rejects one that leaves a view where it was; and it is handed no
    /// `Unfocus`, so it puts a view back only as another shape does.
    let union<'View, 'Kernel, 'InView, 'InKernel>
        (cases : ShapeMap<'View, 'Kernel> -> 'InView -> 'InKernel)
        : Shape<'View, 'Kernel, 'InView, 'InKernel>
        =
        Shape (fun (unfocus : Unfocus<'View, 'Kernel>) (answer : 'InView) ->
            let shapes =
                { new ShapeMap<'View, 'Kernel> with
                    member _.Map<'Part, 'PartInKernel>
                        (shape : Shape<'View, 'Kernel, 'Part, 'PartInKernel>)
                        (part : 'Part)
                        : 'PartInKernel
                        =
                        map unfocus shape part
                }

            cases shapes answer
        )

/// What the thread making a call must be doing as it makes it, which `Entry`
/// checks before the call runs.
[<RequireQualifiedAccess>]
type internal CallerRequirement =
    /// Running its own code, so parked in no syscall and owing no return to
    /// user mode: what a call requires of the thread making it.
    | Running
    /// Parked in a syscall, and woken by `UnixWait.wake`: what a finishing
    /// function requires of the thread whose call it finishes.
    | Woken
    /// Parked in no syscall, whether or not it owes a return: what
    /// `UnixSignal.onReturnToUser` requires of the thread returning to user
    /// mode.
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
        | CallerRequirement.Woken -> UnixThreadTable.requireWoken operation thread slot.Threads
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
    /// body changed nothing (`ProcessView.unfocusFrom`); or, for a process that
    /// ended, the kernel without it (`ProcessView.unfocusWithout`).
    /// `operation` names the function the client called.
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

        let unfocus =
            {
                Back = ProcessView.unfocusFrom system focused
                Without = ProcessView.unfocusWithout
            }

        Shape.map unfocus shape (body focused)

    /// A call resumed after it paused to copy from the caller's memory:
    /// `answer`, which the resumption gave from the view the paused value
    /// held. `shape` says where the views sit in it, and each is put back into
    /// the kernel as the resumption left it, or, for a process that ended,
    /// leaves the kernel without it.
    ///
    /// The caller is not checked again. It was checked as the call began, and
    /// the paused value holds the view, with the rest of the kernel, so nothing
    /// can have happened to the caller since.
    let resume<'Thread, 'Handler, 'InView, 'InKernel when 'Thread : comparison and 'Handler : equality>
        (shape : Shape<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel
        =
        let unfocus =
            {
                Back = ProcessView.unfocus
                Without = ProcessView.unfocusWithout
            }

        Shape.map unfocus shape answer

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
