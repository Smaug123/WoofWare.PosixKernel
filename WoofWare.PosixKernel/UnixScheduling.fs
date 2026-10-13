namespace WoofWare.PosixKernel

/// One of the machine's NUMA nodes, as `getcpu(2)` reports it.
type NumaNode =
    | NumaNode of int

    /// <summary>
    /// A human-readable description of the NUMA node.
    /// </summary>
    override this.ToString () =
        match this with
        | NumaNode.NumaNode i -> $"<numa node #%i{i}>"

/// What `getcpu(2)` answers: where the calling thread is running.
type GetCpuAnswer =
    {
        /// The logical processor the thread is running on.
        Cpu : CpuId
        /// The NUMA node that processor belongs to. This library models a
        /// machine with one node, so it is always node 0, which is what every
        /// `getcpu` answered on Linux 6.18.5 at two and at five processors
        /// (`docs/plans/2026-08-23-posix-kernel-extraction/cpu-placement.c`).
        Node : NumaNode
    }

/// Why this kernel will not answer a `getcpu(2)`.
[<RequireQualifiedAccess>]
type internal GetCpuRefusal =
    /// This kernel is not Linux-flavoured, and only Linux has `getcpu`.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal GetCpuRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which of its entry points asked.
    let describe (refusal : GetCpuRefusal) : string =
        match refusal with
        | GetCpuRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and getcpu exists on Linux only. Darwin's libc has neither sched_getcpu nor getcpu."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : GetCpuRefusal) : RefusalKind =
        match refusal with
        | GetCpuRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform

/// Which thread runs on which of the machine's logical processors.
///
/// The client chooses which thread runs where, and reports each choice with
/// `dispatch`; this library records it, and answers `getcpu` from the record.
/// A thread's processor (`UnixThreadState.cpu`) is the one it last ran on, or,
/// before it first runs, the one its creator named. Each processor of the
/// machine runs at most one thread, whichever process it belongs to, and a thread
/// is running exactly when it is its processor's (`runningOn`).
///
/// A thread stops running when the client dispatches another to its processor,
/// when it parks in a syscall, and when it exits or its process ends. A parked
/// thread may be dispatched: that is how a woken thread gets back onto a processor
/// to finish its call.
[<RequireQualifiedAccess>]
module UnixScheduling =

    /// `thread` is now running on the logical processor `cpu`: the client's
    /// report of a dispatch.
    ///
    /// `thread`'s processor becomes `cpu`. Whichever thread `cpu` was running,
    /// in this process or another on the machine, stops running there and
    /// keeps `cpu` as its processor, as a preempted thread does. If `thread` was
    /// running on another processor, that one is now idle. Dispatching a thread
    /// to the processor it is already running on changes nothing, and answers
    /// `system` itself.
    ///
    /// A parked thread may be dispatched. Whether it was woken is the client's
    /// record (`UnixWait.wakes`), so this library does not refuse one that was
    /// not.
    ///
    /// Fails loudly if `thread` names no thread, or if `cpu` is not one of the
    /// machine's processors (`UnixSystem.processorCount`): each is a bug in
    /// the client.
    let dispatch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (cpu : CpuId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let state = UnixThreadTable.get thread system.Threads

        if not (UnixMachineState.hasProcessor cpu system.Machine) then
            failwith
                $"UnixScheduling.dispatch: %O{thread} was dispatched to %O{cpu}, but the machine has %d{system.Machine.ProcessorCount} logical processors, numbered from 0 (this is a bug in the client)."

        if
            state.Cpu = cpu
            && UnixSchedulingState.runs cpu state.OsThreadId system.Scheduling
        then
            system
        else

        let scheduling =
            let vacated =
                UnixSchedulingState.vacate state.Cpu state.OsThreadId system.Scheduling

            { vacated with
                Occupants = Map.add cpu state.OsThreadId vacated.Occupants
            }

        let threads =
            if state.Cpu = cpu then
                system.Threads
            else
                Map.add
                    thread
                    { state with
                        Cpu = cpu
                    }
                    system.Threads

        { system with
            Scheduling = scheduling
            Threads = threads
        }

    /// The logical processor `thread` is running on: `None` if it is not
    /// running, because the client has not dispatched it since it was created
    /// or since it last parked, or has dispatched another thread to its
    /// processor since, and `None` if `thread` names no thread.
    let runningOn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : CpuId option
        =
        match Map.tryFind thread system.Threads with
        | Some state when UnixSchedulingState.runs state.Cpu state.OsThreadId system.Scheduling -> Some state.Cpu
        | Some _
        | None -> None

    /// `getcpu`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetcpu<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetCpuAnswer, GetCpuRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (GetCpuRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        let state = UnixThreadTable.get thread system.Threads

        match state.Parked with
        | Some park ->
            failwith
                $"UnixScheduling.getcpu: thread %O{thread} is parked in %A{park.Syscall}, so it cannot be making the getcpu syscall (this is a bug in the client)."
        | None ->

        match Map.tryFind state.Cpu system.Scheduling.Occupants with
        | Some running when running = state.OsThreadId ->
            Ok
                {
                    Cpu = state.Cpu
                    Node = NumaNode 0
                }
        | occupant ->
            let occupied =
                match occupant with
                | Some other -> $"%O{state.Cpu} is running the thread with thread ID %O{other}"
                | None -> $"%O{state.Cpu} is idle"

            failwith
                $"UnixScheduling.getcpu: thread %O{thread} is not running on any processor (%s{occupied}), so it cannot be making the getcpu syscall. Report each thread the client runs with UnixScheduling.dispatch (this is a bug in the client)."

    /// <summary>
    /// `getcpu(2)`, made by `thread`: the processor it is running on, and that
    /// processor's NUMA node. glibc's `sched_getcpu(3)` reads the same value.
    ///
    /// Refuses under Darwin, which has no `getcpu`.
    ///
    /// Fails loudly if `thread` names no thread, is parked in a syscall, or is not
    /// running (`runningOn`): a thread making a syscall is running, so each
    /// means the client's record of what it runs disagrees with this
    /// library's, which is a bug in the client.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and only Linux has `getcpu`.</exception>
    let getcpu<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetCpuAnswer
        =
        tryGetcpu thread system
        |> Refusal.orRaise "UnixScheduling.getcpu" GetCpuRefusal.kind GetCpuRefusal.describe
