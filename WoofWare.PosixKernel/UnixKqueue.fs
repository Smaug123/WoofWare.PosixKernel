namespace WoofWare.PosixKernel

/// One Darwin `struct kevent`: an entry of the changelist `kevent(2)` reads, or
/// of the eventlist it fills, each field in Darwin's own numbering.
type Kevent =
    {
        /// `ident`: what the filter watches. For `KeventFilter.Read` and
        /// `KeventFilter.Write`, a descriptor number.
        Ident : uint64
        /// `filter`: which filter, such as `KeventFilter.Read`.
        Filter : int16
        /// `flags`: what to do with the filter, and how it reports, such as
        /// `KeventFlags.Add`.
        Flags : uint16
        /// `fflags`: flags particular to the filter.
        FilterFlags : uint32
        /// `data`: a value particular to the filter.
        Data : int64
        /// `udata`: the caller's own value, which every event the filter
        /// reports carries back verbatim.
        UserData : uint64
    }

/// Darwin's `<sys/event.h>` filter numbers.
[<RequireQualifiedAccess>]
module KeventFilter =
    /// `EVFILT_READ`.
    [<Literal>]
    let Read : int16 = -1s

    /// `EVFILT_WRITE`.
    [<Literal>]
    let Write : int16 = -2s

/// Darwin's `<sys/event.h>` flag bits, of a change in the changelist and of an
/// entry in the eventlist.
[<RequireQualifiedAccess>]
module KeventFlags =
    /// `EV_ADD`: add the filter, or change it if it is already registered.
    [<Literal>]
    let Add : uint16 = 0x0001us

    /// `EV_DELETE`: remove the filter.
    [<Literal>]
    let Delete : uint16 = 0x0002us

    /// `EV_CLEAR`: reset the filter's state once its event has been taken.
    [<Literal>]
    let Clear : uint16 = 0x0020us

    /// `EV_RECEIPT`: report the outcome of the change in the eventlist, rather
    /// than failing the call.
    [<Literal>]
    let Receipt : uint16 = 0x0040us

    /// `EV_ERROR`: in an entry `kevent` writes, the entry echoes a change, and
    /// `data` holds its outcome (0, or an errno).
    [<Literal>]
    let Error : uint16 = 0x4000us

    /// `EV_EOF`: in an event `kevent` reports, the descriptor can receive no
    /// more (or, for `EVFILT_WRITE`, send no more).
    [<Literal>]
    let Eof : uint16 = 0x8000us

/// The `timeout` argument of `kevent(2)`, as the kernel's copy-in finds it.
///
/// The caller classifies it, because only the caller knows what its memory
/// holds.
[<RequireQualifiedAccess>]
type KeventTimeout =
    /// A null pointer: the call waits for as long as it takes.
    | Null
    /// The pointer names a readable `struct timespec` holding these.
    | Readable of seconds : int64 * nanoseconds : int64
    /// The pointer is not null, and names no readable `struct timespec`.
    | Unreadable

/// Why this kernel will not answer a `kqueue(2)`.
[<RequireQualifiedAccess>]
type internal KqueueRefusal =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// This kernel is not Darwin-flavoured, and only Darwin has kqueue.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal KqueueRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which of its entry points asked.
    let describe (refusal : KqueueRefusal) : string =
        match refusal with
        | KqueueRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | KqueueRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and kqueue exists on Darwin only."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : KqueueRefusal) : RefusalKind =
        match refusal with
        | KqueueRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | KqueueRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform

/// What became of a `kevent(2)` this kernel could answer.
[<RequireQualifiedAccess>]
type KeventOutcome =
    /// `kevent` failed with this errno.
    ///
    /// Any change the call applied before it failed stays applied, with the
    /// system this rides with. A finishing call fails with `EBADF` when a close
    /// has drained the kqueue (see `UnixDescriptor.close`).
    | Failed of error : UnixError
    /// `kevent` returned these entries of its changelist, in changelist order:
    /// each change made with `EV_RECEIPT`, or that failed, while the eventlist
    /// had room. Each is the change as given, with `KeventFlags.Error` added to
    /// its flags and `data` its outcome: 0, or the raw Darwin errno it failed
    /// with.
    ///
    /// A call that returns any such entry reports no events and does not wait,
    /// whatever is queued and whatever its timeout.
    | Echoed of changes : Kevent list
    /// `kevent` failed with this errno, having first written these entries of
    /// its changelist into the eventlist, as `Echoed` describes them. The call
    /// returned -1, so only the eventlist's memory shows them.
    ///
    /// Any change the call applied before it failed stays applied, with the
    /// system this rides with.
    | FailedAfterEchoing of error : UnixError * changes : Kevent list
    /// `kevent` returned these events, in the order it reports them.
    ///
    /// Empty for a wait that timed out, for a timeout of zero with nothing to
    /// report, and for an `nevents` of zero or less.
    | Answered of events : Kevent list
    /// `kevent` did not return. The calling thread is parked, and sleeps until
    /// `UnixWait.satisfied` of the thread is non-empty and
    /// `UnixWait.wake` wakes it; then `UnixKqueue.finishKevent` finishes the
    /// call.
    | WouldBlock of WakeCondition
    /// The call was asleep, and a signal interrupted it. The thread is no
    /// longer parked, and owes a return to user mode
    /// (`UnixSignal.onReturnToUser`), which it makes before any other call:
    /// that return says whether the call fails with `EINTR` or restarts.
    ///
    /// Only `UnixKqueue.finishKevent` answers this.
    | Interrupted

/// Why this kernel will not answer a `kevent(2)`.
[<RequireQualifiedAccess>]
type internal KeventRefusal =
    /// This kernel is not Darwin-flavoured, and only Darwin has kqueue.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// The changelist holds this change, whose flags are not one of the
    /// combinations this library applies: `EV_ADD`, optionally with
    /// `EV_CLEAR` and `EV_RECEIPT`, or `EV_DELETE`, optionally with
    /// `EV_RECEIPT`.
    | UnmodelledFlags of change : Kevent
    /// The changelist holds this change, whose filter is neither `EVFILT_READ`
    /// nor `EVFILT_WRITE`.
    | UnmodelledFilter of change : Kevent
    /// The changelist holds this change, whose `fflags` or `data` is not zero.
    /// What a filter makes of its parameters (`NOTE_LOWAT`, for instance) is
    /// not modelled.
    | UnmodelledFilterParameters of change : Kevent
    /// The changelist holds this `EV_ADD`, whose descriptor names something
    /// other than a socket. A regular file, a pipe and a kqueue register on
    /// Darwin, and what they report is not modelled.
    | UnmodelledTarget of change : Kevent * target : OpenFileTarget
    /// The changelist holds this `EV_ADD`, whose descriptor names a socket of
    /// a kind whose filters this library does not model: anything but a
    /// stream socket of `AF_INET` or `AF_INET6`.
    | UnmodelledSocket of change : Kevent * domain : SocketDomain * kind : SocketKind
    /// The eventlist reached a copy and has no address to copy to, or bytes
    /// the caller cannot produce.
    | Buffer of BufferRefusal
    /// The call has events to copy out to the eventlist, and the eventlist is
    /// unmapped, so the copy faults. What Darwin answers then for several
    /// events, and what becomes of each, is not measured. (An entry of the
    /// changelist echoed into such an eventlist is answered: `EFAULT`.)
    | UnmeasuredCopyOutFault of kqueue : OpenFileDescriptionId
    /// Nothing is reportable, and the timeout ends past the last instant the
    /// machine's monotonic clock (`UnixSystem.nanosecondsSinceBoot`, an
    /// `int64` of nanoseconds) can represent: `nanosecondsSinceBoot` plus the
    /// timeout overflows it.
    | DeadlineBeyondClock of nanosecondsSinceBoot : int64 * seconds : int64 * nanoseconds : int64
    /// The wait was asleep, and both a close had drained the kqueue and the
    /// wait's deadline had passed when it was woken. Darwin answers whichever
    /// of the two reached the sleeping thread first, which a wake that found
    /// both does not say.
    | DrainBesideDeadline of kqueue : OpenFileDescriptionId
    /// The wait was asleep, both its deadline had passed and the kqueue had an
    /// event to report when it was woken, and it has an event to report, or
    /// the kqueue has been drained, now. Darwin answers whichever of the two
    /// reached the sleeping thread first, which a wake that found both does
    /// not say.
    | EventsBesideDeadline of kqueue : OpenFileDescriptionId
    /// The wait was asleep and a signal is pending for the thread, and this
    /// library will not say how the signal ends it.
    | Interruption of SyscallInterruptionRefusal

[<RequireQualifiedAccess>]
module internal KeventRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point asked, and what it actually passed.
    let describe (refusal : KeventRefusal) : string =
        match refusal with
        | KeventRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and kevent exists on Darwin only."
        | KeventRefusal.UnmodelledFlags change ->
            $"the changelist holds %A{change}, whose flags 0x%x{change.Flags} are not EV_ADD (optionally with EV_CLEAR and EV_RECEIPT) or EV_DELETE (optionally with EV_RECEIPT), the only changes this kernel applies."
        | KeventRefusal.UnmodelledFilter change ->
            $"the changelist holds %A{change}, whose filter %d{change.Filter} is neither EVFILT_READ nor EVFILT_WRITE, the only filters this kernel models."
        | KeventRefusal.UnmodelledFilterParameters change ->
            $"the changelist holds %A{change}, whose fflags (0x%x{change.FilterFlags}) or data (%d{change.Data}) is not zero, and this kernel does not model what a filter makes of its parameters."
        | KeventRefusal.UnmodelledTarget (change, target) ->
            $"the changelist holds %A{change}, an EV_ADD on a descriptor naming %A{target}. Darwin registers a filter on a regular file, a pipe and a kqueue too, but this kernel models a filter's readiness for sockets only."
        | KeventRefusal.UnmodelledSocket (change, domain, kind) ->
            $"the changelist holds %A{change}, an EV_ADD on a %O{kind} socket in %O{domain}. This kernel models a filter's readiness for IPv4 and IPv6 stream sockets only: what activates a datagram socket's filters is not modelled, and a Unix-domain socket's are not measured."
        | KeventRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | KeventRefusal.UnmeasuredCopyOutFault kqueue ->
            $"kevent on kqueue %O{kqueue} has events to copy out, and the eventlist is unmapped, so the copy faults. What Darwin answers then, and what becomes of each event it would have copied, is not measured."
        | KeventRefusal.DeadlineBeyondClock (now, seconds, nanoseconds) ->
            $"the machine has been up for %d{now} ns and the timeout is %d{seconds} s and %d{nanoseconds} ns, which ends past the last nanosecond the monotonic clock can represent."
        | KeventRefusal.DrainBesideDeadline kqueue ->
            $"a thread asleep in kevent on kqueue %O{kqueue} was woken with the kqueue both drained by a close (EBADF) and past its deadline (0 events). Darwin answers whichever of the two reached the sleeping thread first, which the wake does not say."
        | KeventRefusal.EventsBesideDeadline kqueue ->
            $"a thread asleep in kevent on kqueue %O{kqueue} was woken both past its deadline (0 events) and with an event to report, and has something other than 0 events to answer now. Darwin answers whichever of the two reached the sleeping thread first, which the wake does not say."
        | KeventRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : KeventRefusal) : RefusalKind =
        match refusal with
        | KeventRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | KeventRefusal.UnmodelledFlags _ -> RefusalKind.Unmodelled
        | KeventRefusal.UnmodelledFilter _ -> RefusalKind.Unmodelled
        | KeventRefusal.UnmodelledFilterParameters _ -> RefusalKind.Unmodelled
        | KeventRefusal.UnmodelledTarget _ -> RefusalKind.Unmodelled
        | KeventRefusal.UnmodelledSocket _ -> RefusalKind.Unmodelled
        | KeventRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | KeventRefusal.UnmeasuredCopyOutFault _ -> RefusalKind.Unmodelled
        | KeventRefusal.DeadlineBeyondClock _ -> RefusalKind.Unmodelled
        | KeventRefusal.DrainBesideDeadline _ -> RefusalKind.Unmodelled
        | KeventRefusal.EventsBesideDeadline _ -> RefusalKind.Unmodelled
        | KeventRefusal.Interruption inner -> SyscallInterruptionRefusal.kind inner

/// Darwin's kqueue: `kqueue(2)`, and `kevent(2)`.
[<RequireQualifiedAccess>]
module UnixKqueue =

    /// `tryKqueue` once `Entry` has admitted its caller.
    let private tryKqueueIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : Result<int * ProcessView<'Thread, 'Handler>, KqueueRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux -> Error (KqueueRefusal.UnmodelledFlavour SimulatedUnixFlavour.Linux)
        | SimulatedUnixFlavour.Darwin ->

        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal -> Error (KqueueRefusal.DescriptorLimit refusal)
        | Ok () ->

        // Measured on 27.0.0 (`kqueue-kevent.c`, section A): the lowest free
        // descriptor, O_RDWR, not O_NONBLOCK; and (`fcntl-dup.c`, KIND rows)
        // F_GETFD reports FD_CLOEXEC|FD_CLOFORK.
        let fd, registry =
            FileDescriptorRegistry.createKqueue
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                system.Process.ProcessId
                (UnixSystemState.fileDescriptors system)
            |> fun (fd, registry) ->
                fd,
                FileDescriptorRegistry.setFlags
                    fd
                    (DescriptorFlags.Darwin (closeOnExec = true, closeOnFork = true))
                    registry

        Ok (fd, UnixSystemState.withFileDescriptors registry system)

    /// `kqueue`, with a refusal answered as the `Error` rather than raised.
    let internal tryKqueue<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<int * UnixSystem<'Thread, 'Handler>, KqueueRefusal>
        =
        Entry.call
            "UnixKqueue.kqueue"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            tryKqueueIn
            system

    /// <summary>
    /// `kqueue(2)`: create a kqueue, owned by the calling process, and a
    /// descriptor onto it, the lowest one not in use. The description is
    /// blocking, and the descriptor has `FD_CLOEXEC` and `FD_CLOFORK`.
    ///
    /// Under the Linux flavour every call is refused: Linux has no kqueue.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has kqueue.</exception>
    let kqueue<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : int * UnixSystem<'Thread, 'Handler>
        =
        tryKqueue caller system
        |> Refusal.orRaise "UnixKqueue.kqueue" KqueueRefusal.kind KqueueRefusal.describe

    /// Whether a close has drained the kqueue `kqueue`: the same question the
    /// wake condition of a waiter on it asks.
    let private drained<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (kqueue : OpenFileDescriptionId)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        WakeCondition.satisfied thread (WakeCondition.Primitive (WakePrimitive.KqueueDrained kqueue)) system
        |> Set.isEmpty
        |> not

    let private kqueueState<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (kqueue : OpenFileDescriptionId)
        (system : ProcessView<'Thread, 'Handler>)
        : KqueueState
        =
        match OpenFileTable.tryFind kqueue system.Machine.OpenFiles with
        | Some {
                   Target = OpenFileTarget.Kqueue state
               } -> state
        | other ->
            failwith
                $"UnixKqueue: %O{kqueue} names %A{other} rather than a live kqueue, where the call resolved it as one (this is a bug in this library)."

    let private filterNumber (filter : KqueueFilter) : int16 =
        match filter with
        | KqueueFilter.Read -> KeventFilter.Read
        | KqueueFilter.Write -> KeventFilter.Write
        // `EVFILT_TIMER`, in Darwin's `<sys/event.h>`.
        | KqueueFilter.Timer -> -7s

    /// The event `report` is, in Darwin's numbering.
    let private eventOf (platform : SimulatedUnixPlatform) (report : KqueueReport) : Kevent =
        let registration = report.Registration

        // Measured on 27.0.0 (`kevent-register.c`): an event carries the
        // registration's flags as its first EV_ADD gave them (D3, D4, X7), and
        // EV_EOF with the pending error in `fflags` (P3).
        let flags =
            KeventFlags.Add
            ||| (if registration.Clear then KeventFlags.Clear else 0us)
            ||| (if registration.Receipt then KeventFlags.Receipt else 0us)

        let flags, filterFlags, data =
            match report.Report with
            | KqueueFilterReport.Ready data -> flags, 0u, data
            | KqueueFilterReport.EndOfFile (data, error) ->
                let filterFlags =
                    match error with
                    | None -> 0u
                    | Some error ->
                        uint32 (UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) error)

                flags ||| KeventFlags.Eof, filterFlags, data

        {
            Ident = uint64 report.Fd
            Filter = filterNumber report.Filter
            Flags = flags
            FilterFlags = filterFlags
            Data = data
            UserData = registration.UserData
        }

    /// Whether `count` entries or events can be copied out to `eventlist`: a
    /// call that copies nothing never looks at it.
    let private copyOut
        (kqueue : OpenFileDescriptionId)
        (eventlist : UserBuffer)
        (count : int)
        : Result<unit, KeventRefusal>
        =
        if count = 0 then
            Ok ()
        else
            match eventlist with
            | UserBuffer.Mapped -> Ok ()
            | UserBuffer.Unmapped _ -> Error (KeventRefusal.UnmeasuredCopyOutFault kqueue)
            | UserBuffer.Opaque -> Error (KeventRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
            | UserBuffer.Addressless -> Error (KeventRefusal.Buffer BufferRefusal.AddresslessAtTransfer)

    /// Apply one readable change to the kqueue `kqueue`: `None` when it
    /// succeeded, or the errno it failed with, and the system it left.
    let private applyChange<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (kqueue : OpenFileDescriptionId)
        (change : Kevent)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<UnixError option * ProcessView<'Thread, 'Handler>, KeventRefusal>
        =
        let add = KeventFlags.Add
        let delete = KeventFlags.Delete

        let adds =
            [
                add
                add ||| KeventFlags.Clear
                add ||| KeventFlags.Receipt
                add ||| KeventFlags.Clear ||| KeventFlags.Receipt
            ]

        let deletes = [ delete ; delete ||| KeventFlags.Receipt ]

        let filter =
            match change.Filter with
            | KeventFilter.Read -> Some KqueueFilter.Read
            | KeventFilter.Write -> Some KqueueFilter.Write
            | _ -> None

        if not (List.contains change.Flags adds || List.contains change.Flags deletes) then
            Error (KeventRefusal.UnmodelledFlags change)
        else

        match filter with
        | None -> Error (KeventRefusal.UnmodelledFilter change)
        | Some filter ->

        if change.FilterFlags <> 0u || change.Data <> 0L then
            Error (KeventRefusal.UnmodelledFilterParameters change)
        else

        let state = kqueueState kqueue system

        if List.contains change.Flags deletes then
            // Measured on 27.0.0 (`kevent-register.c`, R4, R10, X2, X3):
            // deleting what is not registered is ENOENT whatever the ident
            // names, a closed descriptor and every non-socket included. Only a
            // descriptor number is ever registered, so a larger ident names
            // nothing.
            let key =
                if change.Ident <= uint64 System.Int32.MaxValue then
                    Some (int change.Ident, filter)
                else
                    None

            match key with
            | Some key when Map.containsKey key state.Registrations ->
                Ok (None, UnixSystemState.mapOpenFiles (OpenFileTable.unregisterFromKqueue kqueue key) system)
            | Some _
            | None -> Ok (Some UnixError.ENOENT, system)
        else

        // Measured on 27.0.0 (`kevent-register.c`, X2, over six high halves by
        // five low halves): EV_ADD reads the ident's low 32 bits as a
        // descriptor, and one that is not open (a negative one included) is
        // EBADF; an open one with any high bit set is EINVAL.
        let fd = int (uint32 (change.Ident &&& 0xFFFF_FFFFUL))

        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (Some UnixError.EBADF, system)
        | Some (OpenFileTarget.Socket socketId) ->
            let socket = UnixMachineState.socket socketId system.Machine

            if not (DarwinReadiness.modelsSocket socket) then
                Error (KeventRefusal.UnmodelledSocket (change, socket.Domain, socket.Kind))
            elif change.Ident >>> 32 <> 0UL then
                Ok (Some UnixError.EINVAL, system)
            else

            let key = fd, filter

            // Measured on 27.0.0 (`kevent-register.c`, D1 to D8, X7): an ADD of
            // a pair already registered keeps its flags and replaces its udata;
            // either way the registration is activated if its filter is ready.
            let registration, system =
                match Map.tryFind key state.Registrations with
                | Some registration ->
                    { registration with
                        UserData = change.UserData
                    },
                    system
                | None ->
                    let ordinal = system.Machine.NextEventRegistrationOrdinal

                    let registration =
                        {
                            Clear = change.Flags &&& KeventFlags.Clear <> 0us
                            Receipt = change.Flags &&& KeventFlags.Receipt <> 0us
                            UserData = change.UserData
                            RegisteredAt = ordinal
                            Socket = socketId
                        }

                    registration,
                    { system with
                        Machine =
                            { system.Machine with
                                NextEventRegistrationOrdinal = ordinal + 1L
                            }
                    }

            Ok (
                None,
                UnixSystemState.mapOpenFiles (OpenFileTable.registerInKqueue kqueue key registration) system
                |> KqueueQueue.activateRegistration kqueue key
            )
        | Some target -> Error (KeventRefusal.UnmodelledTarget (change, target))

    /// The outcome of the changelist: the entries it echoes, or the errno that
    /// ended the call and the entries echoed before it; and the system its
    /// applied changes left.
    [<RequireQualifiedAccess>]
    type private ChangelistOutcome<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
        | Applied of echoed : Kevent list * system : ProcessView<'Thread, 'Handler>
        | Failed of error : UnixError * echoed : Kevent list * system : ProcessView<'Thread, 'Handler>

    /// Apply the readable `changes` of a changelist of `nchanges` entries in
    /// order, with room for `room` entries in `eventlist`.
    let private applyChangelist<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (kqueue : OpenFileDescriptionId)
        (nchanges : int)
        (changes : Kevent list)
        (room : int)
        (eventlist : UserBuffer)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ChangelistOutcome<'Thread, 'Handler>, KeventRefusal>
        =
        let numbering = SimulatedUnixPlatform.rawErrnoNumbering system.Machine.UnixPlatform

        // Measured on 27.0.0 (`kevent-register.c`, sections R, X and Y): a
        // change with EV_RECEIPT, or one that fails, is echoed while there is
        // room; with no room a receipt is dropped and its change still applies,
        // and a failure ends the call, the changes after it unapplied and the
        // entries echoed before it left in the eventlist (Y4). An echo into an
        // eventlist that cannot be written ends the call with EFAULT, its change
        // applied (Y5).
        let rec apply
            (echoed : Kevent list)
            (room : int)
            (system : ProcessView<'Thread, 'Handler>)
            (remaining : Kevent list)
            : Result<ChangelistOutcome<'Thread, 'Handler>, KeventRefusal>
            =
            match remaining with
            | [] -> Ok (ChangelistOutcome.Applied (List.rev echoed, system))
            | change :: rest ->

            match applyChange kqueue change system with
            | Error refusal -> Error refusal
            | Ok (failure, system) ->

            let echoes = failure.IsSome || change.Flags &&& KeventFlags.Receipt <> 0us

            if not echoes then
                apply echoed room system rest
            elif room > 0 then
                match eventlist with
                | UserBuffer.Opaque -> Error (KeventRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
                | UserBuffer.Addressless -> Error (KeventRefusal.Buffer BufferRefusal.AddresslessAtTransfer)
                | UserBuffer.Unmapped _ -> Ok (ChangelistOutcome.Failed (UnixError.EFAULT, List.rev echoed, system))
                | UserBuffer.Mapped ->
                    let entry =
                        { change with
                            Flags = change.Flags ||| KeventFlags.Error
                            Data =
                                match failure with
                                | None -> 0L
                                | Some error -> int64 (UnixError.toRawErrnoUnder numbering error)
                        }

                    apply (entry :: echoed) (room - 1) system rest
            else
                match failure with
                | Some error -> Ok (ChangelistOutcome.Failed (error, List.rev echoed, system))
                | None -> apply echoed room system rest

        match apply [] room system changes with
        // Measured (Y3): a change the copy-in cannot read ends the call with
        // EFAULT, the readable ones before it applied.
        | Ok (ChangelistOutcome.Applied (echoed, system)) when nchanges > List.length changes ->
            Ok (ChangelistOutcome.Failed (UnixError.EFAULT, echoed, system))
        | other -> other

    /// `tryKevent` once `Entry` has admitted its caller.
    let private tryKeventIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (kq : int)
        (nchanges : int)
        (changes : Kevent list)
        (nevents : int)
        (eventlist : UserBuffer)
        (timeout : KeventTimeout)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<KeventOutcome * ProcessView<'Thread, 'Handler>, KeventRefusal>
        =
        if List.length changes > max nchanges 0 then
            raise (
                Refusal.exceptionOf
                    "UnixKqueue.kevent"
                    (RefusalKind.Contradictory "changes")
                    $"%d{List.length changes} changes were passed for an nchanges of %d{nchanges}, and the copy-in reads at most nchanges and none for zero or less (this is a bug in the client)."
            )

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux -> Error (KeventRefusal.UnmodelledFlavour SimulatedUnixFlavour.Linux)
        | SimulatedUnixFlavour.Darwin ->

        // Measured on 27.0.0 (`kqueue-kevent.c`, section B, all 5040 calls):
        // the timeout first, then the descriptor, then the changelist, then
        // nevents, then the kqueue itself.
        let timeout =
            match timeout with
            | KeventTimeout.Unreadable -> Error UnixError.EFAULT
            | KeventTimeout.Readable (seconds, nanoseconds) when
                seconds < 0L
                || seconds > int64 System.Int32.MaxValue
                || nanoseconds < 0L
                || nanoseconds > UnixTimestamp.nanosecondsPerSecond
                ->
                Error UnixError.EINVAL
            | KeventTimeout.Readable (seconds, nanoseconds) -> Ok (Some (seconds, nanoseconds))
            | KeventTimeout.Null -> Ok None

        match timeout with
        | Error error -> Ok (KeventOutcome.Failed error, system)
        | Ok timeout ->

        // "Not a kqueue" is EBADF, as "not open" is.
        let kqueue =
            match FileDescriptorRegistry.tryFindWithId kq (UnixSystemState.fileDescriptors system) with
            | Some (id,
                    {
                        Target = OpenFileTarget.Kqueue _
                    }) -> Some id
            | Some _
            | None -> None

        match kqueue with
        | None -> Ok (KeventOutcome.Failed UnixError.EBADF, system)
        | Some kqueue ->

        match applyChangelist kqueue nchanges changes (max nevents 0) eventlist system with
        | Error refusal -> Error refusal
        | Ok (ChangelistOutcome.Failed (error, [], system)) -> Ok (KeventOutcome.Failed error, system)
        | Ok (ChangelistOutcome.Failed (error, echoed, system)) ->
            Ok (KeventOutcome.FailedAfterEchoing (error, echoed), system)
        | Ok (ChangelistOutcome.Applied (echoed, system)) ->

        if not (List.isEmpty echoed) then
            Ok (KeventOutcome.Echoed echoed, system)
        elif nevents <= 0 then
            Ok (KeventOutcome.Answered [], system)
        // Measured (`kevent-register.c`, Y1): a wait that reaches a drained
        // kqueue is EBADF even with an event to report.
        elif drained thread kqueue system then
            Ok (KeventOutcome.Failed UnixError.EBADF, system)
        else

        // The walk's consumption stands whether or not the call then sleeps.
        let reports, system = KqueueQueue.drain kqueue nevents system

        if not (List.isEmpty reports) then
            copyOut kqueue eventlist (List.length reports)
            |> Result.map (fun () ->
                KeventOutcome.Answered (reports |> List.map (eventOf system.Machine.UnixPlatform)), system
            )
        else

        let park (deadline : int64 option) =
            let parked =
                ParkedSyscall.Kevent
                    {
                        Kqueue = kqueue
                        Fd = kq
                        MaxEvents = nevents
                        Buffer = eventlist
                        Deadline = deadline
                    }

            Ok (KeventOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked system)

        match timeout with
        | None -> park None
        | Some (0L, 0L) -> Ok (KeventOutcome.Answered [], system)
        | Some (seconds, nanoseconds) ->

        // Within `int64`: the screen above bounds `seconds` by INT32_MAX.
        let duration = seconds * UnixTimestamp.nanosecondsPerSecond + nanoseconds
        let now = system.Scheduling.NanosecondsSinceBoot

        if now > System.Int64.MaxValue - duration then
            Error (KeventRefusal.DeadlineBeyondClock (now, seconds, nanoseconds))
        else
            park (Some (now + duration))

    /// `kevent`, with a refusal answered as the `Error` rather than raised.
    let internal tryKevent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (kq : int)
        (nchanges : int)
        (changes : Kevent list)
        (nevents : int)
        (eventlist : UserBuffer)
        (timeout : KeventTimeout)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<KeventOutcome * UnixSystem<'Thread, 'Handler>, KeventRefusal>
        =
        Entry.call
            "UnixKqueue.kevent"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryKeventIn (Caller.thread caller) kq nchanges changes nevents eventlist timeout)
            system

    /// <summary>
    /// `kevent(2)`, made by `caller` through the descriptor `kq`, with a
    /// changelist of `nchanges` entries and room for `nevents` events in
    /// `eventlist`.
    ///
    /// `changes` is what the copy-in finds at the changelist, from its start:
    /// every one of the `nchanges` entries when all are readable, and fewer
    /// when one is not, the next entry being the first that cannot be read.
    /// It is never longer than `nchanges`, and is empty when `nchanges` is zero
    /// or less, since then no entry is read.
    ///
    /// The argument checks come first, in Darwin's order: `EFAULT` for an
    /// unreadable timeout and `EINVAL` for a timeout whose `tv_sec` is below 0
    /// or above `INT32_MAX`, or whose `tv_nsec` is below 0 or above
    /// 1000000000; then `EBADF` for a descriptor that is not open or is not a
    /// kqueue. Such a failure changes nothing.
    ///
    /// Then the changes are applied in order. `EV_ADD` registers a filter on
    /// the socket the change's descriptor names, or, of a pair already
    /// registered, replaces its `udata`; `EV_DELETE` removes one. A change with
    /// `EV_RECEIPT`, or one that fails, is echoed into the eventlist while it
    /// has room (`KeventOutcome.Echoed`); a failure with no room left ends the
    /// call with its errno, a change the copy-in could not read with `EFAULT`,
    /// and an echo into an `Unmapped` eventlist with `EFAULT` too, and either
    /// way the changes before it stay applied and the entries echoed before it
    /// stay written (`KeventOutcome.FailedAfterEchoing`). A call that echoes
    /// anything returns at once with no events.
    ///
    /// Otherwise an `nevents` of zero or less returns no events at once; a
    /// kqueue a close has drained (see `UnixDescriptor.close`) fails with
    /// `EBADF`; and otherwise the call reports up to `nevents` events. It walks
    /// the kqueue's queue in order, reading each registration's filter again:
    /// one no longer ready leaves the queue and reports nothing, and one that
    /// reports leaves it if it was added with `EV_CLEAR` and otherwise goes
    /// back to the tail; entries the walk did not reach stay queued in order.
    /// With nothing to report, a timeout of zero returns
    /// no events at once; a positive one parks the caller's thread until an
    /// event is reportable or that much time has passed on the machine's
    /// monotonic clock, and a null one parks it until an event is reportable.
    /// A parked wait is finished with `finishKevent`.
    ///
    /// Every waiter on one kqueue is woken by an event to report and by the
    /// close that drains it, and a deadline or a signal is each waiter's own.
    ///
    /// Refused are a change this library does not apply,
    /// a copy of events to an eventlist that is not `Mapped`, and an echo into
    /// an `Opaque` or `Addressless` one.
    /// The caller's thread must not already be parked. Under the Linux flavour
    /// every call is refused: Linux has no kqueue.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">`changes` holds more changes than `nchanges`, or any for an `nchanges` of zero or less: the copy-in reads at most `nchanges`.</exception>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has kqueue.</exception>
    let kevent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (kq : int)
        (nchanges : int)
        (changes : Kevent list)
        (nevents : int)
        (eventlist : UserBuffer)
        (timeout : KeventTimeout)
        (system : UnixSystem<'Thread, 'Handler>)
        : KeventOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryKevent caller kq nchanges changes nevents eventlist timeout system
        |> Refusal.orRaise "UnixKqueue.kevent" KeventRefusal.kind KeventRefusal.describe

    let private finishKeventHolding<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<KeventOutcome * ProcessView<'Thread, 'Handler>, KeventRefusal>
        =
        let parked =
            UnixThreadTable.expectParked
                "UnixKqueue.finishKevent"
                (fun parked ->
                    match parked with
                    | ParkedSyscall.Kevent parked -> Some parked
                    | _ -> None
                )
                thread
                system.Threads

        let isDrained = drained thread parked.Kqueue system

        let deliverable = KqueueQueue.hasDeliverableEvent parked.Kqueue system

        let timedOut = WakeCondition.deadlinePassed parked.Deadline system

        let completing (outcome : KeventOutcome) (answered : ProcessView<'Thread, 'Handler>) =
            Ok (outcome, UnixParkState.unpark thread answered)

        let interrupted () =
            match SyscallInterruption.ofPark thread system with
            | Error refusal -> Error (KeventRefusal.Interruption refusal)
            | Ok (Some interruption) ->
                Ok (
                    KeventOutcome.Interrupted,
                    OwedReturns.interrupt thread interruption (UnixParkState.unpark thread system)
                )
            | Ok None ->
                failwith
                    $"UnixKqueue.finishKevent: a signal woke thread %O{thread}'s kevent, which a signal gone by its finish fails with EINTR or is refused, and SyscallInterruption.ofPark says it sleeps on (this is a bug in this library)."

        // Measured on Darwin 27.0.0 (`docs/probes/first-wake`, the events
        // rows): held off the CPU from its wake until a second wake-up had
        // come, a woken kevent answered what woke it: a drain's EBADF, 0 events
        // for its deadline, or EINTR for a signal, whatever came second. Woken
        // by an event, it reports what it finds, or EBADF if a close has since
        // drained the kqueue. A close of the kqueue waits for the waiter to
        // leave its call, so nothing comes between a drain and the waiter's
        // answer. Woken by more than one, it gives their answer where they
        // agree (a drain and an event both answer EBADF; an event with nothing
        // left to report waits again, as below), and otherwise cannot be told
        // which came first.
        let fired = SyscallInterruption.wokenBy thread system

        let byDrain =
            fired
            |> Set.exists (fun primitive ->
                match primitive with
                | WakePrimitive.KqueueDrained _ -> true
                | _ -> false
            )

        let byEvent =
            fired
            |> Set.exists (fun primitive ->
                match primitive with
                | WakePrimitive.KqueueEventDeliverable _ -> true
                | _ -> false
            )

        let byDeadline =
            fired
            |> Set.exists (fun primitive ->
                match primitive with
                | WakePrimitive.DeadlinePassed _ -> true
                | _ -> false
            )

        let bySignal = Set.contains WakePrimitive.SignalDeliverable fired

        let signalBeside =
            KeventRefusal.Interruption (SyscallInterruptionRefusal.SignalBesideCompletion SimulatedUnixFlavour.Darwin)

        match byDrain, byEvent, byDeadline, bySignal with
        | true, _, true, _ -> Error (KeventRefusal.DrainBesideDeadline parked.Kqueue)
        | true, _, false, true -> Error signalBeside
        // Measured on 27.0.0 (`kqueue-kevent.c`, section E).
        | true, _, false, false -> completing (KeventOutcome.Failed UnixError.EBADF) system
        | false, false, true, false -> completing (KeventOutcome.Answered []) system
        | false, false, false, true -> interrupted ()
        | false, false, true, true -> Error signalBeside
        | false, true, true, _ when deliverable || isDrained -> Error (KeventRefusal.EventsBesideDeadline parked.Kqueue)
        | false, true, _, true when deliverable || isDrained -> Error signalBeside
        | false, true, _, _
        | false, false, false, false ->

        if isDrained then
            completing (KeventOutcome.Failed UnixError.EBADF) system
        elif deliverable then
            let reports, answered = KqueueQueue.drain parked.Kqueue parked.MaxEvents system

            copyOut parked.Kqueue parked.Buffer (List.length reports)
            |> Result.bind (fun () ->
                completing
                    (KeventOutcome.Answered (reports |> List.map (eventOf system.Machine.UnixPlatform)))
                    answered
            )
        elif timedOut then
            // What woke it has gone, and its deadline has passed since: it
            // waits again, and whether a pending signal or the deadline then
            // ends that wait is unmeasured.
            match SyscallInterruption.beforeCompleting thread system with
            | Error refusal -> Error (KeventRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes -> completing (KeventOutcome.Answered []) system
            | Ok (SyscallInterruption.Completion.Interrupted _) -> Error signalBeside
        else

        // Measured on 27.0.0 (`kqueue-kevent.c`, section D): a caught signal
        // ends the wait with EINTR, under SA_RESTART or not, which the
        // thread's return to user mode answers (`SyscallInterruption.ruleOf`).
        match SyscallInterruption.ofPark thread system with
        | Error refusal -> Error (KeventRefusal.Interruption refusal)
        | Ok (Some interruption) ->
            Ok (
                KeventOutcome.Interrupted,
                OwedReturns.interrupt thread interruption (UnixParkState.unpark thread system)
            )
        | Ok None ->
            // Whatever woke the thread has gone again: another waiter took it, or
            // its filter is no longer ready. The thread walks the queue as a woken
            // real wait does, which reports nothing and drops each entry whose
            // filter is no longer ready, and sleeps again.
            let _, swept = KqueueQueue.drain parked.Kqueue parked.MaxEvents system
            let parkedAgain = ParkedSyscall.Kevent parked

            Ok (
                KeventOutcome.WouldBlock (WakeCondition.ofPark parkedAgain),
                Parking.parkWaiting thread parkedAgain swept
            )

    /// `tryFinishKevent` once `Entry` has admitted its caller.
    let internal tryFinishKeventIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<KeventOutcome * ProcessView<'Thread, 'Handler>, KeventRefusal>
        =
        let held =
            match UnixThreadTable.parkedFor thread system.Threads with
            | Some parked -> ParkedSyscall.descriptions parked
            | None -> []

        // A drain ends the wait while the kqueue may have no descriptor left
        // (`kqueue-kevent.c` section E1), and the call's reference to it goes
        // as it returns.
        finishKeventHolding thread system
        |> Result.map (fun (outcome, after) ->
            outcome, ObjectLifetime.releaseUnreferencedUnrefusable "UnixKqueue.finishKevent" held after
        )

    /// `finishKevent`, with a refusal answered as the `Error` rather than raised.
    let internal tryFinishKevent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<KeventOutcome * UnixSystem<'Thread, 'Handler>, KeventRefusal>
        =
        Entry.call
            "UnixKqueue.finishKevent"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFinishKeventIn (Caller.thread caller))
            system

    /// <summary>
    /// Finish the `kevent` wait `caller` is parked in, as a woken real wait does.
    ///
    /// Answers as what woke the thread (`ParkState.Woken`) says, whatever has
    /// happened since: `EBADF` for a close that drained the kqueue; no events
    /// for the deadline; `Interrupted` for a signal, which the thread's return
    /// to user mode then ends, failing the call with `EINTR` even if another
    /// thread has ignored the signal since; and for an event, the events it
    /// has to report (as `kevent` reports them), up to the call's `nevents`,
    /// or `EBADF` if a close has drained the kqueue since. Woken by an event
    /// and finding nothing to report, it answers no events if the deadline has
    /// passed, `Interrupted` if the thread would take a signal as it returned
    /// to user mode, and otherwise re-parks the thread on the same kqueue and
    /// deadline. Refused, since Darwin answers whichever reached the sleeping
    /// thread first, where the wake found two of these whose answers differ:
    /// a drain beside an expired deadline or a signal, an expired deadline
    /// beside a signal, and an event beside either while there is an event to
    /// report or the kqueue has been drained. Refused too, since they are
    /// unmeasured: a call with a timeout whose waking signal has gone, and one
    /// woken by an event, finding nothing to report past its deadline with a
    /// signal pending.
    /// An answer clears the park, and with it the call's hold on the kqueue,
    /// which goes then if no descriptor names it any more.
    ///
    /// Reporting events copies them out to the eventlist the call was made
    /// with; see `kevent` for the eventlists that refuses.
    ///
    /// `caller` must be parked in a `kevent`, and woken (`UnixWait.wake`).
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Darwin-flavoured, and only Darwin has kqueue.</exception>
    let finishKevent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : KeventOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishKevent caller system
        |> Refusal.orRaise "UnixKqueue.finishKevent" KeventRefusal.kind KeventRefusal.describe
