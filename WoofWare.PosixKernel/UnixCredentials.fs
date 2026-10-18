namespace WoofWare.PosixKernel

/// The `gid_t`s of the list a `setgroups(2)` names, as far as the caller could
/// read them.
///
/// The words are raw: `(gid_t)-1`, which no process can hold, is one of the
/// things the kernel checks them for.
[<RequireQualifiedAccess>]
type GroupListWords =
    /// Every word of the list: exactly as many as the call's size says.
    | Readable of words : uint32 list
    /// The words before the first one the caller could not read, in order,
    /// and fewer than the call's size says. The kernel faults where it reaches
    /// the next.
    ///
    /// `FaultsAfter []` is also the argument for a list the caller did not
    /// read because its size is negative or above the platform's
    /// `SimulatedUnixPlatform.supplementaryGroupLimit`: no kernel copies such a
    /// list, so what it holds never matters.
    | FaultsAfter of readable : uint32 list

/// What `getresuid(2)` or `getresgid(2)` does with the caller's three buffers.
[<RequireQualifiedAccess>]
type GetIdsAnswer<'Id> =
    /// The call writes the real, effective and saved IDs to the three buffers,
    /// in that order, and returns 0.
    | Copied of real : 'Id * effective : 'Id * saved : 'Id
    /// The call writes `written` to the buffers before the first one it could
    /// not write, in order (the real ID first), and fails with `EFAULT`.
    | Faulted of written : 'Id list

/// Why this kernel will not answer one of the C library's credential calls
/// under Linux. glibc's wrapper makes every other thread of the process repeat
/// the call by sending it signal 33 (SIGSETXID), caught with `SA_RESTART`, and
/// this kernel does not model that signal.
[<RequireQualifiedAccess>]
type internal SetxidSignalRefusal =
    /// Another thread of the process blocks signal 33. The wrapper then never
    /// returns.
    | OtherThreadBlocksSignal
    /// Another thread of the process is asleep in a call, or owes a return to
    /// user mode. The signal would end or restart the call it is asleep in, as
    /// a caught `SA_RESTART` signal does, or be taken beside the signals it
    /// takes on its return.
    | OtherThreadInKernel

[<RequireQualifiedAccess>]
module internal SetxidSignalRefusal =
    /// What this kernel knows about why it will not answer.
    let describe (refusal : SetxidSignalRefusal) : string =
        match refusal with
        | SetxidSignalRefusal.OtherThreadBlocksSignal ->
            "under Linux the C library's wrapper makes every other thread repeat the call by sending it signal 33, and another thread blocks that signal, so the wrapper never returns."
        | SetxidSignalRefusal.OtherThreadInKernel ->
            "under Linux the C library's wrapper makes every other thread repeat the call by sending it signal 33, caught with SA_RESTART, and another thread is asleep in a call or owes a return to user mode. The signal would end or restart that call, or be taken beside the signals the thread takes on its return, and this kernel does not model it."

/// Why this kernel will not answer a `setresuid(2)` or `setresgid(2)`.
[<RequireQualifiedAccess>]
type internal SetIdsRefusal =
    /// This flavour has no such call: Darwin declares neither `setresuid` nor
    /// `setresgid`.
    | NoSuchCall of flavour : SimulatedUnixFlavour
    /// The call would change the effective ID of a process that writes core
    /// dumps.
    ///
    /// Linux then makes the process dumpable or not according to the
    /// `fs.suid_dumpable` sysctl, which this kernel does not model, so whether
    /// the process still writes a core dump is unknown.
    | DumpabilityUnmodelled
    /// The C library's signal to the process's other threads would reach one
    /// this kernel cannot answer for.
    | SetxidSignal of SetxidSignalRefusal

[<RequireQualifiedAccess>]
module internal SetIdsRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which IDs.
    let describe (refusal : SetIdsRefusal) : string =
        match refusal with
        | SetIdsRefusal.NoSuchCall flavour ->
            $"%O{flavour} has no setresuid(2) or setresgid(2); its C library declares neither."
        | SetIdsRefusal.DumpabilityUnmodelled ->
            "the call changes the effective ID of a process that writes core dumps. Linux then sets the process's dumpable flag from the fs.suid_dumpable sysctl, which this kernel does not model, so whether the process would still write a core dump is unknown."
        | SetIdsRefusal.SetxidSignal refusal -> SetxidSignalRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SetIdsRefusal) : RefusalKind =
        match refusal with
        | SetIdsRefusal.NoSuchCall _ -> RefusalKind.NotOnPlatform
        | SetIdsRefusal.DumpabilityUnmodelled -> RefusalKind.Unmodelled
        | SetIdsRefusal.SetxidSignal _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer a `setgroups(2)`.
[<RequireQualifiedAccess>]
type internal SetGroupsRefusal =
    /// A privileged Darwin process asked for no groups at all, from an
    /// effective group other than 0. Darwin then holds a list of one group,
    /// measured only from effective group 0, where it is 0; whether it is 0 or
    /// the effective group from any other is unmeasured.
    | EmptyFromNonZeroEffectiveGroup of effectiveGroup : GroupId
    /// A privileged Darwin process's list holds `(gid_t)-1` at `index`.
    /// Darwin takes it as a group like any other, even as the effective
    /// group, and this kernel holds no such group ID.
    | MinusOneGroup of index : int
    /// A privileged Darwin process that writes core dumps would change its
    /// groups. Darwin may then mark the process as having changed its
    /// credentials, after which whether it dumps core turns on the
    /// `kern.sugid_coredump` sysctl; neither is measured or modelled.
    | DumpabilityUnmodelled
    /// The C library's signal to the process's other threads would reach one
    /// this kernel cannot answer for.
    | SetxidSignal of SetxidSignalRefusal

[<RequireQualifiedAccess>]
module internal SetGroupsRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which list.
    let describe (refusal : SetGroupsRefusal) : string =
        match refusal with
        | SetGroupsRefusal.EmptyFromNonZeroEffectiveGroup effectiveGroup ->
            $"the process is privileged and asks for no groups, from effective group %O{effectiveGroup}. Darwin then holds one group, which was measured only from effective group 0, where it is 0; from any other it may be 0 or the effective group."
        | SetGroupsRefusal.MinusOneGroup index ->
            $"the process is privileged and the list holds (gid_t)-1 at index %d{index}. Darwin takes it as a group like any other (as the effective group when it comes first), and this kernel holds no such group ID: it reads -1 as \"leave the ID unchanged\" everywhere else."
        | SetGroupsRefusal.DumpabilityUnmodelled ->
            "the process is privileged, writes core dumps, and would change its groups. Darwin may then mark it as having changed its credentials (P_SUGID), after which whether it dumps core turns on the kern.sugid_coredump sysctl; neither has been measured, and this kernel models neither."
        | SetGroupsRefusal.SetxidSignal refusal -> SetxidSignalRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SetGroupsRefusal) : RefusalKind =
        match refusal with
        | SetGroupsRefusal.EmptyFromNonZeroEffectiveGroup _ -> RefusalKind.Unmodelled
        | SetGroupsRefusal.MinusOneGroup _ -> RefusalKind.Unmodelled
        | SetGroupsRefusal.DumpabilityUnmodelled -> RefusalKind.Unmodelled
        | SetGroupsRefusal.SetxidSignal _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer a `getresuid(2)` or `getresgid(2)`.
[<RequireQualifiedAccess>]
type internal GetIdsRefusal =
    /// This flavour has no such call: Darwin declares neither `getresuid` nor
    /// `getresgid`.
    | NoSuchCall of flavour : SimulatedUnixFlavour
    /// A buffer has no answer at the write that reaches it.
    | Buffer of BufferRefusal

[<RequireQualifiedAccess>]
module internal GetIdsRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and what the buffers were.
    let describe (refusal : GetIdsRefusal) : string =
        match refusal with
        | GetIdsRefusal.NoSuchCall flavour ->
            $"%O{flavour} has no getresuid(2) or getresgid(2); its C library declares neither."
        | GetIdsRefusal.Buffer refusal -> BufferRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : GetIdsRefusal) : RefusalKind =
        match refusal with
        | GetIdsRefusal.NoSuchCall _ -> RefusalKind.NotOnPlatform
        | GetIdsRefusal.Buffer refusal -> BufferRefusal.kind refusal

/// The calls by which a process reads and changes who it is: `getresuid(2)`,
/// `getresgid(2)`, and the C library's `setresuid(3)`, `setresgid(3)` and
/// `setgroups(3)`.
///
/// Each change is the whole process's, every thread alike, as the C library's
/// functions make it. Linux's system calls beneath them change only the
/// calling thread, and are not modelled: glibc makes every other thread repeat
/// the call by sending it signal 33, so under Linux each of the three is
/// refused while another thread blocks that signal, is asleep in a call, or
/// owes a return to user mode.
[<RequireQualifiedAccess>]
module UnixCredentials =

    // The three IDs of a `getresuid` or `getresgid`, written one buffer at a
    // time. Measured on Linux 6.18.5 (`setresid.c`): with any one of the three
    // pointers NULL the call is EFAULT, and the IDs before it have been
    // written and those after it have not.
    let private getIds<'Id, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        ((realId, effectiveId, savedId) : 'Id * 'Id * 'Id)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetIdsAnswer<'Id>, GetIdsRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (GetIdsRefusal.NoSuchCall SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        let rec write
            (written : 'Id list)
            (remaining : (UserBuffer * 'Id) list)
            : Result<GetIdsAnswer<'Id>, GetIdsRefusal>
            =
            match remaining with
            | [] -> Ok (GetIdsAnswer.Copied (realId, effectiveId, savedId))
            | (buffer, id) :: rest ->
                // Each buffer is decided by the write that reaches it: real
                // storage takes its ID, and an unmapped address faults there.
                match buffer with
                | UserBuffer.Mapped -> write (id :: written) rest
                | UserBuffer.Unmapped _ -> Ok (GetIdsAnswer.Faulted (List.rev written))
                | UserBuffer.Opaque -> Error (GetIdsRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
                | UserBuffer.Addressless -> Error (GetIdsRefusal.Buffer BufferRefusal.AddresslessAtTransfer)

        write [] [ real, realId ; effective, effectiveId ; saved, savedId ]

    /// `tryGetresuid` once `Entry` has admitted its caller.
    let private tryGetresuidIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetIdsAnswer<UserId>, GetIdsRefusal>
        =
        let credentials = system.Process.Credentials

        getIds real effective saved (credentials.RealUser, credentials.EffectiveUser, credentials.SavedUser) system

    /// `getresuid`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetresuid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetIdsAnswer<UserId>, GetIdsRefusal>
        =
        Entry.call
            "UnixCredentials.getresuid"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryGetresuidIn real effective saved)
            system

    /// <summary>
    /// `getresuid(2)`: the process's real, effective and saved user IDs, into
    /// three buffers.
    ///
    /// Changes nothing, so it returns no system. Refused on Darwin, which has
    /// no such call.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This flavour has no such call: Darwin declares neither `getresuid` nor `getresgid`.</exception>
    let getresuid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetIdsAnswer<UserId>
        =
        tryGetresuid caller real effective saved system
        |> Refusal.orRaise "UnixCredentials.getresuid" GetIdsRefusal.kind GetIdsRefusal.describe

    /// `tryGetresgid` once `Entry` has admitted its caller.
    let private tryGetresgidIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetIdsAnswer<GroupId>, GetIdsRefusal>
        =
        let credentials = system.Process.Credentials

        getIds real effective saved (credentials.RealGroup, credentials.EffectiveGroup, credentials.SavedGroup) system

    /// `getresgid`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetresgid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetIdsAnswer<GroupId>, GetIdsRefusal>
        =
        Entry.call
            "UnixCredentials.getresgid"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryGetresgidIn real effective saved)
            system

    /// <summary>
    /// `getresgid(2)`: the process's real, effective and saved group IDs, into
    /// three buffers.
    ///
    /// Changes nothing, so it returns no system. Refused on Darwin, which has
    /// no such call.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This flavour has no such call: Darwin declares neither `getresuid` nor `getresgid`.</exception>
    let getresgid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserBuffer)
        (effective : UserBuffer)
        (saved : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetIdsAnswer<GroupId>
        =
        tryGetresgid caller real effective saved system
        |> Refusal.orRaise "UnixCredentials.getresgid" GetIdsRefusal.kind GetIdsRefusal.describe

    // Measured on Linux 6.18.5 with glibc 2.41 (`docs/probes/setxid-threads`):
    // glibc's wrapper sends every other thread signal 33, whose SA_RESTART
    // handler makes the same system call there, before it makes its own, so
    // even a call that then fails reaches them. A thread asleep in a call had
    // the call ended or restarted as a caught SA_RESTART signal ends or
    // restarts it, in every one of 20 trials of each call measured, and with a
    // thread blocking the signal the wrapper never returned. A thread owing a
    // return would take the signal beside the ones it takes there. Darwin's
    // calls change the process, and end no other thread's call.
    let private checkSetxidSignal<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<unit, SetxidSignalRefusal>
        =
        let others = system.Threads |> Map.remove caller

        let blocksSignal =
            others
            |> Map.exists (fun thread _ ->
                SignalMask.contains (Signal.RealTime 1) (SignalState.maskOf thread system.Process.Signals)
            )

        let inKernel =
            others
            |> Map.exists (fun _ state -> Option.isSome state.Parked || Option.isSome state.Owes)

        if blocksSignal then
            Error SetxidSignalRefusal.OtherThreadBlocksSignal
        elif inKernel then
            Error SetxidSignalRefusal.OtherThreadInKernel
        else
            Ok ()

    // Linux's rule for `setresuid` and `setresgid`, which differ only in which
    // triple they replace: a privileged process may set each ID to anything,
    // and any other process only to one of the three it already holds. On
    // success, `-1` keeps an ID and every other request replaces it.
    //
    // Measured on Linux 6.18.5 (`setresid.c`), as the whole product of every
    // starting triple over {0, 1000, 1001} and every requested triple over
    // {-1, 0, 1000, 1001, 1002}, from three starting user triples for the
    // groups. "Privileged" is an effective user ID of 0, for the group IDs as
    // for the user IDs (`Credentials.privilege`): an effective group of 0
    // grants nothing, nor does a real or saved user ID of 0, and a process
    // holding a supplementary group may not take it as a real, effective or
    // saved group. In every row the filesystem uid and gid, which this model
    // does not keep apart, followed the effective ones.
    let private replaceIds<'Id when 'Id : equality>
        (privilege : CallerPrivilege)
        ((real, effective, saved) : 'Id * 'Id * 'Id)
        ((askedReal, askedEffective, askedSaved) : 'Id option * 'Id option * 'Id option)
        : ('Id * 'Id * 'Id) option
        =
        let held = [ real ; effective ; saved ]

        let permitted (asked : 'Id option) : bool =
            match privilege, asked with
            | _, None
            | CallerPrivilege.Privileged, Some _ -> true
            | CallerPrivilege.Unprivileged, Some id -> List.contains id held

        if permitted askedReal && permitted askedEffective && permitted askedSaved then
            Some (
                Option.defaultValue real askedReal,
                Option.defaultValue effective askedEffective,
                Option.defaultValue saved askedSaved
            )
        else
            None

    // What a successful change of IDs does to whether the process dumps core.
    //
    // Measured on Linux 6.18.5 (`setresid.c`): the process's dumpable flag
    // was cleared by exactly those successful calls that changed its effective
    // user or group ID, with `fs.suid_dumpable` at its default of 0. Linux sets
    // the flag from that sysctl, which this kernel does not model, so a process
    // that writes core dumps is refused. One that writes none goes on writing
    // none whatever the sysctl says: `CoreDumps.Suppressed` is a suppression
    // the dumpable flag does not decide (the process started dumpable, and a
    // flag set again by a later change cannot lift an `RLIMIT_CORE` of 0).
    let private keepCoreDumps<'Id, 'Thread, 'Handler
        when 'Id : equality and 'Thread : comparison and 'Handler : equality>
        (effectiveBefore : 'Id)
        (effectiveAfter : 'Id)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<unit, SetIdsRefusal>
        =
        match system.Process.CoreDumps with
        | CoreDumps.Written when effectiveBefore <> effectiveAfter -> Error SetIdsRefusal.DumpabilityUnmodelled
        | CoreDumps.Written
        | CoreDumps.Suppressed -> Ok ()

    /// `trySetresuid` once `Entry` has admitted its caller.
    let private trySetresuidIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : 'Thread)
        (real : UserId option)
        (effective : UserId option)
        (saved : UserId option)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, SetIdsRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (SetIdsRefusal.NoSuchCall SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        match checkSetxidSignal caller system with
        | Error refusal -> Error (SetIdsRefusal.SetxidSignal refusal)
        | Ok () ->

        let credentials = system.Process.Credentials

        match
            replaceIds
                (Credentials.privilege credentials)
                (credentials.RealUser, credentials.EffectiveUser, credentials.SavedUser)
                (real, effective, saved)
        with
        | None -> Ok (SyscallAnswer.Failed UnixError.EPERM, system)
        | Some (real, effective, saved) ->

        keepCoreDumps credentials.EffectiveUser effective system
        |> Result.map (fun () ->
            SyscallAnswer.Completed 0L,
            { system with
                Process =
                    { system.Process with
                        Credentials =
                            { credentials with
                                RealUser = real
                                EffectiveUser = effective
                                SavedUser = saved
                            }
                    }
            }
        )

    /// `setresuid`, with a refusal answered as the `Error` rather than raised.
    let internal trySetresuid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserId option)
        (effective : UserId option)
        (saved : UserId option)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SetIdsRefusal>
        =
        Entry.call
            "UnixCredentials.setresuid"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (trySetresuidIn (Caller.thread caller) real effective saved)
            system

    /// <summary>
    /// `setresuid(3)`: set the process's real, effective and saved user IDs,
    /// for every thread. `None` leaves an ID as it is.
    ///
    /// A privileged process may set them to anything. Any other process may
    /// only set each to one of the three it already holds, and is otherwise
    /// answered `EPERM` with nothing changed.
    ///
    /// Refused on Darwin, which has no such call; under Linux while another
    /// thread blocks signal 33, is asleep in a call, or owes a return to user
    /// mode, since the C library reaches every other thread with that signal;
    /// and for a process that writes core dumps when its effective user ID
    /// would change: whether it still writes one turns on `fs.suid_dumpable`,
    /// which this kernel does not model.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This flavour has no such call: Darwin declares neither `setresuid` nor `setresgid`.</exception>
    let setresuid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : UserId option)
        (effective : UserId option)
        (saved : UserId option)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySetresuid caller real effective saved system
        |> Refusal.orRaise "UnixCredentials.setresuid" SetIdsRefusal.kind SetIdsRefusal.describe

    /// `trySetresgid` once `Entry` has admitted its caller.
    let private trySetresgidIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : 'Thread)
        (real : GroupId option)
        (effective : GroupId option)
        (saved : GroupId option)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, SetIdsRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (SetIdsRefusal.NoSuchCall SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        match checkSetxidSignal caller system with
        | Error refusal -> Error (SetIdsRefusal.SetxidSignal refusal)
        | Ok () ->

        let credentials = system.Process.Credentials

        match
            replaceIds
                (Credentials.privilege credentials)
                (credentials.RealGroup, credentials.EffectiveGroup, credentials.SavedGroup)
                (real, effective, saved)
        with
        | None -> Ok (SyscallAnswer.Failed UnixError.EPERM, system)
        | Some (real, effective, saved) ->

        keepCoreDumps credentials.EffectiveGroup effective system
        |> Result.map (fun () ->
            SyscallAnswer.Completed 0L,
            { system with
                Process =
                    { system.Process with
                        Credentials =
                            { credentials with
                                RealGroup = real
                                EffectiveGroup = effective
                                SavedGroup = saved
                            }
                    }
            }
        )

    /// `setresgid`, with a refusal answered as the `Error` rather than raised.
    let internal trySetresgid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : GroupId option)
        (effective : GroupId option)
        (saved : GroupId option)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SetIdsRefusal>
        =
        Entry.call
            "UnixCredentials.setresgid"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (trySetresgidIn (Caller.thread caller) real effective saved)
            system

    /// <summary>
    /// `setresgid(3)`: set the process's real, effective and saved group IDs,
    /// for every thread. `None` leaves an ID as it is.
    ///
    /// A privileged process may set them to anything. Any other process may
    /// only set each to one of the three it already holds (its supplementary
    /// groups do not count), and is otherwise answered `EPERM` with nothing
    /// changed. Privilege is the effective *user* ID's, as everywhere else.
    ///
    /// Refused on Darwin, which has no such call; under Linux while another
    /// thread blocks signal 33, is asleep in a call, or owes a return to user
    /// mode, since the C library reaches every other thread with that signal;
    /// and for a process that writes core dumps when its effective group ID
    /// would change: whether it still writes one turns on `fs.suid_dumpable`,
    /// which this kernel does not model.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This flavour has no such call: Darwin declares neither `setresuid` nor `setresgid`.</exception>
    let setresgid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (real : GroupId option)
        (effective : GroupId option)
        (saved : GroupId option)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySetresgid caller real effective saved system
        |> Refusal.orRaise "UnixCredentials.setresgid" SetIdsRefusal.kind SetIdsRefusal.describe

    // Asserted wherever a kernel copies the list: a caller that read the
    // wrong number of words would otherwise be answered about a list it
    // did not pass.
    let private assertWordsAgree (size : int) (words : GroupListWords) : unit =
        match words with
        | GroupListWords.Readable words when List.length words <> size ->
            raise (
                Refusal.exceptionOf
                    "UnixCredentials.setgroups"
                    (RefusalKind.Contradictory "words")
                    $"the list is %d{size} groups long, but the caller read %d{List.length words} words of it; GroupListWords.Readable holds every word of the list."
            )
        | GroupListWords.FaultsAfter readable when List.length readable >= size ->
            raise (
                Refusal.exceptionOf
                    "UnixCredentials.setgroups"
                    (RefusalKind.Contradictory "words")
                    $"the list is %d{size} groups long, and the caller read %d{List.length readable} words of it before the fault; GroupListWords.FaultsAfter holds fewer words than the list has."
            )
        | GroupListWords.Readable _
        | GroupListWords.FaultsAfter _ -> ()

    // Linux reads the list one word at a time, and refuses `(gid_t)-1` as it
    // reaches it: measured, a list whose first two words are readable and
    // whose second is -1 is EINVAL, and one whose first two are readable
    // groups is EFAULT. An empty list is never read, so no buffer faults then.
    let private readGroupsLinux (size : int) (words : GroupListWords) : Result<GroupId list, UnixError> =
        if size = 0 then
            Ok []
        else

        assertWordsAgree size words

        let rec parse (parsed : GroupId list) (remaining : uint32 list) : Result<GroupId list, UnixError> =
            match remaining with
            | [] -> Ok (List.rev parsed)
            | word :: rest ->
                match GroupId.parse word with
                | Some group -> parse (group :: parsed) rest
                | None -> Error UnixError.EINVAL

        match words with
        | GroupListWords.Readable words -> parse [] words
        | GroupListWords.FaultsAfter readable -> parse [] readable |> Result.bind (fun _ -> Error UnixError.EFAULT)

    /// `trySetgroups` once `Entry` has admitted its caller.
    let private trySetgroupsIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : 'Thread)
        (size : int)
        (words : GroupListWords)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, SetGroupsRefusal>
        =
        let platform = system.Machine.UnixPlatform
        let limit = SimulatedUnixPlatform.supplementaryGroupLimit platform
        let privilege = UnixProcessState.callerPrivilege system.Process
        let sizeAdmitted = size >= 0 && size <= limit

        let installed (groups : GroupId list) =
            SyscallAnswer.Completed 0L,
            { system with
                Process =
                    { system.Process with
                        Credentials =
                            { system.Process.Credentials with
                                SupplementaryGroups = groups
                            }
                    }
            }

        // Darwin's list, whose first group is the effective group. A process
        // that writes no core dumps goes on writing none: no credential flag
        // lifts the suppression.
        let installedOnDarwin
            (effective : GroupId)
            (rest : GroupId list)
            : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, SetGroupsRefusal>
            =
            match system.Process.CoreDumps with
            | CoreDumps.Written -> Error SetGroupsRefusal.DumpabilityUnmodelled
            | CoreDumps.Suppressed ->

            Ok (
                SyscallAnswer.Completed 0L,
                { system with
                    Process =
                        { system.Process with
                            Credentials =
                                { system.Process.Credentials with
                                    EffectiveGroup = effective
                                    SupplementaryGroups = rest
                                }
                        }
                }
            )

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            // Measured on Linux 6.18.5 (`setresid.c`): the privilege check comes
            // first, so an unprivileged process is EPERM whatever it passes;
            // then the size, which is EINVAL whatever the buffer; then the
            // words. Changing the groups leaves the dumpable flag alone.
            match checkSetxidSignal caller system with
            | Error refusal -> Error (SetGroupsRefusal.SetxidSignal refusal)
            | Ok () ->

            match privilege with
            | CallerPrivilege.Unprivileged -> Ok (SyscallAnswer.Failed UnixError.EPERM, system)
            | CallerPrivilege.Privileged ->

            if not sizeAdmitted then
                Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
            else

            match readGroupsLinux size words with
            | Error error -> Ok (SyscallAnswer.Failed error, system)
            | Ok groups -> Ok (installed groups)
        | SimulatedUnixFlavour.Darwin ->
            match privilege with
            | CallerPrivilege.Privileged ->
                // Measured on Darwin 27.0 as root (`setresid.c`, and
                // `docs/probes/darwin-root/credentials.c`): the size is screened
                // first (EINVAL), then a non-empty list is copied (EFAULT at any
                // fault, changing nothing). Darwin keeps one list whose first
                // group is the effective group: the list given becomes it, as
                // given, duplicates and all, so its first group becomes the
                // effective group and getgroups reports the list unchanged; the
                // real group is left alone. An empty list leaves one group, 0,
                // from effective group 0. `(gid_t)-1` is taken as a group.
                if not sizeAdmitted then
                    Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
                elif size = 0 then
                    let effective = system.Process.Credentials.EffectiveGroup
                    let wheel = GroupId.parseOrFail "UnixCredentials.setgroups" 0u

                    if effective <> wheel then
                        Error (SetGroupsRefusal.EmptyFromNonZeroEffectiveGroup effective)
                    else
                        installedOnDarwin wheel []
                else

                assertWordsAgree size words

                match words with
                | GroupListWords.FaultsAfter _ -> Ok (SyscallAnswer.Failed UnixError.EFAULT, system)
                | GroupListWords.Readable words ->

                match words |> List.tryFindIndex (fun word -> GroupId.parse word = None) with
                | Some index -> Error (SetGroupsRefusal.MinusOneGroup index)
                | None ->

                match words |> List.map (GroupId.parseOrFail "UnixCredentials.setgroups") with
                | effective :: rest -> installedOnDarwin effective rest
                | [] ->
                    failwith
                        "UnixCredentials.setgroups: a list of at least one group read as none (this is a bug in this library)."
            | CallerPrivilege.Unprivileged ->

            // Measured on Darwin 27.0 at uid 501 (`setresid.c`): the size comes
            // first (as an unsigned count, so a negative one is EINVAL too),
            // then the copy of a non-empty list, whose every fault is EFAULT
            // whatever the words before it held, and only then the privilege
            // check, which is EPERM even for an empty list and for one holding
            // `(gid_t)-1`.
            if not sizeAdmitted then
                Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
            elif size = 0 then
                Ok (SyscallAnswer.Failed UnixError.EPERM, system)
            else

            assertWordsAgree size words

            match words with
            | GroupListWords.FaultsAfter _ -> Ok (SyscallAnswer.Failed UnixError.EFAULT, system)
            | GroupListWords.Readable _ -> Ok (SyscallAnswer.Failed UnixError.EPERM, system)

    /// `setgroups`, with a refusal answered as the `Error` rather than raised.
    let internal trySetgroups<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (size : int)
        (words : GroupListWords)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, SetGroupsRefusal>
        =
        Entry.call
            "UnixCredentials.setgroups"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (trySetgroupsIn (Caller.thread caller) size words)
            system

    /// `setgroups(3)`: replace the process's supplementary groups, for every
    /// thread, with the `size` groups `words` holds, kept in the order given.
    /// Darwin keeps one list whose first group is the effective group, so
    /// there the first group given becomes the effective group and the rest
    /// the supplementary groups.
    ///
    /// Only a privileged process may. A list longer than the platform's
    /// `SimulatedUnixPlatform.supplementaryGroupLimit`, or of negative size, is
    /// `EINVAL`; an unreadable word is `EFAULT`; and on Linux `(gid_t)-1`,
    /// which no process can hold, is `EINVAL`. The flavours check these in
    /// different orders.
    ///
    /// Refused for a privileged Darwin process whose list holds `(gid_t)-1`,
    /// which Darwin takes as a group and this kernel cannot hold, or that asks
    /// for no groups from an effective group other than 0, which is
    /// unmeasured; for a privileged Darwin process that writes core dumps and
    /// would change its groups, since whether it still dumps core afterwards is
    /// unmeasured; and under Linux, whatever the call would answer, while
    /// another thread blocks signal 33, is asleep in a call, or owes a return
    /// to user mode, since the C library reaches every other thread with that
    /// signal.
    ///
    /// Throws `ArgumentException` where the kernel would copy the list and
    /// `words` disagrees with `size`: `Readable` holding other than `size`
    /// words, or `FaultsAfter` holding `size` or more.
    let setgroups<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (size : int)
        (words : GroupListWords)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        trySetgroups caller size words system
        |> Refusal.orRaise "UnixCredentials.setgroups" SetGroupsRefusal.kind SetGroupsRefusal.describe
