namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open WoofWare.PosixKernel

/// `UnixWait.finish` held to the finishing function of each woken call's own
/// family, which it must answer exactly as.
[<RequireQualifiedAccess>]
module internal FinishOracle =

    /// The bytes a write stopped at the copy is given here: each byte its
    /// offset into the caller's buffer, so that the same range gets the same
    /// bytes from every resumption.
    let private bytesOf (range : CopyRange) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (Array.init range.ByteCount (fun i -> byte (range.FirstByte + i)))

    /// What a woken call's finish came to, as a label: its outcome's case, or,
    /// for a write, the case of what its progress holds.
    let private writeLabel<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (progress : CallProgress<PausedWrite<'Thread, 'Handler>, ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>>)
        : string
        =
        match progress with
        | CallProgress.NeedsCopyIn _ -> "NeedsCopyIn"
        | CallProgress.Answered (ProcessFate.ProcessEnded _) -> "ProcessEnded"
        | CallProgress.Answered (ProcessFate.Continues (outcome, _)) -> UnionCaseName.ofValue outcome

    /// The system a finish left the caller's process in, if the process
    /// carries on and the call did not stop at a copy.
    let private systemOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (finished : FinishedCall<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler> option
        =
        match finished with
        | FinishedCall.EpollWait (_, system)
        | FinishedCall.Kevent (_, system)
        | FinishedCall.Flock (_, system)
        | FinishedCall.Poll (_, system)
        | FinishedCall.KqueuePoll (_, system)
        | FinishedCall.Accept (_, system)
        | FinishedCall.PipeRead (_, system)
        | FinishedCall.ConnectionRead (_, system)
        | FinishedCall.SigSuspend (_, system)
        | FinishedCall.InotifyRead (_, system)
        | FinishedCall.Futex (_, system) -> Some system
        | FinishedCall.PipeWrite (CallProgress.Answered (ProcessFate.Continues (_, system)))
        | FinishedCall.ConnectionWrite (CallProgress.Answered (ProcessFate.Continues (_, system))) -> Some system
        | FinishedCall.PipeWrite _
        | FinishedCall.ConnectionWrite _ -> None
        | FinishedCall.Sleep _
        | FinishedCall.FifoOpen _
        | FinishedCall.Select _
        | FinishedCall.SignalWait _
        | FinishedCall.DatagramReceive _
        | FinishedCall.DatagramSend _
        | FinishedCall.Connect _ -> None

    /// `UnixWait.tryFinish` of `caller` in `system`, held to `family`, what the
    /// finishing function of the family of the call `caller` is parked in
    /// answered of the same: `finish` must answer the case `carried` reads,
    /// holding what `family` holds (`agrees`), or refuse with the family's own
    /// refusal, which `refused` reads. Fails the test otherwise. Answers what
    /// `label` makes of the answer, or "refused".
    let private held<'Thread, 'Handler, 'Answer, 'Refusal
        when 'Thread : comparison and 'Handler : equality and 'Refusal : equality>
        (caller : Caller<'Thread>)
        (kind : string)
        (finished : Result<FinishedCall<'Thread, 'Handler>, FinishRefusal>)
        (carried : FinishedCall<'Thread, 'Handler> -> 'Answer option)
        (refused : FinishRefusal -> 'Refusal option)
        (family : Result<'Answer, 'Refusal>)
        (agrees : 'Answer -> 'Answer -> string option)
        (label : 'Answer -> string)
        : string
        =
        let fail (what : string) : string =
            failwith $"UnixWait.finish of %O{caller}, parked in %s{kind}: %s{what}"

        match finished, family with
        | Ok finished, Ok family ->
            match carried finished with
            | None ->
                fail
                    $"answered FinishedCall.%s{UnionCaseName.ofValue finished}, not the case of the park, FinishedCall.%s{kind}"
            | Some answer ->
                match agrees answer family with
                | Some difference -> fail difference
                | None -> label answer
        | Error refusal, Error familyRefusal ->
            match refused refusal with
            | Some refusal when refusal = familyRefusal -> "refused"
            | _ -> fail $"refused with %A{refusal}, where the family's function refused with %A{familyRefusal}"
        | Ok finished, Error familyRefusal ->
            fail
                $"answered FinishedCall.%s{UnionCaseName.ofValue finished}, where the family's function refused with %A{familyRefusal}"
        | Error refusal, Ok _ -> fail $"refused with %A{refusal}, where the family's function answered"

    /// Where an outcome and the system beside it differ from the family's.
    let private sameOutcome<'Outcome, 'Thread, 'Handler
        when 'Outcome : equality and 'Thread : comparison and 'Handler : equality>
        (outcome : 'Outcome, system : UnixSystem<'Thread, 'Handler>)
        (familyOutcome : 'Outcome, familySystem : UnixSystem<'Thread, 'Handler>)
        : string option
        =
        if outcome <> familyOutcome then
            Some $"answered %A{outcome}, where the family's function answered %A{familyOutcome}"
        elif system <> familySystem then
            Some $"answered %A{outcome} as the family's function did, but left another system"
        else
            None

    /// Where a write's progress differs from the family's: an answer, or a call
    /// stopped at the same copy whose resumption with the same bytes answers
    /// the same.
    let private sameProgress<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (progress : CallProgress<PausedWrite<'Thread, 'Handler>, ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>>)
        (family : CallProgress<PausedWrite<'Thread, 'Handler>, ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>>)
        : string option
        =
        match progress, family with
        | CallProgress.Answered fate, CallProgress.Answered familyFate ->
            if fate = familyFate then
                None
            else
                Some $"answered %A{fate}, where the family's function answered %A{familyFate}"
        | CallProgress.NeedsCopyIn paused, CallProgress.NeedsCopyIn familyPaused ->
            let range = PausedWrite.copyRange paused
            let familyRange = PausedWrite.copyRange familyPaused

            if range <> familyRange then
                Some $"stopped to copy %A{range}, where the family's function stopped to copy %A{familyRange}"
            else

            let resumed = UnixReadWrite.tryWriteWithBytes (bytesOf range) paused
            let familyResumed = UnixReadWrite.tryWriteWithBytes (bytesOf range) familyPaused

            if resumed = familyResumed then
                None
            else
                Some
                    $"stopped to copy %A{range} as the family's function did, but its resumption answered %A{resumed}, where the family's answered %A{familyResumed}"
        | progress, family ->
            Some
                $"answered %s{UnionCaseName.ofValue progress}, where the family's function answered %s{UnionCaseName.ofValue family}"

    /// `UnixWait.tryFinish caller system`, held to the finishing function of
    /// the family of the call `caller` is woken in, made of the same `system`:
    /// `finish` must answer the case named as the park's `ParkedSyscall` case
    /// is, holding exactly what that function answers, the system included,
    /// and so whether the thread owes a return to user mode; or refuse with
    /// that function's own refusal. A write stopped at the copy agrees where it
    /// stopped at the same range and its resumption with the same bytes answers
    /// the same. Fails the test otherwise.
    ///
    /// Answers a label of what the finish came to: the park's kind, then the
    /// case of its outcome or "refused", then, for a thread whose process
    /// carries on owing a return to user mode, which return it owes.
    let agree<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : string
        =
        let parked =
            match UnixThreadTable.parkOf (Caller.thread caller) (Proc.threads (Caller.processId caller) system) with
            | Some {
                       Syscall = parked
                       State = ParkState.Woken _
                   } -> parked
            | other -> failwith $"FinishOracle.agree: %O{caller} is not woken in a call: %A{other}"

        let kind = UnionCaseName.ofValue parked
        let finished = UnixWait.tryFinish caller system

        let outcome =
            match parked with
            | ParkedSyscall.EpollWait _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.EpollWait (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.EpollWait refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixPoll.tryFinishEpollWait caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Kevent _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.Kevent (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Kevent refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixKqueue.tryFinishKevent caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Flock _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.Flock (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Flock refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixDescriptor.tryFlockAcquire caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Poll _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.Poll (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Poll refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixPoll.tryFinishPoll caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.KqueuePoll _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.KqueuePoll (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Poll refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixPoll.tryFinishPoll caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Accept _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.Accept (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Accept refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixConnection.tryFinishAccept caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.PipeRead _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.PipeRead (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Read refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixReadWrite.tryFinishRead caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.ConnectionRead _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.ConnectionRead (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Read refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixReadWrite.tryFinishRead caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.InotifyRead _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.InotifyRead (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Read refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixReadWrite.tryFinishRead caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Futex _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.Futex (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Futex refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixFutex.tryFinishFutexWait caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.PipeWrite _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.PipeWrite progress -> Some progress
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Write refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixReadWrite.tryFinishWrite caller system)
                    sameProgress
                    writeLabel
            | ParkedSyscall.ConnectionWrite _ ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.ConnectionWrite progress -> Some progress
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Write refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixReadWrite.tryFinishWrite caller system)
                    sameProgress
                    writeLabel
            | ParkedSyscall.SigSuspend ->
                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.SigSuspend (outcome, system) -> Some (outcome, system)
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Sigsuspend refusal -> Some refusal
                        | _ -> None
                    )
                    (UnixSignal.tryFinishSigsuspend caller system)
                    sameOutcome
                    (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Sleep _
            | ParkedSyscall.FifoOpen _
            | ParkedSyscall.Select _
            | ParkedSyscall.SignalWait _
            | ParkedSyscall.DatagramReceive _
            | ParkedSyscall.DatagramSend _
            | ParkedSyscall.Connect _ ->
                match finished with
                | Error (FinishRefusal.Reserved reserved) when reserved = parked -> "refused"
                | Error refusal ->
                    failwith $"UnixWait.finish of %O{caller}, parked in %s{kind}: refused with %A{refusal}"
                | Ok finished ->
                    failwith
                        $"UnixWait.finish of %O{caller}, parked in %s{kind}: answered FinishedCall.%s{UnionCaseName.ofValue finished}, where nothing finishes a reserved park"

        let owes =
            match finished with
            | Ok finished ->
                systemOf finished
                |> Option.bind (fun system ->
                    match Map.tryFind (ProcessId.toInt32 (Caller.processId caller)) system.Processes with
                    | Some slot -> UnixThreadTable.owedBy (Caller.thread caller) slot.Threads
                    | None -> None
                )
            | Error _ -> None

        match owes with
        | None -> $"%s{kind} %s{outcome}"
        | Some owed -> $"%s{kind} %s{outcome}, owing %s{UnionCaseName.ofValue owed}"
