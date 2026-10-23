namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open WoofWare.PosixKernel

/// `UnixWait.finish` held to the finishing function of each woken call's own
/// family, which it must answer exactly as.
[<RequireQualifiedAccess>]
module internal FinishOracle =

    /// The bytes of `ParkedCall.buffer` that `range` names: what `finish`
    /// copies of the buffer of the `Syscall` `ParkedCall.ofPark` makes.
    let private bytesOf (range : CopyRange) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (Array.init range.ByteCount (fun i -> byte (range.FirstByte + i)))

    /// What a woken write's finish came to, as a label: "NeedsCopyIn" first
    /// where the family's finishing function stopped at its copy, then the
    /// case of its outcome, or "ProcessEnded".
    let private writeLabel<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stopped : bool)
        (fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>)
        : string
        =
        let outcome =
            match fate with
            | ProcessFate.ProcessEnded _ -> "ProcessEnded"
            | ProcessFate.Continues (outcome, _) -> UnionCaseName.ofValue outcome

        if stopped then $"NeedsCopyIn %s{outcome}" else outcome

    /// What the family's functions answer for the woken write `caller` is
    /// parked in: `finishWrite`, and where that stops at its copy,
    /// `writeWithBytes` of the bytes `bytesOf` gives, which must deliver
    /// nothing out of the machine; and whether it stopped.
    let private familyWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : bool * Result<ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>, WriteRefusal>
        =
        match UnixReadWrite.tryFinishWrite caller system with
        | Error refusal -> false, Error refusal
        | Ok (CallProgress.Answered fate) -> false, Ok fate
        | Ok (CallProgress.NeedsCopyIn paused) ->
            let resumed =
                UnixReadWrite.tryWriteWithBytes (bytesOf (PausedWrite.copyRange paused)) paused
                |> Result.map (fun (fate, delivery) ->
                    match delivery with
                    | None -> fate
                    | Some delivery -> failwith $"the woken write of %O{caller} delivered %A{delivery}"
                )

            true, resumed

    /// The system a finish left the caller's process in, if the process
    /// carries on.
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
        | FinishedCall.DatagramReceive (FinishedDatagramReceive.Read (_, system))
        | FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (_, system))
        | FinishedCall.Futex (_, system) -> Some system
        | FinishedCall.PipeWrite (ProcessFate.Continues (_, system))
        | FinishedCall.ConnectionWrite (ProcessFate.Continues (_, system)) -> Some system
        | FinishedCall.PipeWrite _
        | FinishedCall.ConnectionWrite _ -> None
        | FinishedCall.Sleep _
        | FinishedCall.FifoOpen _
        | FinishedCall.Select _
        | FinishedCall.SignalWait _
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

    /// Where a write's fate differs from the family's.
    let private sameFate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>)
        (family : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>)
        : string option
        =
        if fate = family then
            None
        else
            Some $"answered %A{fate}, where the family's functions answered %A{family}"

    /// `UnixWait.tryFinish` of `caller` in `system`, given the `Syscall`
    /// `ParkedCall.ofPark` makes of its park, held to the finishing function of
    /// the family of the call `caller` is woken in, made of the same `system`:
    /// `finish` must answer the case named as the park's `ParkedSyscall` case
    /// is, holding exactly what that function answers, the system included,
    /// and so whether the thread owes a return to user mode; or refuse with
    /// that function's own refusal. For a write that stops at its copy, that
    /// function is its resumption (`writeWithBytes`) after it, given the bytes
    /// of the `Syscall`'s buffer it names. Fails the test otherwise.
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
            match Proc.parkOf caller system with
            | Some {
                       Syscall = parked
                       State = ParkState.Woken _
                   } -> parked
            | other -> failwith $"FinishOracle.agree: %O{caller} is not woken in a call: %A{other}"

        let kind = UnionCaseName.ofValue parked
        let finished = UnixWait.tryFinish caller (ParkedCall.ofPark parked) system

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
                let stopped, family = familyWrite caller system

                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.PipeWrite fate -> Some fate
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Write refusal -> Some refusal
                        | _ -> None
                    )
                    family
                    sameFate
                    (writeLabel stopped)
            | ParkedSyscall.ConnectionWrite _ ->
                let stopped, family = familyWrite caller system

                held
                    caller
                    kind
                    finished
                    (fun finished ->
                        match finished with
                        | FinishedCall.ConnectionWrite fate -> Some fate
                        | _ -> None
                    )
                    (fun refusal ->
                        match refusal with
                        | FinishRefusal.Write refusal -> Some refusal
                        | _ -> None
                    )
                    family
                    sameFate
                    (writeLabel stopped)
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
            | ParkedSyscall.DatagramReceive receive ->
                match receive.Call with
                | ParkedDatagramReceiveCall.Read
                | ParkedDatagramReceiveCall.Receive _ ->
                    held
                        caller
                        kind
                        finished
                        (fun finished ->
                            match finished with
                            | FinishedCall.DatagramReceive (FinishedDatagramReceive.Read (outcome, system)) ->
                                Some (outcome, system)
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
                | ParkedDatagramReceiveCall.ReceiveFrom _ ->
                    held
                        caller
                        kind
                        finished
                        (fun finished ->
                            match finished with
                            | FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (outcome, system)) ->
                                Some (outcome, system)
                            | _ -> None
                        )
                        (fun refusal ->
                            match refusal with
                            | FinishRefusal.Receive refusal -> Some refusal
                            | _ -> None
                        )
                        // A Linux call stops for its length cell, which
                        // `ParkedCall.ofPark` gives as holding 16.
                        (UnixReadWrite.tryFinishRecvFrom caller system
                         |> CallProgress.resumeWith (UnixReadWrite.tryRecvFromWithLength 16u))
                        sameOutcome
                        (fst >> UnionCaseName.ofValue)
            | ParkedSyscall.Sleep _
            | ParkedSyscall.FifoOpen _
            | ParkedSyscall.Select _
            | ParkedSyscall.SignalWait _
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
                    if Set.contains (Caller.processId caller) (UnixSystem.processIds system) then
                        Proc.owedBy caller system
                    else
                        None
                )
            | Error _ -> None

        match owes with
        | None -> $"%s{kind} %s{outcome}"
        | Some owed -> $"%s{kind} %s{outcome}, owing %s{UnionCaseName.ofValue owed}"

    /// A `Syscall` of every case that parks a thread somewhere, and of one
    /// that parks none, each with placeholder arguments.
    let private probes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Syscall<'Thread, 'Handler> list =
        [
            Syscall.EpollWait (0, UserBuffer.Mapped, 1, -1)
            Syscall.Kevent (0, [], 0, UserBuffer.Mapped, 1, TimespecArgument.Null)
            Syscall.FLock (0, 0)
            Syscall.Poll ([], -1)
            Syscall.Accept (0, UserBuffer.Mapped, Some 16u, 0)
            Syscall.Read (0, UserBuffer.Mapped, 0UL)
            Syscall.Recv (0, UserBuffer.Mapped, 0UL, 0)
            Syscall.Write (0, CopiedArgument.Readable (ParkedCall.buffer 0), 0UL)
            Syscall.Send (0, CopiedArgument.Readable (ParkedCall.buffer 0), 0UL, 0)
            Syscall.SendTo (0, CopiedArgument.Readable (ParkedCall.buffer 0), 0UL, 0, CopiedArgument.Unmapped 0UL, 0u)
            Syscall.SendTo (
                0,
                CopiedArgument.Readable (ParkedCall.buffer 0),
                0UL,
                0,
                CopiedArgument.Readable (ParkedCall.buffer 16),
                16u
            )
            Syscall.RecvFrom (0, UserBuffer.Mapped, 0UL, 0, UserBuffer.Unmapped 0UL, CopiedArgument.Unmapped 0UL)
            Syscall.SigSuspend SignalMask.Empty
            Syscall.RtSigSuspend (SignalMask.Empty, 8UL)
            Syscall.Pause
            Syscall.Futex (0UL, 0, 0, CopiedArgument.Readable 0u, TimespecArgument.Null, 0u)
            Syscall.GetProcessId
        ]

    /// The `Syscall` cases whose call parks a thread in `parked`, by name.
    let private parkingCases (parked : ParkedSyscall) : string list =
        match parked with
        | ParkedSyscall.EpollWait _ -> [ "EpollWait" ]
        | ParkedSyscall.Kevent _ -> [ "Kevent" ]
        | ParkedSyscall.Flock _ -> [ "FLock" ]
        | ParkedSyscall.Poll _
        | ParkedSyscall.KqueuePoll _ -> [ "Poll" ]
        | ParkedSyscall.Accept _ -> [ "Accept" ]
        | ParkedSyscall.PipeRead _
        | ParkedSyscall.InotifyRead _ -> [ "Read" ]
        | ParkedSyscall.ConnectionRead read ->
            match read.Call with
            | TcpReceiveCall.Read -> [ "Read" ]
            | TcpReceiveCall.Receive
            | TcpReceiveCall.Peek -> [ "Recv" ]
        | ParkedSyscall.PipeWrite _ -> [ "Write" ]
        | ParkedSyscall.ConnectionWrite write ->
            match write.Call with
            | TcpSendCall.Write -> [ "Write" ]
            | TcpSendCall.Send _ -> [ "Send" ; "SendTo" ]
        | ParkedSyscall.SigSuspend -> [ "SigSuspend" ; "RtSigSuspend" ; "Pause" ]
        | ParkedSyscall.Futex _ -> [ "Futex" ]
        | ParkedSyscall.DatagramReceive receive ->
            match receive.Call with
            | ParkedDatagramReceiveCall.Read -> [ "Read" ]
            | ParkedDatagramReceiveCall.Receive _ -> [ "Recv" ]
            | ParkedDatagramReceiveCall.ReceiveFrom _ -> [ "RecvFrom" ]
        | ParkedSyscall.Sleep _
        | ParkedSyscall.FifoOpen _
        | ParkedSyscall.Select _
        | ParkedSyscall.SignalWait _
        | ParkedSyscall.DatagramSend _
        | ParkedSyscall.Connect _ -> []

    /// `ParkedCall.ofPark parked`, a write, with `buffer` as its buffer.
    let private writeWith<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (parked : ParkedSyscall)
        (buffer : CopiedArgument<ImmutableArray<byte>>)
        : Syscall<'Thread, 'Handler>
        =
        match (ParkedCall.ofPark parked : Syscall<'Thread, 'Handler>) with
        | Syscall.Write (fd, _, count) -> Syscall.Write (fd, buffer, count)
        | Syscall.Send (fd, _, count, flags) -> Syscall.Send (fd, buffer, count, flags)
        | other -> failwith $"FinishOracle.writeWith: %A{parked} is not a write, but %A{other}"

    /// What `UnixWait.finish` of the woken thread `caller` does with a `Syscall`
    /// that does not describe its call, failing the test unless: it refuses
    /// every `Syscall` of a case that parks no thread where `caller` is parked,
    /// `ArgumentException` naming `call`; and, for a write, it refuses a buffer
    /// given as anything but readable where it copies, `UnmodelledException`,
    /// and fails with `InvalidOperationException` for contents that end before
    /// what it copies, and answers as `agree` checks, whatever the buffer, where
    /// it does not copy. Answers a label of each of those it reached.
    let refusesMisuse<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : string list
        =
        let parked =
            match Proc.parkOf caller system with
            | Some {
                       Syscall = parked
                       State = ParkState.Woken _
                   } -> parked
            | other -> failwith $"FinishOracle.refusesMisuse: %O{caller} is not woken in a call: %A{other}"

        let fail (what : string) : 'a =
            failwith $"UnixWait.finish of %O{caller}, parked in %s{UnionCaseName.ofValue parked}: %s{what}"

        let cases = parkingCases parked

        // A `sendto` with no destination is a `send`, and parks as one; with a
        // destination it is a datagram's, which parks in no connection.
        let fits (call : Syscall<'Thread, 'Handler>) : bool =
            List.contains (UnionCaseName.ofValue call) cases
            && (
                match call with
                | Syscall.SendTo (_, _, _, _, destination, _) -> destination = CopiedArgument.Unmapped 0UL
                | _ -> true
            )

        if List.isEmpty cases then
            []
        else

        let mismatches = probes |> List.filter (fits >> not)

        for call in mismatches do
            match UnixWait.tryFinish caller call system with
            | Error (FinishRefusal.NotTheParkedCall refused) when refused = parked -> ()
            | other -> fail $"given %A{call}, answered %A{other}, not NotTheParkedCall"

        match mismatches with
        | [] -> ()
        | call :: _ ->
            try
                UnixWait.finish caller call system |> ignore<FinishedCall<'Thread, 'Handler>>
                fail $"given %A{call}, did not throw"
            with :? System.ArgumentException as e when e.ParamName = "call" ->
                ()

        let mismatched = $"misuse: %s{UnionCaseName.ofValue parked} given another call"

        // A `send` finishes as the `sendto` with no destination that is the
        // same call would, given what `whole` answered for the `send`.
        let sendAsSendTo (whole : Result<FinishedCall<'Thread, 'Handler>, FinishRefusal>) : string list =
            match (ParkedCall.ofPark parked : Syscall<'Thread, 'Handler>) with
            | Syscall.Send (fd, buffer, count, flags) ->
                let sendto : Syscall<'Thread, 'Handler> =
                    Syscall.SendTo (fd, buffer, count, flags, CopiedArgument.Unmapped 0UL, 0u)

                let answered = UnixWait.tryFinish caller sendto system

                match whole, answered with
                | Ok (FinishedCall.ConnectionWrite fate), Ok (FinishedCall.ConnectionWrite fate') when fate = fate' ->
                    ()
                | Error refusal, Error refusal' when refusal = refusal' -> ()
                | _ -> fail $"answered %A{answered} given %A{sendto}, and %A{whole} given the send it is"

                [ "a send finished as a sendto with no destination" ]
            | _ -> []

        match parked with
        | ParkedSyscall.PipeWrite _
        | ParkedSyscall.ConnectionWrite _ ->
            let whole = UnixWait.tryFinish caller (ParkedCall.ofPark parked) system

            match UnixReadWrite.tryFinishWrite caller system with
            | Ok (CallProgress.NeedsCopyIn paused) ->
                for buffer in
                    [
                        CopiedArgument.Unmapped 0x1000UL
                        CopiedArgument.Opaque
                        CopiedArgument.Addressless
                    ] do
                    match UnixWait.tryFinish caller (writeWith parked buffer) system with
                    | Error (FinishRefusal.UnreadableBuffer (refused, given)) when
                        refused = parked && given = CopiedArgument.userBuffer buffer
                        ->
                        ()
                    | other -> fail $"given the buffer %A{buffer}, answered %A{other}, not UnreadableBuffer"

                let range = PausedWrite.copyRange paused
                let short = ParkedCall.buffer (range.FirstByte + range.ByteCount - 1)

                try
                    UnixWait.finish caller (writeWith parked (CopiedArgument.Readable short)) system
                    |> ignore<FinishedCall<'Thread, 'Handler>>

                    fail $"given %d{short.Length} bytes, short of %A{range}, did not throw"
                with :? System.InvalidOperationException as e when e.Message.Contains "hold only" ->
                    ()

                [
                    mismatched
                    "misuse: a write that copies given a buffer it cannot copy from"
                    yield! sendAsSendTo whole
                ]
            | Ok (CallProgress.Answered _)
            | Error _ ->
                let unread =
                    UnixWait.tryFinish caller (writeWith parked (CopiedArgument.Unmapped 0x1000UL)) system

                match whole, unread with
                | Ok (FinishedCall.PipeWrite fate), Ok (FinishedCall.PipeWrite fate')
                | Ok (FinishedCall.ConnectionWrite fate), Ok (FinishedCall.ConnectionWrite fate') when fate = fate' ->
                    ()
                | Error refusal, Error refusal' when refusal = refusal' -> ()
                | _ ->
                    fail
                        $"answered %A{unread} given an unmapped buffer it does not copy, and %A{whole} given one it can"

                [
                    mismatched
                    "misuse: a write that copies nothing given a buffer it cannot copy from"
                    yield! sendAsSendTo whole
                ]
        | ParkedSyscall.DatagramReceive {
                                            Call = ParkedDatagramReceiveCall.ReceiveFrom _
                                        } ->
            let whole = UnixWait.tryFinish caller (ParkedCall.ofPark parked) system

            let withCell (cell : CopiedArgument<uint32>) : Syscall<'Thread, 'Handler> =
                match (ParkedCall.ofPark parked : Syscall<'Thread, 'Handler>) with
                | Syscall.RecvFrom (fd, buffer, count, flags, source, _) ->
                    Syscall.RecvFrom (fd, buffer, count, flags, source, cell)
                | other -> failwith $"FinishOracle.refusesMisuse: %A{parked} is not a recvfrom, but %A{other}"

            match UnixReadWrite.tryFinishRecvFrom caller system with
            | Ok (CallProgress.NeedsCopyIn _) ->
                for cell in
                    [
                        CopiedArgument.Unmapped 0x1000UL
                        CopiedArgument.Opaque
                        CopiedArgument.Addressless
                    ] do
                    match UnixWait.tryFinish caller (withCell cell) system with
                    | Error (FinishRefusal.UnreadableBuffer (refused, given)) when
                        refused = parked && given = CopiedArgument.userBuffer cell
                        ->
                        ()
                    | other -> fail $"given the length cell %A{cell}, answered %A{other}, not UnreadableBuffer"

                [
                    mismatched
                    "misuse: a recvfrom that reads its length cell given one it cannot read"
                ]
            | Ok (CallProgress.Answered _)
            | Error _ ->
                let unread =
                    UnixWait.tryFinish caller (withCell (CopiedArgument.Unmapped 0x1000UL)) system

                match whole, unread with
                | Ok (FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (outcome, after))),
                  Ok (FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (outcome', after'))) when
                    outcome = outcome' && after = after'
                    ->
                    ()
                | Error refusal, Error refusal' when refusal = refusal' -> ()
                | _ ->
                    fail
                        $"answered %A{unread} given an unmapped length cell it does not read, and %A{whole} given one it can"

                [
                    mismatched
                    "misuse: a recvfrom that reads no length cell given one it cannot read"
                ]
        | _ -> [ mismatched ]
