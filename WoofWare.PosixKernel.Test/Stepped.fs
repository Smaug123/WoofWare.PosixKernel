namespace WoofWare.PosixKernel.Test

open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open WoofWare.PosixKernel

/// A `SteppedCall`, which has no equality of its own, as a value a test can
/// compare: the name of its case, and its fields; and what it says of the
/// process and the system it left.
[<RequireQualifiedAccess>]
module internal Stepped =

    /// The name of `stepped`'s case, and its fields in order, each compared by
    /// F#'s structural equality.
    let view<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stepped : SteppedCall<'Thread, 'Handler>)
        : string * obj list
        =
        let case, fields =
            FSharpValue.GetUnionFields (stepped, typeof<SteppedCall<'Thread, 'Handler>>, BindingFlags.Public)

        case.Name, List.ofArray fields

    /// Fails unless `actual` is `expected`: the same case, holding equal fields.
    let shouldBe<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (expected : SteppedCall<'Thread, 'Handler>)
        (actual : SteppedCall<'Thread, 'Handler>)
        : unit
        =
        view actual |> shouldEqual (view expected)

    /// As `shouldBe`, of what `UnixSystem.tryStep` answers: the same refusal, or
    /// the same case holding equal fields.
    let resultShouldBe<'Thread, 'Handler, 'Refusal
        when 'Thread : comparison and 'Handler : equality and 'Refusal : equality>
        (expected : Result<SteppedCall<'Thread, 'Handler>, 'Refusal>)
        (actual : Result<SteppedCall<'Thread, 'Handler>, 'Refusal>)
        : unit
        =
        Result.map view actual |> shouldEqual (Result.map view expected)

    /// The `SyscallAnswer` `stepped` holds, with the system beside it where its
    /// case holds one; `None` for a case that holds no `SyscallAnswer`.
    let syscallAnswer<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stepped : SteppedCall<'Thread, 'Handler>)
        : (SyscallAnswer * UnixSystem<'Thread, 'Handler> option) option
        =
        match view stepped with
        | _, [ :? SyscallAnswer as answer ] -> Some (answer, None)
        | _, [ :? SyscallAnswer as answer ; :? UnixSystem<'Thread, 'Handler> as system ] -> Some (answer, Some system)
        | _ -> None

    /// The system a call left, if it answered without parking its thread and
    /// its process carries on.
    let carriedOn (stepped : SteppedCall<int, string>) : UnixSystem<int, string> option =
        match stepped with
        | SteppedCall.FLock (SyscallOutcome.Answered _, system)
        | SteppedCall.Open (SyscallOutcome.Answered _, system)
        | SteppedCall.OpenAt (SyscallOutcome.Answered _, system)
        | SteppedCall.Connect (SyscallOutcome.Answered _, system)
        | SteppedCall.Read (ReadOutcome.Answered _, system)
        | SteppedCall.Recv (ReadOutcome.Answered _, system)
        // A signal a write raised is taken as its thread returns to user
        // mode.
        | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns _, system))
        | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.ReturnsRaising _, system))
        | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns _, system))
        | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.ReturnsRaising _, system))
        | SteppedCall.Socket (Ok (_, system))
        | SteppedCall.EpollCreate1 (Ok (_, system))
        | SteppedCall.InotifyInit1 (Ok (_, system))
        | SteppedCall.Kill (Ok (ProcessFate.Continues (_, system)))
        | SteppedCall.PthreadKill (Ok (ProcessFate.Continues (_, system)))
        | SteppedCall.SigAction (Ok (_, system))
        | SteppedCall.SigActionSyscall (Ok (_, system))
        | SteppedCall.PthreadSigMask (Ok (_, system))
        | SteppedCall.SigProcMask (Ok (_, system))
        | SteppedCall.RtSigProcMask (Ok (_, system))
        | SteppedCall.ExitThread (ProcessFate.Continues ((), system)) -> Some system
        | SteppedCall.FLock _
        | SteppedCall.Open _
        | SteppedCall.OpenAt _
        | SteppedCall.Connect _
        | SteppedCall.Read _
        | SteppedCall.Recv _
        | SteppedCall.Write _
        | SteppedCall.Send _
        | SteppedCall.Socket (Error _)
        | SteppedCall.EpollCreate1 (Error _)
        | SteppedCall.InotifyInit1 (Error _)
        | SteppedCall.Kill _
        | SteppedCall.PthreadKill _
        | SteppedCall.SigAction (Error _)
        | SteppedCall.SigActionSyscall (Error _)
        | SteppedCall.PthreadSigMask (Error _)
        | SteppedCall.SigProcMask (Error _)
        | SteppedCall.RtSigProcMask (Error _)
        | SteppedCall.ExitThread (ProcessFate.ProcessEnded _)
        | SteppedCall.ExitGroup _ -> None
        | SteppedCall.Accept (AcceptOutcome.WouldBlock _, _)
        | SteppedCall.Poll (PollOutcome.WouldBlock _, _)
        | SteppedCall.EpollWait (EpollWaitOutcome.WouldBlock _, _)
        | SteppedCall.Kevent (KeventOutcome.WouldBlock _, _)
        | SteppedCall.SigSuspend (SigsuspendOutcome.WouldBlock _, _)
        | SteppedCall.RtSigSuspend (SigsuspendOutcome.WouldBlock _, _)
        | SteppedCall.Pause (SigsuspendOutcome.WouldBlock _, _) -> None
        | SteppedCall.UMask (_, system)
        | SteppedCall.ReadDirectoryEntry (_, system)
        | SteppedCall.PRead (_, system)
        | SteppedCall.PWrite (_, system)
        | SteppedCall.Pipe2 (_, system)
        | SteppedCall.Bind (_, system)
        | SteppedCall.SetSockOpt (_, system)
        | SteppedCall.GetSockOpt (_, system)
        | SteppedCall.Listen (_, system)
        | SteppedCall.Accept (_, system)
        | SteppedCall.Shutdown (_, system)
        | SteppedCall.Poll (_, system)
        | SteppedCall.EpollCtl (_, system)
        | SteppedCall.EpollWait (_, system)
        | SteppedCall.Kqueue (_, system)
        | SteppedCall.Kevent (_, system)
        | SteppedCall.SigSuspend (_, system)
        | SteppedCall.RtSigSuspend (_, system)
        | SteppedCall.Pause (_, system)
        | SteppedCall.SigReturn system
        | SteppedCall.GetRandom (_, system)
        | SteppedCall.GetEntropy (_, system)
        | SteppedCall.Spawn (_, system) -> Some system
        | stepped ->
            match syscallAnswer stepped with
            | Some (_, system) -> system
            | None -> None

    /// Whether `stepped` is the end of the calling process: the call's
    /// `ProcessFate.ProcessEnded`, or an `exit_group`'s.
    let endsProcess (stepped : SteppedCall<int, string>) : bool =
        match stepped with
        | SteppedCall.Kill (Ok (ProcessFate.ProcessEnded _))
        | SteppedCall.PthreadKill (Ok (ProcessFate.ProcessEnded _))
        | SteppedCall.ExitThread (ProcessFate.ProcessEnded _)
        | SteppedCall.ExitGroup _ -> true
        | _ -> false

    /// Whether `stepped` is a call a signal interrupted as it was made.
    let interrupted (stepped : SteppedCall<int, string>) : bool =
        match stepped with
        | SteppedCall.SigSuspend (SigsuspendOutcome.Interrupted, _)
        | SteppedCall.RtSigSuspend (SigsuspendOutcome.Interrupted, _)
        | SteppedCall.Pause (SigsuspendOutcome.Interrupted, _) -> true
        | _ -> false
