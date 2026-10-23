namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open WoofWare.PosixKernel

/// What is pending when a thread starts a transfer whose real kernel checks
/// `signal_pending` partway through: a read or write of `/dev/urandom`, or
/// `getrandom(2)`.
[<RequireQualifiedAccess>]
type PendingSignal =
    | Nothing
    /// SIGUSR1, caught, sent to the transferring thread.
    | CaughtForTransferrer
    /// SIGUSR1, caught, sent to another thread.
    | CaughtForAnother
    /// SIGUSR1, ignored, sent to the transferring thread, which discards it.
    | IgnoredForTransferrer
    /// SIGCONT at its default, sent to the transferring thread, which does not
    /// block it: the kernel discards it as it is sent.
    | DefaultForTransferrer

[<RequireQualifiedAccess>]
module PendingSignal =

    let gen : Gen<PendingSignal> =
        Gen.elements
            [
                PendingSignal.Nothing
                PendingSignal.CaughtForTransferrer
                PendingSignal.CaughtForAnother
                PendingSignal.IgnoredForTransferrer
                PendingSignal.DefaultForTransferrer
            ]

    /// Whether `pending` leaves a signal the transferring thread takes as it
    /// returns to user mode, which is what Linux's `signal_pending` asks: one
    /// deliverable to it, for which it owes that return before it makes
    /// another call.
    let transferrerHasSignal (pending : PendingSignal) : bool =
        match pending with
        | PendingSignal.CaughtForTransferrer -> true
        | PendingSignal.Nothing
        | PendingSignal.CaughtForAnother
        | PendingSignal.IgnoredForTransferrer
        | PendingSignal.DefaultForTransferrer -> false

    /// `system` with thread 1 beside `transferrer`, which must not be 1, and
    /// `pending` made so through the leader's `sigaction` and thread 1's
    /// `pthread_kill`. A signal the transferrer takes leaves it owing a return
    /// to user mode, which `returned` makes.
    let make
        (transferrer : int)
        (pending : PendingSignal)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        if transferrer = 1 then
            failwith "PendingSignal.make: thread 1 is the other thread"

        let system = Threads.ensure 1 system

        let install (disposition : SignalDisposition<string>) (system : UnixSystem<int, string>) =
            match UnixSignal.sigaction (Callers.leader system) 10 (Some disposition) system with
            | SigactionAnswer.Completed _, system -> system
            | SigactionAnswer.Failed error, _ -> failwith $"sigaction: %O{error}"

        let send (target : int) (signo : int) (system : UnixSystem<int, string>) =
            match UnixSignal.tryPthreadKill (Callers.thread 1 system) target signo system with
            | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) -> system
            | other -> failwith $"pthread_kill %d{target} %d{signo}: %A{other}"

        match pending with
        | PendingSignal.Nothing -> system
        | PendingSignal.CaughtForTransferrer ->
            system
            |> install (SignalDisposition.Catch (SignalCatch.ofHandler "h"))
            |> send transferrer 10
        | PendingSignal.CaughtForAnother ->
            system
            |> install (SignalDisposition.Catch (SignalCatch.ofHandler "h"))
            |> send 1 10
        | PendingSignal.IgnoredForTransferrer -> system |> install SignalDisposition.Ignore |> send transferrer 10
        | PendingSignal.DefaultForTransferrer -> system |> send transferrer 18

    /// `system` with `transferrer`, of a system `make` made, returned to user
    /// mode before its transfer, running and returning from any handler it
    /// takes there: a thread takes a signal deliverable to it before it runs
    /// more of its own code. Fails the test unless it owed that return exactly
    /// where `pending` left it a signal to take.
    let returned
        (transferrer : int)
        (pending : PendingSignal)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let owed = Lone.owedBy transferrer system

        match owed, transferrerHasSignal pending with
        | Some OwedReturn.SignalDue, true
        | None, false -> ()
        | owed, _ ->
            failwith
                $"PendingSignal.returned: with %A{pending}, thread %d{transferrer} owes %A{owed} before its transfer"

        ReturnsToUser.untilResumed (Callers.thread transferrer system) system
