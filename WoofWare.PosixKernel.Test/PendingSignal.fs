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
    /// returns to user mode, which is what Linux's `signal_pending` asks.
    let transferrerHasSignal (pending : PendingSignal) : bool =
        match pending with
        | PendingSignal.CaughtForTransferrer -> true
        | PendingSignal.Nothing
        | PendingSignal.CaughtForAnother
        | PendingSignal.IgnoredForTransferrer
        | PendingSignal.DefaultForTransferrer -> false

    /// `system` with thread 1 beside `transferrer`, which must not be 1, and
    /// `pending` made so through the leader's `sigaction` and thread 1's
    /// `pthread_kill`: thread 1 sends, so that a signal the transferrer would
    /// take is pending as it makes its next call, as it is on a real kernel
    /// only when another thread sent it.
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
            | Ok (_, system) -> system
            | Error error -> failwith $"sigaction: %O{error}"

        let send (target : int) (signo : int) (system : UnixSystem<int, string>) =
            match UnixSignal.tryPthreadKill (Callers.thread 1 system) target signo system with
            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> system
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
