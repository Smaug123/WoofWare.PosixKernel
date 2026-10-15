namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A thread owes its return to user mode from the moment a signal is
/// deliverable to it, whichever thread's call made it so, and until it has
/// returned, any call it makes throws `InvalidOperationException`.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSignalDue =

    /// `caller`'s return to user mode, at which it takes nothing.
    let private resumes (caller : Caller<int>) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"%O{caller}'s return to user mode: expected it to take nothing, got %A{other}"

    let private signo (system : UnixSystem<int, string>) (signal : Signal) : int =
        Signal.toRawSignoUnder (Lone.UnixSystemState.signalNumbering system) signal

    /// `sigaction(signal, disposition)` by `caller`, followed by its return to
    /// user mode.
    let private dispose
        (caller : Caller<int>)
        (signal : Signal)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction caller (signo system signal) (Some disposition) system with
        | Ok (_, system) -> resumes caller system
        | Error error -> failwith $"sigaction of %O{signal} by %O{caller}: %O{error}"

    /// The sequence a signal's receiver could make were it not held to its
    /// return: thread 1 sends thread 0 a caught SIGUSR1; thread 0 calls
    /// `getpid`, which is answered with no system to mark it in, then ignores
    /// SIGUSR1, which discards it, so that its handler never runs. A real
    /// thread takes the signal before it runs more of its own code, so the
    /// `getpid` is refused.
    [<Test>]
    let ``a signal another thread sends holds its receiver to its return before the receiver's next call`` () : unit =
        for platform in Machines.platforms do
            let pids, system = Machines.withThreads platform 1 2
            let pid = List.exactlyOne pids
            let receiver = Caller.make pid 0
            let sender = Caller.make pid 1

            let usr1 =
                Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering platform) Signal.SIGUSR1

            let sent =
                let caught =
                    dispose receiver Signal.SIGUSR1 (SignalDisposition.Catch (SignalCatch.ofHandler "h")) system

                match UnixSignal.pthreadKill sender 0 usr1 caught with
                | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> resumes sender system
                | other -> failwith $"%O{platform}: pthread_kill of thread 0: %A{other}"

            let getpid =
                try
                    Ok (UnixSystem.processId receiver sent)
                with :? InvalidOperationException as e ->
                    Error e.Message

            match getpid with
            | Error message ->
                message |> shouldContainText "UnixSystem.processId: "
                message |> shouldContainText "a signal is deliverable to it"
            | Ok _ ->
                // What the client could go on to do: ignore the signal, so that
                // the handler it was sent to never runs.
                let ignored = dispose receiver Signal.SIGUSR1 SignalDisposition.Ignore sent

                failwith
                    $"%O{platform}: thread 0 made getpid with SIGUSR1 deliverable to it, then ignored SIGUSR1 and returned to user mode, and no handler ran; pending afterwards: %A{SignalState.pending (Lone.proc ignored).Signals}"

            // The return the receiver owes runs the handler.
            match UnixSignal.onReturnToUser receiver sent with
            | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), _) ->
                frame.Entry.Signal |> shouldEqual Signal.SIGUSR1
            | other -> failwith $"%O{platform}: thread 0's return to user mode: %A{other}"
