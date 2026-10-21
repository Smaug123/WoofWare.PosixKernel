namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A transfer asleep on a pipe or a connected TCP socket, its open file
/// description made non-blocking while it sleeps, then sent a caught signal
/// with what it waits for still absent: every row of
/// `docs/probes/nonblocking-asleep`, measured on Linux 6.18.5 aarch64 and
/// Darwin 27.0.0 arm64 and embedded, replayed against the platform that
/// measured it, as a client drives the library.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestNonBlockingAsleepMeasured =

    /// The probe's row names.
    [<RequireQualifiedAccess>]
    type private Transfer =
        /// `P-write0`: a 1-byte write into a full pipe.
        | PipeWriteNothingIn
        /// `P-partial`: a 200000-byte write into an empty pipe.
        | PipeWritePartlyIn
        /// `P-read`: a 1-byte read of an empty pipe.
        | PipeRead
        /// `T-write0`: a 1-byte write into a full connection.
        | ConnectionWriteNothingTaken
        /// `T-read`: a 1-byte read of an empty connection.
        | ConnectionRead

    /// What a call came to, as the probe prints it: a count, or an errno.
    type private Answer = Result<int64, UnixError>

    [<RequireQualifiedAccess>]
    type private Ending =
        /// The call returned within the probe's wait after the signal.
        | Returned of Answer
        /// The call was still asleep then, and answered this once the main
        /// thread gave it what it waited for.
        | SleptOn of Answer

    type private Row =
        {
            Line : string
            Transfer : Transfer
            NonBlock : bool
            Restart : bool
            Held : int
            AsleepAtFlag : bool
            AsleepAtSignal : bool
            Ending : Ending
            Handled : int
            /// What the same call of one byte, made non-blocking, answered once
            /// the call had returned; `None` for a call that slept on.
            Then : Answer option
        }

    let private rowPattern : Regex =
        Regex
            @"^(P-write0|P-partial|P-read|T-write0|T-read) nonblock=([01]) restart=([01]) trial=[0-9]+: held=([0-9]+) asleep_at_flag=([01]) asleep_at_signal=([01]) at_signal=(returned|slept-on) rv=(-?[0-9]+) errno=([A-Z]+|-) handled=([0-9]+) then=([A-Z]+|[0-9]+|-)$"

    let private errorNamed (line : string) (name : string) : UnixError =
        match name with
        | "EAGAIN" -> UnixError.EAGAIN
        | "EINTR" -> UnixError.EINTR
        | "EPIPE" -> UnixError.EPIPE
        | "EBADF" -> UnixError.EBADF
        | "ECONNRESET" -> UnixError.ECONNRESET
        | other -> failwith $"%s{line}: unknown errno %s{other}"

    let private parseRow (line : string) : Row =
        let m = rowPattern.Match line

        if not m.Success then
            failwith $"unparsed row: %s{line}"

        let group (i : int) = m.Groups.[i].Value

        let answer =
            match Int64.Parse (group 8), group 9 with
            | rv, "-" when rv >= 0L -> Ok rv
            | -1L, name -> Error (errorNamed line name)
            | _ -> failwith $"%s{line}: rv and errno disagree"

        {
            Line = line
            Transfer =
                match group 1 with
                | "P-write0" -> Transfer.PipeWriteNothingIn
                | "P-partial" -> Transfer.PipeWritePartlyIn
                | "P-read" -> Transfer.PipeRead
                | "T-write0" -> Transfer.ConnectionWriteNothingTaken
                | _ -> Transfer.ConnectionRead
            NonBlock = group 2 = "1"
            Restart = group 3 = "1"
            Held = Int32.Parse (group 4)
            AsleepAtFlag = group 5 = "1"
            AsleepAtSignal = group 6 = "1"
            Ending =
                match group 7 with
                | "returned" -> Ending.Returned answer
                | _ -> Ending.SleptOn answer
            Handled = Int32.Parse (group 10)
            Then =
                match group 11 with
                | "-" -> None
                | text when Char.IsDigit text.[0] -> Some (Ok (Int64.Parse text))
                | name -> Some (Error (errorNamed line name))
        }

    /// The platform the output `name` was measured on, and its rows.
    let private measured (name : string) : SimulatedUnixPlatform * Row list =
        match
            SocketLadder.resource name
            |> Array.map (fun line -> line.TrimEnd '\r')
            |> List.ofArray
        with
        | "uname: Linux 6.18.5 aarch64" :: rows -> SimulatedUnixPlatform.linuxArm64, List.map parseRow rows
        | "uname: Darwin 27.0.0 arm64" :: rows -> SimulatedUnixPlatform.macOsArm64, List.map parseRow rows
        | header :: _ -> failwith $"%s{name}: unexpected header %s{header}"
        | [] -> failwith $"%s{name} is empty"

    /// The thread whose call sleeps; the leader makes every other call.
    let private sleeper : int = 1

    let private port : uint16 = 6300us

    let private partialCount : int = 200000

    let private bytesOf (count : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Array.create count 7uy)

    /// A system on `platform` with `sleeper` a thread, `SIGUSR1` caught with
    /// `SA_RESTART` if `restart`, and `SIGPIPE` ignored.
    let private boot (platform : SimulatedUnixPlatform) (restart : bool) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn sleeper

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    proc.Signals
                    |> SignalState.setDisposition
                        (Kernel.signalNumbering system)
                        Signal.SIGPIPE
                        SignalDisposition.Ignore
                    |> SignalState.setDisposition
                        (Kernel.signalNumbering system)
                        Signal.SIGUSR1
                        (SignalDisposition.Catch
                            { SignalCatch.ofHandler "h" with
                                Restart = restart
                            })
            }
        )

    let private isWrite (transfer : Transfer) : bool =
        match transfer with
        | Transfer.PipeWriteNothingIn
        | Transfer.PipeWritePartlyIn
        | Transfer.ConnectionWriteNothingTaken -> true
        | Transfer.PipeRead
        | Transfer.ConnectionRead -> false

    let private countOf (transfer : Transfer) : int =
        match transfer with
        | Transfer.PipeWritePartlyIn -> partialCount
        | Transfer.PipeWriteNothingIn
        | Transfer.PipeRead
        | Transfer.ConnectionWriteNothingTaken
        | Transfer.ConnectionRead -> 1

    /// What a call came to, in a shape every transfer here shares.
    [<RequireQualifiedAccess>]
    type private Step =
        | Answered of Answer
        | Sleeps
        /// A signal interrupted the call: the thread's return to user mode
        /// says how it ends.
        | Interrupted

    let private ofWrite
        (where : string)
        (progress : CallProgress<PausedWrite<int, string>, ProcessFate<WriteOutcome<int>, int, string>>)
        : Step * UnixSystem<int, string>
        =
        let fate =
            match progress with
            | CallProgress.Answered fate -> fate
            | CallProgress.NeedsCopyIn paused ->
                match UnixReadWrite.writeWithBytes (bytesOf (PausedWrite.copyRange paused).ByteCount) paused with
                | fate, None -> fate
                | _, Some delivery -> failwith $"%s{where}: a write into a pipe the process made delivered %A{delivery}"

        match fate with
        | ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed n), system) -> Step.Answered (Ok n), system
        | ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Failed error), system) ->
            Step.Answered (Error error), system
        | ProcessFate.Continues (WriteOutcome.WouldBlock _, system) -> Step.Sleeps, system
        | ProcessFate.Continues (WriteOutcome.Interrupted, system) -> Step.Interrupted, system
        | other -> failwith $"%s{where}: the write came to %A{other}"

    let private ofRead (where : string) (outcome : ReadOutcome, system : UnixSystem<int, string>) =
        match outcome with
        | ReadOutcome.Answered (ReadAnswer.Completed bytes) -> Step.Answered (Ok (int64 bytes.Length)), system
        | ReadOutcome.Answered (ReadAnswer.Failed error) -> Step.Answered (Error error), system
        | ReadOutcome.WouldBlock _ -> Step.Sleeps, system
        | ReadOutcome.Interrupted -> Step.Interrupted, system
        | other -> failwith $"%s{where}: the read came to %A{other}"

    /// `thread` writes `count` bytes through `fd`.
    let private writeCall
        (where : string)
        (thread : int)
        (fd : int)
        (count : int)
        (system : UnixSystem<int, string>)
        : Step * UnixSystem<int, string>
        =
        UnixReadWrite.write (Callers.thread thread system) fd UserBuffer.Mapped (uint64 count) system
        |> ofWrite where

    /// `thread` reads up to `count` bytes through `fd`.
    let private readCall
        (where : string)
        (thread : int)
        (fd : int)
        (count : int)
        (system : UnixSystem<int, string>)
        : Step * UnixSystem<int, string>
        =
        UnixReadWrite.read (Callers.thread thread system) fd UserBuffer.Mapped (uint64 count) system
        |> ofRead where

    /// `thread` makes the transfer's call of `count` bytes through `fd`.
    let private issue
        (where : string)
        (transfer : Transfer)
        (thread : int)
        (fd : int)
        (count : int)
        (system : UnixSystem<int, string>)
        : Step * UnixSystem<int, string>
        =
        if isWrite transfer then
            writeCall where thread fd count system
        else
            readCall where thread fd count system

    /// The woken sleeper's call, finished.
    let private finish (where : string) (transfer : Transfer) (system : UnixSystem<int, string>) =
        if isWrite transfer then
            UnixReadWrite.finishWrite (Callers.thread sleeper system) system
            |> ofWrite where
        else
            UnixReadWrite.finishRead (Callers.thread sleeper system) system |> ofRead where

    /// The sleeper returns to user mode: every handler it takes runs and
    /// returns. How many ran.
    let rec private returnToUser (where : string) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixSignal.onReturnToUser (Callers.thread sleeper system) system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> 0, system
        | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, None), system) ->
            let system =
                (system, frames)
                ||> List.fold (fun system frame -> UnixSignal.sigreturn (Callers.thread sleeper system) frame.Id system)

            let more, system = returnToUser where system
            List.length frames + more, system
        | other -> failwith $"%s{where}: returning to user mode came to %A{other}"

    /// The sleeper, whose call a signal interrupted, returns to user mode: how
    /// the call ends, and how many handlers ran, every one returning.
    let private returnFromInterrupted
        (where : string)
        (system : UnixSystem<int, string>)
        : InterruptedCall * int * UnixSystem<int, string>
        =
        match UnixSignal.onReturnToUser (Callers.thread sleeper system) system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes (Some call), system) -> call, 0, system
        | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, Some call), system) ->
            let system =
                (system, frames)
                ||> List.fold (fun system frame -> UnixSignal.sigreturn (Callers.thread sleeper system) frame.Id system)

            let more, system = returnToUser where system
            call, List.length frames + more, system
        | other -> failwith $"%s{where}: returning from the interrupted call came to %A{other}"

    /// Non-blocking writes of `chunk` bytes through `fd` by the leader until
    /// EAGAIN.
    let private filled (where : string) (fd : int) (chunk : int) (system : UnixSystem<int, string>) =
        let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) fd true system

        let rec fill (system : UnixSystem<int, string>) =
            match writeCall where (Lone.leader system) fd chunk system with
            | Step.Answered (Ok _), system -> fill system
            | Step.Answered (Error UnixError.EAGAIN), system -> system
            | other, _ -> failwith $"%s{where}: filling fd %d{fd} came to %A{other}"

        let system = fill system
        UnixDescriptor.setNonBlocking (Callers.leader system) fd false system |> snd

    /// Non-blocking reads through `fd` by the leader until EAGAIN.
    let private drained (where : string) (fd : int) (system : UnixSystem<int, string>) =
        let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) fd true system

        let rec drain (system : UnixSystem<int, string>) =
            match readCall where (Lone.leader system) fd 65536 system with
            | Step.Answered (Ok n), system when n > 0L -> drain system
            | Step.Answered (Error UnixError.EAGAIN), system -> system
            | other, _ -> failwith $"%s{where}: draining fd %d{fd} came to %A{other}"

        drain system

    /// The descriptor the sleeper's call is made through and the other end's,
    /// with the call's end filled as the probe fills it.
    let private setUp (where : string) (transfer : Transfer) (system : UnixSystem<int, string>) =
        match transfer with
        | Transfer.PipeWriteNothingIn
        | Transfer.PipeWritePartlyIn
        | Transfer.PipeRead ->
            let readFd, writeFd, system =
                match UnixPipe.pipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
                | Pipe2Answer.Created (r, w), system -> r, w, system
                | other -> failwith $"%s{where}: pipe2 came to %A{other}"

            match transfer with
            | Transfer.PipeWriteNothingIn ->
                // The probe fills by 1-byte writes; whole pages first, then a
                // byte at a time, reach the same full pipe.
                let system = system |> filled where writeFd 65536 |> filled where writeFd 1
                writeFd, readFd, system
            | Transfer.PipeWritePartlyIn -> writeFd, readFd, system
            | _ -> readFd, writeFd, system
        | Transfer.ConnectionWriteNothingTaken
        | Transfer.ConnectionRead ->
            let listener, system = KeventWorld.listenerAt port system
            let client, system = KeventWorld.stream false system

            let system =
                match KeventWorld.connect client port system with
                | SyscallAnswer.Completed 0L, system -> system
                | other, _ -> failwith $"%s{where}: connect came to %A{other}"

            let server, system = KeventWorld.accept listener system
            let system = KeventWorld.close listener system

            let _, system =
                UnixDescriptor.setNonBlocking (Callers.leader system) server false system

            match transfer with
            | Transfer.ConnectionWriteNothingTaken -> client, server, filled where client 65536 system
            | _ -> client, server, system

    /// What the other end could read, for a pipe; the probe's TCP buffers were
    /// fixed at sizes this replay does not configure, so a connection's is not
    /// compared.
    let private heldIn (transfer : Transfer) (callFd : int) (system : UnixSystem<int, string>) : int option =
        match transfer with
        | Transfer.PipeWriteNothingIn
        | Transfer.PipeWritePartlyIn
        | Transfer.PipeRead ->
            match FileDescriptorRegistry.tryFindTarget callFd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Pipe (pipeId, _)) ->
                Some (PipeBuffer.held (UnixMachineState.pipe pipeId (Kernel.machine system)).Buffer)
            | other -> failwith $"fd %d{callFd} names %A{other}"
        | Transfer.ConnectionWriteNothingTaken
        | Transfer.ConnectionRead -> None

    /// What the other end does to unstick a sleeper, as the probe does: take
    /// what fills it, or give it a byte.
    let private unstuck (where : string) (transfer : Transfer) (otherFd : int) (system : UnixSystem<int, string>) =
        if isWrite transfer then
            drained where otherFd system
        else
            match writeCall where (Lone.leader system) otherFd 1 system with
            | Step.Answered (Ok 1L), system -> system
            | other, _ -> failwith $"%s{where}: writing a byte through fd %d{otherFd} came to %A{other}"

    let private replay (platform : SimulatedUnixPlatform) (row : Row) : unit =
        let where = $"%O{platform}: %s{row.Line}"

        // A row whose call was not asleep throughout measured nothing.
        if not (row.AsleepAtFlag && row.AsleepAtSignal) then
            failwith $"%s{where}: the call was not asleep when the flag changed and the signal was sent"

        let system = boot platform row.Restart
        let callFd, otherFd, system = setUp where row.Transfer system
        let count = countOf row.Transfer

        let system =
            match issue where row.Transfer sleeper callFd count system with
            | Step.Sleeps, system -> system
            | other, _ -> failwith $"%s{where}: expected the call to sleep, got %A{other}"

        match heldIn row.Transfer callFd system with
        | Some held when held <> row.Held -> failwith $"%s{where}: the pipe holds %d{held}, measured %d{row.Held}"
        | _ -> ()

        let system =
            if row.NonBlock then
                UnixDescriptor.setNonBlocking (Callers.leader system) callFd true system |> snd
            else
                system

        // Setting the flag wakes nothing: the call was still asleep at the
        // signal.
        Lone.wakes system |> shouldEqual []

        let signo =
            Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering platform) Signal.SIGUSR1

        let system =
            match UnixSignal.pthreadKill (Callers.leader system) sleeper signo system with
            | ProcessFate.Continues (KillAnswer.Completed _, system) -> system
            | other -> failwith $"%s{where}: pthread_kill came to %A{other}"

        let system = Lone.waking [ sleeper ] system

        // As a client does: answered, the thread returns to user mode and runs
        // its handler; restarted, it runs its handler and makes the call again.
        let ending, handled, system =
            match finish where row.Transfer system with
            | Step.Answered answer, system ->
                let handled, system = returnToUser where system
                Ending.Returned answer, handled, system
            | Step.Sleeps, _ -> failwith $"%s{where}: the signalled call slept on without a restart"
            | Step.Interrupted, system ->

            match returnFromInterrupted where system with
            | InterruptedCall.FailsWithEintr, handled, system ->
                Ending.Returned (Error UnixError.EINTR), handled, system
            | InterruptedCall.Restarts, handled, system ->

                match issue where row.Transfer sleeper callFd count system with
                | Step.Answered answer, system ->
                    let more, system = returnToUser where system
                    Ending.Returned answer, handled + more, system
                | Step.Sleeps, system ->
                    let system = unstuck where row.Transfer otherFd system

                    let system = Lone.waking [ sleeper ] system

                    match finish where row.Transfer system with
                    | Step.Answered answer, system ->
                        let more, system = returnToUser where system
                        Ending.SleptOn answer, handled + more, system
                    | other, _ -> failwith $"%s{where}: the unstuck call came to %A{other}"
                | Step.Interrupted, _ -> failwith $"%s{where}: the restarted call was interrupted again"

        if ending <> row.Ending || handled <> row.Handled then
            failwith $"%s{where}: came to %A{ending} with %d{handled} handlers run"

        match row.Then with
        | None -> ()
        | Some measured ->
            let _, system =
                UnixDescriptor.setNonBlocking (Callers.leader system) callFd true system

            match issue where row.Transfer sleeper callFd 1 system with
            | Step.Answered answer, _ when answer = measured -> ()
            | other, _ -> failwith $"%s{where}: the non-blocking call afterwards came to %A{other}"

    let private resources : string list =
        [ "nonblocking-asleep.linux.txt" ; "nonblocking-asleep.darwin.txt" ]

    [<TestCaseSource(nameof resources)>]
    let ``every row replays as measured`` (resource : string) : unit =
        let platform, rows = measured resource
        rows |> List.isEmpty |> shouldEqual false
        rows |> List.iter (replay platform)

    /// The rows where the flavours part: a pipe write asleep with nothing in,
    /// made non-blocking, then signalled without `SA_RESTART`. Asserted of the
    /// outputs themselves, so that an output measured again without them fails
    /// here rather than leaving the replay green.
    [<Test>]
    let ``the outputs hold the rows where the flavours part`` () : unit =
        let answersOf (resource : string) =
            measured resource
            |> snd
            |> List.filter (fun row -> row.Transfer = Transfer.PipeWriteNothingIn && row.NonBlock && not row.Restart)
            |> List.map (fun row -> row.Ending)
            |> List.distinct

        answersOf "nonblocking-asleep.linux.txt"
        |> shouldEqual [ Ending.Returned (Error UnixError.EAGAIN) ]

        answersOf "nonblocking-asleep.darwin.txt"
        |> shouldEqual [ Ending.Returned (Error UnixError.EINTR) ]
