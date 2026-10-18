namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Every row of `docs/probes/huge-timeout` (measured 2026-10-17 on Linux 6.18.5
/// aarch64 and Darwin 27.0.0 arm64) whose call the model makes, replayed from
/// the embedded outputs: `futex(FUTEX_WAIT_PRIVATE)`, `poll` and `epoll_wait`
/// under Linux, and `poll` and `kevent` under Darwin, each with a timeout too
/// large for the clock, a field out of range, or a 1.5 s control. Each replay
/// starts the model's clock where the probe's header says the host's was, since
/// whether Linux's sum of the time now and a timeout overflows depends on it.
///
/// A row the probe measured returning at once is the model's answer to the
/// call; the control times out 1.5 s in, and not a nanosecond sooner; and a row
/// the probe found still asleep 2 s in is asleep 2 s in. A futex row asleep at
/// 2 s then ends as the probe measured: a wake takes it and it answers 0, or
/// an `SA_RESTART` handler's signal ends it with `EINTR` or restarts it.
///
/// The probe ended a sleeping `poll`, `epoll_wait` or `kevent` by writing to a
/// pipe it watched, to show the call was watching; the model's calls here
/// watch nothing, since the timeout is all a row varies, and readiness ending
/// a wait is held by the fixtures of each call. The `ppoll` and
/// `epoll_pwait2` rows have no call in the model, and are not replayed.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestHugeTimeoutMeasured =

    let private linux : SimulatedUnixPlatform =
        HostPlatform.platformOf SimulatedUnixFlavour.Linux

    let private darwin : SimulatedUnixPlatform =
        HostPlatform.platformOf SimulatedUnixFlavour.Darwin

    /// How long the probe watched a call before ending it.
    let private watch : int64 = 2_000_000_000L

    let private address : uint64 = 0x1000UL

    // ------------------------------ The rows ------------------------------- //

    /// A row's timeout, as the probe passed it.
    [<RequireQualifiedAccess>]
    type private Timeout =
        | Milliseconds of int
        | Timespec of seconds : int64 * nanoseconds : int64
        | Null

    /// What the probe measured of a row's call.
    [<RequireQualifiedAccess>]
    type private Measured =
        /// It returned before the watch ended.
        | Returned of ret : int64 * errno : string
        /// It was asleep when the watch ended; `rest` is what the row's ender
        /// then recorded.
        | Asleep of rest : string

    type private Row =
        {
            Line : string
            Call : string
            Ender : string
            Timeout : Timeout
            Measured : Measured
        }

    let private allLines (resource : string) : string list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"embedded resource %s{resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList

    let private lines (resource : string) : string list =
        allLines resource
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))

    /// The monotonic clock's reading, in nanoseconds, when the probe started,
    /// from its header: Linux adds a relative timeout to the time now, so a
    /// replay starts the model's clock there too.
    let private uptimeOf (resource : string) : int64 =
        let header =
            allLines resource
            |> List.pick (fun line ->
                let at = line.IndexOf "CLOCK_MONOTONIC at start "

                if line.StartsWith "#" && at >= 0 then
                    Some (line.Substring (at + "CLOCK_MONOTONIC at start ".Length))
                else
                    None
            )

        match header.Split ([| '.' ; ' ' |]) with
        | [| seconds ; nanoseconds ; "s" |] when nanoseconds.Length = 9 ->
            Int64.Parse seconds * 1_000_000_000L + Int64.Parse nanoseconds
        | _ -> failwith $"unparsed clock reading: %s{header}"

    let private int64Of (text : string) : int64 =
        match text with
        | "INT64_MAX" -> Int64.MaxValue
        | "INT64_MIN" -> Int64.MinValue
        | text -> Int64.Parse text

    let private timeoutOf (call : string) (label : string) : Timeout =
        match call, label with
        | ("poll" | "epoll_wait"), "INT_MAX" -> Timeout.Milliseconds Int32.MaxValue
        | ("poll" | "epoll_wait"), "INT_MIN" -> Timeout.Milliseconds Int32.MinValue
        | ("poll" | "epoll_wait"), label -> Timeout.Milliseconds (Int32.Parse label)
        | _, "null" -> Timeout.Null
        | _, label ->
            match label.Split ',' with
            | [| seconds ; nanoseconds |] -> Timeout.Timespec (int64Of seconds, int64Of nanoseconds)
            | _ -> failwith $"the probe names no timeout %s{label}"

    /// The value of `key=` in `fields`, the first such.
    let private field (key : string) (fields : string list) : string =
        match
            fields
            |> List.tryPick (fun f ->
                if f.StartsWith (key + "=") then
                    Some (f.Substring (key.Length + 1))
                else
                    None
            )
        with
        | Some value -> value
        | None -> failwith $"no %s{key}= among %A{fields}"

    let private rowOf (line : string) : Row =
        match line.Split ' ' |> Array.toList with
        | call :: ender :: timeout :: rest when ender.StartsWith "ender=" && timeout.StartsWith "timeout=" ->
            let measured =
                match rest with
                | asleep :: rest when asleep.StartsWith "asleep-at=" ->
                    field "asleep-at" [ asleep ] |> shouldEqual (string (watch / 1_000_000L))
                    Measured.Asleep (String.Join (" ", rest))
                | fields -> Measured.Returned (Int64.Parse (field "ret" fields), field "errno" fields)

            {
                Line = line
                Call = call
                Ender = ender.Substring "ender=".Length
                Timeout = timeoutOf call (timeout.Substring "timeout=".Length)
                Measured = measured
            }
        | _ -> failwith $"unparsed row: %s{line}"

    let private linuxResource : string =
        "WoofWare.PosixKernel.Test.huge-timeout.linux.txt"

    let private darwinResource : string =
        "WoofWare.PosixKernel.Test.huge-timeout.darwin.txt"

    let private linuxRows : Row list = lines linuxResource |> List.map rowOf

    let private darwinRows : Row list = lines darwinResource |> List.map rowOf

    let private rowsOf (call : string) (rows : Row list) : Row list =
        let rows = rows |> List.filter (fun row -> row.Call = call)

        if List.isEmpty rows then
            failwith $"the probe output has no %s{call} rows"

        rows

    let private errorOf (name : string) : UnixError =
        match name with
        | "EINVAL" -> UnixError.EINVAL
        | "ETIMEDOUT" -> UnixError.ETIMEDOUT
        | other -> failwith $"the probe names no error %s{other} in these rows"

    /// How long the control row's timeout is: 1.5 s, the only timeout the probe
    /// measured expiring.
    let private controlLength (row : Row) : int64 =
        match row.Timeout with
        | Timeout.Milliseconds 1500
        | Timeout.Timespec (1L, 500_000_000L) -> 1_500_000_000L
        | _ -> failwith $"only the 1.5 s control is measured expiring, not: %s{row.Line}"

    // ---------------------------- The machinery ---------------------------- //

    /// One process with threads 0 to `threads - 1`, up for as long as the
    /// probe's machine was when it started.
    let private boot (platform : SimulatedUnixPlatform) (threads : int) : ProcessId * UnixSystem<int, string> =
        let uptime =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> uptimeOf linuxResource
            | SimulatedUnixFlavour.Darwin -> uptimeOf darwinResource

        match Machines.withThreads platform 1 threads with
        | [ pid ], system -> pid, UnixSystem.advanceClock uptime system
        | pids, _ -> failwith $"expected one process, got %A{pids}"

    let private step
        (pid : ProcessId)
        (thread : int)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : SteppedCall<int, string>
        =
        UnixSystem.step (Caller.make pid thread) call system

    let private advance (nanoseconds : int64) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixSystem.advanceClock nanoseconds system

    /// The threads of `pid` that `UnixWait.wake` wakes, and the system after.
    let private sweep (pid : ProcessId) (system : UnixSystem<int, string>) : int list * UnixSystem<int, string> =
        let woken, system = UnixWait.wake system

        woken
        |> List.filter (fun (caller, _) -> Caller.processId caller = pid)
        |> List.map (fun (caller, _) -> Caller.thread caller),
        system

    /// `thread` of `pid`, parked in `parked`, is asleep `watch` in, and woken
    /// by nothing.
    let private asleepThroughTheWatch
        (row : Row)
        (pid : ProcessId)
        (thread : int)
        (parked : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let watched = advance watch parked
        let woken, watched = sweep pid watched

        if not (List.isEmpty woken) then
            failwith $"the probe found the call asleep %d{watch} ns in, and the model woke %A{woken}: %s{row.Line}"

        Proc.parkedIn (Caller.make pid thread) watched
        |> Option.isSome
        |> shouldEqual true

        watched

    /// `thread` of `pid`, parked in `parked`, wakes exactly `length` in.
    let private wokenAt
        (row : Row)
        (pid : ProcessId)
        (thread : int)
        (length : int64)
        (parked : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let early, parked = sweep pid (advance (length - 1L) parked)

        if not (List.isEmpty early) then
            failwith $"the model woke %A{early} a nanosecond before the timeout: %s{row.Line}"

        let woken, parked = sweep pid (advance 1L parked)
        (row.Line, woken) |> shouldEqual (row.Line, [ thread ])
        parked

    // -------------------------------- futex -------------------------------- //

    let private timespecOf (row : Row) : TimespecArgument =
        match row.Timeout with
        | Timeout.Timespec (seconds, nanoseconds) -> TimespecArgument.Readable (seconds, nanoseconds)
        | Timeout.Null -> TimespecArgument.Null
        | Timeout.Milliseconds _ -> failwith $"a futex row with a timeout in milliseconds: %s{row.Line}"

    let private usr1 (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    /// A row's futex wait by thread 1, on a word that holds what it expects,
    /// with the probe's `SA_RESTART` handler for SIGUSR1 installed.
    let private futexWait (row : Row) : ProcessId * SyscallOutcome * UnixSystem<int, string> =
        let pid, system = boot linux 2

        let restarting =
            SignalDisposition.Catch
                { SignalCatch.ofHandler "h" with
                    Restart = true
                }

        let system =
            match UnixSignal.sigaction (Caller.make pid 0) (usr1 system) (Some restarting) system with
            | Ok (_, system) -> system
            | Error error -> failwith $"sigaction failed with %O{error}"

        let call =
            Syscall.Futex (address, UnixFutex.FutexWaitPrivate, 0, CopiedArgument.Readable 0u, timespecOf row, 0u)

        match step pid 1 call system with
        | SteppedCall.Futex (outcome, system) -> pid, outcome, system
        | other -> failwith $"step answered %A{Stepped.view other}"

    let private finishFutex
        (pid : ProcessId)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        match UnixWait.finish (Caller.make pid 1) system with
        | FinishedCall.Futex (outcome, system) -> outcome, system
        | other -> failwith $"finish answered %s{UnionCaseName.ofValue other}"

    let private replayFutex (row : Row) : unit =
        let pid, outcome, system = futexWait row

        match row.Measured, outcome with
        | Measured.Returned (-1L, errno), SyscallOutcome.Answered answer when errno <> "ETIMEDOUT" ->
            (row.Line, answer)
            |> shouldEqual (row.Line, SyscallAnswer.Failed (errorOf errno))
        | Measured.Returned (-1L, "ETIMEDOUT"), SyscallOutcome.WouldBlock _ ->
            let system = wokenAt row pid 1 (controlLength row) system

            (row.Line, fst (finishFutex pid system))
            |> shouldEqual (row.Line, SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.ETIMEDOUT))
        | Measured.Asleep rest, SyscallOutcome.WouldBlock _ ->
            let system = asleepThroughTheWatch row pid 1 system
            let fields = rest.Split ' ' |> Array.toList

            match row.Ender with
            | "wake" ->
                let woke =
                    match
                        step
                            pid
                            0
                            (Syscall.Futex (
                                address,
                                UnixFutex.FutexWakePrivate,
                                1,
                                CopiedArgument.Addressless,
                                TimespecArgument.Null,
                                0u
                            ))
                            system
                    with
                    | SteppedCall.Futex (SyscallOutcome.Answered (SyscallAnswer.Completed n), system) -> n, system
                    | other -> failwith $"the wake answered %A{Stepped.view other}"

                let count, system = woke
                (row.Line, count) |> shouldEqual (row.Line, Int64.Parse (field "woke" fields))
                let woken, system = sweep pid system
                (row.Line, woken) |> shouldEqual (row.Line, [ 1 ])

                (row.Line, fst (finishFutex pid system))
                |> shouldEqual (
                    row.Line,
                    SyscallOutcome.Answered (SyscallAnswer.Completed (Int64.Parse (field "ret" fields)))
                )
            | "restart" ->
                let system =
                    match UnixSignal.pthreadKill (Caller.make pid 0) 1 (usr1 system) system with
                    | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
                    | other -> failwith $"pthread_kill answered %A{other}"

                let woken, system = sweep pid system
                (row.Line, woken) |> shouldEqual (row.Line, [ 1 ])
                let outcome, system = finishFutex pid system
                (row.Line, outcome) |> shouldEqual (row.Line, SyscallOutcome.Interrupted)

                let expected =
                    if rest.StartsWith "after-signal=asleep" then
                        InterruptedCall.Restarts
                    elif rest.StartsWith "after-signal: " && field "errno" fields = "EINTR" then
                        InterruptedCall.FailsWithEintr
                    else
                        failwith $"unparsed after-signal: %s{row.Line}"

                match Interruptions.handled (Caller.make pid 1) system with
                | Ok (call, _) -> (row.Line, call) |> shouldEqual (row.Line, expected)
                | Error refusal -> failwith $"%s{row.Line}: %s{ReturnToUserRefusal.describe refusal}"
            | ender -> failwith $"the probe names no futex ender %s{ender}"
        | _ -> failwith $"the model answered %A{outcome} for: %s{row.Line}"

    [<Test>]
    let ``every futex row is the model's answer`` () : unit =
        for row in rowsOf "futex-wait-private" linuxRows do
            replayFutex row

    // ----------------------- poll, epoll_wait, kevent ---------------------- //

    /// How a row's call began: failing, answering at once, or parking.
    [<RequireQualifiedAccess>]
    type private Started =
        | Failed of UnixError
        | Answered
        | Parked of UnixSystem<int, string>

    let private finishesEmpty (row : Row) (pid : ProcessId) (system : UnixSystem<int, string>) : unit =
        match UnixWait.finish (Caller.make pid 0) system with
        | FinishedCall.Poll (PollOutcome.Answered (_, 0), _)
        | FinishedCall.KqueuePoll (PollOutcome.Answered (_, 0), _)
        | FinishedCall.EpollWait (EpollWaitOutcome.Answered [], _)
        | FinishedCall.Kevent (KeventOutcome.Answered [], _) -> ()
        | other -> failwith $"finish answered %s{UnionCaseName.ofValue other}, not an empty return: %s{row.Line}"

    let private replay (row : Row) (pid : ProcessId) (started : Started) : unit =
        match row.Measured, started with
        | Measured.Returned (-1L, errno), Started.Failed error ->
            (row.Line, error) |> shouldEqual (row.Line, errorOf errno)
        | Measured.Returned (0L, "0"), Started.Parked system ->
            wokenAt row pid 0 (controlLength row) system |> finishesEmpty row pid
        | Measured.Asleep _, Started.Parked system -> asleepThroughTheWatch row pid 0 system |> ignore
        | _ -> failwith $"the model answered %A{started} for: %s{row.Line}"

    let private milliseconds (row : Row) : int =
        match row.Timeout with
        | Timeout.Milliseconds ms -> ms
        | _ -> failwith $"a row with a timespec where milliseconds were expected: %s{row.Line}"

    let private poll (platform : SimulatedUnixPlatform) (row : Row) : ProcessId * Started =
        let pid, system = boot platform 1

        match step pid 0 (Syscall.Poll ([], milliseconds row)) system with
        | SteppedCall.Poll (PollOutcome.Failed error, _) -> pid, Started.Failed error
        | SteppedCall.Poll (PollOutcome.Answered _, _) -> pid, Started.Answered
        | SteppedCall.Poll (PollOutcome.WouldBlock _, system) -> pid, Started.Parked system
        | other -> failwith $"step answered %A{Stepped.view other}"

    [<Test>]
    let ``every Linux poll row is the model's answer`` () : unit =
        for row in rowsOf "poll" linuxRows do
            poll linux row ||> replay row

    [<Test>]
    let ``every Darwin poll row is the model's answer`` () : unit =
        for row in rowsOf "poll" darwinRows do
            match row.Timeout, row.Measured with
            // Asleep 2 s in, which cannot tell waiting for ever from waiting
            // 2^31 ms, the unsigned reading of INT_MIN; so the model refuses.
            | Timeout.Milliseconds ms, Measured.Asleep _ when ms < -1 ->
                Assert.Throws<UnmodelledException> (fun () -> poll darwin row |> ignore)
                |> ignore<UnmodelledException>
            | _ -> poll darwin row ||> replay row

    [<Test>]
    let ``every epoll_wait row is the model's answer`` () : unit =
        for row in rowsOf "epoll_wait" linuxRows do
            let pid, system = boot linux 1

            let epfd, system =
                match step pid 0 (Syscall.EpollCreate1 0) system with
                | SteppedCall.EpollCreate1 (Ok (epfd, system)) -> epfd, system
                | other -> failwith $"epoll_create1 answered %A{Stepped.view other}"

            let started =
                match step pid 0 (Syscall.EpollWait (epfd, UserBuffer.Mapped, 1, milliseconds row)) system with
                | SteppedCall.EpollWait (EpollWaitOutcome.Failed error, _) -> Started.Failed error
                | SteppedCall.EpollWait (EpollWaitOutcome.Answered _, _) -> Started.Answered
                | SteppedCall.EpollWait (EpollWaitOutcome.WouldBlock _, system) -> Started.Parked system
                | other -> failwith $"step answered %A{Stepped.view other}"

            replay row pid started

    [<Test>]
    let ``every kevent row is the model's answer`` () : unit =
        for row in rowsOf "kevent" darwinRows do
            let pid, system = boot darwin 1

            let kq, system =
                match step pid 0 Syscall.Kqueue system with
                | SteppedCall.Kqueue (kq, system) -> kq, system
                | other -> failwith $"kqueue answered %A{Stepped.view other}"

            let timeout =
                match row.Timeout with
                | Timeout.Timespec (seconds, nanoseconds) -> KeventTimeout.Readable (seconds, nanoseconds)
                | Timeout.Null -> KeventTimeout.Null
                | Timeout.Milliseconds _ -> failwith $"a kevent row with a timeout in milliseconds: %s{row.Line}"

            let started =
                match step pid 0 (Syscall.Kevent (kq, [], 0, UserBuffer.Mapped, 1, timeout)) system with
                | SteppedCall.Kevent (KeventOutcome.Failed error, _) -> Started.Failed error
                | SteppedCall.Kevent (KeventOutcome.Answered _, _) -> Started.Answered
                | SteppedCall.Kevent (KeventOutcome.WouldBlock _, system) -> Started.Parked system
                | other -> failwith $"step answered %A{Stepped.view other}"

            replay row pid started
