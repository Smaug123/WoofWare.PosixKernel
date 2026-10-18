namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixFutex`: every row of `docs/probes/futex` (measured 2026-10-17 on Linux
/// 6.18.5 aarch64, glibc 2.41), the screens and counts replayed from its
/// embedded output and the rest transcribed; and the queues held to a
/// first-in-first-out reference over random waits, wakes, signals and clock
/// advances in two processes.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFutex =

    let private linux : SimulatedUnixPlatform =
        HostPlatform.platformOf SimulatedUnixFlavour.Linux

    /// An aligned address every test waits on unless it says otherwise.
    let private address : uint64 = 0x1000UL

    /// One process with threads 0 to `threads - 1`.
    let private boot (threads : int) : ProcessId * UnixSystem<int, string> =
        match Machines.withThreads linux 1 threads with
        | [ pid ], system -> pid, system
        | pids, _ -> failwith $"expected one process, got %A{pids}"

    let private seconds (s : int64) (ns : int64) : TimespecArgument = TimespecArgument.Readable (s, ns)

    /// What `Syscall.Futex` answers for `thread` of `pid`.
    let private futex
        (pid : ProcessId)
        (thread : int)
        (at : uint64)
        (op : int)
        (value : int)
        (word : CopiedArgument<uint32>)
        (timeout : TimespecArgument)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        match UnixSystem.step (Caller.make pid thread) (Syscall.Futex (at, op, value, word, timeout)) system with
        | SteppedCall.Futex (outcome, system) -> outcome, system
        | other -> failwith $"step answered %A{Stepped.view other}"

    /// A `FUTEX_WAIT_PRIVATE` by `thread` at `at`, expecting 0, of a word that
    /// holds `word`.
    let private waitOn
        (pid : ProcessId)
        (thread : int)
        (at : uint64)
        (word : uint32)
        (timeout : TimespecArgument)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        futex pid thread at UnixFutex.FutexWaitPrivate 0 (CopiedArgument.Readable word) timeout system

    /// `thread` waits at `address` on a word that holds what it expects, and
    /// must park.
    let private parks
        (pid : ProcessId)
        (thread : int)
        (timeout : TimespecArgument)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match waitOn pid thread address 0u timeout system with
        | SyscallOutcome.WouldBlock _, system -> system
        | other, _ -> failwith $"thread %d{thread}'s wait answered %A{other} rather than parking"

    /// A `FUTEX_WAKE_PRIVATE` of `n` by `thread` at `at`: how many it took.
    let private wakeAt
        (pid : ProcessId)
        (thread : int)
        (at : uint64)
        (n : int)
        (system : UnixSystem<int, string>)
        : int64 * UnixSystem<int, string>
        =
        match
            futex pid thread at UnixFutex.FutexWakePrivate n CopiedArgument.Addressless TimespecArgument.Null system
        with
        | SyscallOutcome.Answered (SyscallAnswer.Completed count), system -> count, system
        | other, _ -> failwith $"the wake answered %A{other}"

    /// What finishing `thread`'s woken wait answers, through `UnixWait.finish`.
    let private finish
        (pid : ProcessId)
        (thread : int)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        match UnixWait.finish (Caller.make pid thread) system with
        | FinishedCall.Futex (outcome, system) -> outcome, system
        | other -> failwith $"finish answered %s{UnionCaseName.ofValue other}"

    /// The threads of `pid` that `UnixWait.wake` wakes, and the system after.
    let private sweep (pid : ProcessId) (system : UnixSystem<int, string>) : int list * UnixSystem<int, string> =
        let woken, system = UnixWait.wake system

        woken
        |> List.filter (fun (caller, _) -> Caller.processId caller = pid)
        |> List.map (fun (caller, _) -> Caller.thread caller),
        system

    let private usr1 (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    let private urg (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGURG

    /// `disposition` for `signo`, installed by `pid`'s leader.
    let private install
        (pid : ProcessId)
        (signo : int32)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction (Caller.make pid 0) signo (Some disposition) system with
        | Ok (_, system) -> system
        | Error error -> failwith $"sigaction failed with %O{error}"

    let private handler (restart : bool) : SignalDisposition<string> =
        SignalDisposition.Catch
            { SignalCatch.ofHandler "h" with
                Restart = restart
            }

    /// `signo` sent by `pid`'s `sender` to its `target`.
    let private kill
        (pid : ProcessId)
        (sender : int)
        (target : int)
        (signo : int32)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.pthreadKill (Caller.make pid sender) target signo system with
        | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
        | other -> failwith $"pthread_kill answered %A{other}"

    let private owed (pid : ProcessId) (thread : int) (system : UnixSystem<int, string>) : OwedReturn option =
        UnixThreadTable.owedBy thread (UnixSystem.threads pid system)

    let private failed (error : UnixError) : SyscallOutcome =
        SyscallOutcome.Answered (SyscallAnswer.Failed error)

    let private completed (count : int64) : SyscallOutcome =
        SyscallOutcome.Answered (SyscallAnswer.Completed count)

    // ------------------------- Replaying the probe ------------------------- //

    let private measured : string list =
        let name = "WoofWare.PosixKernel.Test.futex.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))

    let private errorOf (name : string) : UnixError =
        match name with
        | "EINVAL" -> UnixError.EINVAL
        | "EAGAIN" -> UnixError.EAGAIN
        | "EFAULT" -> UnixError.EFAULT
        | "ETIMEDOUT" -> UnixError.ETIMEDOUT
        | other -> failwith $"the probe names no error %s{other} in these rows"

    /// The probe's addresses: where each lies, what the caller's memory there
    /// is, and the value the wait expects.
    let private probeAddress (name : string) : uint64 * CopiedArgument<uint32> * int =
        match name with
        | "match" -> address, CopiedArgument.Readable 0u, 0
        | "mismatch" -> address, CopiedArgument.Readable 0u, 7
        | "misaligned" -> address + 1UL, CopiedArgument.Readable 0u, 0
        | "misaligned-mismatch" -> address + 1UL, CopiedArgument.Readable 0u, 7
        | "unmapped" -> 0x2000UL, CopiedArgument.Unmapped 0x2000UL, 0
        | "unmapped-misaligned" -> 0x2001UL, CopiedArgument.Unmapped 0x2001UL, 0
        | "null" -> 0UL, CopiedArgument.Unmapped 0UL, 0
        // The wake rows' own names.
        | "aligned-no-waiters" -> address, CopiedArgument.Addressless, 0
        | other -> failwith $"the probe names no address %s{other}"

    /// The probe's timeouts, and their length in nanoseconds where they have one.
    let private probeTimeout (name : string) : TimespecArgument * int64 option =
        match name with
        | "null" -> TimespecArgument.Null, None
        | "10ms" -> seconds 0L 10_000_000L, Some 10_000_000L
        | "zero" -> seconds 0L 0L, Some 0L
        | "nsec=1e9" -> seconds 0L 1_000_000_000L, None
        | "nsec=-1" -> seconds 0L -1L, None
        | "sec=-1" -> seconds -1L 0L, None
        | "unmapped" -> TimespecArgument.Unreadable, None
        | other -> failwith $"the probe names no timeout %s{other}"

    [<Test>]
    let ``every wait-screen row is the model's answer`` () : unit =
        let rows =
            measured
            |> List.choose (fun line ->
                let row =
                    Regex.Match (line, @"^wait-screen addr=(\S+) timeout=(\S+) ret=(-?\d+) errno=(\S+) took=\d+$")

                if row.Success then
                    Some (line, row.Groups.[1].Value, row.Groups.[2].Value, row.Groups.[4].Value)
                else
                    None
            )

        rows |> List.length |> shouldEqual 48

        for line, addressName, timeoutName, errno in rows do
            let pid, system = boot 1
            let at, word, value = probeAddress addressName
            let timeout, length = probeTimeout timeoutName

            let answer =
                match futex pid 0 at UnixFutex.FutexWaitPrivate value word timeout system with
                | SyscallOutcome.Answered answer, _ -> answer
                | SyscallOutcome.WouldBlock _, parked ->
                    // A wait that times out sleeps first, even for a zero
                    // timeout: its deadline passes, and it is finished.
                    let length =
                        match length with
                        | Some length -> length
                        | None -> failwith $"%s{line}: parked with no timeout"

                    let woken, parked = sweep pid (UnixSystem.advanceClock length parked)
                    woken |> shouldEqual [ 0 ]

                    match finish pid 0 parked with
                    | SyscallOutcome.Answered answer, _ -> answer
                    | other, _ -> failwith $"%s{line}: finishing answered %A{other}"
                | other, _ -> failwith $"%s{line}: answered %A{other}"

            (line, answer) |> shouldEqual (line, SyscallAnswer.Failed (errorOf errno))

    [<Test>]
    let ``every wake-screen row is the model's answer`` () : unit =
        let rows =
            measured
            |> List.choose (fun line ->
                let row =
                    Regex.Match (line, @"^wake-screen addr=(\S+) n=1 ret=(-?\d+) errno=(\S+)$")

                if row.Success then
                    Some (line, row.Groups.[1].Value, int64 row.Groups.[2].Value, row.Groups.[3].Value)
                else
                    None
            )

        rows |> List.length |> shouldEqual 5

        for line, addressName, ret, errno in rows do
            let pid, system = boot 1
            let at, word, _ = probeAddress addressName

            let expected =
                if errno = "0" then
                    SyscallAnswer.Completed ret
                else
                    SyscallAnswer.Failed (errorOf errno)

            match futex pid 0 at UnixFutex.FutexWakePrivate 1 word TimespecArgument.Null system with
            | SyscallOutcome.Answered answer, _ -> (line, answer) |> shouldEqual (line, expected)
            | other, _ -> failwith $"%s{line}: answered %A{other}"

    [<Test>]
    let ``every count row is the model's answer`` () : unit =
        let rows =
            measured
            |> List.choose (fun line ->
                let row =
                    Regex.Match (line, @"^count waiters=(\d) n=(\S+) ret=(\d+) errno=0 returned=(\d)(.*)$")

                if row.Success then
                    let n =
                        match row.Groups.[2].Value with
                        | "INT_MAX" -> Int32.MaxValue
                        | "INT_MIN" -> Int32.MinValue
                        | n -> int n

                    let returned =
                        Regex.Matches (row.Groups.[5].Value, @"([ABC]):ret=0")
                        |> Seq.map (fun m -> int m.Groups.[1].Value.[0] - int 'A' + 1)
                        |> List.ofSeq

                    Some (line, int row.Groups.[1].Value, n, int64 row.Groups.[3].Value, returned)
                else
                    None
            )

        rows |> List.length |> shouldEqual 14

        for line, waiters, n, ret, returned in rows do
            // The probe's waiters A, B and C are threads 1, 2 and 3, parked in
            // that order; thread 0 wakes.
            let pid, system = boot 4

            let system =
                (system, [ 1..waiters ])
                ||> List.fold (fun system thread -> parks pid thread TimespecArgument.Null system)

            let count, system = wakeAt pid 0 address n system
            let woken, _ = sweep pid system
            (line, count, woken) |> shouldEqual (line, ret, returned)

    [<Test>]
    let ``every range row is the model's answer, under the probe's address limit`` () : unit =
        // The probe ran on an aarch64 kernel with a 48-bit user address space.
        let configure (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
            UnixBootImage.withUserAddressLimit ObservedUserAddressLimit.Arm64FortyEightBit image

        let rows =
            measured
            |> List.choose (fun line ->
                let row =
                    Regex.Match (
                        line,
                        @"^range (wait|wake) addr=0x([0-9a-f]+)( timeout=nsec=1e9)? ret=(-?\d+) errno=(\S+)$"
                    )

                if row.Success then
                    let op =
                        if row.Groups.[1].Value = "wait" then
                            UnixFutex.FutexWaitPrivate
                        else
                            UnixFutex.FutexWakePrivate

                    let timeout =
                        if row.Groups.[3].Success then
                            seconds 0L 1_000_000_000L
                        else
                            seconds 0L 10_000_000L

                    let expected =
                        match row.Groups.[5].Value with
                        | "0" -> SyscallAnswer.Completed (int64 row.Groups.[4].Value)
                        | errno -> SyscallAnswer.Failed (errorOf errno)

                    Some (line, op, Convert.ToUInt64 (row.Groups.[2].Value, 16), timeout, expected)
                else
                    None
            )

        rows |> List.length |> shouldEqual 15

        for line, op, at, timeout, expected in rows do
            match Machines.withThreadsOn configure SimulatedUnixPlatform.linuxArm64 1 1 with
            | [ pid ], system ->
                // Nothing maps these addresses.
                match futex pid 0 at op 0 (CopiedArgument.Unmapped at) timeout system with
                | SyscallOutcome.Answered answer, _ -> (line, answer) |> shouldEqual (line, expected)
                | other, _ -> failwith $"%s{line}: answered %A{other}"
            | pids, _ -> failwith $"expected one process, got %A{pids}"

    // ------------------------- The transcribed rows ------------------------ //

    [<Test>]
    let ``the comparison is of 32-bit words`` () : unit =
        // The "compare" row: a word of 0xFFFFFFFF matches -1, and 0x80000000
        // matches INT_MIN, so each parks and times out.
        for word, value in [ 0xFFFFFFFFu, -1 ; 0x80000000u, Int32.MinValue ] do
            let pid, system = boot 1

            match
                futex
                    pid
                    0
                    address
                    UnixFutex.FutexWaitPrivate
                    value
                    (CopiedArgument.Readable word)
                    (seconds 0L 10_000_000L)
                    system
            with
            | SyscallOutcome.WouldBlock _, _ -> ()
            | other, _ -> failwith $"word 0x%x{word} against %d{value}: %A{other}"

    [<Test>]
    let ``a zero timeout parks, and a wake before it runs takes it`` () : unit =
        // The "switches" rows: a zero timeout sleeps before it answers
        // ETIMEDOUT. So a wake made before the waiter runs takes it, as the
        // "race" rows show of an expired timeout.
        let pid, system = boot 2
        let system = parks pid 1 (seconds 0L 0L) system
        let count, system = wakeAt pid 0 address 1 system
        count |> shouldEqual 1L
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ]
        finish pid 1 system |> fst |> shouldEqual (completed 0L)

        // Unwoken, it times out at once.
        let pid, system = boot 2
        let system = parks pid 1 (seconds 0L 0L) system
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ]
        finish pid 1 system |> fst |> shouldEqual (failed UnixError.ETIMEDOUT)

    /// `KTIME_SEC_MAX`: from this many seconds, Linux saturates a timeout.
    let private ktimeSecondsMax : int64 = 9223372036L

    /// The reference: when a wait made at `now` with a relative timeout of
    /// `s` seconds and `ns` nanoseconds times out. Linux saturates the timeout
    /// from `KTIME_SEC_MAX` seconds, and its sum with the time now where that
    /// overflows; a saturated wait never times out. Any other keeps its
    /// instant, computed here without overflow.
    let private referenceTimeout (now : int64) (s : int64) (ns : int64) : FutexTimeout =
        if s >= ktimeSecondsMax then
            FutexTimeout.Unbounded
        else
            let sum = bigint now + bigint s * bigint 1_000_000_000L + bigint ns

            if sum > bigint Int64.MaxValue then
                FutexTimeout.Unbounded
            else
                FutexTimeout.Until (int64 sum)

    /// The timeout of the futex wait `thread` of `pid` is parked in.
    let private parkedTimeout (pid : ProcessId) (thread : int) (system : UnixSystem<int, string>) : FutexTimeout =
        match UnixThreadTable.parkedFor thread (UnixSystem.threads pid system) with
        | Some (ParkedSyscall.Futex wait) -> wait.FutexTimeout
        | other -> failwith $"thread %d{thread} is parked in %A{other}, not a futex wait"

    [<Test>]
    let ``a timeout Linux saturates never times out, and every other keeps its instant`` () : unit =
        // The "huge" rows and `docs/probes/huge-timeout`: every valid timeout
        // too large for the clock slept until a wake ended it.
        let sumBoundary = Int64.MaxValue - 9223372035_000_000_000L

        for uptime, s, ns, expected in
            [
                5_000L, 9223372035L, 0L, FutexTimeout.Until 9223372035_000_005_000L
                5_000L, 9223372035L, 999_999_999L, FutexTimeout.Until (9223372035_999_999_999L + 5_000L)
                5_000L, 9223372036L, 0L, FutexTimeout.Unbounded
                5_000L, Int64.MaxValue, 999_999_999L, FutexTimeout.Unbounded
                sumBoundary, 9223372035L, 0L, FutexTimeout.Until Int64.MaxValue
                sumBoundary + 1L, 9223372035L, 0L, FutexTimeout.Unbounded
                Int64.MaxValue, 0L, 1L, FutexTimeout.Unbounded
            ] do
            let pid, system = boot 2
            let system = UnixSystem.advanceClock uptime system
            let system = parks pid 1 (seconds s ns) system
            let row = $"%d{uptime} ns up, %d{s} s %d{ns} ns"
            (row, parkedTimeout pid 1 system) |> shouldEqual (row, expected)

            match expected with
            | FutexTimeout.Until deadline -> (row, UnixWait.deadlines system) |> shouldEqual (row, [ deadline ])
            | FutexTimeout.Untimed -> failwith "no row here is untimed"
            | FutexTimeout.Unbounded ->
                (row, UnixWait.deadlines system) |> shouldEqual (row, [])

                // The clock's last instant does not end it; a wake does.
                let system =
                    UnixSystem.advanceClock (Int64.MaxValue - UnixSystem.nanosecondsSinceBoot system) system

                (row, fst (sweep pid system)) |> shouldEqual (row, [])
                let count, system = wakeAt pid 0 address 1 system
                count |> shouldEqual 1L
                let _, system = sweep pid system
                (row, fst (finish pid 1 system)) |> shouldEqual (row, completed 0L)

    /// Which of Linux's three cases a timeout falls in.
    [<RequireQualifiedAccess>]
    type private SaturationLabel =
        | Kept
        | TimeoutSaturates
        | SumSaturates

    [<Test>]
    let ``a wait's timeout is the reference's, at any uptime`` () : unit =
        let uptimeGen : Gen<int64> =
            Gen.oneof
                [
                    Gen.choose64 (0L, 10_000_000_000L)
                    Gen.choose64 (0L, Int64.MaxValue)
                    Gen.choose64 (0L, 2_000_000_000L) |> Gen.map (fun d -> Int64.MaxValue - d)
                ]

        let caseGen : Gen<int64 * int64 * int64> =
            gen {
                let! uptime = uptimeGen
                // Seconds where the sum with the uptime just fits or just
                // overflows, as well as around `KTIME_SEC_MAX` and anywhere.
                let edge = (Int64.MaxValue - uptime) / 1_000_000_000L

                let! s =
                    Gen.oneof
                        [
                            Gen.choose64 (0L, 100L)
                            Gen.choose64 (max 0L (edge - 2L), edge + 2L)
                            Gen.choose64 (ktimeSecondsMax - 3L, ktimeSecondsMax + 3L)
                            Gen.choose64 (0L, Int64.MaxValue)
                        ]

                let! ns =
                    Gen.oneof
                        [
                            Gen.constant 0L
                            Gen.constant 999_999_999L
                            Gen.choose64 (0L, 999_999_999L)
                        ]

                return uptime, s, ns
            }

        let property (cover : SaturationLabel -> unit) ((uptime, s, ns) : int64 * int64 * int64) : unit =
            let expected = referenceTimeout uptime s ns

            match expected with
            | FutexTimeout.Until _ -> cover SaturationLabel.Kept
            | FutexTimeout.Unbounded when s >= ktimeSecondsMax -> cover SaturationLabel.TimeoutSaturates
            | FutexTimeout.Unbounded -> cover SaturationLabel.SumSaturates
            | FutexTimeout.Untimed -> failwith "the reference made a timespec untimed"

            let pid, system = boot 2
            let system = UnixSystem.advanceClock uptime system
            let system = parks pid 1 (seconds s ns) system
            parkedTimeout pid 1 system |> shouldEqual expected

            UnixWait.deadlines system
            |> shouldEqual (
                match expected with
                | FutexTimeout.Until deadline -> [ deadline ]
                | FutexTimeout.Untimed
                | FutexTimeout.Unbounded -> []
            )

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen caseGen) property

        for label in
            [
                SaturationLabel.Kept
                SaturationLabel.TimeoutSaturates
                SaturationLabel.SumSaturates
            ] do
            coverage.Count label |> shouldBeGreaterThan 20

    [<Test>]
    let ``waiters wake first in, first out`` () : unit =
        // The "order fifo" rows: A, B, C, one at a time.
        let pid, system = boot 4

        let system =
            (system, [ 1..3 ])
            ||> List.fold (fun system thread -> parks pid thread TimespecArgument.Null system)

        let order, _ =
            ((([] : int list), system), [ 1..3 ])
            ||> List.fold (fun (order, system) _ ->
                let count, system = wakeAt pid 0 address 1 system
                count |> shouldEqual 1L
                let woken, system = sweep pid system

                let system =
                    (system, woken)
                    ||> List.fold (fun system thread ->
                        let outcome, system = finish pid thread system
                        outcome |> shouldEqual (completed 0L)
                        system
                    )

                order @ woken, system
            )

        order |> shouldEqual [ 1 ; 2 ; 3 ]

    [<Test>]
    let ``a waiter that waits again goes to the back`` () : unit =
        // The "order rewait" rows: A, B, C, A, B, C.
        let pid, system = boot 4

        let system =
            (system, [ 1..3 ])
            ||> List.fold (fun system thread -> parks pid thread TimespecArgument.Null system)

        let order, _ =
            ((([] : int list), system), [ 1..6 ])
            ||> List.fold (fun (order, system) _ ->
                let _, system = wakeAt pid 0 address 1 system
                let woken, system = sweep pid system

                let system =
                    (system, woken)
                    ||> List.fold (fun system thread ->
                        let _, system = finish pid thread system
                        parks pid thread TimespecArgument.Null system
                    )

                order @ woken, system
            )

        order |> shouldEqual [ 1 ; 2 ; 3 ; 1 ; 2 ; 3 ]

    [<Test>]
    let ``a wake of two takes the first two`` () : unit =
        // The "order n=2" rows: AB, then C.
        let pid, system = boot 4

        let system =
            (system, [ 1..3 ])
            ||> List.fold (fun system thread -> parks pid thread TimespecArgument.Null system)

        let count, system = wakeAt pid 0 address 2 system
        count |> shouldEqual 2L
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ; 2 ]
        let count, system = wakeAt pid 0 address 1 system
        count |> shouldEqual 1L
        sweep pid system |> fst |> shouldEqual [ 3 ]

    /// A waiter, thread 1, parked with `timeout`, sent USR1 by thread 0 under
    /// `disposition`, then woken and finished.
    let private signalled
        (timeout : TimespecArgument)
        (disposition : SignalDisposition<string>)
        : ProcessId * SyscallOutcome * UnixSystem<int, string>
        =
        let pid, system = boot 2
        let system = install pid (usr1 system) disposition system
        let system = parks pid 1 timeout system
        let system = kill pid 0 1 (usr1 system) system
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ]
        let outcome, system = finish pid 1 system
        pid, outcome, system

    [<Test>]
    let ``a handler's signal interrupts a wait as the probe measured`` () : unit =
        // The "signal handler" rows: untimed, EINTR without SA_RESTART and a
        // restart with it; timed, EINTR either way.
        for timeout, restart, expected in
            [
                TimespecArgument.Null, false, InterruptedCall.FailsWithEintr
                TimespecArgument.Null, true, InterruptedCall.Restarts
                seconds 2L 0L, false, InterruptedCall.FailsWithEintr
                seconds 2L 0L, true, InterruptedCall.FailsWithEintr
            ] do
            let pid, outcome, system = signalled timeout (handler restart)
            outcome |> shouldEqual SyscallOutcome.Interrupted

            match Interruptions.handled (Caller.make pid 1) system with
            | Ok (call, _) -> (timeout, restart, call) |> shouldEqual (timeout, restart, expected)
            | Error refusal -> failwith $"%A{timeout} restart=%b{restart}: %s{ReturnToUserRefusal.describe refusal}"

    [<Test>]
    let ``a restarted wait reads its word again`` () : unit =
        // The "signal handler-stores-1 flags=SA_RESTART untimed" row: the
        // handler stored 1 to the word, and the restart answered EAGAIN. The
        // caller makes the restarted call, reading the word as it does.
        let pid, outcome, system = signalled TimespecArgument.Null (handler true)
        outcome |> shouldEqual SyscallOutcome.Interrupted

        match Interruptions.handled (Caller.make pid 1) system with
        | Ok (InterruptedCall.Restarts, system) ->
            waitOn pid 1 address 1u TimespecArgument.Null system
            |> fst
            |> shouldEqual (failed UnixError.EAGAIN)
        | other -> failwith $"%A{other}"

    [<Test>]
    let ``an ignored, defaulted or blocked signal does not end a wait`` () : unit =
        // The "signal SIG_IGN", "signal URG-default" and "signal
        // blocked-by-waiter" rows: each wait ended at the wake, with 0.
        let ignored () =
            let pid, system = boot 2
            let system = install pid (usr1 system) SignalDisposition.Ignore system
            pid, usr1 system, system

        let defaulted () =
            let pid, system = boot 2
            pid, urg system, system

        let blocked () =
            let pid, system = boot 2
            let system = install pid (usr1 system) (handler false) system

            let numbering = HostPlatform.signalNumberingOf SimulatedUnixFlavour.Linux
            let mask = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR1)

            match UnixSignal.pthreadSigmask (Caller.make pid 1) (MaskHow.block numbering) (Some mask) system with
            | Ok (_, system) -> pid, usr1 system, system
            | Error error -> failwith $"pthread_sigmask: %O{error}"

        for make in [ ignored ; defaulted ; blocked ] do
            let pid, signo, system = make ()
            let system = parks pid 1 TimespecArgument.Null system
            let system = kill pid 0 1 signo system
            sweep pid system |> fst |> shouldEqual []
            let count, system = wakeAt pid 0 address 1 system
            count |> shouldEqual 1L
            let _, system = sweep pid system
            finish pid 1 system |> fst |> shouldEqual (completed 0L)

    [<Test>]
    let ``a wait whose waking signal has gone restarts through its caller, or is refused if it has a deadline``
        ()
        : unit
        =
        // The "stop" rows: with no handler run, Linux restarts the wait,
        // reading its word again, and a timed one keeps its first deadline.
        // Here a handler's signal wakes the waiter, and the leader ignores the
        // signal before the wait is finished, discarding it. A wait Linux
        // saturated keeps a deadline that never comes, which the call made
        // again from the start has too.
        let woken (timeout : TimespecArgument) =
            let pid, system = boot 2
            let system = install pid (usr1 system) (handler true) system
            let system = parks pid 1 timeout system
            let system = kill pid 0 1 (usr1 system) system
            let woken, system = sweep pid system
            woken |> shouldEqual [ 1 ]
            pid, install pid (usr1 system) SignalDisposition.Ignore system

        for timeout in [ TimespecArgument.Null ; seconds Int64.MaxValue 0L ] do
            let pid, system = woken timeout
            let outcome, system = finish pid 1 system
            outcome |> shouldEqual SyscallOutcome.Interrupted

            match Interruptions.handled (Caller.make pid 1) system with
            | Ok (InterruptedCall.Restarts, system) ->
                // The word changed while the wait slept: the restart reads it.
                waitOn pid 1 address 1u timeout system
                |> fst
                |> shouldEqual (failed UnixError.EAGAIN)
            | other -> failwith $"%A{timeout}: %A{other}"

        let pid, system = woken (seconds 2L 0L)

        (fun () -> UnixWait.finish (Caller.make pid 1) system |> ignore<FinishedCall<int, string>>)
        |> shouldFail<UnmodelledException>

    [<Test>]
    let ``a wake takes a waiter a signal woke, and the handler runs as it returns`` () : unit =
        // The "race signal-then-wake" rows: the wake returned 1, the waiter 0,
        // and the handler ran; untimed with flags 0 and SA_RESTART, and timed.
        for timeout, restart in
            [
                TimespecArgument.Null, false
                TimespecArgument.Null, true
                seconds 2L 0L, false
            ] do
            let pid, system = boot 2
            let system = install pid (usr1 system) (handler restart) system
            let system = parks pid 1 timeout system
            let system = kill pid 0 1 (usr1 system) system
            let count, system = wakeAt pid 0 address 1 system
            count |> shouldEqual 1L
            let _, system = sweep pid system
            let outcome, system = finish pid 1 system
            outcome |> shouldEqual (completed 0L)
            owed pid 1 system |> shouldEqual (Some OwedReturn.SignalDue)

    [<Test>]
    let ``a wake takes a waiter whose timeout has passed`` () : unit =
        // The "race timeout-then-wake" rows.
        let pid, system = boot 2
        let system = parks pid 1 (seconds 0L 10_000_000L) system
        let system = UnixSystem.advanceClock 50_000_000L system
        let count, system = wakeAt pid 0 address 1 system
        count |> shouldEqual 1L
        let _, system = sweep pid system
        finish pid 1 system |> fst |> shouldEqual (completed 0L)

    [<Test>]
    let ``a timeout beats a signal, and the handler runs as the wait returns`` () : unit =
        // The "race timeout-then-signal" rows: ETIMEDOUT, and the handler ran;
        // flags 0 and SA_RESTART.
        for restart in [ false ; true ] do
            let pid, system = boot 2
            let system = install pid (usr1 system) (handler restart) system
            let system = parks pid 1 (seconds 0L 10_000_000L) system
            let system = UnixSystem.advanceClock 50_000_000L system
            let system = kill pid 0 1 (usr1 system) system
            let _, system = sweep pid system
            let outcome, system = finish pid 1 system
            outcome |> shouldEqual (failed UnixError.ETIMEDOUT)
            owed pid 1 system |> shouldEqual (Some OwedReturn.SignalDue)

    [<Test>]
    let ``a waiter woken some other way keeps its place until it runs`` () : unit =
        // The "race signalled-A-keeps-slot" and "race timed-out-A-keeps-slot"
        // rows: A then B parked; A woken by a signal, or by its timeout; a
        // wake of one takes A, and B sleeps on.
        let bySignal () =
            let pid, system = boot 3
            let system = install pid (usr1 system) (handler false) system
            let system = parks pid 1 TimespecArgument.Null system
            let system = parks pid 2 TimespecArgument.Null system
            pid, kill pid 0 1 (usr1 system) system

        let byTimeout () =
            let pid, system = boot 3
            let system = parks pid 1 (seconds 0L 10_000_000L) system
            let system = parks pid 2 TimespecArgument.Null system
            pid, UnixSystem.advanceClock 50_000_000L system

        for make in [ bySignal ; byTimeout ] do
            let pid, system = make ()
            let woken, system = sweep pid system
            woken |> shouldEqual [ 1 ]
            let count, system = wakeAt pid 0 address 1 system
            count |> shouldEqual 1L
            sweep pid system |> fst |> shouldEqual []
            let outcome, system = finish pid 1 system
            outcome |> shouldEqual (completed 0L)
            sweep pid system |> fst |> shouldEqual []

    [<Test>]
    let ``a waiter a wake has taken is skipped by the next`` () : unit =
        // The "race taken-A-is-skipped" rows: 1 and 1, and both return 0.
        let pid, system = boot 3
        let system = parks pid 1 TimespecArgument.Null system
        let system = parks pid 2 TimespecArgument.Null system
        let first, system = wakeAt pid 0 address 1 system
        let second, system = wakeAt pid 0 address 1 system
        (first, second) |> shouldEqual (1L, 1L)
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ; 2 ]
        finish pid 1 system |> fst |> shouldEqual (completed 0L)
        finish pid 2 system |> fst |> shouldEqual (completed 0L)

    [<Test>]
    let ``another process's wake does not reach a private waiter`` () : unit =
        // The "xproc" rows: the parent's wake returned 0, and the child timed
        // out.
        match Machines.withThreads linux 2 2 with
        | [ waiter ; waker ], system ->
            let system = parks waiter 1 (seconds 0L 300_000_000L) system
            let count, system = wakeAt waker 0 address 1 system
            count |> shouldEqual 0L
            Machines.wakes system |> shouldEqual []
        | pids, _ -> failwith $"expected two processes, got %A{pids}"

    // ------------------------------ Refusals ------------------------------- //

    let private direct (platform : SimulatedUnixPlatform) (op : int) (at : uint64) (word : UserBuffer) : unit -> unit =
        fun () ->
            let system =
                UnixSystem.initial<int, string> platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            UnixFutex.futex (Callers.leader system) at op 0 word TimespecArgument.Null system
            |> ignore<CallProgress<PausedFutexWait<int, string>, SyscallOutcome * UnixSystem<int, string>>>

    [<Test>]
    let ``Darwin has no futex`` () : unit =
        for op in [ UnixFutex.FutexWaitPrivate ; UnixFutex.FutexWakePrivate ] do
            direct SimulatedUnixPlatform.macOsArm64 op address UserBuffer.Mapped
            |> shouldFail<PlatformNotSupportedException>

    [<Test>]
    let ``every other operation is refused`` () : unit =
        // FUTEX_WAIT and FUTEX_WAKE without FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE,
        // FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAKE_BITSET_PRIVATE, FUTEX_LOCK_PI,
        // FUTEX_WAIT_PRIVATE with FUTEX_CLOCK_REALTIME, and nonsense.
        for op in [ 0 ; 1 ; 3 ; 9 ; 10 ; 137 ; 138 ; 6 ; 384 ; -1 ; 999 ] do
            direct linux op address UserBuffer.Mapped |> shouldFail<UnmodelledException>

    [<Test>]
    let ``a wait whose word the caller cannot produce is refused`` () : unit =
        direct linux UnixFutex.FutexWaitPrivate address UserBuffer.Opaque
        |> shouldFail<UnmodelledException>

    [<Test>]
    let ``a wait whose word is described elsewhere is a contradiction`` () : unit =
        for word in [ UserBuffer.Addressless ; UserBuffer.Unmapped (address + 4UL) ] do
            direct linux UnixFutex.FutexWaitPrivate address word
            |> shouldFail<ArgumentException>

    [<Test>]
    let ``a misaligned wait answers EINVAL whatever its word`` () : unit =
        // The screen comes before the word is read, so no word is consulted.
        for word in [ UserBuffer.Opaque ; UserBuffer.Addressless ; UserBuffer.Mapped ] do
            let system =
                UnixSystem.initial<int, string> linux
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            match
                UnixFutex.futex
                    (Callers.leader system)
                    (address + 2UL)
                    UnixFutex.FutexWaitPrivate
                    0
                    word
                    TimespecArgument.Null
                    system
            with
            | CallProgress.Answered (outcome, _) -> outcome |> shouldEqual (failed UnixError.EINVAL)
            | CallProgress.NeedsCopyIn _ -> failwith "a misaligned wait read its word"

    // ---------------------- The reference model ---------------------------- //

    /// One step of a random run, by a thread of process `Process` (0 or 1).
    [<RequireQualifiedAccess>]
    type private Op =
        /// `Thread` waits at address `Address` (0 or 1), with a timeout of
        /// `Timeout` nanoseconds if any, on a word that holds what it expects
        /// if `Matches`.
        | Wait of Process : int * Thread : int * Address : int * Timeout : int64 option * Matches : bool
        | Wake of Process : int * Thread : int * Address : int * Count : int
        /// `Sender` sends USR1 to `Target`, both of process `Process`.
        | Kill of Process : int * Sender : int * Target : int
        | Advance of nanoseconds : int64
        | Sweep
        | Finish of Process : int * Thread : int
        /// Every woken thread's wait finished, in order of process and thread.
        | FinishAll
        | Return of Process : int * Thread : int
        /// Every thread that owes a return to user mode returned, in order of
        /// process and thread.
        | ReturnAll

    /// A thread as the reference sees it.
    [<RequireQualifiedAccess>]
    type private RefThread =
        | Running
        /// Owes a return to user mode: for a signal (`None`), or to end an
        /// interrupted wait as it says.
        | Owes of InterruptedCall option
        | Parked of RefPark

    and private RefPark =
        {
            Address : int
            Timeout : FutexTimeout
            Ordinal : int64
            Taken : bool
            Woken : bool
        }

    type private RefState =
        {
            Clock : int64
            NextOrdinal : int64
            Threads : Map<int * int, RefThread>
            /// The threads with USR1 pending.
            Pending : Set<int * int>
            /// Whether each process's handler is installed with `SA_RESTART`.
            Restart : Map<int, bool>
        }

    /// What the reference answers for an op it can make.
    [<RequireQualifiedAccess>]
    type private RefAnswer =
        | Outcome of string
        | Woken of (int * int) list
        | Ended of InterruptedCall option
        | Nothing
        | Each of ((int * int) * RefAnswer) list

    let private addresses : uint64 list = [ 0x1000UL ; 0x1004UL ]
    let private threadsEach : int = 4

    let private opGen : Gen<Op> =
        let proc = Gen.choose (0, 1)
        let thread = Gen.choose (0, threadsEach - 1)
        let addr = Gen.choose (0, 1)

        Gen.frequency
            [
                6,
                gen {
                    let! p = proc
                    let! t = thread
                    let! a = addr

                    let! timeout =
                        Gen.elements [ None ; None ; Some 0L ; Some 1_000L ; Some 10_000_000L ; Some Int64.MaxValue ]

                    let! matches = Gen.frequency [ 5, Gen.constant true ; 1, Gen.constant false ]
                    return Op.Wait (p, t, a, timeout, matches)
                }
                4,
                gen {
                    let! p = proc
                    let! t = thread
                    let! a = addr
                    let! n = Gen.choose (-2, 3)
                    return Op.Wake (p, t, a, n)
                }
                4,
                gen {
                    let! p = proc
                    let! s = thread
                    let! t = thread
                    return Op.Kill (p, s, t)
                }
                2, Gen.elements [ 0L ; 500L ; 5_000_000L ; 20_000_000L ] |> Gen.map Op.Advance
                3, Gen.constant Op.Sweep
                2, Gen.zip proc thread |> Gen.map Op.Finish
                3, Gen.constant Op.FinishAll
                2, Gen.zip proc thread |> Gen.map Op.Return
                3, Gen.constant Op.ReturnAll
            ]

    let private runGen : Gen<bool * bool * Op list> =
        gen {
            let! restart0 = Gen.elements [ false ; true ]
            let! restart1 = Gen.elements [ false ; true ]
            let! length = Gen.choose (0, 80)
            let! ops = Gen.listOfLength length opGen
            return restart0, restart1, ops
        }

    let private refThread (state : RefState) (key : int * int) : RefThread = Map.find key state.Threads

    /// The reference's answer to `op`, and its state after, or `None` where the
    /// op is not one the thread can make now, which the run skips.
    let rec private refStep (state : RefState) (op : Op) : (RefAnswer * RefState) option =
        let running (key : int * int) : bool = refThread state key = RefThread.Running

        let leavePark (key : int * int) (state : RefState) : RefState =
            { state with
                Threads =
                    Map.add
                        key
                        (if Set.contains key state.Pending then
                             RefThread.Owes None
                         else
                             RefThread.Running)
                        state.Threads
            }

        match op with
        | Op.Wait (p, t, a, timeout, matches) when running (p, t) ->
            if not matches then
                Some (RefAnswer.Outcome "EAGAIN", state)
            else
                let park =
                    {
                        Address = a
                        Timeout =
                            match timeout with
                            | None -> FutexTimeout.Untimed
                            | Some ns -> referenceTimeout state.Clock (ns / 1_000_000_000L) (ns % 1_000_000_000L)
                        Ordinal = state.NextOrdinal
                        Taken = false
                        Woken = false
                    }

                Some (
                    RefAnswer.Outcome "WouldBlock",
                    { state with
                        NextOrdinal = state.NextOrdinal + 1L
                        Threads = Map.add (p, t) (RefThread.Parked park) state.Threads
                    }
                )
        | Op.Wake (p, t, a, n) when running (p, t) ->
            let taken =
                state.Threads
                |> Map.toList
                |> List.choose (fun ((p', t'), thread) ->
                    match thread with
                    | RefThread.Parked park when p' = p && park.Address = a && not park.Taken ->
                        Some (park.Ordinal, (p', t'))
                    | _ -> None
                )
                |> List.sortBy fst
                |> List.truncate (max n 1)
                |> List.map snd

            let threads =
                (state.Threads, taken)
                ||> List.fold (fun threads key ->
                    match Map.find key threads with
                    | RefThread.Parked park ->
                        Map.add
                            key
                            (RefThread.Parked
                                { park with
                                    Taken = true
                                })
                            threads
                    | other -> failwith $"took %A{other}"
                )

            Some (
                RefAnswer.Outcome $"Completed %d{List.length taken}",
                { state with
                    Threads = threads
                }
            )
        | Op.Kill (p, s, t) when running (p, s) ->
            let threads =
                match refThread state (p, t) with
                | RefThread.Running -> Map.add (p, t) (RefThread.Owes None) state.Threads
                | RefThread.Owes _
                | RefThread.Parked _ -> state.Threads

            Some (
                RefAnswer.Nothing,
                { state with
                    Threads = threads
                    Pending = Set.add (p, t) state.Pending
                }
            )
        | Op.Advance ns ->
            Some (
                RefAnswer.Nothing,
                { state with
                    Clock = state.Clock + ns
                }
            )
        | Op.Sweep ->
            let deadlinePassed (park : RefPark) : bool =
                match park.Timeout with
                | FutexTimeout.Until deadline -> state.Clock >= deadline
                | FutexTimeout.Untimed
                | FutexTimeout.Unbounded -> false

            let woken =
                state.Threads
                |> Map.toList
                |> List.choose (fun (key, thread) ->
                    match thread with
                    | RefThread.Parked park when
                        not park.Woken
                        && (park.Taken || deadlinePassed park || Set.contains key state.Pending)
                        ->
                        Some (key, park)
                    | _ -> None
                )

            let threads =
                (state.Threads, woken)
                ||> List.fold (fun threads (key, park) ->
                    Map.add
                        key
                        (RefThread.Parked
                            { park with
                                Woken = true
                            })
                        threads
                )

            Some (
                RefAnswer.Woken (woken |> List.map fst |> List.sort),
                { state with
                    Threads = threads
                }
            )
        | Op.Finish (p, t) ->
            match refThread state (p, t) with
            | RefThread.Parked park when park.Woken ->
                let timedOut =
                    match park.Timeout with
                    | FutexTimeout.Until deadline -> state.Clock >= deadline
                    | FutexTimeout.Untimed
                    | FutexTimeout.Unbounded -> false

                if park.Taken then
                    Some (RefAnswer.Outcome "Completed 0", leavePark (p, t) state)
                elif timedOut then
                    Some (RefAnswer.Outcome "Failed ETIMEDOUT", leavePark (p, t) state)
                elif Set.contains (p, t) state.Pending then
                    let ending =
                        match park.Timeout with
                        | FutexTimeout.Until _
                        | FutexTimeout.Unbounded -> InterruptedCall.FailsWithEintr
                        | FutexTimeout.Untimed when Map.find p state.Restart -> InterruptedCall.Restarts
                        | FutexTimeout.Untimed -> InterruptedCall.FailsWithEintr

                    Some (
                        RefAnswer.Outcome "Interrupted",
                        { state with
                            Threads = Map.add (p, t) (RefThread.Owes (Some ending)) state.Threads
                        }
                    )
                else
                    failwith $"the reference woke %A{(p, t)} for nothing"
            | _ -> None
        | Op.Return (p, t) ->
            match refThread state (p, t) with
            | RefThread.Owes ending ->
                Some (
                    RefAnswer.Ended ending,
                    { state with
                        Threads = Map.add (p, t) RefThread.Running state.Threads
                        Pending = Set.remove (p, t) state.Pending
                    }
                )
            | _ -> None
        | Op.FinishAll
        | Op.ReturnAll ->
            let each (key : int * int) : Op =
                match op with
                | Op.FinishAll -> Op.Finish key
                | _ -> Op.Return key

            let answers, state =
                ((([] : ((int * int) * RefAnswer) list), state), Map.keys state.Threads |> List.ofSeq |> List.sort)
                ||> List.fold (fun (answers, state) key ->
                    match refStep state (each key) with
                    | Some (answer, state) -> answers @ [ key, answer ], state
                    | None -> answers, state
                )

            Some (RefAnswer.Each answers, state)
        | Op.Wait _
        | Op.Wake _
        | Op.Kill _ -> None

    /// The kernel's answer to `op`, which the reference could make, and the
    /// system after.
    let rec private kernelStep
        (pids : ProcessId list)
        (op : Op)
        (system : UnixSystem<int, string>)
        : RefAnswer * UnixSystem<int, string>
        =
        let label (outcome : SyscallOutcome) : string =
            match outcome with
            | SyscallOutcome.Answered (SyscallAnswer.Completed n) -> $"Completed %d{n}"
            | SyscallOutcome.Answered (SyscallAnswer.Failed error) -> $"Failed %O{error}"
            | other -> UnionCaseName.ofValue other

        match op with
        | Op.Wait (p, t, a, timeout, matches) ->
            let word = if matches then 0u else 1u

            let timeout =
                match timeout with
                | None -> TimespecArgument.Null
                | Some ns -> seconds (ns / 1_000_000_000L) (ns % 1_000_000_000L)

            let outcome, system = waitOn pids.[p] t addresses.[a] word timeout system

            let outcome =
                match outcome with
                | SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EAGAIN) -> "EAGAIN"
                | other -> label other

            RefAnswer.Outcome outcome, system
        | Op.Wake (p, t, a, n) ->
            let count, system = wakeAt pids.[p] t addresses.[a] n system
            RefAnswer.Outcome $"Completed %d{count}", system
        | Op.Kill (p, s, t) -> RefAnswer.Nothing, kill pids.[p] s t (usr1 system) system
        | Op.Advance ns -> RefAnswer.Nothing, UnixSystem.advanceClock ns system
        | Op.Sweep ->
            let woken, system = UnixWait.wake system

            let woken =
                woken
                |> List.map (fun (caller, _) ->
                    List.findIndex ((=) (Caller.processId caller)) pids, Caller.thread caller
                )
                |> List.sort

            RefAnswer.Woken woken, system
        | Op.Finish (p, t) ->
            let outcome, system = finish pids.[p] t system
            RefAnswer.Outcome (label outcome), system
        | Op.Return (p, t) ->
            let caller = Caller.make pids.[p] t

            match owed pids.[p] t system with
            | Some (OwedReturn.Interrupted _) ->
                match Interruptions.handled caller system with
                | Ok (call, system) -> RefAnswer.Ended (Some call), system
                | Error refusal -> failwith (ReturnToUserRefusal.describe refusal)
            | _ -> RefAnswer.Ended None, ReturnsToUser.untilResumed caller system
        | Op.FinishAll
        | Op.ReturnAll ->
            // Each thread the kernel says is woken, or owes a return, in order.
            let due =
                pids
                |> List.mapi (fun p pid ->
                    UnixSystem.threads pid system
                    |> Map.toList
                    |> List.choose (fun (t, state) ->
                        let woken =
                            match UnixThreadState.park state with
                            | Some {
                                       State = ParkState.Woken _
                                   } -> true
                            | _ -> false

                        let owes = (UnixThreadTable.owedBy t (UnixSystem.threads pid system)).IsSome

                        match op with
                        | Op.FinishAll when woken -> Some (p, t)
                        | Op.ReturnAll when owes -> Some (p, t)
                        | _ -> None
                    )
                )
                |> List.concat
                |> List.sort

            let answers, system =
                ((([] : ((int * int) * RefAnswer) list), system), due)
                ||> List.fold (fun (answers, system) key ->
                    let each =
                        match op with
                        | Op.FinishAll -> Op.Finish key
                        | _ -> Op.Return key

                    let answer, system = kernelStep pids each system
                    answers @ [ key, answer ], system
                )

            RefAnswer.Each answers, system

    /// What the kernel holds of each thread, as the reference states it.
    let private kernelThreads (pids : ProcessId list) (system : UnixSystem<int, string>) : Map<int * int, string> =
        pids
        |> List.mapi (fun p pid ->
            UnixSystem.threads pid system
            |> Map.toList
            |> List.map (fun (t, state) ->
                let shown =
                    match UnixThreadState.park state, UnixThreadTable.owedBy t (UnixSystem.threads pid system) with
                    | Some park, None ->
                        match park.Syscall with
                        | ParkedSyscall.Futex wait ->
                            let woken =
                                match park.State with
                                | ParkState.Asleep -> false
                                | ParkState.Woken _ -> true

                            $"parked %d{List.findIndex ((=) wait.FutexAddress) addresses} %A{wait.FutexTimeout} taken=%b{wait.TakenByWake} woken=%b{woken}"
                        | other -> $"parked in %s{UnionCaseName.ofValue other}"
                    | None, None -> "running"
                    | None, Some (OwedReturn.Interrupted _) -> "owes interrupted"
                    | None, Some OwedReturn.SignalDue -> "owes signal"
                    | Some _, Some owed -> $"parked and owing %A{owed}"

                (p, t), shown
            )
        )
        |> List.concat
        |> Map.ofList

    let private refThreads (state : RefState) : Map<int * int, string> =
        state.Threads
        |> Map.map (fun _ thread ->
            match thread with
            | RefThread.Running -> "running"
            | RefThread.Owes None -> "owes signal"
            | RefThread.Owes (Some _) -> "owes interrupted"
            | RefThread.Parked park ->
                $"parked %d{park.Address} %A{park.Timeout} taken=%b{park.Taken} woken=%b{park.Woken}"
        )

    /// What a run of the reference reached, for coverage.
    [<RequireQualifiedAccess>]
    type private RunLabel =
        | TakenAfterSignal
        | TakenAfterTimeout
        | TimedOut
        | Interrupted
        | Restarted
        | WokeSeveral
        | WokeNone
        /// A signal ended a wait whose timeout Linux saturates.
        | UnboundedInterrupted

    [<Test>]
    let ``the kernel's futex queues are the reference's`` () : unit =
        let property (cover : RunLabel -> unit) ((restart0, restart1, ops) : bool * bool * Op list) : unit =
            let pids, system = Machines.withThreads linux 2 threadsEach

            let system =
                (system, List.zip pids [ restart0 ; restart1 ])
                ||> List.fold (fun system (pid, restart) -> install pid (usr1 system) (handler restart) system)

            let initial =
                {
                    Clock = UnixSystem.nanosecondsSinceBoot system
                    NextOrdinal = 0L
                    Threads =
                        [
                            for p in 0..1 do
                                for t in 0 .. threadsEach - 1 do
                                    (p, t), RefThread.Running
                        ]
                        |> Map.ofList
                    Pending = Set.empty
                    Restart = Map.ofList [ 0, restart0 ; 1, restart1 ]
                }

            ((initial, system), ops)
            ||> List.fold (fun (state, system) op ->
                match refStep state op with
                | None -> state, system
                | Some (expected, after) ->
                    let actual, system = kernelStep pids op system
                    (op, actual) |> shouldEqual (op, expected)

                    let rec label (op : Op) (answer : RefAnswer) : unit =
                        match op, answer with
                        | Op.Finish (p, t), RefAnswer.Outcome "Completed 0" ->
                            if Set.contains (p, t) state.Pending then
                                cover RunLabel.TakenAfterSignal

                            match refThread state (p, t) with
                            | RefThread.Parked {
                                                   Timeout = FutexTimeout.Until deadline
                                               } when state.Clock >= deadline -> cover RunLabel.TakenAfterTimeout
                            | _ -> ()
                        | Op.Finish _, RefAnswer.Outcome "Failed ETIMEDOUT" -> cover RunLabel.TimedOut
                        | Op.Finish (p, t), RefAnswer.Outcome "Interrupted" ->
                            cover RunLabel.Interrupted

                            match refThread state (p, t) with
                            | RefThread.Parked {
                                                   Timeout = FutexTimeout.Unbounded
                                               } -> cover RunLabel.UnboundedInterrupted
                            | _ -> ()
                        | Op.Return _, RefAnswer.Ended (Some InterruptedCall.Restarts) -> cover RunLabel.Restarted
                        | Op.Wake _, RefAnswer.Outcome "Completed 0" -> cover RunLabel.WokeNone
                        | Op.Wake _, RefAnswer.Outcome count when count <> "Completed 1" -> cover RunLabel.WokeSeveral
                        | Op.FinishAll, RefAnswer.Each answers ->
                            for key, answer in answers do
                                label (Op.Finish key) answer
                        | Op.ReturnAll, RefAnswer.Each answers ->
                            for key, answer in answers do
                                label (Op.Return key) answer
                        | _ -> ()

                    label op expected

                    kernelThreads pids system |> shouldEqual (refThreads after)
                    Machines.checkInvariants system |> shouldEqual []
                    after, system
            )
            |> ignore

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen runGen) property

        for label in
            [
                RunLabel.TakenAfterSignal
                RunLabel.TakenAfterTimeout
                RunLabel.TimedOut
                RunLabel.Interrupted
                RunLabel.Restarted
                RunLabel.WokeSeveral
                RunLabel.WokeNone
                RunLabel.UnboundedInterrupted
            ] do
            (label, coverage.Count label > 5) |> shouldEqual (label, true)
