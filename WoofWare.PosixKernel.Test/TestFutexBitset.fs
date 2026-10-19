namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixFutex`'s bitset waits and wakes, and how it decodes `op`: every row of
/// `docs/probes/futex-bitset` (measured 2026-10-18 on Linux 6.18.5 aarch64,
/// glibc 2.41), the decode, screen, huge, match and order rows replayed from
/// its embedded output and the rest transcribed as states.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFutexBitset =

    /// An aligned address every test waits on unless it says otherwise.
    let private address : uint64 = 0x1000UL

    /// 2026-10-18, half a second in: after the epoch, so that the realtime
    /// clock and the monotonic one differ.
    let private bootNanoseconds : int64 = 1_792_281_600_500_000_000L

    let private realtimeWait : int =
        UnixFutex.FutexWaitBitsetPrivate ||| UnixFutex.FutexClockRealtime

    let private any : uint32 = UnixFutex.FutexBitsetMatchAny

    /// One process with threads 0 to `threads - 1`, on a kernel with the
    /// probe's 48-bit user address space, booted at `bootNanoseconds`.
    let private bootAt (bootTime : UnixTimestamp) (threads : int) : ProcessId * UnixSystem<int, string> =
        let configure (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
            image
            |> UnixBootImage.withUserAddressLimit ObservedUserAddressLimit.Arm64FortyEightBit
            |> UnixBootImage.withBootTime bootTime

        match Machines.withThreadsOn configure SimulatedUnixPlatform.linuxArm64 1 threads with
        | [ pid ], system -> pid, system
        | pids, _ -> failwith $"expected one process, got %A{pids}"

    let private boot (threads : int) : ProcessId * UnixSystem<int, string> =
        bootAt
            (UnixTimestamp.createOrFail
                "TestFutexBitset"
                (bootNanoseconds / 1_000_000_000L)
                (int (bootNanoseconds % 1_000_000_000L)))
            threads

    /// A readable timespec of `s` seconds and `ns` nanoseconds.
    let private readable (s : int64) (ns : int64) : TimespecArgument =
        TimespecArgument.Readable
            {
                Seconds = s
                Nanoseconds = ns
            }

    let private timespec (ns : int64) : TimespecArgument =
        readable (ns / 1_000_000_000L) (ns % 1_000_000_000L)

    /// The instant `ms` milliseconds after `system`'s present, on the clock a
    /// bitset wait with `op` measures its deadline on, as the probe's
    /// `deadline_ms` names it from the row's start.
    let private deadlineAfter (op : int) (ms : int64) (system : UnixSystem<int, string>) : TimespecArgument =
        let onClock =
            if op &&& UnixFutex.FutexClockRealtime <> 0 then
                bootNanoseconds
            else
                0L

        timespec (onClock + UnixSystem.nanosecondsSinceBoot system + ms * 1_000_000L)

    /// What `Syscall.Futex` answers for `thread` of `pid`.
    let private futex
        (pid : ProcessId)
        (thread : int)
        (at : uint64)
        (op : int)
        (value : int)
        (word : CopiedArgument<uint32>)
        (timeout : TimespecArgument)
        (val3 : uint32)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        match UnixSystem.step (Caller.make pid thread) (Syscall.Futex (at, op, value, word, timeout, val3)) system with
        | SteppedCall.Futex (outcome, system) -> outcome, system
        | other -> failwith $"step answered %A{Stepped.view other}"

    /// `thread` waits at `address` with `op` and `bitset` on a word that holds
    /// `word`, expecting 0.
    let private waitOn
        (pid : ProcessId)
        (thread : int)
        (op : int)
        (bitset : uint32)
        (word : uint32)
        (timeout : TimespecArgument)
        (system : UnixSystem<int, string>)
        : SyscallOutcome * UnixSystem<int, string>
        =
        futex pid thread address op 0 (CopiedArgument.Readable word) timeout bitset system

    /// `thread` waits at `address` on a word that holds what it expects, and
    /// must park.
    let private parks
        (pid : ProcessId)
        (thread : int)
        (op : int)
        (bitset : uint32)
        (timeout : TimespecArgument)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match waitOn pid thread op bitset 0u timeout system with
        | SyscallOutcome.WouldBlock _, system -> system
        | other, _ -> failwith $"thread %d{thread}'s wait answered %A{other} rather than parking"

    /// A wake of `n` by thread 0 at `address` with `op` and `bitset`: how many
    /// it took.
    let private wake
        (pid : ProcessId)
        (op : int)
        (n : int)
        (bitset : uint32)
        (system : UnixSystem<int, string>)
        : int64 * UnixSystem<int, string>
        =
        match futex pid 0 address op n CopiedArgument.Addressless TimespecArgument.Null bitset system with
        | SyscallOutcome.Answered (SyscallAnswer.Completed count), system -> count, system
        | other, _ -> failwith $"the wake answered %A{other}"

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
        |> List.map (fun (caller, _) -> Caller.thread caller)
        |> List.sort,
        system

    let private usr1 (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    let private install
        (pid : ProcessId)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction (Caller.make pid 0) (usr1 system) (Some disposition) system with
        | Ok (_, system) -> system
        | Error error -> failwith $"sigaction failed with %O{error}"

    let private handler (restart : bool) : SignalDisposition<string> =
        SignalDisposition.Catch
            { SignalCatch.ofHandler "h" with
                Restart = restart
            }

    /// USR1 sent by `pid`'s thread 0 to its thread 1.
    let private kill (pid : ProcessId) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixSignal.pthreadKill (Caller.make pid 0) 1 (usr1 system) system with
        | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
        | other -> failwith $"pthread_kill answered %A{other}"

    let private parkedTimeout (pid : ProcessId) (thread : int) (system : UnixSystem<int, string>) : FutexTimeout =
        match Proc.parkedIn (Caller.make pid thread) system with
        | Some (ParkedSyscall.Futex wait) -> wait.FutexTimeout
        | other -> failwith $"thread %d{thread} is parked in %A{other}, not a futex wait"

    let private failed (error : UnixError) : SyscallOutcome =
        SyscallOutcome.Answered (SyscallAnswer.Failed error)

    let private completed (count : int64) : SyscallOutcome =
        SyscallOutcome.Answered (SyscallAnswer.Completed count)

    // ------------------------- Replaying the probe ------------------------- //

    let private measured : string list =
        let name = "WoofWare.PosixKernel.Test.futex-bitset.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))

    /// The rows matching `pattern`, as its groups.
    let private rowsOf (pattern : string) : (string * string list) list =
        measured
        |> List.choose (fun line ->
            let row = Regex.Match (line, pattern)

            if row.Success then
                Some (line, [ for group in Seq.tail row.Groups -> group.Value ])
            else
                None
        )

    let private errorOf (name : string) : UnixError =
        match name with
        | "EINVAL" -> UnixError.EINVAL
        | "EAGAIN" -> UnixError.EAGAIN
        | "EFAULT" -> UnixError.EFAULT
        | "ETIMEDOUT" -> UnixError.ETIMEDOUT
        | "ENOSYS" -> UnixError.ENOSYS
        | other -> failwith $"the probe names no error %s{other} in these rows"

    let private answerOf (ret : string) (errno : string) : SyscallAnswer =
        if errno = "0" then
            SyscallAnswer.Completed (int64 ret)
        else
            SyscallAnswer.Failed (errorOf errno)

    let private opOf (name : string) : int =
        match name with
        | "WAIT_PRIVATE" -> UnixFutex.FutexWaitPrivate
        | "WAKE_PRIVATE" -> UnixFutex.FutexWakePrivate
        | "WAIT_BITSET_PRIVATE" -> UnixFutex.FutexWaitBitsetPrivate
        | "WAKE_BITSET_PRIVATE" -> UnixFutex.FutexWakeBitsetPrivate
        | "WAIT_BITSET_PRIVATE|CLOCK_REALTIME" -> realtimeWait
        | other -> failwith $"the probe names no op %s{other}"

    let private bitsetOf (name : string) : uint32 =
        match name with
        | "any" -> any
        | hex when hex.StartsWith ("0x", StringComparison.Ordinal) -> Convert.ToUInt32 (hex.Substring 2, 16)
        | other -> failwith $"the probe names no bitset %s{other}"

    let private countOf (name : string) : int =
        match name with
        | "INT_MAX" -> Int32.MaxValue
        | "INT_MIN" -> Int32.MinValue
        | n -> int n

    /// The probe's addresses: where each lies, what the caller's memory there
    /// is, and the value a wait expects.
    let private probeAddress (name : string) : uint64 * CopiedArgument<uint32> * int =
        let beyond = 0x0001000000000000UL

        match name with
        | "match" -> address, CopiedArgument.Readable 0u, 0
        | "mismatch" -> address, CopiedArgument.Readable 0u, 7
        | "misaligned" -> address + 1UL, CopiedArgument.Readable 0u, 0
        | "misaligned-mismatch" -> address + 1UL, CopiedArgument.Readable 0u, 7
        | "unmapped" -> 0x2000UL, CopiedArgument.Unmapped 0x2000UL, 0
        | "unmapped-misaligned" -> 0x2001UL, CopiedArgument.Unmapped 0x2001UL, 0
        | "null" -> 0UL, CopiedArgument.Unmapped 0UL, 0
        | "beyond" -> beyond, CopiedArgument.Unmapped beyond, 0
        | "beyond-misaligned" -> beyond + 2UL, CopiedArgument.Unmapped (beyond + 2UL), 0
        | "kernel-half" -> 0x8000000000000000UL, CopiedArgument.Unmapped 0x8000000000000000UL, 0
        // The wake rows' own name.
        | "aligned-no-waiters" -> address, CopiedArgument.Addressless, 0
        | other -> failwith $"the probe names no address %s{other}"

    /// The probe's timeouts for a wait made with `op` from `system`, and how
    /// far off a deadline is, where it has one.
    let private probeTimeout
        (op : int)
        (name : string)
        (system : UnixSystem<int, string>)
        : TimespecArgument * int64 option
        =
        match name with
        | "null" -> TimespecArgument.Null, None
        | "past" -> readable 0L 0L, Some 0L
        | "soon" -> deadlineAfter op 10L system, Some 10_000_000L
        | "nsec=1e9" -> readable 0L 1_000_000_000L, None
        | "nsec=-1" -> readable 0L (-1L), None
        | "sec=-1" -> readable (-1L) 0L, None
        | "unmapped" -> TimespecArgument.Unreadable, None
        | other -> failwith $"the probe names no timeout %s{other}"

    [<Test>]
    let ``every decode row is the model's answer, or a shared command it refuses`` () : unit =
        let rows =
            rowsOf @"^decode op=(-?\d+) \(\S+\) timeout=(\S+) ret=(-?\d+) errno=(\S+)$"

        rows |> List.length |> shouldEqual 160

        let refused =
            [
                for line, groups in rows do
                    match groups with
                    | [ op ; timeoutName ; ret ; errno ] ->
                        let op = int op
                        let pid, system = boot 1
                        let timeout, _ = probeTimeout op timeoutName system

                        let call () =
                            futex pid 0 address op 7 (CopiedArgument.Readable 0u) timeout any system

                        // Linux answered a command without FUTEX_PRIVATE_FLAG
                        // past its screens, which this kernel does not model.
                        if op &&& 128 = 0 && (errno = "EAGAIN" || errno = "0") then
                            (fun () -> call () |> ignore<SyscallOutcome * UnixSystem<int, string>>)
                            |> shouldFail<UnmodelledException>

                            yield line
                        else
                            match call () with
                            | SyscallOutcome.Answered answer, _ ->
                                (line, answer) |> shouldEqual (line, answerOf ret errno)
                            | other, _ -> failwith $"%s{line}: answered %A{other}"
                    | _ -> failwith $"%s{line}: %A{groups}"
            ]

        // FUTEX_WAIT and FUTEX_WAIT_BITSET (on either clock) with no timeout
        // and a past one, and FUTEX_WAKE and FUTEX_WAKE_BITSET with each.
        refused |> List.length |> shouldEqual 14

    [<Test>]
    let ``every wait-screen row is the model's answer`` () : unit =
        let rows =
            rowsOf @"^wait-screen op=(\S+) addr=(\S+) timeout=(\S+) mask=(\S+) ret=(-?\d+) errno=(\S+) took=\d+$"

        rows |> List.length |> shouldEqual 250

        for line, groups in rows do
            match groups with
            | [ opName ; addressName ; timeoutName ; mask ; _ ; errno ] ->
                let op = opOf opName
                let pid, system = boot 1
                let at, word, value = probeAddress addressName
                let timeout, offset = probeTimeout op timeoutName system

                let answer =
                    match futex pid 0 at op value word timeout (bitsetOf mask) system with
                    | SyscallOutcome.Answered answer, _ -> answer
                    | SyscallOutcome.WouldBlock _, parked ->
                        // A wait that times out sleeps first, even for a
                        // deadline already passed: it passes, and the wait is
                        // finished.
                        let offset =
                            match offset with
                            | Some offset -> offset
                            | None -> failwith $"%s{line}: parked with no timeout"

                        let woken, parked = sweep pid (UnixSystem.advanceClock offset parked)
                        (line, woken) |> shouldEqual (line, [ 0 ])

                        match finish pid 0 parked with
                        | SyscallOutcome.Answered answer, _ -> answer
                        | other, _ -> failwith $"%s{line}: finishing answered %A{other}"
                    | other, _ -> failwith $"%s{line}: answered %A{other}"

                (line, answer) |> shouldEqual (line, SyscallAnswer.Failed (errorOf errno))
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every wake-screen row is the model's answer`` () : unit =
        let rows = rowsOf @"^wake-screen addr=(\S+) mask=(\S+) n=1 ret=(-?\d+) errno=(\S+)$"
        rows |> List.length |> shouldEqual 24

        for line, groups in rows do
            match groups with
            | [ addressName ; mask ; ret ; errno ] ->
                let pid, system = boot 1
                let at, word, _ = probeAddress addressName

                match
                    futex pid 0 at UnixFutex.FutexWakeBitsetPrivate 1 word TimespecArgument.Null (bitsetOf mask) system
                with
                | SyscallOutcome.Answered answer, _ -> (line, answer) |> shouldEqual (line, answerOf ret errno)
                | other, _ -> failwith $"%s{line}: answered %A{other}"
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every huge row sleeps until a wake ends it`` () : unit =
        // From `KTIME_SEC_MAX` seconds Linux saturates the deadline; 9223372035
        // seconds is an instant, some 292 years after boot or the epoch.
        let rows = rowsOf @"^huge op=(\S+) tv_sec=(\d+) woke=1 W:ret=0 errno=0 at=\d+$"
        rows |> List.length |> shouldEqual 6

        for line, groups in rows do
            match groups with
            | [ opName ; tvSec ] ->
                let op = opOf opName
                let tvSec = int64 tvSec
                let pid, system = boot 2

                let system = parks pid 1 op any (readable tvSec 0L) system

                let expected =
                    if tvSec >= 9223372036L then
                        FutexTimeout.Unbounded
                    elif op = realtimeWait then
                        FutexTimeout.At (tvSec * 1_000_000_000L - bootNanoseconds)
                    else
                        FutexTimeout.At (tvSec * 1_000_000_000L)

                (line, parkedTimeout pid 1 system) |> shouldEqual (line, expected)
                let woken, system = sweep pid (UnixSystem.advanceClock 100_000_000L system)
                (line, woken) |> shouldEqual (line, [])
                let count, system = wake pid UnixFutex.FutexWakePrivate 1 0u system
                (line, count) |> shouldEqual (line, 1L)
                let _, system = sweep pid system
                (line, fst (finish pid 1 system)) |> shouldEqual (line, completed 0L)
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every match row is the model's answer`` () : unit =
        let rows =
            rowsOf
                @"^match (wait=(\S+) )?(wait-mask=(\S+) )?(wake=(\S+) )?(wake-mask=(\S+) )?woke=(\d) errno=0 (W:ret=0 errno=0 at=\d+|W=asleep)$"

        rows |> List.length |> shouldEqual 31

        for line, groups in rows do
            match groups with
            | [ _ ; waitName ; _ ; waitMask ; _ ; wakeName ; _ ; wakeMask ; woke ; waiter ] ->
                let waitOp =
                    if waitName = "" then
                        UnixFutex.FutexWaitBitsetPrivate
                    else
                        opOf waitName

                let wakeOp =
                    if wakeName = "" then
                        UnixFutex.FutexWakeBitsetPrivate
                    else
                        opOf wakeName

                let pid, system = boot 2

                // The probe's waiter times out 300 ms in, after the row.
                let timeout =
                    if waitOp = UnixFutex.FutexWaitPrivate then
                        timespec 300_000_000L
                    else
                        deadlineAfter waitOp 300L system

                let waitBitset = if waitMask = "" then 0u else bitsetOf waitMask
                let wakeBitset = if wakeMask = "" then 0u else bitsetOf wakeMask
                let system = parks pid 1 waitOp waitBitset timeout system
                let count, system = wake pid wakeOp 1 wakeBitset system
                (line, count) |> shouldEqual (line, int64 woke)
                let woken, system = sweep pid system

                if waiter = "W=asleep" then
                    (line, woken) |> shouldEqual (line, [])
                else
                    (line, woken) |> shouldEqual (line, [ 1 ])
                    (line, fst (finish pid 1 system)) |> shouldEqual (line, completed 0L)
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every order row is the model's answer`` () : unit =
        // A (thread 1, bitset 1), B (2, bitset 2), C (3, bitset 1) and D (4,
        // any), parked in that order.
        let rows = rowsOf @"^order (.+) trial=\d+ woke=(\S+)((?: [A-D]=asleep)*)$"
        rows |> List.length |> shouldEqual 23

        let threadOf (letter : char) : int = int letter - int 'A' + 1

        for line, groups in rows do
            match groups with
            | [ label ; woke ; asleep ] ->
                let wakes =
                    label.Split "; "
                    |> Array.toList
                    |> List.collect (fun spec ->
                        let spec = Regex.Match (spec, @"^mask=(\S+),n=(\S+?)( x(\d))?$")

                        if not spec.Success then
                            failwith $"%s{line}: no wake in %s{label}"

                        let times =
                            if spec.Groups.[3].Success then
                                int spec.Groups.[4].Value
                            else
                                1

                        List.replicate times (bitsetOf spec.Groups.[1].Value, countOf spec.Groups.[2].Value)
                    )

                let woke =
                    woke.Split ','
                    |> Array.toList
                    |> List.map (fun one ->
                        match one.Split ':' with
                        | [| count ; letters |] -> int64 count, letters |> Seq.map threadOf |> List.ofSeq |> List.sort
                        | _ -> failwith $"%s{line}: %s{one}"
                    )

                (line, List.length wakes) |> shouldEqual (line, List.length woke)

                let pid, system = boot 5

                let system =
                    (system, List.zip [ 1..4 ] [ 1u ; 2u ; 1u ; any ])
                    ||> List.fold (fun system (thread, bitset) ->
                        parks pid thread UnixFutex.FutexWaitBitsetPrivate bitset TimespecArgument.Null system
                    )

                let system =
                    (system, List.zip wakes woke)
                    ||> List.fold (fun system ((bitset, n), (count, threads)) ->
                        let taken, system = wake pid UnixFutex.FutexWakeBitsetPrivate n bitset system
                        (line, taken) |> shouldEqual (line, count)
                        let woken, system = sweep pid system
                        (line, woken) |> shouldEqual (line, threads)

                        (system, woken)
                        ||> List.fold (fun system thread ->
                            let outcome, system = finish pid thread system
                            (line, outcome) |> shouldEqual (line, completed 0L)
                            system
                        )
                    )

                let stillAsleep =
                    Regex.Matches (asleep, @"([A-D])=asleep")
                    |> Seq.map (fun m -> threadOf m.Groups.[1].Value.[0])
                    |> List.ofSeq

                for thread in stillAsleep do
                    match Proc.parkOf (Caller.make pid thread) system with
                    | Some park -> (line, thread, park.State) |> shouldEqual (line, thread, ParkState.Asleep)
                    | None -> failwith $"%s{line}: thread %d{thread} is not parked"
            | _ -> failwith $"%s{line}: %A{groups}"

    // ------------------------- The transcribed rows ------------------------ //

    [<Test>]
    let ``a deadline already passed parks, and a wake before it runs takes it`` () : unit =
        // The "switches" rows: a bitset wait whose deadline has passed sleeps
        // before it answers ETIMEDOUT, on either clock. So a wake made before
        // the waiter runs takes it, as the "race" rows show of a deadline that
        // passes while the waiter sleeps.
        let rows =
            rowsOf @"^switches op=(\S+) deadline=(past|now) x1000 switches=(\d+) ETIMEDOUT=1000 .*$"

        rows |> List.length |> shouldEqual 4

        for line, groups in rows do
            match groups with
            | [ _ ; _ ; switches ] -> (line, int switches >= 990) |> shouldEqual (line, true)
            | _ -> failwith $"%s{line}: %A{groups}"

        for op in [ UnixFutex.FutexWaitBitsetPrivate ; realtimeWait ] do
            for deadline in [ readable 0L 0L ; deadlineAfter op 0L (snd (boot 1)) ] do
                let pid, system = boot 2
                let system = parks pid 1 op any deadline system
                let count, system = wake pid UnixFutex.FutexWakePrivate 1 0u system
                count |> shouldEqual 1L
                let woken, system = sweep pid system
                woken |> shouldEqual [ 1 ]
                finish pid 1 system |> fst |> shouldEqual (completed 0L)

                let pid, system = boot 2
                let system = parks pid 1 op any deadline system
                let woken, system = sweep pid system
                woken |> shouldEqual [ 1 ]
                finish pid 1 system |> fst |> shouldEqual (failed UnixError.ETIMEDOUT)

    [<Test>]
    let ``a realtime deadline is the instant less the boot time`` () : unit =
        // The modelled realtime clock is the boot time plus the uptime, and
        // never steps.
        for sinceBoot in [ 0L ; 1L ; 10_000_000L ; -1L ; -bootNanoseconds ] do
            let pid, system = boot 2

            let system =
                parks pid 1 realtimeWait any (timespec (bootNanoseconds + sinceBoot)) system

            (sinceBoot, parkedTimeout pid 1 system)
            |> shouldEqual (sinceBoot, FutexTimeout.At sinceBoot)

        // And a monotonic one is the instant itself.
        let pid, system = boot 2

        let system =
            parks pid 1 UnixFutex.FutexWaitBitsetPrivate any (timespec 10_000_000L) system

        parkedTimeout pid 1 system |> shouldEqual (FutexTimeout.At 10_000_000L)

    [<Test>]
    let ``a realtime deadline with no instant since boot is refused, but only where it would park`` () : unit =
        // A machine booted in the year 2265: the epoch lies more than
        // Int64.MaxValue nanoseconds before it.
        let pid, system =
            bootAt (UnixTimestamp.createOrFail "TestFutexBitset" 9_300_000_000L 0) 2

        waitOn pid 1 realtimeWait any 1u (readable 0L 0L) system
        |> fst
        |> shouldEqual (failed UnixError.EAGAIN)

        (fun () ->
            waitOn pid 1 realtimeWait any 0u (readable 0L 0L) system
            |> ignore<SyscallOutcome * UnixSystem<int, string>>
        )
        |> shouldFail<UnmodelledException>

        // The last instant before Linux saturates a deadline lies within
        // Int64.MaxValue nanoseconds of that boot, before it.
        let late = readable 9_223_372_035L 0L

        match waitOn pid 1 realtimeWait any 0u late system with
        | SyscallOutcome.WouldBlock _, system ->
            parkedTimeout pid 1 system
            |> shouldEqual (FutexTimeout.At -76_627_965_000_000_000L)
        | other, _ -> failwith $"%A{other}"

    /// A waiter, thread 1, parked by `op` with `timeout`, sent USR1 under a
    /// handler with `SA_RESTART` if `restart`, then woken and finished.
    let private signalled
        (op : int)
        (restart : bool)
        (timed : bool)
        : ProcessId * SyscallOutcome * UnixSystem<int, string>
        =
        let pid, system = boot 2
        let system = install pid (handler restart) system

        let timeout =
            if timed then
                deadlineAfter op 2_000L system
            else
                TimespecArgument.Null

        let system = parks pid 1 op any timeout system
        let system = UnixSystem.advanceClock 100_000_000L (kill pid system)
        let woken, system = sweep pid system
        woken |> shouldEqual [ 1 ]
        let outcome, system = finish pid 1 system
        pid, outcome, system

    [<Test>]
    let ``every signal row is the model's answer`` () : unit =
        let rows =
            rowsOf
                @"^signal op=(\S+) (handler|handler-stores-1) flags=(0|SA_RESTART) (untimed|deadline=2s) handled=\d+ woke=(\d) W:ret=(-?\d+) errno=(\S+) at=\d+$"

        rows |> List.length |> shouldEqual 16

        for line, groups in rows do
            match groups with
            | [ opName ; stores ; flags ; timed ; woke ; _ ; errno ] ->
                let op = opOf opName
                let pid, outcome, system = signalled op (flags = "SA_RESTART") (timed <> "untimed")
                (line, outcome) |> shouldEqual (line, SyscallOutcome.Interrupted)

                match Interruptions.handled (Caller.make pid 1) system, errno with
                | Ok (InterruptedCall.FailsWithEintr, _), "EINTR" -> ()
                | Ok (InterruptedCall.Restarts, system), _ ->
                    // The caller makes the call again, reading the word, which
                    // the handler stored 1 to in the "stores" rows.
                    let word = if stores = "handler-stores-1" then 1u else 0u

                    match waitOn pid 1 op any word TimespecArgument.Null system, errno with
                    | (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EAGAIN), _), "EAGAIN" -> ()
                    | (SyscallOutcome.WouldBlock _, system), "0" ->
                        let count, system = wake pid UnixFutex.FutexWakePrivate 1 0u system
                        (line, count, woke) |> shouldEqual (line, 1L, "1")
                        let _, system = sweep pid system
                        (line, fst (finish pid 1 system)) |> shouldEqual (line, completed 0L)
                    | (other, _), _ -> failwith $"%s{line}: the restarted call answered %A{other}"
                | other, _ -> failwith $"%s{line}: %A{other}"
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every stop row is the model's answer: a restart keeps the instant the call named`` () : unit =
        // A stop, as this kernel sees it, is a signal that woke the waiter and
        // is gone by the time the wait is finished: here the leader ignores it.
        // The wait restarts through its caller, which makes the call again with
        // its first arguments, and so names the same deadline.
        let rows =
            rowsOf
                @"^stop op=(\S+) (untimed|deadline=300ms|deadline=2s) (no-store|store-1) ready-at=\d+ stop-at=\d+ stopped=1 woke=(\d) W:ret=(-?\d+) errno=(\S+) at=(\d+)$"

        rows |> List.length |> shouldEqual 8

        for line, groups in rows do
            match groups with
            | [ opName ; timed ; store ; _ ; _ ; errno ; _ ] ->
                let op = opOf opName
                let pid, system = boot 2
                let system = install pid (handler true) system

                let timeout =
                    match timed with
                    | "untimed" -> TimespecArgument.Null
                    | "deadline=300ms" -> deadlineAfter op 300L system
                    | _ -> deadlineAfter op 2_000L system

                let system = parks pid 1 op any timeout system
                let system = kill pid (UnixSystem.advanceClock 100_000_000L system)
                let woken, system = sweep pid system
                (line, woken) |> shouldEqual (line, [ 1 ])
                let system = install pid SignalDisposition.Ignore system
                let outcome, system = finish pid 1 system
                (line, outcome) |> shouldEqual (line, SyscallOutcome.Interrupted)

                match Interruptions.handled (Caller.make pid 1) system with
                | Ok (InterruptedCall.Restarts, system) ->
                    let system = UnixSystem.advanceClock 100_000_000L system
                    let word = if store = "store-1" then 1u else 0u

                    match waitOn pid 1 op any word timeout system, errno with
                    | (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EAGAIN), _), "EAGAIN" -> ()
                    | (SyscallOutcome.WouldBlock _, system), "ETIMEDOUT" ->
                        // 200 ms in: the deadline is 300 ms in, as the row's
                        // ETIMEDOUT at 300 ms says, and no later.
                        let toDeadline = 100_000_000L
                        let woken, system = sweep pid (UnixSystem.advanceClock (toDeadline - 1L) system)
                        (line, woken) |> shouldEqual (line, [])
                        let woken, system = sweep pid (UnixSystem.advanceClock 1L system)
                        (line, woken) |> shouldEqual (line, [ 1 ])

                        (line, fst (finish pid 1 system))
                        |> shouldEqual (line, failed UnixError.ETIMEDOUT)
                    | (SyscallOutcome.WouldBlock _, system), "0" ->
                        let count, system = wake pid UnixFutex.FutexWakePrivate 1 0u system
                        (line, count) |> shouldEqual (line, 1L)
                        let _, system = sweep pid system
                        (line, fst (finish pid 1 system)) |> shouldEqual (line, completed 0L)
                    | (other, _), _ -> failwith $"%s{line}: the restarted call answered %A{other}"
                | other -> failwith $"%s{line}: %A{other}"
            | _ -> failwith $"%s{line}: %A{groups}"

    [<Test>]
    let ``every race row is the model's answer`` () : unit =
        let rows =
            rowsOf
                @"^race op=(\S+) (signal-then-wake|timeout-then-wake|timeout-then-signal) .* ran-early=0 woke=(-?\d) handled=(yes|-) A:ret=(-?\d+) errno=(\S+) at=\d+$"

        rows |> List.length |> shouldEqual 18

        for line, groups in rows do
            match groups with
            | [ opName ; kind ; woke ; handled ; ret ; errno ] ->
                let op = opOf opName
                let pid, system = boot 2
                let system = install pid (handler true) system

                let deadline = if kind = "signal-then-wake" then 2_000L else 10L
                let system = parks pid 1 op any (deadlineAfter op deadline system) system

                let system =
                    match kind with
                    | "signal-then-wake" -> kill pid system
                    | _ -> UnixSystem.advanceClock 50_000_000L system

                let system =
                    match kind with
                    | "timeout-then-signal" -> kill pid system
                    | _ ->
                        let count, system = wake pid UnixFutex.FutexWakePrivate 1 0u system
                        (line, count) |> shouldEqual (line, int64 woke)
                        system

                let woken, system = sweep pid system
                (line, woken) |> shouldEqual (line, [ 1 ])
                let outcome, system = finish pid 1 system

                (line, outcome)
                |> shouldEqual (line, SyscallOutcome.Answered (answerOf ret errno))

                (line, Proc.owedBy (Caller.make pid 1) system)
                |> shouldEqual (line, if handled = "yes" then Some OwedReturn.SignalDue else None)
            | _ -> failwith $"%s{line}: %A{groups}"
