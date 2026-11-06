namespace WoofWare.PosixKernel.Test

open System.Diagnostics
open System.Runtime.InteropServices
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Measures the host's `clock_gettime` and checks the model's per-flavour decoding of
/// a clock id against it: which ids are `EINVAL`, and which clocks report only whole
/// microseconds.
///
/// macOS runs it locally and Linux in CI, so each run falsifies one flavour's column.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestClockAgainstHost =

    /// `struct timespec` on both 64-bit hosts this runs on: two 8-byte fields.
    [<Struct ; StructLayout(LayoutKind.Sequential)>]
    type private Timespec =
        val mutable Seconds : int64
        val mutable Nanoseconds : int64

    [<DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)>]
    extern int private hostClockGettime(int clockId, Timespec& reading)

    [<Literal>]
    let private EINVAL = 22

    /// What the host did with a clock id.
    [<RequireQualifiedAccess>]
    type private HostOutcome =
        | Read of Timespec
        | Failed of errno : int

    let private hostRead (clockId : int) : HostOutcome =
        let mutable reading = Timespec ()
        Marshal.SetLastPInvokeError 0

        if hostClockGettime (clockId, &reading) = 0 then
            HostOutcome.Read reading
        else
            HostOutcome.Failed (Marshal.GetLastPInvokeError ())

    let private sweptIds : int list =
        [ -4096 .. 4096 ] @ [ System.Int32.MinValue ; System.Int32.MaxValue ]

    let private imageOn (flavour : SimulatedUnixFlavour) : UnixBootImage<int, string> =
        UnixSystem.initial<int, string> (HostPlatform.platformOf flavour)

    [<Test>]
    let ``an id is EINVAL here exactly when the host says so, unless it is refused`` () : unit =
        HostPlatform.onUnixHost (fun flavour ->
            let system =
                (Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)) (imageOn flavour)

            let disagreements =
                sweptIds
                |> List.choose (fun clockId ->
                    match UnixClock.tryClockGettime (Callers.leader system) clockId system, hostRead clockId with
                    // A refusal is this kernel declining to model a clock; the host may
                    // answer it or not, and either is consistent with declining.
                    | Error _, _ -> None
                    | Ok (ClockGettimeAnswer.Failed UnixError.EINVAL), HostOutcome.Failed errno when errno = EINVAL ->
                        None
                    | Ok (ClockGettimeAnswer.Completed _), HostOutcome.Read _ -> None
                    | modelled, host -> Some $"id %d{clockId}: model %A{modelled}, host %A{host}"
                )

            disagreements |> shouldEqual []
        )

    /// How many distinct whole-microsecond readings `showsSubMicrosecondDigits` takes as
    /// showing that a clock keeps only whole microseconds.
    [<Literal>]
    let private WholeMicrosecondReadings = 20

    /// Whether the host's readings of `clockId` carry a digit finer than a microsecond:
    /// true at the first reading that does, and false once `WholeMicrosecondReadings`
    /// readings, each differing from the one before, have not.
    ///
    /// It counts distinct readings, not calls or elapsed time. A coarse clock repeats its
    /// value until its next tick, so calls alone do not show it changing; and a reader the
    /// scheduler or the garbage collector holds up reads nothing while held, so time alone
    /// does not either.
    ///
    /// Fails if the clock has not shown that many values by `deadline`.
    let private showsSubMicrosecondDigits (clockId : int) (deadline : System.TimeSpan) : bool =
        let stopwatch = Stopwatch.StartNew ()
        let mutable verdict : bool voption = ValueNone
        let mutable previous : Timespec voption = ValueNone
        let mutable distinct = 0

        while verdict.IsNone do
            if distinct >= WholeMicrosecondReadings then
                verdict <- ValueSome false
            elif stopwatch.Elapsed > deadline then
                failwith
                    $"clock id %d{clockId} showed %d{distinct} distinct whole-microsecond readings in %O{deadline}, short of the %d{WholeMicrosecondReadings} its verdict needs"
            else
                match hostRead clockId with
                | HostOutcome.Failed errno ->
                    failwith $"clock id %d{clockId} answered once and then failed with %d{errno}"
                | HostOutcome.Read reading when reading.Nanoseconds % 1000L <> 0L -> verdict <- ValueSome true
                | HostOutcome.Read reading ->
                    match previous with
                    | ValueSome before when before.Seconds = reading.Seconds && before.Nanoseconds = reading.Nanoseconds ->
                        ()
                    | ValueSome _
                    | ValueNone -> distinct <- distinct + 1

                    previous <- ValueSome reading

        verdict.Value

    [<Test>]
    let ``a clock reports whole microseconds here exactly when it does on the host`` () : unit =
        HostPlatform.onUnixHost (fun flavour ->
            // Two clocks, the monotonic one and the realtime one, and one reading
            // of each whose sub-microsecond part is non-zero: a clock that keeps
            // whole microseconds drops it, and one that does not keeps it.
            let system =
                imageOn flavour
                |> UnixBootImage.tryWithBootTime (UnixTimestamp.ofSeconds 1_000_000L)
                |> Configured.expectOk BootTimeRefusal.describe
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
                |> UnixSystem.advanceClock 1_000_000_123L

            // Linux's CLOCK_REALTIME_COARSE carries sub-microsecond digits only
            // once something has set the realtime clock to a time that has them
            // (`coarse-realtime-digits.c`), which is how the host was set up
            // rather than what the clock is, so the host cannot settle it.
            let hostDependent (clockId : int) =
                flavour = SimulatedUnixFlavour.Linux && clockId = 5

            for clockId in [ 0..16 ] |> List.filter (hostDependent >> not) do
                match UnixClock.tryClockGettime (Callers.leader system) clockId system with
                | Ok (ClockGettimeAnswer.Completed reading) ->
                    let modelKeepsNanoseconds = UnixTimestamp.nanoseconds reading % 1000 <> 0

                    // A fine clock on the hosts measured (`clock-sub-microsecond.c`) ticks
                    // every 42 ns and lands at most one tick in 24 on a whole microsecond,
                    // so it passes for a whole-microsecond clock only if all 20 distinct
                    // readings land on one. Readings a tick apart cannot both, so that
                    // takes the reader held up between every two of them, and even then
                    // the chance is about 24^-20, under 10^-27. Linux's coarse clocks tick
                    // every 4 ms in the measured VM, and every 10 ms at the slowest HZ
                    // Linux builds with, so 20 values take at most 200 ms, far inside the
                    // deadline.
                    let hostKeepsNanoseconds =
                        showsSubMicrosecondDigits clockId (System.TimeSpan.FromSeconds 10.0)

                    if modelKeepsNanoseconds <> hostKeepsNanoseconds then
                        failwith
                            $"%O{flavour} clock id %d{clockId}: the model keeps sub-microsecond digits = %b{modelKeepsNanoseconds}, the host = %b{hostKeepsNanoseconds}"
                | Ok (ClockGettimeAnswer.Failed _)
                | Error _ -> ()
        )
