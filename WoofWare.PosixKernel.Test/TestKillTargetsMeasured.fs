namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `kill(2)` of each kind of target, held to the `target` rows of
/// `docs/probes/kill-targets`: the calling process's own pid is answered as
/// the kernel answered it, and every other target is refused, since the model
/// sends no signal beyond its own process and does not say whether a pid names
/// one.
///
/// The probe measured what a model of those targets would need: a pid naming
/// nothing is ESRCH on both flavours (on Linux before the number is read, on
/// Darwin after); 0, -1 and a process group reach the processes they name; a
/// Linux thread ID is not ESRCH but reaches its process, the handler running
/// on that thread; and the permission rule between two users (the `cred`,
/// `cont` and `all` rows, Linux only).
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestKillTargetsMeasured =

    let private resource (flavour : SimulatedUnixFlavour) (uid : int) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> $"WoofWare.PosixKernel.Test.kill-targets.linux-uid%d{uid}.txt"
        | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.kill-targets.darwin.txt"

    /// The `target` rows of one output: the target's name, the signal, and the
    /// answer (`0` or an errno's name).
    let private targetRows (name : string) : (string * string * string) list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> line.StartsWith ("section=target ", StringComparison.Ordinal))
        |> List.map (fun line ->
            let m =
                Regex.Match (line, @"^section=target target=(\S+) sig=(\S+) answer=(\S+)(?: handler-on=\S+)?$")

            if not m.Success then
                failwith $"%s{name}: unrecognised row: %s{line}"

            m.Groups.[1].Value, m.Groups.[2].Value, m.Groups.[3].Value
        )

    let private replay (flavour : SimulatedUnixFlavour) (uid : int) : unit =
        let platform = HostPlatform.platformOf flavour
        let numbering = SimulatedUnixPlatform.signalNumbering platform

        let booted : UnixSystem<int, string> =
            UnixSystem.initial platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1

        let self = ProcessId.toInt32 (Lone.pid booted)

        let threadId =
            UnixSystem.threads (Lone.pid booted) booted
            |> Map.find 1
            |> UnixThreadState.osThreadId
            |> OsThreadId.toUInt64
            |> int32

        // A pid the machine has given nothing: no process and no thread.
        let nothing = self + 1000

        let rows = targetRows (resource flavour uid)
        rows |> List.isEmpty |> shouldEqual false

        for target, signal, answer in rows do
            let pid =
                match target with
                | "self" -> self
                | "reaped" -> nothing
                | "INT_MAX" -> Int32.MaxValue
                | "zero" -> 0
                | "minus-one" -> -1
                | "minus-own-pgid" -> -self
                | "minus-reaped" -> -nothing
                | "INT_MIN" -> Int32.MinValue
                | "pid-one" -> 1
                | "tid"
                | "exited-tid" -> threadId
                | other -> failwith $"unrecognised target %s{other}"

            let signo =
                match signal with
                | "USR1" -> Signal.toRawSignoUnder numbering Signal.SIGUSR1
                | number -> Int32.Parse number

            let modelled =
                match UnixSignal.tryKill (Callers.leader booted) pid signo booted with
                | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, _))) -> Some "0"
                | Ok (Error errno) -> Some (string<UnixError> errno)
                | Ok other -> failwith $"%s{target} %s{signal}: unexpected %A{other}"
                | Error _ -> None

            match target, modelled with
            | "self", Some modelled ->
                if modelled <> answer then
                    failwith
                        $"kill of the process's own pid with %s{signal}: the model answers %s{modelled}, the probe %s{answer}"
            | "self", None -> failwith $"kill of the process's own pid with %s{signal} was refused"
            | _, None -> ()
            | _, Some modelled ->
                failwith
                    $"kill of %s{target} with %s{signal}: the model answers %s{modelled} (the probe %s{answer}), where it holds no rule for that target"

    [<Test>]
    let ``Linux as root: the process's own pid is answered as measured, and every other target refused`` () =
        replay SimulatedUnixFlavour.Linux 0

    [<Test>]
    let ``Linux as uid 1000: the process's own pid is answered as measured, and every other target refused`` () =
        replay SimulatedUnixFlavour.Linux 1000

    [<Test>]
    let ``Darwin: the process's own pid is answered as measured, and every other target refused`` () =
        replay SimulatedUnixFlavour.Darwin 501
