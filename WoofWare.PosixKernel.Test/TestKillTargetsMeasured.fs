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

/// `kill(2)` of each kind of target, held to the `target` rows of
/// `docs/probes/kill-targets`.
///
/// A pid that names no process on the machine, and on Linux no thread either,
/// is ESRCH: on Linux whatever the signal number, and on Darwin once the
/// number has passed (a number that is no signal is EINVAL first). The model
/// refuses the targets it holds no rule for: 0, -1 and process groups;
/// process 1, which every real machine has and a model machine never does;
/// another process on the machine; and a Linux thread ID, which reaches the
/// thread's process with that thread preferred.
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

    /// A machine of three processes, each with threads 0 and 1: the first makes
    /// the calls, the second runs on, and the third has ended. The first also
    /// had a thread 2, which has exited.
    type private World =
        {
            System : UnixSystem<int, string>
            Caller : Caller<int>
            Other : ProcessId
            Ended : ProcessId
            /// The thread ID of the first process's thread 1.
            OwnThread : int32
            /// The thread ID of the second process's thread 1.
            OthersThread : int32
            /// The thread ID the first process's thread 2 had.
            ExitedThread : int32
        }

    let private threadIdOf (pid : ProcessId) (thread : int) (system : UnixSystem<int, string>) : int32 =
        UnixSystem.threads pid system
        |> Map.find thread
        |> UnixThreadState.osThreadId
        |> OsThreadId.toUInt64
        |> int32

    let private worldOf (flavour : SimulatedUnixFlavour) : World =
        let platform = HostPlatform.platformOf flavour

        match Machines.withThreads platform 3 2 with
        | [ first ; other ; ended ], system ->
            let caller = Caller.make first 0
            let system = Threads.spawnIn first 2 system
            let exited = threadIdOf first 2 system

            let system =
                match UnixThreadLifecycle.exitThread (Caller.make first 2) 0 system with
                | ProcessFate.Continues ((), system) -> system
                | ProcessFate.ProcessEnded _ -> failwith "thread 2's exit ended its process"

            let _, system = UnixThreadLifecycle.exitGroup (Caller.make ended 0) 0 system

            {
                System = system
                Caller = caller
                Other = other
                Ended = ended
                OwnThread = threadIdOf first 1 system
                OthersThread = threadIdOf other 1 system
                ExitedThread = exited
            }
        | pids, _ -> failwith $"expected three processes, got %A{pids}"

    /// What the model answers for `kill(pid, signo)`: `Some` of `0` or an
    /// errno's name, or `None` for a refusal.
    let private modelled (world : World) (pid : int32) (signo : int32) : string option =
        match UnixSignal.tryKill world.Caller pid signo world.System with
        | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, _)) -> Some "0"
        | Ok (ProcessFate.Continues (KillAnswer.Failed errno, after)) ->
            after |> shouldEqual world.System
            Some (string<UnixError> errno)
        | Ok other -> failwith $"kill(%d{pid}, %d{signo}): unexpected %A{other}"
        | Error _ -> None

    let private replay (flavour : SimulatedUnixFlavour) (uid : int) : unit =
        let numbering = HostPlatform.signalNumberingOf flavour
        let world = worldOf flavour
        let self = ProcessId.toInt32 (Caller.processId world.Caller)

        let rows = targetRows (resource flavour uid)
        rows |> List.isEmpty |> shouldEqual false

        for target, signal, answer in rows do
            // Each target as the model's machine has it, and whether the model
            // answers it.
            let pid, answered =
                match target with
                | "self" -> self, true
                | "reaped" -> ProcessId.toInt32 world.Ended, true
                | "INT_MAX" -> Int32.MaxValue, true
                | "exited-tid" -> world.ExitedThread, true
                | "zero" -> 0, false
                | "minus-one" -> -1, false
                | "minus-own-pgid" -> -self, false
                | "minus-reaped" -> -(ProcessId.toInt32 world.Ended), false
                | "INT_MIN" -> Int32.MinValue, false
                | "pid-one" -> 1, false
                | "tid" -> world.OwnThread, false
                | other -> failwith $"unrecognised target %s{other}"

            let signo =
                match signal with
                | "USR1" -> Signal.toRawSignoUnder numbering Signal.SIGUSR1
                | number -> Int32.Parse number

            match answered, modelled world pid signo with
            | true, Some modelled ->
                if modelled <> answer then
                    failwith $"kill of %s{target} with %s{signal}: the model answers %s{modelled}, the probe %s{answer}"
            | true, None -> failwith $"kill of %s{target} with %s{signal} was refused (the probe: %s{answer})"
            | false, None -> ()
            | false, Some modelled ->
                failwith
                    $"kill of %s{target} with %s{signal}: the model answers %s{modelled} (the probe %s{answer}), where it holds no rule for that target"

    [<Test>]
    let ``Linux as root: every target row is answered as measured, or refused where the model holds no rule`` () =
        replay SimulatedUnixFlavour.Linux 0

    [<Test>]
    let ``Linux as uid 1000: every target row is answered as measured, or refused where the model holds no rule`` () =
        replay SimulatedUnixFlavour.Linux 1000

    [<Test>]
    let ``Darwin: every target row is answered as measured, or refused where the model holds no rule`` () =
        replay SimulatedUnixFlavour.Darwin 501

    [<Test>]
    let ``another process on the machine, and on Linux its thread, are refused`` () =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let world = worldOf flavour
            modelled world (ProcessId.toInt32 world.Other) 0 |> shouldEqual None

            match flavour with
            | SimulatedUnixFlavour.Linux -> modelled world world.OthersThread 0 |> shouldEqual None
            | SimulatedUnixFlavour.Darwin -> ()

    /// For every pid and number: a pid that names no process on the machine,
    /// is not 1, and on Linux names no thread, is ESRCH, on Darwin after the
    /// number's EINVAL; every other pid but the caller's own is refused.
    [<Test>]
    let ``a pid naming nothing on the machine is ESRCH, and every other target the model holds no rule for is refused``
        ()
        =
        let worlds =
            [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]
            |> List.map (fun flavour -> flavour, worldOf flavour)
            |> Map.ofList

        let property (linux : bool) (pick : int) (offset : int) (signo : int) : unit =
            let flavour =
                if linux then
                    SimulatedUnixFlavour.Linux
                else
                    SimulatedUnixFlavour.Darwin

            let world = worlds.[flavour]
            let numbering = HostPlatform.signalNumberingOf flavour
            let self = ProcessId.toInt32 (Caller.processId world.Caller)

            let processes =
                UnixSystem.processIds world.System |> Seq.map ProcessId.toInt32 |> Set.ofSeq

            let threadIds =
                UnixSystem.processIds world.System
                |> Seq.collect (fun pid ->
                    Map.keys (UnixSystem.threads pid world.System)
                    |> Seq.map (fun t -> threadIdOf pid t world.System)
                )
                |> Set.ofSeq

            // Near every interesting pid, and anywhere at all.
            let anchors =
                [
                    self
                    ProcessId.toInt32 world.Other
                    ProcessId.toInt32 world.Ended
                    world.OwnThread
                    world.OthersThread
                    world.ExitedThread
                    1
                    0
                    Int32.MaxValue
                ]

            let pid =
                match abs (pick % (anchors.Length + 1)) with
                | i when i < anchors.Length -> anchors.[i] + (offset % 3)
                | _ -> offset

            let expected =
                if pid = self then
                    None
                elif pid <= 0 || pid = 1 || Set.contains pid processes then
                    Some None
                elif flavour = SimulatedUnixFlavour.Linux && Set.contains pid threadIds then
                    Some None
                elif
                    flavour = SimulatedUnixFlavour.Darwin
                    && signo <> 0
                    && (Signal.ofRawSignoUnder numbering signo).IsNone
                then
                    Some (Some "EINVAL")
                else
                    Some (Some "ESRCH")

            match expected with
            | None -> ()
            | Some expected ->
                let actual = modelled world pid signo

                if actual <> expected then
                    failwith
                        $"%O{flavour}: kill(%d{pid}, %d{signo}): the model answers %A{actual}, expected %A{expected}"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 2000, property)
