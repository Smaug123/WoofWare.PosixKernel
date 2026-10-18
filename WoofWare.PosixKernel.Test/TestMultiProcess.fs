namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Several processes in one `UnixSystem`, each call naming its caller's
/// process: the kernel chooses each later process's ID, the processes share
/// the machine's ports, filesystem and pipes and nothing of each other's own
/// state, and every invariant holds after every call.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestMultiProcess =

    let private context : string = "TestMultiProcess"

    let private launchOn (platform : SimulatedUnixPlatform) : ProcessLaunch<int> =
        Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A machine of `platform` with `count` processes, the first booted and
    /// the rest launched, and their process IDs in that order.
    let private machineOf (platform : SimulatedUnixPlatform) (count : int) : ProcessId list * UnixSystem<int, string> =
        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let machine = Machines.ofSystem first

        ((([ Lone.pid first ], machine)), [ 2..count ])
        ||> List.fold (fun (pids, machine) _ ->
            match Machines.tryLaunch (launchOn platform) machine with
            | Ok (pid, machine) -> pids @ [ pid ], machine
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"
        )

    let private viewOf (pid : ProcessId) (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
        match Machines.focus pid machine with
        | Some view -> view
        | None -> failwith $"no process %O{pid}"

    /// `f` in the view of `pid`, written back.
    let private inProcess
        (pid : ProcessId)
        (f : UnixSystem<int, string> -> 'a * UnixSystem<int, string>)
        (machine : UnixSystem<int, string>)
        : 'a * UnixSystem<int, string>
        =
        match Machines.inView pid f machine with
        | Some answered -> answered
        | None -> failwith $"no process %O{pid}"

    let private assertClean (machine : UnixSystem<int, string>) : unit = Machines.assertClean machine

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    // ------------------------------------------------------------- process IDs

    [<Test>]
    let ``Linux mints a later process's ID from the thread ID counter, and its leader's thread ID is it`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64

        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        // A thread of the first process takes the next thread ID, so the
        // second process gets the one after.
        let worker, first =
            match UnixThreadLifecycle.trySpawn (Callers.thread 0 first) 1 (CpuId 0) first with
            | Ok (SpawnAnswer.Spawned worker, first) -> worker, first
            | Ok (SpawnAnswer.Failed error, _) -> failwith $"spawn: %O{error}"
            | Error refusal -> failwith $"spawn: %s{SpawnRefusal.describe refusal}"

        OsThreadId.toUInt64 worker |> shouldEqual 4243UL

        let pid, machine =
            match Machines.tryLaunch (launchOn platform) (Machines.ofSystem first) with
            | Ok launched -> launched
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

        ProcessId.toInt32 pid |> shouldEqual 4244

        let view = viewOf pid machine

        UnixThreadState.osThreadId (Proc.thread (Caller.make pid 0) view)
        |> OsThreadId.toUInt64
        |> shouldEqual 4244UL

        Machines.processIds machine |> shouldEqual (Set.ofList [ Lone.pid first ; pid ])

        assertClean machine

    [<Test>]
    let ``Darwin mints a later process's ID from a counter of its own, and its leader's thread ID from the thread counter``
        ()
        : unit
        =
        let platform = SimulatedUnixPlatform.macOsArm64

        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.processId (ProcessId.parseOrFail context 500)
            |> Launched.leaderThreadId 9000UL
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let pids, machine =
            ((([], Machines.ofSystem first)), [ 1..2 ])
            ||> List.fold (fun (pids, machine) _ ->
                match Machines.tryLaunch (launchOn platform) machine with
                | Ok (pid, machine) -> pids @ [ pid ], machine
                | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"
            )

        pids |> List.map ProcessId.toInt32 |> shouldEqual [ 501 ; 502 ]

        pids
        |> List.map (fun pid ->
            UnixThreadState.osThreadId (Proc.thread (Caller.make pid 0) (viewOf pid machine))
            |> OsThreadId.toUInt64
        )
        |> shouldEqual [ 9001UL ; 9002UL ]

        assertClean machine

    [<Test>]
    let ``Darwin refuses a process ID at PID_MAX, and stops at it rather than wrapping`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64

        UnixSystem.initial<int, string> platform
        |> UnixBootImage.tryWithProcessId (ProcessId.parseOrFail context ProcessIdTable.darwinPidMax)
        |> Result.map ignore
        |> shouldEqual (
            Error (
                ProcessIdRefusal.NotBelowDarwinPidMax (
                    ProcessId.parseOrFail context ProcessIdTable.darwinPidMax,
                    ProcessIdTable.darwinPidMax
                )
            )
        )

        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.processId (ProcessId.parseOrFail context (ProcessIdTable.darwinPidMax - 1))
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        Machines.tryLaunch (launchOn platform) (Machines.ofSystem first)
        |> Result.map ignore
        |> shouldEqual (Error (ProcessCreationRefusal.DarwinPidMaxReached ProcessIdTable.darwinPidMax))

    [<Test>]
    let ``Darwin refuses a launch once its thread ID counter has reached the top`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64

        // The leader takes UInt64.MaxValue - 1, so the counter is left at
        // UInt64.MaxValue, beyond which what Darwin does is unmeasured.
        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.leaderThreadId (System.UInt64.MaxValue - 1UL)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        Machines.tryLaunch (launchOn platform) (Machines.ofSystem first)
        |> Result.map ignore
        |> shouldEqual (Error ProcessCreationRefusal.DarwinThreadIdCounterExhausted)

        // One below, the launch takes the counter's last ID, and the next is refused.
        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.leaderThreadId (System.UInt64.MaxValue - 2UL)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let pid, machine =
            match Machines.tryLaunch (launchOn platform) (Machines.ofSystem first) with
            | Ok launched -> launched
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

        UnixThreadState.osThreadId (Proc.thread (Caller.make pid 0) (viewOf pid machine))
        |> OsThreadId.toUInt64
        |> shouldEqual (System.UInt64.MaxValue - 1UL)

        Machines.tryLaunch (launchOn platform) machine
        |> Result.map ignore
        |> shouldEqual (Error ProcessCreationRefusal.DarwinThreadIdCounterExhausted)

    [<Test>]
    let ``Linux refuses a launch once every process ID it would hand out is a live thread's`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64

        // pid_max 301 leaves 300 alone free once the first process is 299.
        let first =
            UnixSystem.initial<int, string> platform
            |> Launched.processId (ProcessId.parseOrFail context 299)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> UnixSystem.writePidMaxSysctl 301

        let pid, machine =
            match Machines.tryLaunch (launchOn platform) (Machines.ofSystem first) with
            | Ok launched -> launched
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

        ProcessId.toInt32 pid |> shouldEqual 300

        Machines.tryLaunch (launchOn platform) machine
        |> Result.map ignore
        |> shouldEqual (Error ProcessCreationRefusal.NoFreeProcessId)

    [<Test>]
    let ``a launch is refused for another platform, and for a directory the filesystem does not hold`` () : unit =
        let _, machine = machineOf SimulatedUnixPlatform.linuxX64 1

        Machines.tryLaunch (launchOn SimulatedUnixPlatform.linuxArm64) machine
        |> Result.map ignore
        |> shouldEqual (
            Error (
                ProcessCreationRefusal.Launch (
                    LaunchRefusal.NotOfPlatform (SimulatedUnixPlatform.linuxArm64, SimulatedUnixPlatform.linuxX64)
                )
            )
        )

        let nowhere = AbsoluteUnixPath.parseOrFail context "/nowhere"

        Machines.tryLaunch
            (launchOn SimulatedUnixPlatform.linuxX64
             |> ProcessLaunch.withCurrentDirectory nowhere)
            machine
        |> Result.map ignore
        |> shouldEqual (
            Error (
                ProcessCreationRefusal.Launch (
                    LaunchRefusal.CurrentDirectory (nowhere, CurrentDirectoryFault.DoesNotResolve UnixError.ENOENT)
                )
            )
        )

    // ---------------------------------------------------------- shared machine

    let private bindAt
        (pid : ProcessId)
        (port : uint16)
        (view : UnixSystem<int, string>)
        : BindAnswer * UnixSystem<int, string>
        =
        let fd, view = KeventWorld.streamIn pid true view

        match
            CopyIn.bindAs
                (Caller.make pid (Proc.leader pid view))
                fd
                UserBuffer.Mapped
                16u
                (CopyIn.inet (UnixSystem.platform view) (KeventWorld.loopback port))
                view
        with
        | Ok answered -> answered
        | Error refusal -> failwith $"bind: %s{BindRefusal.describe refusal}"

    [<Test>]
    let ``a port one process has bound is EADDRINUSE to another`` () : unit =
        for platform in platforms do
            let pids, machine = machineOf platform 2
            let a, b = pids.[0], pids.[1]

            let answer, machine = inProcess a (bindAt a 8080us) machine

            match answer with
            | BindAnswer.Bound _ -> ()
            | other -> failwith $"the first bind answered %A{other}"

            let answer, machine = inProcess b (bindAt b 8080us) machine
            answer |> shouldEqual (BindAnswer.Failed UnixError.EADDRINUSE)

            // ...and a different port is free to it.
            let answer, machine = inProcess b (bindAt b 8081us) machine

            match answer with
            | BindAnswer.Bound _ -> ()
            | other -> failwith $"the second process's bind of a free port answered %A{other}"

            assertClean machine

    [<Test>]
    let ``each process's descriptors are numbered on their own, and each writes to its own output`` () : unit =
        for platform in platforms do
            let pids, machine = machineOf platform 2

            let opened (pid : ProcessId) (view : UnixSystem<int, string>) =
                match
                    OpenFlagWords.openPathIn
                        pid
                        {
                            Access = FileAccessMode.ReadWrite
                            Create = true
                            Exclusive = false
                            Truncate = false
                            NoFollow = false
                            CloseOnExec = false
                            Synchronous = false
                            DataSynchronous = false
                            Directory = false
                        }
                        (PathArg.ofText "/shared")
                        0o644
                        view
                with
                | Ok (SyscallAnswer.Completed fd, view) -> int fd, view
                | other -> failwith $"open: %A{other}"

            let fds, machine =
                (([], machine), pids)
                ||> List.fold (fun (fds, machine) pid ->
                    let fd, machine = inProcess pid (opened pid) machine
                    fds @ [ fd ], machine
                )

            // The three launched descriptors are each process's own, so each
            // first open is 3.
            fds |> shouldEqual [ 3 ; 3 ]

            let write (pid : ProcessId) (text : string) (view : UnixSystem<int, string>) =
                match
                    WriteOutcomes.writeBytesAs
                        (Caller.make pid 0)
                        1
                        (ImmutableArray.CreateRange (System.Text.Encoding.ASCII.GetBytes text))
                        view
                with
                | Ok (WriteStep.Returns (_, view)) -> (), view
                | other -> failwith $"write: %A{other}"

            let (), machine = inProcess pids.[0] (write pids.[0] "first") machine
            let (), machine = inProcess pids.[1] (write pids.[1] "second") machine
            let (), machine = inProcess pids.[0] (write pids.[0] "again") machine

            UnixSystem.delivered (viewOf pids.[0] machine)
            |> DeliveryLog.toList
            |> List.map (fun delivery ->
                delivery.Endpoint, System.Text.Encoding.ASCII.GetString (delivery.Bytes.AsSpan ())
            )
            |> shouldEqual
                [
                    ExternalEndpoint (pids.[0], 1), "first"
                    ExternalEndpoint (pids.[1], 1), "second"
                    ExternalEndpoint (pids.[0], 1), "again"
                ]

            assertClean machine

    let private mkdir
        (pid : ProcessId)
        (path : string)
        (view : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        Answered.mkdir (Caller.make pid (Proc.leader pid view)) (PathArg.ofText path) 0o755 view

    let private chdir
        (pid : ProcessId)
        (path : string)
        (view : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        Answered.chdir (Caller.make pid (Proc.leader pid view)) (PathArg.ofText path) view

    let private rmdir
        (pid : ProcessId)
        (path : string)
        (view : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        match UnixNamespace.tryRmdir (Caller.make pid (Proc.leader pid view)) (PathArg.ofText path) view with
        | Ok answered -> answered
        | Error refusal -> failwith $"rmdir: %s{RemovalRefusal.describe refusal}"

    [<Test>]
    let ``a directory one process stands in outlives its removal by another, until it steps out`` () : unit =
        for platform in platforms do
            let pids, machine = machineOf platform 2
            let a, b = pids.[0], pids.[1]

            let _, machine = inProcess a (mkdir a "/d") machine
            let _, machine = inProcess a (chdir a "/d") machine
            let standing = (Proc.state a (viewOf a machine)).CurrentDirectoryInode

            let answer, machine = inProcess b (rmdir b "/d") machine
            answer |> shouldEqual (SyscallAnswer.Completed 0L)

            // No name reaches it, and it is still there: a stands in it.
            VirtualFileSystem.tryGet standing (viewOf b machine).Machine.FileSystem
            |> Option.isSome
            |> shouldEqual true

            assertClean machine

            // Stepping out lets it go.
            let _, machine = inProcess a (chdir a "/") machine

            VirtualFileSystem.tryGet standing (viewOf b machine).Machine.FileSystem
            |> shouldEqual None

            assertClean machine

    [<Test>]
    let ``pid_max may be lowered past another process's live thread ID`` () : unit =
        let pids, machine = machineOf SimulatedUnixPlatform.linuxX64 2

        // The second process's leader is 4243. Linux keeps a live ID that a
        // lowered pid_max no longer admits (`pid-max-below-live.c`), so a write
        // at or below it takes, and leaves the machine as consistent as it
        // found it.
        ProcessId.toInt32 pids.[1] |> shouldEqual 4243

        let (), lowered =
            inProcess pids.[0] (fun view -> (), UnixSystem.writePidMaxSysctl 4243 view) machine

        assertClean lowered
        Proc.state pids.[1] lowered |> shouldEqual (Proc.state pids.[1] machine)
        Proc.threadMap pids.[1] lowered |> shouldEqual (Proc.threadMap pids.[1] machine)

    [<Test>]
    let ``a process ID recorded as live that no process has is reported`` () : unit =
        let _, machine = machineOf SimulatedUnixPlatform.linuxX64 2

        // Clean, the machine recording each process's thread and process IDs,
        // its holds and its current directory.
        UnixSystem.checkInvariants machine |> shouldEqual []

        let ghost = ProcessId.parseOrFail context 77

        let forged =
            { machine with
                Machine =
                    { machine.Machine with
                        ProcessIds = ProcessIdTable.add ghost machine.Machine.ProcessIds
                    }
            }

        Machines.checkInvariants forged
        |> shouldEqual [ UnixSystemDefect.LiveProcessIdsMismatch (Set.singleton ghost, Set.empty) ]

    [<Test>]
    let ``the machine reports a current directory hold no process stands in, and a missing one`` () : unit =
        let pids, machine = machineOf SimulatedUnixPlatform.linuxX64 2
        let root = (Proc.state pids.[0] (viewOf pids.[0] machine)).CurrentDirectoryInode

        machine.Machine.CurrentDirectories |> shouldEqual (Map.ofList [ root, 2 ])

        let short =
            { machine with
                Machine = UnixMachineState.releaseCurrentDirectory root machine.Machine
            }

        Machines.checkInvariants short
        |> shouldEqual [ UnixSystemDefect.CurrentDirectoryHoldMismatch (root, 1, 2) ]
