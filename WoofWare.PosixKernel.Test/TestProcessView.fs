namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The view of one process a call's body works on: putting a view back gives
/// the kernel it was focused from, the very value when nothing in it changed;
/// and `checkInvariants` reports the clauses that relate a kernel's processes
/// to each other.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestProcessView =

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private world (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial<int, string> platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private sorted (defects : 'a list) : 'a list = List.sortBy (sprintf "%A") defects

    /// One step of a walk through the processes' own syscalls, each made by
    /// the leader of the `proc`th process, read modulo how many there are.
    [<RequireQualifiedAccess>]
    type private Op =
        /// A listening socket bound to one of `ports`, read modulo how many
        /// there are.
        | Listener of proc : int * port : int
        /// A socket connecting to one of `ports`, read modulo how many there
        /// are.
        | Client of proc : int * port : int
        /// `call`, made through `UnixSystem.tryStep`.
        | Call of proc : int * call : Syscall<int, string>
        | Launch

    let private opGen : Gen<Op> =
        let small = Gen.choose (0, 63)
        let fd = Gen.choose (0, 15)

        Gen.frequency
            [
                2, Gen.map2 (fun p port -> Op.Listener (p, port)) small small
                3, Gen.map2 (fun p port -> Op.Client (p, port)) small small
                2, Gen.map2 (fun p fd -> Op.Call (p, Syscall.Accept (fd, UserBuffer.Mapped, 16u))) small fd
                2, Gen.map (fun p -> Op.Call (p, Syscall.Pipe2 (UserBuffer.Mapped, 0))) small
                2, Gen.map2 (fun p fd -> Op.Call (p, Syscall.Dup fd)) small fd
                3, Gen.map2 (fun p fd -> Op.Call (p, Syscall.Close fd)) small fd
                1, Gen.constant Op.Launch
            ]

    let private ports : uint16 list = [ 8080us ; 8081us ]

    let private apply (system : UnixSystem<int, string>) (op : Op) : UnixSystem<int, string> =
        let processes = UnixSystem.processIds system |> Set.toList

        let leaderOf (i : int) : Caller<int> =
            Caller.make processes.[i % processes.Length] 0

        match op with
        | Op.Listener (proc, port) ->
            let caller = leaderOf proc
            let fd, system = KeventWorld.streamAs caller true system
            let port = ports.[port % ports.Length]

            match
                CopyIn.bindAs
                    caller
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet (UnixSystem.platform system) (KeventWorld.loopback port))
                    system
            with
            | Ok (BindAnswer.Bound _, system) ->
                match UnixSocket.tryListen caller fd 8 system with
                | Ok (_, system) -> system
                | Error refusal -> failwith $"listen: %A{refusal}"
            | Ok (BindAnswer.Failed _, system) -> system
            | other -> failwith $"bind: %A{other}"
        | Op.Client (proc, port) ->
            let caller = leaderOf proc
            let fd, system = KeventWorld.streamAs caller true system
            let port = ports.[port % ports.Length]

            match
                CopyIn.connectAs
                    caller
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet (UnixSystem.platform system) (KeventWorld.loopback port))
                    system
            with
            | Ok (_, system) -> system
            // A full accept queue is outside what the kernel models; the socket
            // stays, unconnected.
            | Error _ -> system
        | Op.Call (proc, call) ->
            match UnixSystem.tryStep (leaderOf proc) call system with
            | Ok stepped ->
                match Stepped.carriedOn stepped with
                | Some system -> system
                | None -> failwith $"%A{call} answered %A{Stepped.view stepped}, leaving no system to walk on from"
            // Outside what the kernel models, so the step changes nothing.
            | Error (SyscallRefusal.Accept _)
            | Error (SyscallRefusal.Close _) -> system
            | Error refusal -> failwith $"%A{call}: %s{SyscallRefusal.describe refusal}"
        | Op.Launch ->
            match Machines.tryLaunch (Machines.launchOn (UnixSystem.platform system)) system with
            | Ok (_, system) -> system
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

    /// What a walk's kernel ended holding.
    [<RequireQualifiedAccess>]
    type private HeldLabel =
        | Connection
        /// A pipe a process made, beyond the standard streams'.
        | Pipe
        /// A description that two or more descriptors name.
        | DuplicatedDescriptor
        /// More than one process.
        | SeveralProcesses

    [<Test>]
    let ``every process's view of a walk's kernel puts back to that kernel, the very value when unchanged`` () : unit =
        let property (cover : HeldLabel -> unit) (platform : SimulatedUnixPlatform, ops : Op list) : unit =
            let system = List.fold apply (world platform) ops

            if not system.Machine.Connections.IsEmpty then
                cover HeldLabel.Connection

            if system.Machine.Pipes.Count > 3 * (UnixSystem.processIds system).Count then
                cover HeldLabel.Pipe

            if
                OpenFileTable.descriptions system.Machine.OpenFiles
                |> Map.exists (fun id _ -> OpenFileTable.descriptorCount id system.Machine.OpenFiles > Some 1)
            then
                cover HeldLabel.DuplicatedDescriptor

            if (UnixSystem.processIds system).Count > 1 then
                cover HeldLabel.SeveralProcesses

            UnixSystem.checkInvariants system |> shouldEqual []

            for pid in UnixSystem.processIds system do
                let focused = Proc.view pid system

                focused.ProcessId |> shouldEqual pid

                (ProcessTable.slots focused.Others).ContainsKey (ProcessId.toInt32 pid)
                |> shouldEqual false

                (ProcessTable.slots focused.Others).Count
                |> shouldEqual ((UnixSystem.processIds system).Count - 1)

                ProcessView.unfocus focused |> shouldEqual system

                obj.ReferenceEquals (ProcessView.unfocusFrom system focused focused, system)
                |> shouldEqual true

        let coverage =
            CoverageSample.check
                (Config.QuickThrowOnFailure.WithMaxTest 200)
                (Arb.fromGen (Gen.zip (Gen.elements platforms) (Gen.listOf opGen)))
                property

        // Counted over the fixed sample.
        coverage.Count HeldLabel.Connection |> shouldBeGreaterThan 20
        coverage.Count HeldLabel.Pipe |> shouldBeGreaterThan 20
        coverage.Count HeldLabel.DuplicatedDescriptor |> shouldBeGreaterThan 20
        coverage.Count HeldLabel.SeveralProcesses |> shouldBeGreaterThan 20

    [<Test>]
    let ``a view put back from the kernel it was focused from is a new kernel exactly when one of its parts is a new value``
        ()
        : unit
        =
        for platform in platforms do
            let pids, system = Machines.withThreads platform 2 2
            let pid = List.head pids
            let focused = Proc.view pid system

            let unchanged (view : ProcessView<int, string>) : bool =
                obj.ReferenceEquals (ProcessView.unfocusFrom system focused view, system)

            unchanged focused |> shouldEqual true

            // An equal leader is the same leader, whatever value holds it.
            unchanged
                { focused with
                    Leader = 0
                }
            |> shouldEqual true

            // Each part, rebuilt as an equal but distinct value, makes a new
            // kernel, equal to the one it was focused from.
            let rebuilt : (string * ProcessView<int, string>) list =
                [
                    "machine",
                    { focused with
                        Machine =
                            { focused.Machine with
                                SoMaxConn = focused.Machine.SoMaxConn
                            }
                    }
                    "scheduling",
                    { focused with
                        Scheduling =
                            { focused.Scheduling with
                                NanosecondsSinceBoot = focused.Scheduling.NanosecondsSinceBoot
                            }
                    }
                    "process",
                    { focused with
                        Process =
                            { focused.Process with
                                Umask = focused.Process.Umask
                            }
                    }
                    "threads",
                    { focused with
                        Threads = UnixThreadTable.withCpu 0 (UnixThreadTable.get 0 focused.Threads).Cpu focused.Threads
                    }
                    "others",
                    (let key = Seq.head (Map.keys (ProcessTable.slots focused.Others))

                     { focused with
                         Others = ProcessTable.add key (ProcessTable.find "test" key focused.Others) focused.Others
                     })
                ]

            for part, view in rebuilt do
                let after = ProcessView.unfocusFrom system focused view

                if obj.ReferenceEquals (after, system) then
                    failwith $"a view whose %s{part} was rebuilt was put back as the kernel it was focused from"

                after |> shouldEqual system

            // A different leader is a different kernel.
            let led =
                ProcessView.unfocusFrom
                    system
                    focused
                    { focused with
                        Leader = 1
                    }

            obj.ReferenceEquals (led, system) |> shouldEqual false
            Proc.leader pid led |> shouldEqual 1

    [<Test>]
    let ``a call that changes nothing answers the kernel it was given`` () : unit =
        for platform in platforms do
            let pids, system = Machines.withThreads platform 2 1

            for pid in pids do
                // close(2) of a descriptor the process does not have: EBADF, and
                // nothing moves.
                match UnixDescriptor.tryClose (Caller.make pid 0) 99 system with
                | Ok (SyscallAnswer.Failed UnixError.EBADF, after) ->
                    obj.ReferenceEquals (after, system) |> shouldEqual true
                | other -> failwith $"close of an unopened descriptor: %A{other}"

                // A call that does change something answers a new kernel, in
                // which only the caller's process has moved.
                match UnixDescriptor.tryDup (Caller.make pid 0) 1 system with
                | Ok (SyscallAnswer.Completed _, after) ->
                    obj.ReferenceEquals (after, system) |> shouldEqual false

                    for other in pids do
                        if other <> pid then
                            obj.ReferenceEquals (
                                ProcessTable.find "test" (ProcessId.toInt32 other) after.Processes,
                                ProcessTable.find "test" (ProcessId.toInt32 other) system.Processes
                            )
                            |> shouldEqual true
                | other -> failwith $"dup: %A{other}"

    [<Test>]
    let ``step by a name that is no thread of the process throws`` () : unit =
        for platform in platforms do
            let system = world platform
            let pid = Lone.pid system

            Assert.Throws<System.InvalidOperationException> (fun () ->
                UnixSystem.tryStep (Caller.make pid 99) Syscall.GetProcessId system |> ignore
            )
            |> ignore

            let error =
                Assert.Throws<System.InvalidOperationException> (fun () ->
                    UnixSystem.step (Caller.make pid 99) Syscall.GetProcessId system |> ignore
                )

            error.Message
            |> shouldContainText "thread 99 is not one of the process's threads"

    [<Test>]
    let ``a process held under a second ID as well is reported by every clause it breaks`` () : unit =
        for platform in platforms do
            let system = world platform
            let pid = Lone.pid system
            let other = ProcessId.parseOrFail "test" 77

            let cloned =
                { system with
                    Processes =
                        ProcessTable.add
                            (ProcessId.toInt32 other)
                            (ProcessTable.find "test" (ProcessId.toInt32 pid) system.Processes)
                            system.Processes
                }

            let leaderTid =
                UnixThreadState.osThreadId (UnixThreadTable.get 0 (Lone.threads system))

            // The launched pipes' three descriptions are each named once by the
            // machine's record and twice by the two tables.
            let counts =
                OpenFileTable.descriptions system.Machine.OpenFiles
                |> Map.keys
                |> Seq.map (fun id ->
                    UnixSystemDefect.OpenFiles (FileDescriptorRegistryDefect.DescriptorCountMismatch (id, 1, 2))
                )
                |> List.ofSeq

            counts.Length |> shouldEqual 3

            UnixSystem.checkInvariants cloned
            |> sorted
            |> shouldEqual (
                sorted (
                    [
                        UnixSystemDefect.DuplicateOsThreadId (leaderTid, [ Caller.make pid 0 ; Caller.make pid 0 ])
                        UnixSystemDefect.CurrentDirectoryHoldMismatch ((Lone.proc system).CurrentDirectoryInode, 1, 2)
                        UnixSystemDefect.SlotUnderAnotherProcessId (other, pid)
                        UnixSystemDefect.DuplicateProcessId pid
                    ]
                    @ counts
                )
            )

    [<Test>]
    let ``a kqueue whose owner is no process on the machine is reported, and its registrations are no table's``
        ()
        : unit
        =
        let listener, system = KeventWorld.listenerAt 8080us KeventWorld.darwin
        let kqueue, system = KeventWorld.kqueue system
        let id = KeventWorld.idOf kqueue system
        let pid = Lone.pid system
        let gone = ProcessId.parseOrFail "test" 9

        // Registered through a descriptor that is not open in any table.
        let state (owner : ProcessId) =
            {
                Owner = owner
                Drained = false
                Registrations =
                    Map.ofList
                        [
                            (listener + 40, KqueueFilter.Read),
                            {
                                Clear = true
                                Receipt = false
                                UserData = 0UL
                                RegisteredAt = 0L
                                Socket = SocketId 0L
                            }
                        ]
                Active = []
            }

        let withOwner (owner : ProcessId) =
            Lone.mapOpenFiles (OpenFileTable.setKqueueState id (state owner)) system
            |> fun system ->
                { system with
                    Machine =
                        { system.Machine with
                            NextEventRegistrationOrdinal = 1L
                        }
                }
            |> UnixSystem.checkInvariants

        withOwner pid
        |> shouldEqual
            [
                UnixSystemDefect.DescriptorTable (
                    pid,
                    FileDescriptorRegistryDefect.KqueueRegistrationThroughClosedDescriptor (
                        id,
                        listener + 40,
                        KqueueFilter.Read
                    )
                )
            ]

        withOwner gone
        |> sorted
        |> shouldEqual (
            sorted
                [
                    UnixSystemDefect.KqueueOfAnotherProcess (pid, kqueue, id, gone)
                    UnixSystemDefect.KqueueOwnerNotLive (id, gone)
                ]
        )
