namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A question about one process, and a wake sweep that asks each sleeping
/// thread's wake condition of its own process, cost the same however many
/// other processes the machine holds: answering one must not copy the table of
/// every process. Measured by the bytes each allocates, which unlike time do
/// not move with the host's load, and which a lookup in a larger table of
/// processes does not change: the same question allocates the same bytes on a
/// machine of two processes as on one of 128. The other processes hold no
/// descriptors, so that both machines hold the same open file descriptions.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestQueryCost =

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    /// A machine of `count` processes, each with its leader alone, the first of
    /// which has its standard streams and thread 1 asleep in a read of an empty
    /// pipe of its own, and the rest no descriptor at all; and the first
    /// process's leader and that sleeper.
    let private machine (count : int) : UnixSystem<int, unit> * Caller<int> * Caller<int> =
        let booted =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.boot (ProcessLaunch.create UnixSystem.pipedStandardStreams 0 (CpuId 0))

        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let sleeper = Caller.make (Caller.processId leader) 1

        let readFd, system =
            match UnixPipe.pipe2 leader 0 UserBuffer.Mapped booted with
            | Pipe2Answer.Created (readFd, _), system -> readFd, resume leader system
            | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"

        let system =
            match UnixThreadLifecycle.spawn leader 1 (CpuId 0) system with
            | SpawnAnswer.Spawned _, system -> resume leader system
            | answer, _ -> failwith $"expected thread 1 to start: %A{answer}"

        let system =
            match UnixReadWrite.read sleeper readFd UserBuffer.Mapped 64UL system with
            | ReadOutcome.WouldBlock _, system -> system
            | outcome, _ -> failwith $"expected thread 1's read to sleep: %A{outcome}"

        let system =
            (system, [ 2..count ])
            ||> List.fold (fun system _ -> UnixSystem.launch (ProcessLaunch.create Map.empty 0 (CpuId 0)) system |> snd)

        system, leader, sleeper

    /// The fewest bytes `ask` allocates, of several, after one to warm it up.
    let private bytesOf (ask : unit -> unit) : int64 =
        let once () : int64 =
            let before = System.GC.GetAllocatedBytesForCurrentThread ()
            ask ()
            System.GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    /// Each public question that `Entry.query` answers, by name, asked of the
    /// first process of a machine `machine` made.
    let private question
        (name : string)
        (leader : Caller<int>)
        (sleeper : Caller<int>)
        : UnixSystem<int, unit> -> unit
        =
        let pid = Caller.processId leader

        match name with
        | "owesReturn" -> fun system -> UnixSignal.owesReturn leader system |> ignore<bool>
        | "runningOn" -> fun system -> UnixScheduling.runningOn leader system |> ignore<CpuId option>
        | "satisfied" ->
            fun system ->
                match UnixWait.satisfied sleeper system with
                | Some primitives when Set.isEmpty primitives -> ()
                | other -> failwith $"expected thread 1's read to be unable to go on: %A{other}"
        | "leader" -> fun system -> UnixSystem.leader pid system |> ignore<int>
        | "threads" -> fun system -> UnixSystem.threads pid system |> ignore<Map<int, UnixThreadState>>
        | "signals" -> fun system -> UnixSystem.signals pid system |> ignore<SignalState<int, unit>>
        | "environment" -> fun system -> UnixSystem.environment pid system |> ignore<UnixByteString list>
        | "processPath" -> fun system -> UnixSystem.processPath pid system |> ignore<AbsoluteUnixPath option>
        | "fileDescriptors" -> fun system -> UnixSystem.fileDescriptors pid system |> ignore<FileDescriptorRegistry>
        | "currentDirectoryInode" -> fun system -> UnixSystem.currentDirectoryInode pid system |> ignore<InodeNumber>
        | "credentials" -> fun system -> UnixSystem.credentials pid system |> ignore<Credentials>
        | "fileModeCreationMask" -> fun system -> UnixSystem.fileModeCreationMask pid system |> ignore<PermissionBits>
        | "descriptorTarget" -> fun system -> UnixSystem.descriptorTarget pid 0 system |> ignore<OpenFileTarget option>
        | "currentDirectoryPath" ->
            fun system ->
                UnixPathResolution.currentDirectoryPath pid system
                |> ignore<AbsoluteUnixPath option>
        | name -> failwith $"no question named %s{name}"

    [<TestCase "owesReturn">]
    [<TestCase "runningOn">]
    [<TestCase "satisfied">]
    [<TestCase "leader">]
    [<TestCase "threads">]
    [<TestCase "signals">]
    [<TestCase "environment">]
    [<TestCase "processPath">]
    [<TestCase "fileDescriptors">]
    [<TestCase "currentDirectoryInode">]
    [<TestCase "credentials">]
    [<TestCase "fileModeCreationMask">]
    [<TestCase "descriptorTarget">]
    [<TestCase "currentDirectoryPath">]
    let ``a question about one process allocates as much on a machine of 128 processes as on one of 2``
        (name : string)
        : unit
        =
        let bytesOn (count : int) : int64 =
            let system, leader, sleeper = machine count
            let ask = question name leader sleeper
            bytesOf (fun () -> ask system)

        bytesOn 128 |> shouldEqual (bytesOn 2)

    [<Test>]
    let ``a wake sweep allocates as much on a machine of 128 processes as on one of 2`` () : unit =
        let bytesOn (count : int) : int64 =
            let system, _, _ = machine count

            bytesOf (fun () ->
                match UnixWait.wake system with
                | [], _ -> ()
                | woken, _ -> failwith $"expected the sweep to wake nobody: %A{woken}"
            )

        bytesOn 128 |> shouldEqual (bytesOn 2)
