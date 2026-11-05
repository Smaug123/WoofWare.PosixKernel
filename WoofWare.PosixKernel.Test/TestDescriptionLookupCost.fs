namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Finding one open file description costs the same however many the machine
/// holds: a question that looks one up, and a wake sweep that looks up the
/// description a sleeping read is of, allocate as many bytes on a machine of a
/// few descriptions as on one of hundreds. Measured by bytes rather than time,
/// because bytes do not move with the host's load, and a lookup in a larger
/// table allocates no more unless each comparison of two keys allocates. The
/// extra descriptions are epoll instances, which nothing else on the machine
/// is filed under, so that only the table of descriptions grows.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDescriptionLookupCost =

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    let private pipe (caller : Caller<int>) (system : UnixSystem<int, unit>) : int * UnixSystem<int, unit> =
        match UnixPipe.pipe2 caller 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (readFd, _), system -> readFd, resume caller system
        | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"

    let private epoll (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixPoll.epollCreate1 caller 0 system with
        | DescriptorAnswer.Returned _, system -> resume caller system
        | DescriptorAnswer.Failed error, _ -> failwith $"expected epoll_create1 to make an instance: %O{error}"

    /// A machine of one process, with its standard streams, thread 1 asleep in
    /// a read of an empty pipe of its own, and `epolls` epoll instances made
    /// after that; and the process's leader and that sleeper.
    let private machine (epolls : int) : UnixSystem<int, unit> * Caller<int> * Caller<int> =
        let booted =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.boot (ProcessLaunch.create UnixSystem.pipedStandardStreams 0 (CpuId 0))

        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let sleeper = Caller.make (Caller.processId leader) 1

        let readFd, system = pipe leader booted

        let system =
            match UnixThreadLifecycle.spawn leader 1 (CpuId 0) system with
            | SpawnAnswer.Spawned _, system -> resume leader system
            | answer, _ -> failwith $"expected thread 1 to start: %A{answer}"

        let system =
            match UnixReadWrite.read sleeper readFd UserBuffer.Mapped 64UL system with
            | ReadOutcome.WouldBlock _, system -> system
            | outcome, _ -> failwith $"expected thread 1's read to sleep: %A{outcome}"

        let system =
            (system, [ 1..epolls ]) ||> List.fold (fun system _ -> epoll leader system)

        system, leader, sleeper

    /// The fewest bytes `ask` allocates, of several, after one to warm it up.
    let private bytesOf (ask : unit -> unit) : int64 =
        let once () : int64 =
            let before = System.GC.GetAllocatedBytesForCurrentThread ()
            ask ()
            System.GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    /// Each question, by name, that looks up a description of the process a
    /// machine `machine` made.
    let private question
        (name : string)
        (leader : Caller<int>)
        (sleeper : Caller<int>)
        : UnixSystem<int, unit> -> unit
        =
        let pid = Caller.processId leader

        match name with
        | "satisfied" ->
            fun system ->
                match UnixWait.satisfied sleeper system with
                | Some primitives when Set.isEmpty primitives -> ()
                | other -> failwith $"expected thread 1's read to be unable to go on: %A{other}"
        | "descriptorTarget" ->
            fun system ->
                match UnixSystem.descriptorTarget pid 0 system with
                | Some _ -> ()
                | None -> failwith "expected descriptor 0 to name a description"
        | "wake" ->
            fun system ->
                match UnixWait.wake system with
                | [], _ -> ()
                | woken, _ -> failwith $"expected the sweep to wake nobody: %A{woken}"
        | name -> failwith $"no question named %s{name}"

    [<TestCase "satisfied">]
    [<TestCase "descriptorTarget">]
    [<TestCase "wake">]
    let ``looking up a description allocates as much among hundreds of descriptions as among a few``
        (name : string)
        : unit
        =
        let bytesOn (epolls : int) : int64 =
            let system, leader, sleeper = machine epolls
            let ask = question name leader sleeper
            bytesOf (fun () -> ask system)

        bytesOn 256 |> shouldEqual (bytesOn 1)
