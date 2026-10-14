namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The thread table, exercised directly rather than through a client.
///
/// It is generic in the thread name for the same reason `SignalState` is: naming a
/// scheduling entity is the client's business. These rows use `int` as the name,
/// which is the point — nothing here knows what a `ThreadId` is.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixThreadTable =

    let private empty : Map<int, UnixThreadState> = Map.empty

    /// A Linux process whose leader is thread 0, with process ID 4242, on a
    /// machine with four processors.
    let private initial : UnixSystem<int, string> =
        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> UnixBootImage.tryWithProcessorCount 4
        |> Configured.expectOk ProcessorCountRefusal.describe
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private withThread (name : int) (cpu : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixThreadLifecycle.trySpawn (Lone.leader system) name (CpuId cpu) system with
        | Ok (SpawnAnswer.Spawned _, system) -> system
        | Ok (SpawnAnswer.Failed error, _) -> failwith $"spawning %d{name} failed with %O{error}"
        | Error refusal -> failwith $"spawning %d{name} was refused: %s{SpawnRefusal.describe refusal}"

    let private idOf (name : int) (threads : Map<int, UnixThreadState>) : uint64 =
        OsThreadId.toUInt64 (UnixThreadState.osThreadId (UnixThreadTable.get name threads))

    [<Test>]
    let ``a spawned thread is readable`` () : unit =
        let threads = (Lone.threads (initial |> withThread 7 3))

        UnixThreadState.cpu (UnixThreadTable.get 7 threads) |> shouldEqual (CpuId 3)
        idOf 7 threads |> shouldEqual 4243UL
        UnixThreadTable.parkedFor 7 threads |> shouldEqual None

    [<Test>]
    let ``a name that was never spawned is refused loudly`` () : unit =
        let exn =
            Assert.Throws<exn> (fun () -> UnixThreadTable.get 7 empty |> ignore<UnixThreadState>)

        exn.Message |> shouldContainText "names no thread"

    [<Test>]
    let ``spawning one name twice is refused`` () : unit =
        // A second spawn would discard the first one's processor and OS thread id.
        let system = initial |> withThread 7 3

        let exn =
            Assert.Throws<exn> (fun () -> withThread 7 5 system |> ignore<UnixSystem<int, string>>)

        exn.Message |> shouldContainText "already names a thread"

        let leader =
            Assert.Throws<exn> (fun () -> withThread 0 5 system |> ignore<UnixSystem<int, string>>)

        leader.Message |> shouldContainText "already names a thread"

    [<Test>]
    let ``parking and releasing leave the rest of the thread alone`` () : unit =
        // On a thread that is *not* on processor 0, so that "left alone" and "reset
        // to zero" are distinguishable.
        let system = initial |> withThread 7 3

        let wait : ParkedEpollWait =
            {
                Epoll = OpenFileDescriptionId 5L
                MaxEvents = 8
                Buffer = UserBuffer.Mapped
                Deadline = None
            }

        let parked =
            UnixThreadTable.withPark
                7
                {
                    Syscall = ParkedSyscall.EpollWait wait
                    Ordinal = ParkOrdinal 0L
                }
                (Lone.threads system)

        UnixThreadTable.parkedFor 7 parked
        |> shouldEqual (Some (ParkedSyscall.EpollWait wait))

        UnixThreadState.cpu (UnixThreadTable.get 7 parked) |> shouldEqual (CpuId 3)
        idOf 7 parked |> shouldEqual 4243UL

        let released = UnixThreadTable.unpark 7 parked
        UnixThreadTable.parkedFor 7 released |> shouldEqual None
        UnixThreadState.cpu (UnixThreadTable.get 7 released) |> shouldEqual (CpuId 3)

    [<Test>]
    let ``reconcile is silent when the table matches`` () : unit =
        let threads = (Lone.threads (initial |> withThread 1 0 |> withThread 2 1))

        UnixThreadTable.reconcile (Set.ofList [ 0 ; 1 ; 2 ]) threads
        |> shouldEqual ([], [])

    [<Test>]
    let ``reconcile reports a live thread the table has no entry for`` () : unit =
        let threads = (Lone.threads (initial |> withThread 1 0))

        UnixThreadTable.reconcile (Set.ofList [ 0 ; 1 ; 2 ]) threads
        |> shouldEqual ([ 2 ], [])

    [<Test>]
    let ``reconcile reports an entry no live thread claims`` () : unit =
        let threads = (Lone.threads (initial |> withThread 1 0 |> withThread 2 1))

        UnixThreadTable.reconcile (Set.ofList [ 0 ; 1 ]) threads
        |> shouldEqual ([], [ 2 ])

    [<Test>]
    let ``reconcile reports both directions at once`` () : unit =
        // The row that separates "reports both" from "reports whichever it
        // happens to check first".
        let threads = (Lone.threads (initial |> withThread 1 0 |> withThread 3 1))

        UnixThreadTable.reconcile (Set.ofList [ 0 ; 1 ; 2 ]) threads
        |> shouldEqual ([ 2 ], [ 3 ])
