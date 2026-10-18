namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Random interleavings of several processes' syscalls in one `UnixSystem`,
/// each made by one of its process's threads, with the machine's own steps
/// between them: a wake pass that finishes the calls it wakes, the clock
/// moving on, and a process ending.
///
/// After every step: every invariant holds, the system's and the
/// filesystem's; no pipe is named in two processes' tables; and no process but
/// the stepping one has moved, except where the step is the machine's (a wake
/// pass finishes calls in whichever processes they are in, one at a time, and
/// each finish moves its own process alone; a process's end removes its
/// own). After a call, the calling
/// process's new descriptors are the lowest its own table had free, whatever
/// the other processes hold. A client whose connection waited in a listener's
/// queue is reset exactly when the step released the listener, by a close or
/// its process's end, without first accepting the connection.
///
/// Calls block: sockets are blocking or not, `accept`, `epoll_wait`, `kevent`,
/// `poll`, `flock` and pipe transfers sleep, and a sleeping thread makes no call
/// until a wake pass finishes its own. A connected socket's `read` and `write`
/// move bytes between processes, through buffers small enough that writes
/// fill them, and a blocking one sleeps until the other process's transfer,
/// close or end wakes it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
[<Order(TestOrder.LongRunning)>]
module TestMultiProcessFuzz =

    /// One step; each index is read modulo whatever it picks from.
    [<RequireQualifiedAccess>]
    type private Op =
        | Socket of nonBlocking : bool
        | Bind of fd : int * port : int
        | Listen of fd : int
        | Connect of fd : int * port : int
        | Accept of fd : int
        /// A read of a connected socket, of `size` bytes: one whose
        /// description is non-blocking when `nonBlocking` and there is one.
        | Receive of fd : int * size : int * nonBlocking : bool
        /// A write of `size` bytes to a connected socket, chosen as for
        /// `Receive`.
        | Send of fd : int * size : int * nonBlocking : bool
        /// Set `O_NONBLOCK` on a connected socket's description.
        | MakeNonBlocking of fd : int
        /// A `Receive` on the process's end of the earliest connection it
        /// holds whose server end is at `ports.[port]`, if it holds one, which
        /// `Receive`'s index into every connected socket the process holds
        /// seldom picks out.
        | ReceiveThrough of port : int * size : int
        /// A `Send` on the socket `ReceiveThrough` picks.
        | SendThrough of port : int * size : int
        /// A `close` of the socket `ReceiveThrough` picks.
        | CloseThrough of port : int
        /// Set `O_NONBLOCK` on the description of the socket `ReceiveThrough`
        /// picks.
        | MakeNonBlockingThrough of port : int
        /// A `Receive` on the process's end of the latest connection it
        /// holds, if it holds one: the one its last connect made, which
        /// `Receive`'s index seldom picks out.
        | ReceiveNewest of size : int
        /// A `close` of the process's listener at `ports.[port]`, if it holds
        /// one.
        | CloseListener of port : int
        | Pipe
        | PipeRead of fd : int
        | PipeWrite of fd : int * size : int
        | Open of path : int
        | Close of fd : int
        | Dup of fd : int
        | Flock of fd : int * operation : int
        | MkDir of dir : int
        | RmDir of dir : int
        | ChDir of dir : int
        | EpollCreate
        | EpollAdd of epoll : int * fd : int
        | EpollWait of epoll : int * timeout : int
        | Kqueue
        | KeventAdd of kqueue : int * fd : int * write : bool
        | KeventWait of kqueue : int * timeout : int
        | InotifyInit of nonBlocking : bool
        /// `inotify_add_watch` of `standing.[dir]` on an instance, asking for
        /// every event this kernel raises.
        | InotifyWatch of inotify : int * dir : int
        | InotifyRmWatch of inotify : int * wd : int
        | InotifyRead of inotify : int
        /// A blocking `inotify_init1`, a watch of `standing.[dir]` on it as
        /// `InotifyWatch` asks, and a read of it, which sleeps, since a new
        /// instance holds nothing: an instance `InotifyRead`'s index seldom
        /// picks out with nothing queued and a blocking description.
        | InotifyAwait of dir : int
        /// An `InotifyWatch` on the newest instance the process holds, which
        /// `InotifyWatch`'s index seldom picks out.
        | InotifyWatchNewest of dir : int
        /// An `InotifyRead` of the newest instance the process holds.
        | InotifyReadNewest
        /// `chmod` of `files.[path]` or of `dirs.[path]`.
        | Chmod of path : int * directory : bool
        /// `unlink` of `files.[path]`.
        | Unlink of path : int
        /// A `poll` of `fds` for IN, and for OUT too unless `readOnly`.
        | Poll of fds : int list * timeout : int * readOnly : bool
        /// `poll` for readability on the process's listener at
        /// `ports.[port]`, if it holds one, which `Poll`'s index into every
        /// socket the process holds seldom picks out.
        | PollListener of port : int * timeout : int
        /// Block `fatal.[signal]`, then `pthread_kill(3)` it to the calling
        /// thread, which leaves it pending there; the thread returns to user mode
        /// after each.
        | BlockAndRaise of signal : int
        /// Unblock `fatal.[signal]`, and return to user mode: the process
        /// ends if the signal is pending on the calling thread.
        | Unblock of signal : int
        | Exit of status : int

    /// A step of the machine's own, or a call made by a thread of a process.
    [<RequireQualifiedAccess>]
    type private Step =
        | Call of proc : int * thread : int * op : Op
        /// Find which sleeping calls the machine wakes, and finish up to
        /// `finishing` of the woken calls not yet finished, oldest woken first.
        | WakePass of finishing : int
        /// Let `milliseconds` pass on the machine's clock.
        | Advance of milliseconds : int
        /// Report that a thread of a process, not asleep or woken, runs on the
        /// processor `cpu` (`UnixScheduling.dispatch`).
        | Dispatch of proc : int * thread : int * cpu : int

    let private ports : uint16 list = [ 8080us ; 8081us ; 8082us ]
    let private files : string list = [ "/f0" ; "/f1" ]

    /// Signals whose default terminates the process. No process installs a
    /// handler, and no other signal is sent but a write's SIGPIPE, which
    /// nothing blocks, so it kills at once.
    let private fatal : Signal list = [ Signal.SIGTERM ; Signal.SIGQUIT ]
    let private dirs : string list = [ "/d0" ; "/d1" ]
    let private standing : string list = "/" :: dirs
    let private threads : int = 3

    // `flock`'s operations, the same on both flavours.
    let private lockShared : int = 1
    let private lockExclusive : int = 2
    let private unlock : int = 8

    let private small : Gen<int> = Gen.choose (0, 63)

    /// -1 waits for ever, 0 not at all, and 5 milliseconds until an advance.
    let private timeout : Gen<int> = Gen.elements [ -1 ; -1 ; 0 ; 5 ]

    let private socketOps : (int * Gen<Op>) list =
        [
            3, Gen.map Op.Socket (Gen.elements [ true ; false ])
            3, Gen.map2 (fun f p -> Op.Bind (f, p)) small small
            3, Gen.map Op.Listen small
            4, Gen.map2 (fun f p -> Op.Connect (f, p)) small small
            3, Gen.map Op.Accept small
        ]

    /// Transfers on connected sockets, weighted apart from `socketOps` so that
    /// a case biased towards sockets is not one biased towards transfers.
    let private transferOps : (int * Gen<Op>) list =
        [
            3,
            Gen.map3
                (fun f s n -> Op.Receive (f, s, n))
                small
                (Gen.elements [ 0 ; 1 ; 1000 ; 65536 ])
                (Gen.elements [ true ; false ])
            3,
            Gen.map3
                (fun f s n -> Op.Send (f, s, n))
                small
                (Gen.elements [ 0 ; 1 ; 1000 ; 70000 ; 300000 ])
                (Gen.elements [ true ; false ])
            1, Gen.map Op.MakeNonBlocking small
        ]

    let private fileOps : (int * Gen<Op>) list =
        [
            2, Gen.constant Op.Pipe
            2, Gen.map Op.PipeRead small
            2, Gen.map2 (fun f s -> Op.PipeWrite (f, s)) small (Gen.elements [ 1 ; 4096 ; 70000 ])
            3, Gen.map Op.Open small
            4, Gen.map Op.Close small
            2, Gen.map Op.Dup small
            5,
            Gen.map2
                (fun f o -> Op.Flock (f, o))
                small
                (Gen.elements [ lockShared ; lockExclusive ; lockExclusive ; unlock ])
            2, Gen.map Op.MkDir small
            2, Gen.map Op.RmDir small
            2, Gen.map Op.ChDir small
            5,
            Gen.map3
                (fun fds t r -> Op.Poll (fds, t, r))
                (Gen.listOfLength 2 small)
                timeout
                (Gen.elements [ false ; true ])
        ]

    let private epollOps : (int * Gen<Op>) list =
        [
            2, Gen.constant Op.EpollCreate
            5, Gen.map2 (fun e f -> Op.EpollAdd (e, f)) small small
            4, Gen.map2 (fun e t -> Op.EpollWait (e, t)) small timeout
        ]

    let private inotifyOps : (int * Gen<Op>) list =
        [
            1, Gen.map Op.InotifyInit (Gen.elements [ true ; false ])
            2, Gen.map2 (fun i d -> Op.InotifyWatch (i, d)) small small
            1, Gen.map2 (fun i w -> Op.InotifyRmWatch (i, w)) small small
            2, Gen.map Op.InotifyRead small
            2, Gen.map2 (fun p d -> Op.Chmod (p, d)) small (Gen.elements [ true ; false ])
            1, Gen.map Op.Unlink small
        ]

    let private kqueueOps : (int * Gen<Op>) list =
        [
            2, Gen.constant Op.Kqueue
            5, Gen.map3 (fun k f w -> Op.KeventAdd (k, f, w)) small small (Gen.elements [ false ; true ])
            4, Gen.map2 (fun k t -> Op.KeventWait (k, t)) small timeout
        ]

    /// The calls a process on `platform` may make. `socketBias` weights the
    /// socket calls against the rest, and `transferBias` the transfers on
    /// connected sockets, each drawn per case, so some runs are mostly sockets,
    /// some mostly transfers and some mostly files.
    let private opsFor (socketBias : int) (transferBias : int) (platform : SimulatedUnixPlatform) : Gen<Op> =
        let sockets = socketOps |> List.map (fun (weight, op) -> weight * socketBias, op)

        let transferOps =
            transferOps |> List.map (fun (weight, op) -> weight * transferBias, op)

        let exit = [ 1, Gen.map Op.Exit (Gen.choose (0, 3)) ]

        let signals =
            [
                1, Gen.map Op.BlockAndRaise (Gen.choose (0, fatal.Length - 1))
                1, Gen.map Op.Unblock (Gen.choose (0, fatal.Length - 1))
            ]
        // A process's end is rare, so that most of a run has several processes,
        // and so is a fatal signal held back.
        let common (ops : (int * Gen<Op>) list) =
            ops |> List.map (fun (weight, op) -> 3 * weight, op)

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            Gen.frequency (
                common (sockets @ transferOps @ fileOps @ epollOps @ inotifyOps)
                @ exit
                @ signals
            )
        | SimulatedUnixFlavour.Darwin ->
            Gen.frequency (common (sockets @ transferOps @ fileOps @ kqueueOps) @ exit @ signals)

    type private Case =
        {
            Platform : SimulatedUnixPlatform
            Processes : int
            /// Whether each process starts with a listener at a port of its
            /// own, an epoll instance or kqueue watching it, and a file another
            /// process can lock, so that the random calls after meet something
            /// another process's calls change.
            Prepared : bool
            Steps : Step list
        }

    /// Calls by two processes that independent draws rarely line up: a call of
    /// the first sets something up that only a later call of the second acts
    /// on. The steps are in the order they run; each is an ordinary call, made
    /// and checked as any other.
    let private crossProcessScenario (platform : SimulatedUnixPlatform) (processes : int) : Gen<Step list> =
        gen {
            let! first = Gen.choose (0, processes - 1)
            let! offset = Gen.choose (1, processes - 1)
            let second = (first + offset) % processes
            let! firstThread = Gen.choose (0, threads - 1)
            let! secondThread = Gen.choose (0, threads - 1)
            let! dir = small

            let byFirst (op : Op) : Step = Step.Call (first, firstThread, op)
            let! closeListener = Gen.elements [ true ; false ]
            let! status = Gen.choose (0, 3)
            let bySecond (op : Op) : Step = Step.Call (second, secondThread, op)
            // A prepared process holds the server end of the connection through
            // `ports.[first]`, and the process before it the client end.
            let byClient (op : Op) : Step =
                Step.Call ((first + processes - 1) % processes, secondThread, op)

            // The server end closes the connection the client end has closed,
            // and the client end connects to `ports.[first]` afresh, blocking as
            // a prepared one is, so that a later scenario finds a connection
            // there.
            let reconnect : Step list =
                [
                    byFirst (Op.CloseThrough first)
                    byClient (Op.Socket false)
                    byClient (Op.Connect (0, first))
                    byFirst (Op.Accept 0)
                ]

            return!
                Gen.frequency
                    [
                        // The first makes a directory and stands in it; the
                        // second removes it.
                        1,
                        Gen.constant
                            [
                                byFirst (Op.MkDir dir)
                                byFirst (Op.ChDir (1 + dir % dirs.Length))
                                bySecond (Op.RmDir dir)
                            ]
                        // The first watches the root with a new non-blocking
                        // instance; the second makes a directory or a file
                        // there and changes its mode; the first reads what
                        // that queued.
                        2,
                        Gen.constant (
                            match SimulatedUnixPlatform.flavour platform with
                            | SimulatedUnixFlavour.Darwin -> []
                            | SimulatedUnixFlavour.Linux ->
                                [
                                    byFirst (Op.InotifyInit true)
                                    byFirst (Op.InotifyWatchNewest 0)
                                    (if dir % 2 = 0 then
                                         bySecond (Op.MkDir dir)
                                     else
                                         bySecond (Op.Open dir))
                                    bySecond (Op.Chmod (dir, dir % 2 = 0))
                                    byFirst Op.InotifyReadNewest
                                ]
                        )
                        // The first sleeps reading an inotify instance watching
                        // the root; the second makes a directory there, if
                        // there is none, and changes its mode, or makes a file
                        // there and removes it. Darwin has no inotify.
                        2,
                        Gen.constant (
                            match SimulatedUnixPlatform.flavour platform with
                            | SimulatedUnixFlavour.Darwin -> []
                            | SimulatedUnixFlavour.Linux ->
                                byFirst (Op.InotifyAwait 0)
                                :: (if dir % 2 = 0 then
                                        [ bySecond (Op.MkDir dir) ; bySecond (Op.Chmod (dir, true)) ]
                                    else
                                        [ bySecond (Op.Open dir) ; bySecond (Op.Unlink dir) ])
                        )
                        // The first sleeps on its event queue, which a prepared
                        // process has watching its listener at `ports.[first]`;
                        // the second connects to that port. Only a prepared case
                        // has the queue, so this is drawn three times as often.
                        3,
                        Gen.constant
                            [
                                match SimulatedUnixPlatform.flavour platform with
                                | SimulatedUnixFlavour.Linux -> byFirst (Op.EpollWait (0, -1))
                                | SimulatedUnixFlavour.Darwin -> byFirst (Op.KeventWait (0, -1))
                                bySecond (Op.Socket true)
                                bySecond (Op.Connect (0, first))
                            ]
                        // The first listens at a port, unless it already does,
                        // and sleeps in `poll` on that listener; the second
                        // connects to that port.
                        1,
                        Gen.constant
                            [
                                byFirst (Op.Socket false)
                                byFirst (Op.Bind (0, first))
                                byFirst (Op.Listen 0)
                                byFirst (Op.PollListener (first, -1))
                                bySecond (Op.Socket true)
                                bySecond (Op.Connect (0, first))
                            ]
                        // The first locks the file a prepared process has open,
                        // the second sleeps waiting for it, and the first lets go.
                        2,
                        Gen.constant
                            [
                                byFirst (Op.Flock (0, lockExclusive))
                                bySecond (Op.Flock (0, lockExclusive))
                                byFirst (Op.Flock (0, unlock))
                            ]
                        // The client end of the connection through
                        // `ports.[first]` writes, and the server end, in another
                        // process, reads what it wrote.
                        4,
                        Gen.constant
                            [
                                byClient (Op.SendThrough (first, 1000))
                                byFirst (Op.ReceiveThrough (first, 65536))
                            ]
                        // The client end, blocking, writes more than the buffers
                        // hold, and sleeps; the server end's reads make room,
                        // which wakes it.
                        2,
                        Gen.constant
                            [
                                byClient (Op.SendThrough (first, 300000))
                                byFirst (Op.ReceiveThrough (first, 65536))
                                byFirst (Op.ReceiveThrough (first, 65536))
                            ]
                        // The client end closes with nothing unread, a FIN, and
                        // the server end reads what is left, then end of file.
                        // The client end drains without blocking: a read that
                        // slept would leave the thread asleep, making no close.
                        3,
                        Gen.constant (
                            [
                                byClient (Op.MakeNonBlockingThrough first)
                                byClient (Op.ReceiveThrough (first, 65536))
                                byClient (Op.CloseThrough first)
                                byFirst (Op.ReceiveThrough (first, 65536))
                                byFirst (Op.ReceiveThrough (first, 65536))
                            ]
                            @ reconnect
                        )
                        // The client end, blocking, reads, and sleeps if
                        // nothing has arrived; the server end's process unblocks
                        // a fatal signal pending on one of its threads, which ends
                        // it, and its end wakes the read.
                        1,
                        Gen.constant
                            [
                                byClient (Op.ReceiveThrough (first, 65536))
                                byFirst (Op.BlockAndRaise first)
                                byFirst (Op.Unblock first)
                            ]
                        // The second connects to the first's listener, a
                        // prepared one at `ports.[first]` or one an earlier
                        // scenario made, and sleeps in a blocking read of the
                        // connection, which waits unaccepted in the queue; the
                        // first closes its listener, or ends, which resets the
                        // queued client and wakes the read. A closing first
                        // listens again, so that later scenarios find a
                        // listener there.
                        3,
                        Gen.constant (
                            [
                                bySecond (Op.Socket false)
                                bySecond (Op.Connect (0, first))
                                bySecond (Op.ReceiveNewest 65536)
                            ]
                            @ (if closeListener then
                                   [
                                       byFirst (Op.CloseListener first)
                                       byFirst (Op.Socket false)
                                       byFirst (Op.Bind (0, first))
                                       byFirst (Op.Listen 0)
                                   ]
                               else
                                   [ byFirst (Op.Exit status) ])
                        )
                        // The server end writes, the client end closes with that
                        // unread, a reset, and the server end's read meets it.
                        3,
                        Gen.constant (
                            [
                                byFirst (Op.SendThrough (first, 1000))
                                byClient (Op.CloseThrough first)
                                byFirst (Op.ReceiveThrough (first, 65536))
                            ]
                            @ reconnect
                        )
                    ]
        }

    let private caseGen : Gen<Case> =
        gen {
            let! platform = Gen.elements [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]
            let! processes = Gen.choose (2, 3)
            let! prepared = Gen.elements [ true ; false ]
            // Bias towards one process at a time or towards interleaving, so
            // both long runs within one process and constant switching occur.
            let! stickiness = Gen.choose (0, 9)
            let! socketBias = Gen.choose (1, 6)
            let! transferBias = Gen.elements [ 1 ; 1 ; 1 ; 3 ; 8 ]
            let! length = Gen.choose (20, 120)

            let rec steps (n : int) (current : int) (acc : Step list) : Gen<Step list> =
                if n = 0 then
                    Gen.constant (List.rev acc)
                else
                    gen {
                        let! kind = Gen.choose (0, 99)

                        match kind with
                        | k when k < 10 ->
                            let! scenario = crossProcessScenario platform processes
                            return! steps (n - 1) current (List.rev scenario @ acc)
                        | k when k < 20 ->
                            let! finishing = Gen.choose (1, 4)
                            return! steps (n - 1) current (Step.WakePass finishing :: acc)
                        | k when k < 25 ->
                            let! milliseconds = Gen.elements [ 1 ; 5 ; 10 ]
                            return! steps (n - 1) current (Step.Advance milliseconds :: acc)
                        | _ ->
                            let! switch = Gen.choose (0, 9)
                            let! other = Gen.choose (0, processes - 1)
                            let proc = if switch >= stickiness then other else current
                            let! thread = Gen.choose (0, threads - 1)
                            let! op = opsFor socketBias transferBias platform
                            return! steps (n - 1) proc (Step.Call (proc, thread, op) :: acc)
                    }

            let! steps = steps length 0 []

            return
                {
                    Platform = platform
                    Processes = processes
                    Prepared = prepared
                    Steps = steps
                }
        }

    /// The paths the property exists for, each counted every time a step
    /// reaches it.
    [<RequireQualifiedAccess>]
    type private FuzzLabel =
        | CrossConnect
        | CrossAddressInUse
        | Accept
        | CrossRmDirOfStanding
        | EpollAdd
        | KeventAdd
        | Park
        /// A call in one process that made a call asleep in another wakeable.
        | CrossWake
        /// A wake condition of this kind, named by its case, that such a call
        /// fired.
        | CrossWakeKind of string
        /// A finish that answered, in a process other than the one whose call
        /// made it wakeable.
        | Finish
        | DarwinPollPark
        | KeventPark
        | Exit
        | ExitRefusal
        /// A process a fatal signal ended as one of its threads returned to user
        /// mode, having unblocked it.
        | SignalDeath
        /// A read that took bytes another process's socket had written.
        | CrossRead
        /// A write that took fewer bytes than offered, or none (`EAGAIN`).
        | ShortWrite
        /// A read or write that met a reset (`ECONNRESET` or `EPIPE`).
        | Reset
        /// A read that met end of file.
        | EndOfFile
        /// A blocking read of a connected socket that slept.
        | ConnectionReadPark
        /// A blocking write to a connected socket that slept, having taken
        /// part of its bytes or none.
        | ConnectionWritePark
        /// A finished connection transfer that answered.
        | ConnectionFinish
        /// A step that reset a client whose connection waited in a listener's
        /// queue, by releasing the listener: a close, or its process's end.
        | QueuedClientReset
        /// A `QueuedClientReset` of a client another process holds.
        | CrossQueuedClientReset
        /// A `QueuedClientReset` that made a read asleep in the client's
        /// process wakeable.
        | QueuedClientResetWakesRead
        /// A read of an inotify instance that returned records.
        | InotifyRecordRead
        /// A read of an inotify instance that slept.
        | InotifyReadPark
        /// A read of an inotify instance, woken, that returned records.
        | InotifyReadFinish
        /// A step refused, which tested nothing.
        | Refusal
        | Call

    let private fdsOf (pid : ProcessId) (view : UnixSystem<int, string>) : Map<int, OpenFileTarget> =
        let registry = Proc.fileDescriptors pid view

        FileDescriptorRegistry.fds registry
        |> Map.map (fun fd _ ->
            match FileDescriptorRegistry.tryFindTarget fd registry with
            | Some target -> target
            | None -> failwith $"fd %d{fd} names no description"
        )

    let private pick (i : int) (from : 'a list) : 'a option =
        if from.IsEmpty then None else Some from.[i % from.Length]

    let private ofKind (pid : ProcessId) (accept : OpenFileTarget -> bool) (view : UnixSystem<int, string>) : int list =
        fdsOf pid view
        |> Map.filter (fun _ target -> accept target)
        |> Map.keys
        |> List.ofSeq

    let private isSocket (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.Socket _ -> true
        | _ -> false

    let private isFile (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.File _ -> true
        | _ -> false

    let private isPipeEnd (pipeEnd : PipeEnd) (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.Pipe (_, named) -> named = pipeEnd
        | _ -> false

    let private isEpoll (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.Epoll _ -> true
        | _ -> false

    let private isKqueue (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.Kqueue _ -> true
        | _ -> false

    let private isInotify (target : OpenFileTarget) : bool =
        match target with
        | OpenFileTarget.Inotify _ -> true
        | _ -> false

    /// Every event this kernel raises.
    let private inotifyEvents : uint32 = 0xFC6u

    /// The descriptor of `view` naming the inotify instance made last, by the
    /// order of description IDs, if it holds one.
    let private newestInotify (pid : ProcessId) (view : UnixSystem<int, string>) : int option =
        let registry = Proc.fileDescriptors pid view

        FileDescriptorRegistry.fds registry
        |> Map.toList
        |> List.filter (fun (fd, _) ->
            match FileDescriptorRegistry.tryFindTarget fd registry with
            | Some target -> isInotify target
            | None -> false
        )
        |> List.sortBy snd
        |> List.tryLast
        |> Option.map fst

    /// The descriptors of `view` naming a socket `accept` admits: each call
    /// draws from the sockets it can do something with, so few steps are
    /// spent on the errors other tests cover.
    let private socketsWhere
        (pid : ProcessId)
        (accept : SocketDescription -> bool)
        (view : UnixSystem<int, string>)
        : int list
        =
        fdsOf pid view
        |> Map.filter (fun _ target ->
            match target with
            | OpenFileTarget.Socket socket -> accept (UnixMachineState.socket socket view.Machine)
            | _ -> false
        )
        |> Map.keys
        |> List.ofSeq

    let private unbound (socket : SocketDescription) : bool = socket.Ipv4Binding.IsNone

    let private boundIdle (socket : SocketDescription) : bool =
        socket.Ipv4Binding.IsSome
        && (
            match socket.Phase with
            | SocketPhase.Idle -> true
            | _ -> false
        )

    let private idle (socket : SocketDescription) : bool =
        match socket.Phase with
        | SocketPhase.Idle -> true
        | _ -> false

    let private listening (socket : SocketDescription) : bool =
        match socket.Phase with
        | SocketPhase.Listening _ -> true
        | _ -> false

    let private connected (socket : SocketDescription) : bool =
        (SocketPhase.connectionEnd socket.Phase).IsSome

    /// The descriptors of `view` naming a connected socket, through a
    /// non-blocking description if `nonBlocking` and `view` has one.
    let private connectedFds (pid : ProcessId) (nonBlocking : bool) (view : UnixSystem<int, string>) : int list =
        let all = socketsWhere pid connected view

        let unblocked =
            all
            |> List.filter (fun fd ->
                match FileDescriptorRegistry.tryFind fd (Proc.fileDescriptors pid view) with
                | Some description -> description.NonBlocking
                | None -> false
            )

        if nonBlocking && not unblocked.IsEmpty then
            unblocked
        else
            all

    /// The lowest descriptor of `view` naming its end of the earliest
    /// connection it holds whose server end is at `ports.[port]`, if it holds
    /// one; so the processes at a connection's two ends pick it alike, unless
    /// one of them still holds an earlier connection there whose other end is
    /// closed.
    let private connectedThrough (pid : ProcessId) (port : int) (view : UnixSystem<int, string>) : int option =
        let port = ports.[port % ports.Length]

        fdsOf pid view
        |> Map.toList
        |> List.choose (fun (fd, target) ->
            match target with
            | OpenFileTarget.Socket socket ->
                match SocketPhase.connectionEnd (UnixMachineState.socket socket view.Machine).Phase with
                | Some (connection, _) when
                    (UnixMachineState.connection connection view.Machine).ServerAddress.Port = port
                    ->
                    Some (connection, fd)
                | _ -> None
            | _ -> None
        )
        |> List.sort
        |> List.tryHead
        |> Option.map snd

    /// The descriptor of `view` naming its end of the latest connection it
    /// holds, if it holds one.
    let private newestConnected (pid : ProcessId) (view : UnixSystem<int, string>) : int option =
        fdsOf pid view
        |> Map.toList
        |> List.choose (fun (fd, target) ->
            match target with
            | OpenFileTarget.Socket socket ->
                SocketPhase.connectionEnd (UnixMachineState.socket socket view.Machine).Phase
                |> Option.map (fun (connection, _) -> connection, fd)
            | _ -> None
        )
        |> List.sort
        |> List.tryLast
        |> Option.map snd

    /// The process whose descriptors name the socket at the other end of the
    /// connected socket `socketId`, if one is.
    let private peerOwner (socketId : SocketId) (machine : UnixSystem<int, string>) : ProcessId option =
        let view =
            Machines.focus (Seq.head (Machines.processIds machine)) machine |> Option.get

        match SocketPhase.connectionEnd (UnixMachineState.socket socketId view.Machine).Phase with
        | None -> None
        | Some (connection, connectionEnd) ->
            let other =
                match connectionEnd with
                | ConnectionEnd.Client -> ConnectionEnd.Server
                | ConnectionEnd.Server -> ConnectionEnd.Client

            match UnixMachineState.socketHoldingEnd connection other view.Machine with
            | None -> None
            | Some peer ->
                UnixSystem.processIds machine
                |> Seq.tryPick (fun pid ->
                    let names =
                        fdsOf pid (Machines.focus pid machine |> Option.get)
                        |> Map.exists (fun _ target -> target = OpenFileTarget.Socket peer)

                    if names then Some pid else None
                )

    /// The process whose descriptors name a socket bound at `port` in the
    /// listening phase, if any.
    let private listenerOwner (port : uint16) (machine : UnixSystem<int, string>) : ProcessId option =
        UnixSystem.processIds machine
        |> Seq.tryPick (fun pid ->
            let view = Machines.focus pid machine |> Option.get

            fdsOf pid view
            |> Map.exists (fun _ target ->
                match target with
                | OpenFileTarget.Socket socket ->
                    let description = UnixMachineState.socket socket view.Machine

                    match description.Phase, description.Ipv4Binding with
                    | SocketPhase.Listening _, Some binding -> binding.Endpoint.Port = port
                    | _ -> false
                | _ -> false
            )
            |> fun found -> if found then Some pid else None
        )

    /// Whether the process `pid` holds a socket bound at `port`.
    let private holdsPort (pid : ProcessId) (port : uint16) (view : UnixSystem<int, string>) : bool =
        fdsOf pid view
        |> Map.exists (fun _ target ->
            match target with
            | OpenFileTarget.Socket socket ->
                match (UnixMachineState.socket socket view.Machine).Ipv4Binding with
                | Some binding -> binding.Endpoint.Port = port
                | None -> false
            | _ -> false
        )

    let private openCreating : OpenFlags =
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

    /// What became of a call or a finish.
    [<RequireQualifiedAccess>]
    type private Made =
        /// It answered, or changed nothing, and the process carries on as this.
        | Answered of UnixSystem<int, string>
        /// The calling thread sleeps, in this.
        | Sleeps of UnixSystem<int, string>
        /// The call ended the process, and left the system without it.
        | Ended of EndedProcess * UnixSystem<int, string>
        /// The library refused it, which changes nothing.
        | Refused

    let private ofWrite (outcome : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>) : Made =
        match outcome with
        | Error _ -> Made.Refused
        | Ok (WriteStep.Returns (_, view))
        | Ok (WriteStep.ReturnsRaising (_, _, view))
        | Ok (WriteStep.Interrupted view) -> Made.Answered view
        | Ok (WriteStep.WouldBlock (_, view)) -> Made.Sleeps view
        | Ok (WriteStep.ProcessEnded (ended, after)) -> Made.Ended (ended, after)

    /// `bytes`, for a transcript: how many, and a checksum of them.
    let private bytesText (bytes : ImmutableArray<byte>) : string =
        let sum = Seq.fold (fun (sum : int) (b : byte) -> sum * 31 + int b) 17 bytes
        $"%d{bytes.Length} bytes, checksum %d{sum}"

    /// What a read answered, for a transcript.
    let private readText (outcome : ReadOutcome) : string =
        match outcome with
        | ReadOutcome.Answered (ReadAnswer.Completed bytes) -> $"read %s{bytesText bytes}"
        | outcome -> $"%A{outcome}"

    /// What a call that can end the process did to it, for a transcript.
    let private fateText<'Outcome> (fate : ProcessFate<'Outcome, int, string>) : string =
        match fate with
        | ProcessFate.Continues (outcome, _) -> $"continues %A{outcome}"
        | ProcessFate.ProcessEnded (ended, _) -> $"ends %A{EndedProcess.termination ended}"

    /// What a write answered, for a transcript.
    let private writeText
        (outcome : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>)
        : string
        =
        match outcome with
        | Error refusal -> $"refused %A{refusal}"
        | Ok (WriteStep.Returns (answer, _)) -> $"returns %A{answer}"
        | Ok (WriteStep.ReturnsRaising (answer, signal, _)) -> $"returns %A{answer} raising %A{signal}"
        | Ok (WriteStep.WouldBlock (condition, _)) -> $"sleeps %A{condition}"
        | Ok (WriteStep.Interrupted _) -> "restarts"
        | Ok (WriteStep.ProcessEnded (ended, _)) -> $"ends %A{EndedProcess.termination ended}"

    /// `result`, having written to `log` what it answered, without the system.
    let private logged<'a, 'r>
        (log : string -> unit)
        (result : Result<'a * UnixSystem<int, string>, 'r>)
        : Result<'a * UnixSystem<int, string>, 'r>
        =
        match result with
        | Ok (answer, _) -> log $"  %A{answer}"
        | Error refusal -> log $"  refused %A{refusal}"

        result

    /// `logged`, for a read.
    let private loggedRead<'r>
        (log : string -> unit)
        (result : Result<ReadOutcome * UnixSystem<int, string>, 'r>)
        : Result<ReadOutcome * UnixSystem<int, string>, 'r>
        =
        match result with
        | Ok (outcome, _) -> log $"  %s{readText outcome}"
        | Error refusal -> log $"  refused %A{refusal}"

        result

    /// `logged`, for a write.
    let private loggedWrite
        (log : string -> unit)
        (result : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>)
        : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>
        =
        log $"  %s{writeText result}"
        result

    /// `logged`, for a call that can end the process.
    let private loggedFate<'Outcome, 'r>
        (log : string -> unit)
        (result : Result<ProcessFate<'Outcome, int, string>, 'r>)
        : Result<ProcessFate<'Outcome, int, string>, 'r>
        =
        match result with
        | Ok fate -> log $"  %s{fateText fate}"
        | Error refusal -> log $"  refused %A{refusal}"

        result

    /// `loggedFate`, for a return to user mode, printed as the transcripts the
    /// reference records print it (`AnswersBeforeInterrupted`).
    let private loggedReturn<'r>
        (log : string -> unit)
        (result : Result<ProcessFate<ReturnToUserOutcome<int, string>, int, string>, 'r>)
        : Result<ProcessFate<ReturnToUserOutcome<int, string>, int, string>, 'r>
        =
        match result with
        | Ok fate -> log $"  %s{fateText (AnswersBeforeInterrupted.ofReturnFate fate)}"
        | Error refusal -> log $"  refused %A{refusal}"

        result

    /// `logged`, for a call that answers an errno as its `Error`, or what it
    /// made and the system.
    let private loggedMade<'a, 'r>
        (log : string -> unit)
        (result : Result<Result<'a * UnixSystem<int, string>, UnixError>, 'r>)
        : Result<Result<'a * UnixSystem<int, string>, UnixError>, 'r>
        =
        match result with
        | Ok (Ok (made, _)) -> log $"  made %A{made}"
        | Ok (Error error) -> log $"  failed %A{error}"
        | Error refusal -> log $"  refused %A{refusal}"

        result

    /// `answer`, having written to `log` what it answered, without the system.
    let private said<'a> (log : string -> unit) (answer : 'a * UnixSystem<int, string>) : 'a * UnixSystem<int, string> =
        log $"  %A{fst answer}"
        answer

    /// One call by `thread` of the process `pid`, in its view `view`, on `machine`
    /// as it stood before.
    let private call
        (cover : FuzzLabel -> unit)
        (log : string -> unit)
        (machine : UnixSystem<int, string>)
        (pid : ProcessId)
        (thread : int)
        (op : Op)
        (view : UnixSystem<int, string>)
        : Made
        =
        let any = fdsOf pid view |> Map.keys |> List.ofSeq
        let sockets = ofKind pid isSocket view

        let answered (result : Result<'a * UnixSystem<int, string>, 'r>) : Made =
            match logged log result with
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused

        let poll (entries : PollEntry list) (milliseconds : int) : Made =
            match
                UnixPoll.tryPoll (Caller.make pid thread) entries milliseconds view
                |> logged log
            with
            | Ok (PollOutcome.WouldBlock _, after) ->
                match SimulatedUnixPlatform.flavour view.Machine.UnixPlatform with
                | SimulatedUnixFlavour.Darwin -> cover FuzzLabel.DarwinPollPark
                | SimulatedUnixFlavour.Linux -> ()

                Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused

        // A read of `size` bytes from the connected socket `fd`.
        let receive (fd : int) (size : int) : Made =
            let socketId =
                match FileDescriptorRegistry.tryFindTarget fd (Proc.fileDescriptors pid view) with
                | Some (OpenFileTarget.Socket socketId) -> socketId
                | other -> failwith $"fd %d{fd} names %A{other}"

            let writer = peerOwner socketId machine

            match
                UnixReadWrite.tryRead (Caller.make pid thread) fd UserBuffer.Mapped (uint64 size) view
                |> loggedRead log
            with
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), after) ->
                if not bytes.IsEmpty && writer.IsSome && writer <> Some pid then
                    cover FuzzLabel.CrossRead

                if bytes.IsEmpty && size > 0 then
                    cover FuzzLabel.EndOfFile

                Made.Answered after
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.ECONNRESET), after)
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EPIPE), after) ->
                cover FuzzLabel.Reset
                Made.Answered after
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EAGAIN), after) -> Made.Answered after
            | Ok (ReadOutcome.WouldBlock _, after) ->
                cover FuzzLabel.ConnectionReadPark
                Made.Sleeps after
            | Ok (outcome, _) -> failwith $"a read of a connected socket answered %A{outcome}"
            | Error refusal -> failwith $"a read of a connected socket was refused: %s{ReadRefusal.describe refusal}"

        // A write of `size` bytes to the connected socket `fd`.
        let send (fd : int) (size : int) : Made =
            let bytes = ImmutableArray.Create<byte> (Array.init size byte)

            match
                WriteOutcomes.admitThenWriteAs (Caller.make pid thread) fd UserBuffer.Mapped bytes view
                |> loggedWrite log
            with
            | Ok (WriteStep.Returns (WriteAnswer.Completed written, after)) ->
                if written < int64 size then
                    cover FuzzLabel.ShortWrite

                Made.Answered after
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, after)) ->
                cover FuzzLabel.ShortWrite
                Made.Answered after
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.ECONNRESET, _))
            | Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed UnixError.EPIPE, _, _))
            | Ok (WriteStep.ProcessEnded _) as outcome ->
                cover FuzzLabel.Reset
                ofWrite outcome
            | Ok (WriteStep.WouldBlock (_, after)) ->
                cover FuzzLabel.ConnectionWritePark
                Made.Sleeps after
            | Ok outcome -> failwith $"a write to a connected socket answered %A{outcome}"
            | Error refusal -> failwith $"a write to a connected socket was refused: %s{WriteRefusal.describe refusal}"

        // A read of the inotify instance `fd` names, if there is one.
        let inotifyRead (fd : int option) : Made =
            match fd with
            | None -> Made.Answered view
            | Some fd ->
                match
                    UnixReadWrite.tryRead (Caller.make pid thread) fd UserBuffer.Mapped 4096UL view
                    |> loggedRead log
                with
                | Ok (ReadOutcome.WouldBlock _, after) ->
                    cover FuzzLabel.InotifyReadPark
                    Made.Sleeps after
                | Ok (ReadOutcome.Answered (ReadAnswer.Completed _), after) ->
                    cover FuzzLabel.InotifyRecordRead
                    Made.Answered after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused

        // `thread` returns to user mode from a call that left the process as
        // `after`. The only signals sent are `fatal`'s, at their defaults, and
        // a SIGPIPE nothing blocks, so the process ends exactly when one of
        // `fatal` is pending on `thread` and it does not block it, and then by
        // one of those signals.
        let returnToUser (after : UnixSystem<int, string>) : Made =
            let due =
                SignalState.pending (Proc.state pid after).Signals
                |> List.filter (fun entry ->
                    entry.Target = ValueSome thread
                    && not (
                        SignalMask.contains entry.Signal (SignalState.maskOf thread (Proc.state pid after).Signals)
                    )
                )
                |> List.map (fun entry -> entry.Signal)
                |> Set.ofList

            match UnixSignal.tryOnReturnToUser (Caller.make pid thread) after |> loggedReturn log with
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes None, after)) ->
                due |> shouldEqual Set.empty
                Made.Answered after
            | Ok (ProcessFate.ProcessEnded (ended, kernel)) ->
                match EndedProcess.termination ended with
                | ProcessTermination.Signaled (signal, false) when Set.contains signal due ->
                    cover FuzzLabel.SignalDeath
                    Made.Ended (ended, kernel)
                | termination ->
                    failwith $"thread %d{thread}'s return ended the process with %O{termination}, with %O{due} due"
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes (Some _), _) as other)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers _, _) as other)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped _, _) as other)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ContinueDiscarded _, _) as other) ->
                failwith
                    $"no handler is installed and only %O{fatal} is held back, but thread %d{thread}'s return took %A{other}"
            | Error refusal -> failwith $"thread %d{thread}'s return was refused: %O{refusal}"

        // `pthread_sigmask(2)` of `signal` alone, and the return from it.
        let mask (change : SignalMaskChange) (signal : Signal) (view : UnixSystem<int, string>) : Made =
            let numbering = Lone.UnixSystemState.signalNumbering view
            let set = SignalMask.ofSignals numbering (Set.singleton signal)

            match
                UnixSignal.pthreadSigmask (Caller.make pid thread) (MaskHow.number numbering change) (Some set) view
                |> logged log
            with
            | Ok (_, after) -> returnToUser after
            | Error errno -> failwith $"pthread_sigmask of %O{signal} failed with %O{errno}"

        match op with
        | Op.Socket nonBlocking ->
            Made.Answered (
                KeventWorld.streamAs (Caller.make pid thread) nonBlocking view
                |> said log
                |> snd
            )
        | Op.Bind (fd, port) ->
            match pick fd (socketsWhere pid unbound view) with
            | None -> Made.Answered view
            | Some fd ->
                let port = ports.[port % ports.Length]

                match
                    CopyIn.bindAs
                        (Caller.make pid thread)
                        fd
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet (UnixSystem.platform view) (KeventWorld.loopback port))
                        view
                    |> logged log
                with
                | Ok (BindAnswer.Failed UnixError.EADDRINUSE, after) ->
                    if not (holdsPort pid port view) then
                        cover FuzzLabel.CrossAddressInUse

                    Made.Answered after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.Listen fd ->
            match pick fd (socketsWhere pid boundIdle view) with
            | None -> Made.Answered view
            | Some fd -> UnixSocket.tryListen (Caller.make pid thread) fd 8 view |> answered
        | Op.Connect (fd, port) ->
            match pick fd (socketsWhere pid idle view) with
            | None -> Made.Answered view
            | Some fd ->
                let port = ports.[port % ports.Length]
                let owner = listenerOwner port machine

                // As the thread the fuzzer chose, which fails the run if it
                // sleeps: no connect sleeps yet.
                match
                    CopyIn.connectAs
                        (Caller.make pid thread)
                        fd
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet (UnixSystem.platform view) (KeventWorld.loopback port))
                        view
                    |> logged log
                with
                | Ok (outcome, after) ->
                    match outcome, owner with
                    | SyscallAnswer.Completed 0L, Some owner
                    | SyscallAnswer.Failed UnixError.EINPROGRESS, Some owner when owner <> pid ->
                        cover FuzzLabel.CrossConnect
                    | _ -> ()

                    Made.Answered after
                | Error _ -> Made.Refused
        | Op.Accept fd ->
            match pick fd (socketsWhere pid listening view) with
            | None -> Made.Answered view
            | Some fd ->
                match
                    UnixConnection.tryAccept (Caller.make pid thread) fd UserBuffer.Mapped 16u view
                    |> logged log
                with
                | Ok (AcceptOutcome.Accepted _, after) ->
                    cover FuzzLabel.Accept
                    Made.Answered after
                | Ok (AcceptOutcome.WouldBlock _, after) -> Made.Sleeps after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.MakeNonBlocking fd ->
            match pick fd (socketsWhere pid connected view) with
            | None -> Made.Answered view
            | Some fd ->
                Made.Answered (
                    UnixDescriptor.setNonBlocking (Caller.make pid thread) fd true view
                    |> said log
                    |> snd
                )
        | Op.Receive (fd, size, nonBlocking) ->
            match pick fd (connectedFds pid nonBlocking view) with
            | None -> Made.Answered view
            | Some fd -> receive fd size
        | Op.Send (fd, size, nonBlocking) ->
            match pick fd (connectedFds pid nonBlocking view) with
            | None -> Made.Answered view
            | Some fd -> send fd size
        | Op.ReceiveThrough (port, size) ->
            match connectedThrough pid port view with
            | None -> Made.Answered view
            | Some fd -> receive fd size
        | Op.SendThrough (port, size) ->
            match connectedThrough pid port view with
            | None -> Made.Answered view
            | Some fd -> send fd size
        | Op.CloseThrough port ->
            match connectedThrough pid port view with
            | None -> Made.Answered view
            | Some fd -> UnixDescriptor.tryClose (Caller.make pid thread) fd view |> answered
        | Op.MakeNonBlockingThrough port ->
            match connectedThrough pid port view with
            | None -> Made.Answered view
            | Some fd ->
                Made.Answered (
                    UnixDescriptor.setNonBlocking (Caller.make pid thread) fd true view
                    |> said log
                    |> snd
                )
        | Op.ReceiveNewest size ->
            match newestConnected pid view with
            | None -> Made.Answered view
            | Some fd -> receive fd size
        | Op.CloseListener port ->
            let port = ports.[port % ports.Length]

            let listeningAt (socket : SocketDescription) : bool =
                listening socket
                && socket.Ipv4Binding
                   |> Option.exists (fun binding -> binding.Endpoint.Port = port)

            match socketsWhere pid listeningAt view with
            | [] -> Made.Answered view
            | listener :: _ -> UnixDescriptor.tryClose (Caller.make pid thread) listener view |> answered
        | Op.Pipe -> UnixPipe.tryPipe2 (Caller.make pid thread) 0 UserBuffer.Mapped view |> answered
        | Op.PipeRead fd ->
            match pick fd (ofKind pid (isPipeEnd PipeEnd.Read) view) with
            | None -> Made.Answered view
            | Some fd ->
                match
                    UnixReadWrite.tryRead (Caller.make pid thread) fd UserBuffer.Mapped 4096UL view
                    |> loggedRead log
                with
                | Ok (ReadOutcome.WouldBlock _, after) -> Made.Sleeps after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.PipeWrite (fd, size) ->
            match pick fd (ofKind pid (isPipeEnd PipeEnd.Write) view) with
            | None -> Made.Answered view
            | Some fd ->
                WriteOutcomes.admitThenWriteAs
                    (Caller.make pid thread)
                    fd
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> size))
                    view
                |> loggedWrite log
                |> ofWrite
        | Op.Open path ->
            // `OpenOutcomes.answered` fails the run if the open sleeps: nothing
            // makes a FIFO, so none can.
            UnixNamespace.tryOpenPath
                (Caller.make pid thread)
                (OpenFlagWords.encode (UnixSystem.platform view) openCreating)
                (PathArg.ofText files.[path % files.Length])
                0o644
                view
            |> OpenOutcomes.answered
            |> answered
        | Op.Close fd ->
            match pick fd any with
            | None -> Made.Answered view
            | Some fd -> UnixDescriptor.tryClose (Caller.make pid thread) fd view |> answered
        | Op.Dup fd ->
            match pick fd any with
            | None -> Made.Answered view
            | Some fd -> Made.Answered (Answered.dup (Caller.make pid thread) fd view |> said log |> snd)
        | Op.Flock (fd, operation) ->
            match pick fd (ofKind pid isFile view) with
            | None -> Made.Answered view
            | Some fd ->
                match UnixDescriptor.tryFlock (Caller.make pid thread) fd operation view |> logged log with
                | Ok (SyscallOutcome.WouldBlock _, after) -> Made.Sleeps after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.MkDir dir ->
            UnixNamespace.tryMkdir (Caller.make pid thread) (PathArg.ofText dirs.[dir % dirs.Length]) 0o755 view
            |> answered
        | Op.RmDir dir ->
            let path = dirs.[dir % dirs.Length]

            let inode =
                match
                    UnixPathResolution.resolvePath
                        AtDirectory.CurrentDirectory
                        SymlinkPolicy.NoFollowFinal
                        (UnixPath.parseOrFail "test" path)
                        (Proc.view pid view)
                with
                | Ok inode -> Some inode
                | Error _ -> None

            match
                UnixNamespace.tryRmdir (Caller.make pid thread) (PathArg.ofText path) view
                |> logged log
            with
            | Ok (SyscallAnswer.Completed 0L, after) ->
                let standsElsewhere =
                    UnixSystem.processIds machine
                    |> Seq.exists (fun other ->
                        other <> pid && Some (Proc.state other machine).CurrentDirectoryInode = inode
                    )

                if standsElsewhere then
                    cover FuzzLabel.CrossRmDirOfStanding

                Made.Answered after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Op.ChDir dir ->
            UnixPathResolution.tryChdir (Caller.make pid thread) (PathArg.ofText standing.[dir % standing.Length]) view
            |> answered
        | Op.EpollCreate ->
            match UnixPoll.tryEpollCreate1 (Caller.make pid thread) 0 view |> loggedMade log with
            | Ok (Ok (_, after)) -> Made.Answered after
            | Ok (Error _) -> Made.Answered view
            | Error _ -> Made.Refused
        | Op.EpollAdd (epoll, fd) ->
            match pick epoll (ofKind pid isEpoll view), pick fd sockets with
            | Some epoll, Some fd ->
                match
                    UnixPoll.tryEpollCtl
                        (Caller.make pid thread)
                        epoll
                        1
                        fd
                        (EpollEventArgument.Readable (
                            EpollEvents.In
                            ||| EpollEvents.Out
                            ||| EpollEvents.RdHup
                            ||| EpollEvents.EdgeTriggered,
                            0UL
                        ))
                        view
                    |> logged log
                with
                | Ok (EpollCtlAnswer.Changed, after) ->
                    cover FuzzLabel.EpollAdd
                    Made.Answered after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
            | _ -> Made.Answered view
        | Op.EpollWait (epoll, milliseconds) ->
            match pick epoll (ofKind pid isEpoll view) with
            | None -> Made.Answered view
            | Some epoll ->
                match
                    UnixPoll.tryEpollWait (Caller.make pid thread) epoll 8 UserBuffer.Mapped milliseconds view
                    |> logged log
                with
                | Ok (EpollWaitOutcome.WouldBlock _, after) -> Made.Sleeps after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.Kqueue -> Made.Answered (KeventWorld.kqueueAs (Caller.make pid thread) view |> said log |> snd)
        | Op.KeventAdd (kqueue, fd, write) ->
            match pick kqueue (ofKind pid isKqueue view), pick fd sockets with
            | Some kqueue, Some fd ->
                let filter = if write then KeventFilter.Write else KeventFilter.Read

                match
                    UnixKqueue.tryKevent
                        (Caller.make pid thread)
                        kqueue
                        1
                        [ KeventWorld.change fd filter (KeventFlags.Add ||| KeventFlags.Clear) 0UL ]
                        0
                        UserBuffer.Mapped
                        (KeventTimeout.Readable (0L, 0L))
                        view
                    |> logged log
                with
                | Ok (KeventOutcome.Answered [], after) ->
                    cover FuzzLabel.KeventAdd
                    Made.Answered after
                | Ok (KeventOutcome.WouldBlock condition, _) -> failwith $"kevent with no room parked on %A{condition}"
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
            | _ -> Made.Answered view
        | Op.KeventWait (kqueue, milliseconds) ->
            match pick kqueue (ofKind pid isKqueue view) with
            | None -> Made.Answered view
            | Some kqueue ->
                let timeout =
                    if milliseconds < 0 then
                        KeventTimeout.Null
                    else
                        KeventTimeout.Readable (0L, int64 milliseconds * 1_000_000L)

                match
                    UnixKqueue.tryKevent (Caller.make pid thread) kqueue 0 [] 8 UserBuffer.Mapped timeout view
                    |> logged log
                with
                | Ok (KeventOutcome.WouldBlock _, after) ->
                    cover FuzzLabel.KeventPark
                    Made.Sleeps after
                | Ok (_, after) -> Made.Answered after
                | Error _ -> Made.Refused
        | Op.Poll (fds, milliseconds, readOnly) ->
            let entries =
                fds
                |> List.choose (fun fd -> pick fd (if fd % 4 = 0 then any else sockets))
                |> List.map (fun fd ->
                    {
                        Fd = fd
                        Events = if readOnly then 0x0001s else 0x0001s ||| 0x0004s
                    }
                )

            poll entries milliseconds
        | Op.PollListener (port, milliseconds) ->
            let port = ports.[port % ports.Length]

            let listeningAt (socket : SocketDescription) : bool =
                listening socket
                && socket.Ipv4Binding
                   |> Option.exists (fun binding -> binding.Endpoint.Port = port)

            match socketsWhere pid listeningAt view with
            | [] -> Made.Answered view
            | listener :: _ ->
                poll
                    [
                        {
                            Fd = listener
                            Events = 0x0001s
                        }
                    ]
                    milliseconds
        | Op.BlockAndRaise signal ->
            let signal = fatal.[signal % fatal.Length]

            match mask SignalMaskChange.Block signal view with
            | Made.Answered blocked ->
                let signo =
                    Signal.toRawSignoUnder (Lone.UnixSystemState.signalNumbering blocked) signal

                let killed = UnixSignal.tryPthreadKill (Caller.make pid thread) thread signo blocked

                match killed with
                | Ok (Ok fate) -> log $"  %s{fateText fate}"
                | other -> log $"  %A{other}"

                match killed with
                | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, raised))) -> returnToUser raised
                | other -> failwith $"pthread_kill of a blocked %O{signal} answered %A{other}"
            | made -> made
        | Op.Unblock signal -> mask SignalMaskChange.Unblock fatal.[signal % fatal.Length] view
        | Op.InotifyInit nonBlocking ->
            match
                UnixInotify.tryInotifyInit1 (Caller.make pid thread) (if nonBlocking then 0x800 else 0) view
                |> loggedMade log
            with
            | Ok (Ok (_, after)) -> Made.Answered after
            | Ok (Error _) -> Made.Answered view
            | Error _ -> Made.Refused
        | Op.InotifyWatch (inotify, dir) ->
            match pick inotify (ofKind pid isInotify view) with
            | None -> Made.Answered view
            | Some fd ->
                Eager.tryInotifyAddWatchAs
                    (Caller.make pid thread)
                    fd
                    (PathArg.ofText standing.[dir % standing.Length])
                    inotifyEvents
                    view
                |> answered
        | Op.InotifyRmWatch (inotify, wd) ->
            match pick inotify (ofKind pid isInotify view) with
            | None -> Made.Answered view
            | Some fd ->
                UnixInotify.tryInotifyRmWatch (Caller.make pid thread) fd (1 + wd % 4) view
                |> answered
        | Op.InotifyRead inotify -> inotifyRead (pick inotify (ofKind pid isInotify view))
        | Op.InotifyReadNewest -> inotifyRead (newestInotify pid view)
        | Op.InotifyWatchNewest dir ->
            match newestInotify pid view with
            | None -> Made.Answered view
            | Some fd ->
                Eager.tryInotifyAddWatchAs
                    (Caller.make pid thread)
                    fd
                    (PathArg.ofText standing.[dir % standing.Length])
                    inotifyEvents
                    view
                |> answered
        | Op.InotifyAwait dir ->
            match UnixInotify.tryInotifyInit1 (Caller.make pid thread) 0 view |> loggedMade log with
            | Error _ -> Made.Refused
            | Ok (Error _) -> Made.Answered view
            | Ok (Ok (fd, view)) ->

            match
                Eager.tryInotifyAddWatchAs
                    (Caller.make pid thread)
                    fd
                    (PathArg.ofText standing.[dir % standing.Length])
                    inotifyEvents
                    view
                |> logged log
            with
            | Error _ -> Made.Refused
            | Ok (_, view) ->

            match
                UnixReadWrite.tryRead (Caller.make pid thread) fd UserBuffer.Mapped 4096UL view
                |> loggedRead log
            with
            | Ok (ReadOutcome.WouldBlock _, after) ->
                cover FuzzLabel.InotifyReadPark
                Made.Sleeps after
            | Ok (outcome, _) -> failwith $"a read of a new blocking instance answered %A{outcome}"
            | Error _ -> Made.Refused
        | Op.Chmod (path, directory) ->
            let path =
                if directory then
                    dirs.[path % dirs.Length]
                else
                    files.[path % files.Length]

            UnixPathResolution.tryChmod
                (Caller.make pid thread)
                (PathArg.ofText path)
                (if directory then 0o755 else 0o644)
                view
            |> answered
        | Op.Unlink path ->
            UnixNamespace.tryUnlink (Caller.make pid thread) (PathArg.ofText files.[path % files.Length]) view
            |> answered
        | Op.Exit status ->
            match UnixThreadLifecycle.tryExitGroup (Caller.make pid thread) status view with
            | Ok (ended, after) ->
                log $"  ends %A{EndedProcess.termination ended}"
                Made.Ended (ended, after)
            | Error refusal ->
                log $"  end refused %A{refusal}"
                cover FuzzLabel.ExitRefusal
                Made.Refused

    /// The call `thread` of the view `view` is asleep in, finished.
    let private finish
        (cover : FuzzLabel -> unit)
        (log : string -> unit)
        (pid : ProcessId)
        (thread : int)
        (view : UnixSystem<int, string>)
        : Made
        =
        match UnixThreadTable.parkedFor thread (Proc.threads pid view) with
        | Some (ParkedSyscall.Accept _) ->
            match UnixConnection.tryFinishAccept (Caller.make pid thread) view |> logged log with
            | Ok (AcceptOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.EpollWait _) ->
            match UnixPoll.tryFinishEpollWait (Caller.make pid thread) view |> logged log with
            | Ok (EpollWaitOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.Kevent _) ->
            match UnixKqueue.tryFinishKevent (Caller.make pid thread) view |> logged log with
            | Ok (KeventOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.Poll _)
        | Some (ParkedSyscall.KqueuePoll _) ->
            match UnixPoll.tryFinishPoll (Caller.make pid thread) view |> logged log with
            | Ok (PollOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.Flock _) ->
            match UnixDescriptor.tryFlockAcquire (Caller.make pid thread) view |> logged log with
            | Ok (SyscallOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.PipeRead _) ->
            match UnixReadWrite.tryFinishRead (Caller.make pid thread) view |> loggedRead log with
            | Ok (ReadOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.InotifyRead _) ->
            match UnixReadWrite.tryFinishRead (Caller.make pid thread) view |> loggedRead log with
            | Ok (ReadOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed _), after) ->
                cover FuzzLabel.InotifyReadFinish
                Made.Answered after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.ConnectionRead _) ->
            match UnixReadWrite.tryFinishRead (Caller.make pid thread) view |> loggedRead log with
            | Ok (ReadOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) ->
                cover FuzzLabel.ConnectionFinish
                Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.PipeWrite _)
        | Some (ParkedSyscall.ConnectionWrite _) ->
            let connection =
                match UnixThreadTable.parkedFor thread (Proc.threads pid view) with
                | Some (ParkedSyscall.ConnectionWrite _) -> true
                | _ -> false

            // Through `finishWrite`'s public protocol, held to the steps it is
            // made of.
            let made =
                WriteOutcomes.finishWriteAs
                    (Caller.make pid thread)
                    (fun offset count -> ImmutableArray.Create<byte> (Array.init count (fun i -> byte (offset + i))))
                    view
                |> loggedWrite log
                |> ofWrite

            match made with
            | Made.Answered _ when connection -> cover FuzzLabel.ConnectionFinish
            | _ -> ()

            made
        | Some (ParkedSyscall.Futex _) ->
            match UnixFutex.tryFinishFutexWait (Caller.make pid thread) view |> logged log with
            | Ok (SyscallOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some ParkedSyscall.SigSuspend ->
            match UnixSignal.tryFinishSigsuspend (Caller.make pid thread) view |> logged log with
            | Ok (SigsuspendOutcome.WouldBlock _, after) -> Made.Sleeps after
            | Ok (_, after) -> Made.Answered after
            | Error _ -> Made.Refused
        | Some (ParkedSyscall.Sleep _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a sleep yet, so there is no finishSleep to finish it with"
        | Some (ParkedSyscall.FifoOpen _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a FIFO open yet, so there is no finishOpen to finish it with"
        | Some (ParkedSyscall.Select _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a select yet, so there is no finishSelect to finish it with"
        | Some (ParkedSyscall.SignalWait _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a signal wait yet, so there is no finishSignalWait to finish it with"
        | Some (ParkedSyscall.DatagramReceive _ as parked)
        | Some (ParkedSyscall.DatagramSend _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a datagram transfer yet, so there is no finishing call to finish it with"
        | Some (ParkedSyscall.Connect _ as parked) ->
            failwith
                $"thread %d{thread} is woken in %A{parked}, but nothing parks a thread in a connect yet, so there is no finishConnect to finish it with"
        | None -> failwith $"thread %d{thread} is woken, and parked in nothing"

    /// Everything the run tracks besides the machine.
    type private World =
        {
            Machine : UnixSystem<int, string>
            /// The processes still on the machine, in launch order.
            Live : ProcessId list
            /// The threads held asleep in a call.
            Asleep : Set<ProcessId * int>
            /// The threads a wake pass has woken whose calls have not finished, in
            /// the order they woke.
            Woken : (ProcessId * int) list
        }

    let private wakeable (world : World) : Map<ProcessId * int, Set<WakePrimitive>> =
        Machines.wakes world.Machine |> Map.ofList

    let private assertClean (machine : UnixSystem<int, string>) : unit =
        Machines.checkInvariants machine |> Expect.empty (fun () -> "the system")

        VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes machine) machine.Machine.FileSystem
        |> Expect.empty (fun () -> "the filesystem")

        // Nothing passes a descriptor to another process, so each pipe's ends
        // are one process's.
        let pipesOf (pid : ProcessId) : Set<PipeId> =
            fdsOf pid (Machines.focus pid machine |> Option.get)
            |> Map.values
            |> Seq.choose (fun target ->
                match target with
                | OpenFileTarget.Pipe (pipe, _) -> Some pipe
                | _ -> None
            )
            |> Set.ofSeq

        Machines.processIds machine
        |> Seq.toList
        |> List.collect (fun pid -> pipesOf pid |> Set.toList)
        |> List.countBy id
        |> List.filter (fun (_, count) -> count > 1)
        |> Expect.empty (fun () -> "pipes held by more than one process")

    /// Every slot but `except`'s is as it was.
    let private othersUnmoved
        (except : ProcessId)
        (before : UnixSystem<int, string>)
        (after : UnixSystem<int, string>)
        : unit
        =
        for pid in UnixSystem.processIds after do
            if pid <> except then
                after.Processes.[ProcessId.toInt32 pid]
                |> Expect.equal (fun () -> $"process %O{pid}") before.Processes.[ProcessId.toInt32 pid]

    /// `made`, by `thread` of `pid`, written into `world`: a view written back,
    /// the thread asleep, or the process ended.
    let private settle
        (cover : FuzzLabel -> unit)
        (log : string -> unit)
        (pid : ProcessId)
        (thread : int)
        (made : Made)
        (world : World)
        : World
        =
        match made with
        | Made.Refused ->
            cover FuzzLabel.Refusal
            world
        | Made.Answered view ->
            { world with
                Machine = Machines.unfocus view world.Machine
            }
        | Made.Sleeps view ->
            cover FuzzLabel.Park

            { world with
                Machine = Machines.unfocus view world.Machine
                Asleep = Set.add (pid, thread) world.Asleep
            }
        | Made.Ended (ended, machine) ->
            log $"  ended %A{EndedProcess.termination ended}"
            cover FuzzLabel.Exit
            othersUnmoved pid world.Machine machine
            UnixSystem.processIds machine |> Set.contains pid |> shouldEqual false

            {
                Machine = machine
                Live = world.Live |> List.filter ((<>) pid)
                Asleep = world.Asleep |> Set.filter (fun (owner, _) -> owner <> pid)
                Woken = world.Woken |> List.filter (fun (owner, _) -> owner <> pid)
            }

    let private step (cover : FuzzLabel -> unit) (log : string -> unit) (world : World) (next : Step) : World =
        match next with
        | Step.Advance milliseconds ->
            match world.Live with
            | [] -> world
            | pid :: _ ->

            let before = world.Machine

            let machine =
                Machines.inView
                    pid
                    (fun view -> (), UnixSystem.advanceClock (int64 milliseconds * 1_000_000L) view)
                    world.Machine
                |> Option.get
                |> snd

            othersUnmoved pid before machine

            { world with
                Machine = machine
            }
        | Step.Dispatch (proc, thread, cpu) ->
            match world.Live with
            | [] -> world
            | live ->

            let pid = live.[proc % live.Length]

            if
                Set.contains (pid, thread) world.Asleep
                || List.contains (pid, thread) world.Woken
            then
                world
            else

            let before = world.Machine

            let machine =
                Machines.doIn pid (UnixScheduling.dispatch (Caller.make pid thread) (CpuId cpu)) world.Machine

            othersUnmoved pid before machine

            { world with
                Machine = machine
            }
        | Step.WakePass finishing ->
            let woken, machine = Machines.wake world.Machine
            let woken = woken |> List.map fst

            log $"  woken %A{woken}"

            let world =
                { world with
                    Machine = machine
                    Asleep = Set.difference world.Asleep (Set.ofList woken)
                    Woken = world.Woken @ woken
                }

            let finishing, waiting = List.splitAt (min finishing world.Woken.Length) world.Woken

            ({ world with
                Woken = waiting
             },
             finishing)
            ||> List.fold (fun world (pid, thread) ->
                // A process an earlier finish ended has taken its threads with it.
                if not (List.contains pid world.Live) then
                    world
                else

                let before = world.Machine

                log $"  finish %O{pid} %d{thread}"

                let made =
                    finish cover log pid thread (Machines.focus pid world.Machine |> Option.get)

                match made with
                | Made.Refused ->
                    cover FuzzLabel.Refusal
                    // Left woken, for a later pass.
                    { world with
                        Woken = world.Woken @ [ pid, thread ]
                    }
                | made ->
                    match made with
                    | Made.Answered _ -> cover FuzzLabel.Finish
                    | _ -> ()

                    let world = settle cover log pid thread made world

                    // A finish whose process's end was refused leaves the thread
                    // parked, woken still, for a later pass.
                    let world =
                        match Map.tryFind (ProcessId.toInt32 pid) world.Machine.Processes with
                        | Some slot when
                            (UnixThreadTable.parkedFor thread slot.Threads).IsSome
                            && not (Set.contains (pid, thread) world.Asleep)
                            ->
                            { world with
                                Woken = world.Woken @ [ pid, thread ]
                            }
                        | _ -> world

                    if UnixSystem.processIds world.Machine |> Set.contains pid then
                        othersUnmoved pid before world.Machine

                    assertClean world.Machine
                    world
            )
        | Step.Call (proc, thread, op) ->
            match world.Live with
            | [] -> world
            | live ->

            let pid = live.[proc % live.Length]

            if
                Set.contains (pid, thread) world.Asleep
                || List.contains (pid, thread) world.Woken
            then
                world
            else

            cover FuzzLabel.Call
            let before = world.Machine
            let view = Machines.focus pid before |> Option.get
            let beforeFds = fdsOf pid view |> Map.keys |> Set.ofSeq

            let othersWakeable =
                wakeable world
                |> Map.filter (fun (owner, _) _ -> owner <> pid)
                |> Map.keys
                |> Set.ofSeq

            let world =
                settle cover log pid thread (call cover log before pid thread op view) world

            // A call in this process, its end included, that made a call
            // asleep in another wakeable.
            let newlyWakeable =
                wakeable world
                |> Map.filter (fun (owner, _ as key) _ -> owner <> pid && not (Set.contains key othersWakeable))

            if not newlyWakeable.IsEmpty then
                cover FuzzLabel.CrossWake

                for KeyValue (_, fired) in newlyWakeable do
                    for primitive in fired do
                        let kind = UnionCaseName.ofValue primitive

                        cover (FuzzLabel.CrossWakeKind kind)

            match Map.tryFind (ProcessId.toInt32 pid) world.Machine.Processes with
            | None -> world
            | Some _ ->

            othersUnmoved pid before world.Machine

            // The caller's new descriptors are the lowest its own table had free.
            let afterFds =
                fdsOf pid (Machines.focus pid world.Machine |> Option.get)
                |> Map.keys
                |> Set.ofSeq

            let added = Set.difference afterFds beforeFds

            let lowestFree =
                Seq.initInfinite id
                |> Seq.filter (fun fd -> not (Set.contains fd beforeFds))
                |> Seq.take added.Count
                |> Set.ofSeq

            added
            |> Expect.equal (fun () -> $"process %O{pid}'s new descriptors") lowestFree

            world

    /// The process's listener at `port`, the flavour's event queue watching
    /// it, and `/f0` open.
    let private prepare (pid : ProcessId) (port : uint16) (view : UnixSystem<int, string>) : UnixSystem<int, string> =
        let listener, view = KeventWorld.listenerAtIn pid port view

        let view =
            match SimulatedUnixPlatform.flavour view.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux ->
                let epoll, view =
                    match UnixPoll.tryEpollCreate1 (Caller.make pid (Proc.leader pid view)) 0 view with
                    | Ok (Ok created) -> created
                    | other -> failwith $"epoll_create1: %A{other}"

                match
                    UnixPoll.tryEpollCtl
                        (Caller.make pid (Proc.leader pid view))
                        epoll
                        1
                        listener
                        (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 0UL))
                        view
                with
                | Ok (EpollCtlAnswer.Changed, view) -> view
                | other -> failwith $"epoll_ctl: %A{other}"
            | SimulatedUnixFlavour.Darwin ->
                let kq, view = KeventWorld.kqueueIn pid view

                match
                    UnixKqueue.tryKevent
                        (Caller.make pid 0)
                        kq
                        1
                        [
                            KeventWorld.change listener KeventFilter.Read (KeventFlags.Add ||| KeventFlags.Clear) 0UL
                        ]
                        0
                        UserBuffer.Mapped
                        (KeventTimeout.Readable (0L, 0L))
                        view
                with
                | Ok (KeventOutcome.Answered [], view) -> view
                | other -> failwith $"kevent: %A{other}"

        match OpenFlagWords.openPathIn pid openCreating (PathArg.ofText files.[0]) 0o644 view with
        | Ok (_, view) -> view
        | Error refusal -> failwith $"open: %A{refusal}"

    /// TCP buffers far smaller than the defaults, so that a few writes fill
    /// them: as small as each flavour admits.
    let private smallBuffers (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
        match SimulatedUnixPlatform.flavour (UnixBootImage.platform image) with
        | SimulatedUnixFlavour.Linux ->
            image
            |> UnixBootImage.tryWithTcpSendSpaceMax (Some 16384)
            |> Configured.expectOk TcpSendSpaceMaxRefusal.describe
            |> UnixBootImage.tryWithTcpReceiveSpace (Some 8192)
            |> Configured.expectOk TcpReceiveSpaceRefusal.describe
        | SimulatedUnixFlavour.Darwin ->
            image
            |> UnixBootImage.tryWithTcpSendSpace (Some UnixMachineState.darwinLoopbackSendPipe)
            |> Configured.expectOk TcpSendSpaceRefusal.describe
            |> UnixBootImage.tryWithTcpReceiveSpace (Some UnixMachineState.darwinLoopbackReceivePipe)
            |> Configured.expectOk TcpReceiveSpaceRefusal.describe

    /// A connection waiting in a listener's accept queue, and which process
    /// names each of its two sockets, if one does.
    type private QueuedClient =
        {
            Listener : SocketId
            ListenerOwner : ProcessId option
            Connection : ConnectionId
            Client : SocketId
            ClientOwner : ProcessId option
        }

    /// Every connection waiting in a listener's queue on `machine`.
    let private queuedClients (machine : UnixSystem<int, string>) : QueuedClient list =
        let ownerOf (socket : SocketId) : ProcessId option =
            UnixSystem.processIds machine
            |> Seq.tryPick (fun pid ->
                let names =
                    fdsOf pid (Machines.focus pid machine |> Option.get)
                    |> Map.exists (fun _ target -> target = OpenFileTarget.Socket socket)

                if names then Some pid else None
            )

        machine.Machine.Sockets
        |> Map.toList
        |> List.collect (fun (listener, socket) ->
            match socket.Phase with
            | SocketPhase.Listening listenState ->
                // A connection whose client has closed has nothing left to
                // reset, and is left out.
                ListenState.connections listenState
                |> List.choose (fun connection ->
                    UnixMachineState.socketHoldingEnd connection ConnectionEnd.Client machine.Machine
                    |> Option.map (fun client ->
                        {
                            Listener = listener
                            ListenerOwner = ownerOf listener
                            Connection = connection
                            Client = client
                            ClientOwner = ownerOf client
                        }
                    )
                )
            | _ -> []
        )

    /// Each of `queued`, the connections waiting in a listener's queue before
    /// a step, whose client is still open on `after`: reset if the step
    /// released its listener, unless the step accepted it first, and not
    /// reset while it is still queued.
    ///
    /// One step can accept a connection and then release its listener, as a
    /// wake pass finishes an accept that held the listener's last reference,
    /// and can then close the accepted socket, as the acceptor's process
    /// ends. So a client the step did not reset must show that it was
    /// accepted: its connection's server end has a socket, or has sent it a
    /// FIN, which a queued server end never does.
    ///
    /// The clients the step reset.
    let private checkQueuedClients
        (cover : FuzzLabel -> unit)
        (queued : QueuedClient list)
        (after : UnixSystem<int, string>)
        : QueuedClient list
        =
        queued
        |> List.filter (fun queued ->
            match Map.tryFind queued.Client after.Machine.Sockets with
            | None -> false
            | Some _ ->

            let transfer =
                (UnixMachineState.connection queued.Connection after.Machine).Transfer

            let reset = TcpTransfer.hasBeenReset ConnectionEnd.Client transfer

            let accepted =
                (UnixMachineState.socketHoldingEnd queued.Connection ConnectionEnd.Server after.Machine).IsSome
                || (
                    // The server end, accepted and closed, has made its FIN,
                    // and the client is neither reset nor closed.
                    let towardsClient = TcpTransfer.towards ConnectionEnd.Client transfer

                    match towardsClient.Receiver, towardsClient.Fin with
                    | TcpEndState.Open _, (TcpFin.Queued _ | TcpFin.Arrived _) -> true
                    | TcpEndState.Open _, TcpFin.NotSent
                    | TcpEndState.Reset _, _
                    | TcpEndState.Closed _, _ -> false)

            let stillQueued =
                match Map.tryFind queued.Listener after.Machine.Sockets with
                | Some socket ->
                    match socket.Phase with
                    | SocketPhase.Listening listenState ->
                        List.contains queued.Connection (ListenState.connections listenState)
                    | _ -> false
                | None -> false

            if stillQueued then
                if reset then
                    failwith
                        $"client %O{queued.Client} was reset while its connection waited in listener %O{queued.Listener}'s queue"

                false
            elif Map.containsKey queued.Listener after.Machine.Sockets || accepted then
                false
            elif not reset then
                failwith $"listener %O{queued.Listener} went, and client %O{queued.Client} it queued was not reset"
            else
                cover FuzzLabel.QueuedClientReset

                match queued.ListenerOwner, queued.ClientOwner with
                | Some listenerOwner, Some clientOwner when listenerOwner <> clientOwner ->
                    cover FuzzLabel.CrossQueuedClientReset
                | _ -> ()

                true
        )

    /// `next`, for a transcript: its kind, and for a call, the process, the
    /// thread and the kind of call. Its arguments follow from the case, and
    /// `%A` of every step would make the oracle slow.
    let private stepText (next : Step) : string =
        match next with
        | Step.Call (proc, thread, op) -> "Call " + string proc + " " + string thread + " " + UnionCaseName.ofValue op
        | Step.WakePass finishing -> "WakePass " + string finishing
        | Step.Advance milliseconds -> "Advance " + string milliseconds
        | Step.Dispatch (proc, thread, cpu) -> "Dispatch " + string proc + " " + string thread + " " + string cpu

    /// `case` run on a machine `configure` made, with `observe` shown each
    /// step and the world it left, and the world `observe` answers the one the
    /// run goes on in.
    let private runThreading
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (observe : Step -> World -> World)
        (cover : FuzzLabel -> unit)
        (log : string -> unit)
        (case : Case)
        : unit
        =
        let pids, machine =
            Machines.withThreadsOn configure case.Platform case.Processes threads

        let machine =
            if case.Prepared then
                let machine =
                    (machine, List.indexed pids)
                    ||> List.fold (fun machine (i, pid) ->
                        Machines.doIn pid (prepare pid ports.[i % ports.Length]) machine
                    )

                // Then each process connects to the next one's listener, and
                // the next accepts, so that bytes cross between processes from
                // the first step: the connecting end blocking, so that its
                // transfers sleep, and the accepted end not.
                (machine, List.indexed pids)
                ||> List.fold (fun machine (i, client) ->
                    let next = (i + 1) % pids.Length

                    let machine =
                        Machines.doIn
                            client
                            (fun view ->
                                let fd, view = KeventWorld.clientIn client ports.[next] view

                                UnixDescriptor.setNonBlocking
                                    (Caller.make client (Proc.leader client view))
                                    fd
                                    false
                                    view
                                |> snd
                            )
                            machine

                    Machines.doIn
                        pids.[next]
                        (fun view ->
                            let listener = socketsWhere pids.[next] listening view |> List.head
                            let accepted, view = KeventWorld.acceptIn pids.[next] listener view
                            let server = pids.[next]

                            UnixDescriptor.setNonBlocking
                                (Caller.make server (Proc.leader server view))
                                accepted
                                true
                                view
                            |> snd
                        )
                        machine
                )
            else
                machine

        assertClean machine

        let world =
            {
                Machine = machine
                Live = pids
                Asleep = Set.empty
                Woken = []
            }

        (world, case.Steps)
        ||> List.fold (fun before next ->
            let queued = queuedClients before.Machine

            let wakeableBefore =
                if queued.IsEmpty then
                    Set.empty
                else
                    wakeable before |> Map.keys |> Set.ofSeq

            log (stepText next)
            let world = step cover log before next
            assertClean world.Machine

            let reset = checkQueuedClients cover queued world.Machine
            let owners = reset |> List.choose (fun queued -> queued.ClientOwner) |> Set.ofList

            let wokenRead =
                not reset.IsEmpty
                && wakeable world
                   |> Map.exists (fun (pid, _ as key) fired ->
                       Set.contains pid owners
                       && not (Set.contains key wakeableBefore)
                       && fired
                          |> Set.exists (fun primitive ->
                              match primitive with
                              | WakePrimitive.ConnectionReadable _ -> true
                              | _ -> false
                          )
                   )

            if wokenRead then
                cover FuzzLabel.QueuedClientResetWakesRead

            observe next world
        )
        |> ignore

    /// `case` run on a machine `configure` made, with `observe` shown each
    /// step and the world it left.
    let private runObserving
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (observe : Step -> World -> unit)
        (cover : FuzzLabel -> unit)
        (log : string -> unit)
        (case : Case)
        : unit
        =
        runThreading
            configure
            (fun step world ->
                observe step world
                world
            )
            cover
            log
            case

    let private run (cover : FuzzLabel -> unit) (case : Case) : unit =
        runObserving smallBuffers (fun _ _ -> ()) cover ignore case

    [<Test>]
    let ``random interleavings of several processes' calls, wakes and ends keep every invariant and touch no other process``
        ()
        : unit
        =
        // 1500 cases, because the cases biased towards transfers leave fewer
        // steps for the rest, and 1000 reached the rarest of the paths below
        // too seldom for its bound to be safe.
        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 1500) (Arb.fromGen caseGen) run

        // The paths the property exists for, each reached by the fixed sample
        // often enough that a generator regression shows here rather than as a
        // silently weaker test. Each floor is about a third of the median over
        // 60 seeded runs, so a change that reshuffles the sample keeps meeting
        // it.
        coverage.Count FuzzLabel.CrossConnect |> shouldBeGreaterThan 840
        coverage.Count FuzzLabel.CrossAddressInUse |> shouldBeGreaterThan 173
        coverage.Count FuzzLabel.Accept |> shouldBeGreaterThan 476
        coverage.Count FuzzLabel.CrossRmDirOfStanding |> shouldBeGreaterThan 113
        coverage.Count FuzzLabel.EpollAdd |> shouldBeGreaterThan 152
        coverage.Count FuzzLabel.KeventAdd |> shouldBeGreaterThan 222
        coverage.Count FuzzLabel.Park |> shouldBeGreaterThan 1942
        coverage.Count FuzzLabel.DarwinPollPark |> shouldBeGreaterThan 170
        coverage.Count FuzzLabel.KeventPark |> shouldBeGreaterThan 196
        coverage.Count FuzzLabel.Finish |> shouldBeGreaterThan 569
        coverage.Count FuzzLabel.Exit |> shouldBeGreaterThan 74
        coverage.Count FuzzLabel.SignalDeath |> shouldBeGreaterThan 118
        coverage.Count FuzzLabel.CrossWake |> shouldBeGreaterThan 610
        coverage.Count FuzzLabel.CrossRead |> shouldBeGreaterThan 418
        coverage.Count FuzzLabel.ShortWrite |> shouldBeGreaterThan 113
        coverage.Count FuzzLabel.Reset |> shouldBeGreaterThan 140
        coverage.Count FuzzLabel.EndOfFile |> shouldBeGreaterThan 277
        coverage.Count FuzzLabel.ConnectionReadPark |> shouldBeGreaterThan 180
        coverage.Count FuzzLabel.ConnectionWritePark |> shouldBeGreaterThan 112
        coverage.Count FuzzLabel.ConnectionFinish |> shouldBeGreaterThan 68
        // A third of what the fixed sample reached when these were added.
        coverage.Count FuzzLabel.QueuedClientReset |> shouldBeGreaterThan 145
        coverage.Count FuzzLabel.CrossQueuedClientReset |> shouldBeGreaterThan 136
        coverage.Count FuzzLabel.QueuedClientResetWakesRead |> shouldBeGreaterThan 80
        coverage.Count FuzzLabel.InotifyRecordRead |> shouldBeGreaterThan 80
        coverage.Count FuzzLabel.InotifyReadPark |> shouldBeGreaterThan 90
        coverage.Count FuzzLabel.InotifyReadFinish |> shouldBeGreaterThan 63

        let crossWakes (kind : string) : int =
            coverage.Count (FuzzLabel.CrossWakeKind kind)

        crossWakes "AcceptQueueNonEmpty" |> shouldBeGreaterThan 206
        crossWakes "EpollEventDeliverable" |> shouldBeGreaterThan 73
        crossWakes "KqueueEventDeliverable" |> shouldBeGreaterThan 89
        crossWakes "KqueuePollReportable" |> shouldBeGreaterThan 70
        crossWakes "FlockGrantable" |> shouldBeGreaterThan 80
        crossWakes "DescriptorReady" |> shouldBeGreaterThan 56
        crossWakes "ConnectionReadable" |> shouldBeGreaterThan 52
        crossWakes "ConnectionWritable" |> shouldBeGreaterThan 73
        crossWakes "InotifyRecordQueued" |> shouldBeGreaterThan 64
        // Refusals are steps that tested nothing; they must stay rare in the
        // fixed sample.
        coverage.Count FuzzLabel.Refusal * 10
        |> shouldBeSmallerThan (coverage.Count FuzzLabel.Call)

    /// What `UnixWait.wake` did with the memo the system carries at a step,
    /// each counted every time a step reaches it.
    [<RequireQualifiedAccess>]
    type private MemoLabel =
        /// The memo answered, sweeping nothing, after a step of this kind.
        | Skip of after : string
        /// The memo did not answer, and the sweep ran.
        | Sweep
        /// The sweep ran because the clock had reached a deadline, though
        /// nothing else the memo compares had changed, and woke a thread.
        | ClockOnlyWake
        /// A sweep, after a step whose sweep the memo answered, that woke a thread
        /// whose deadline had passed.
        | DeadlineWakeAfterSkip
        /// A sweep, after a step whose sweep the memo answered, that woke a thread
        /// for something besides its deadline.
        | SyscallWakeAfterSkip

    /// `caseGen`'s cases, run on two processors, with a dispatch or a
    /// millisecond of the clock between some of their steps: the two things a
    /// client does between syscalls.
    let private memoCaseGen : Gen<Case> =
        gen {
            let! case = caseGen

            let rec interleave (steps : Step list) (acc : Step list) : Gen<Step list> =
                match steps with
                | [] -> Gen.constant (List.rev acc)
                | step :: rest ->
                    gen {
                        let! kind = Gen.choose (0, 9)
                        let! proc = Gen.choose (0, case.Processes - 1)
                        let! thread = Gen.choose (0, threads - 1)
                        let! cpu = Gen.frequency [ 4, Gen.constant 0 ; 1, Gen.constant 1 ]

                        let between =
                            match kind with
                            | k when k < 3 -> [ Step.Dispatch (proc, thread, cpu) ]
                            | 3 -> [ Step.Advance 1 ]
                            | 4 -> [ Step.Advance 5 ]
                            | _ -> []

                        return! interleave rest (step :: List.rev between @ acc)
                    }

            let! steps = interleave case.Steps []

            return
                { case with
                    Steps = steps
                }
        }

    let private twoProcessors (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
        smallBuffers image
        |> UnixBootImage.tryWithProcessorCount 2
        |> Configured.expectOk ProcessorCountRefusal.describe

    [<Test>]
    let ``wake answers from the system's memo what the reference sweep answers, at every step of random interleavings``
        ()
        : unit
        =
        let property (cover : MemoLabel -> unit) (case : Case) : unit =
            let lastSkipped = ref false

            let observe (step : Step) (world : World) : World =
                let machine = world.Machine
                let asleep = world.Asleep |> Set.map (fun (pid, thread) -> Caller.make pid thread)
                let reference = ReferenceWake.wakes asleep machine

                let skips, readsSame =
                    match machine.Sweep.Remembered with
                    | ValueNone -> false, false
                    | ValueSome remembered ->
                        WakeMemo.covers remembered machine.Machine machine.Scheduling machine.Processes,
                        WakeMemo.readsSame remembered machine.Machine machine.Processes

                let answer, after = UnixWait.wake machine
                answer |> shouldEqual reference
                obj.ReferenceEquals (after.Machine, machine.Machine) |> shouldEqual true
                obj.ReferenceEquals (after.Scheduling, machine.Scheduling) |> shouldEqual true

                // What a memo remembers is no part of the system: forgetting it
                // makes an equal system, which hashes alike.
                let forgotten =
                    { machine with
                        Sweep = WakeMemo.none
                    }

                forgotten |> shouldEqual machine
                hash forgotten |> shouldEqual (hash machine)

                if skips then
                    obj.ReferenceEquals (after, machine) |> shouldEqual true
                elif answer.IsEmpty then
                    // The sweep woke nobody, and the system it answers remembers
                    // so: equal to the one it was asked of, and made of the same
                    // parts.
                    after.Sweep.Remembered.IsSome |> shouldEqual true
                    after |> shouldEqual machine
                    hash after |> shouldEqual (hash machine)
                    obj.ReferenceEquals (after.Processes, machine.Processes) |> shouldEqual true
                else
                    after.Sweep.Remembered.IsSome |> shouldEqual false

                if skips then
                    let kind =
                        match step with
                        | Step.Call _ -> "Call"
                        | Step.WakePass _ -> "WakePass"
                        | Step.Advance _ -> "Advance"
                        | Step.Dispatch _ -> "Dispatch"

                    cover (MemoLabel.Skip kind)
                else
                    cover MemoLabel.Sweep

                    if readsSame && not answer.IsEmpty then
                        cover MemoLabel.ClockOnlyWake

                    if lastSkipped.Value then
                        let fired = answer |> List.collect (fun (_, fired) -> Set.toList fired)

                        let deadline (primitive : WakePrimitive) : bool =
                            match primitive with
                            | WakePrimitive.DeadlinePassed _ -> true
                            | _ -> false

                        if fired |> List.exists deadline then
                            cover MemoLabel.DeadlineWakeAfterSkip

                        if fired |> List.exists (deadline >> not) then
                            cover MemoLabel.SyscallWakeAfterSkip

                lastSkipped.Value <- skips

                // The run goes on in the system that remembers the sweep. A
                // sweep that woke a thread is left to the run's own wake passes,
                // which keep the run's account of who sleeps.
                if answer.IsEmpty then
                    { world with
                        Machine = after
                    }
                else
                    world

            runThreading twoProcessors observe ignore ignore case

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen memoCaseGen) property

        // A third of what the fixed sample reached when these were added. The
        // memo answers after every kind of step, and a sweep it does not
        // answer still wakes what it should: for a deadline the clock alone
        // reached, and for a syscall, each after a step the memo answered.
        coverage.Count (MemoLabel.Skip "Call") |> shouldBeGreaterThan 4690
        coverage.Count (MemoLabel.Skip "WakePass") |> shouldBeGreaterThan 620
        coverage.Count (MemoLabel.Skip "Advance") |> shouldBeGreaterThan 1980
        coverage.Count (MemoLabel.Skip "Dispatch") |> shouldBeGreaterThan 2020
        coverage.Count MemoLabel.Sweep |> shouldBeGreaterThan 5530
        coverage.Count MemoLabel.ClockOnlyWake |> shouldBeGreaterThan 17
        coverage.Count MemoLabel.DeadlineWakeAfterSkip |> shouldBeGreaterThan 11
        coverage.Count MemoLabel.SyscallWakeAfterSkip |> shouldBeGreaterThan 59

    /// What the library's sweep met at a step, each counted every time a step
    /// reaches it.
    [<RequireQualifiedAccess>]
    type private SweepLabel =
        /// The sweep woke a thread.
        | Woke
        /// A thread was woken and had not yet finished its call.
        | WokenUnfinished
        /// A sleeping thread's condition held on an exclusive queue that a
        /// woken, unfinished thread's call waits on, and the sweep did not
        /// wake it.
        | HeldByWoken

    /// Every thread of `machine`'s processes that is parked in a call.
    let private parkedThreads (machine : UnixSystem<int, string>) : Set<ProcessId * int> =
        machine.Processes
        |> Seq.collect (fun (KeyValue (key, slot)) ->
            let pid = ProcessId.parseOrFail "parkedThreads" key

            slot.Threads
            |> Map.toSeq
            |> Seq.choose (fun (thread, state) ->
                match UnixThreadState.parkedIn state with
                | Some _ -> Some (pid, thread)
                | None -> None
            )
        )
        |> Set.ofSeq

    /// `UnixWait.wake` is the reference sweep (`ReferenceWake`), the sweep as
    /// it was when the client named the threads it held asleep, given the
    /// threads the kernel's parks hold asleep; and it records exactly the wakes
    /// it answers. At each step of the first property's interleavings, the
    /// kernel's parks agree with the client's own bookkeeping of who sleeps and
    /// who has been woken and not yet finished.
    [<Test>]
    let ``wake answers what the reference sweep answers, at every step of random interleavings`` () : unit =
        let property (cover : SweepLabel -> unit) (case : Case) : unit =
            let observe (_ : Step) (world : World) : unit =
                let machine = world.Machine
                let woken = Set.ofList world.Woken

                Set.intersect world.Asleep woken |> shouldEqual Set.empty
                Set.union world.Asleep woken |> shouldEqual (parkedThreads machine)
                Machines.parkStates machine |> shouldEqual (world.Asleep, woken)

                let asleep = world.Asleep |> Set.map (fun (pid, thread) -> Caller.make pid thread)

                let reference = ReferenceWake.wakes asleep machine
                let answer, after = UnixWait.wake machine
                answer |> shouldEqual reference

                // The sweep marks exactly the threads it answers woken, each for
                // what it answers, and changes nothing else.
                let answered =
                    answer
                    |> List.map (fun (caller, fired) -> (Caller.processId caller, Caller.thread caller), fired)
                    |> Map.ofList

                obj.ReferenceEquals (after.Machine, machine.Machine) |> shouldEqual true
                obj.ReferenceEquals (after.Scheduling, machine.Scheduling) |> shouldEqual true

                for pid in UnixSystem.processIds machine do
                    let before = machine.Processes.[ProcessId.toInt32 pid]
                    let slot = after.Processes.[ProcessId.toInt32 pid]
                    obj.ReferenceEquals (slot.Process, before.Process) |> shouldEqual true

                    for KeyValue (thread, state) in before.Threads do
                        let expected =
                            match Map.tryFind (pid, thread) answered with
                            | Some fired ->
                                { state with
                                    Parked =
                                        state.Parked
                                        |> Option.map (fun park ->
                                            { park with
                                                State = ParkState.Woken fired
                                            }
                                        )
                                }
                            | None -> state

                        slot.Threads.[thread] |> shouldEqual expected

                    slot.Threads.Count |> shouldEqual before.Threads.Count

                if answer.IsEmpty then
                    after |> shouldEqual machine
                    obj.ReferenceEquals (after.Processes, machine.Processes) |> shouldEqual true

                UnixWait.deadlines machine
                |> shouldEqual (ReferenceWake.deadlines asleep machine)

                if not reference.IsEmpty then
                    cover SweepLabel.Woke

                if not woken.IsEmpty then
                    cover SweepLabel.WokenUnfinished

                // The exclusive queues the woken threads' calls wait on.
                let held =
                    woken
                    |> Seq.collect (fun (pid, thread) ->
                        match UnixThreadTable.parkOf thread (Proc.threads pid machine) with
                        | Some park -> Parking.exclusiveQueuesOfPark machine.Machine park.Syscall
                        | None -> []
                    )
                    |> Set.ofSeq

                let answered = reference |> List.map fst |> Set.ofList

                let heldBack =
                    asleep
                    |> Set.exists (fun caller ->
                        not (Set.contains caller answered)
                        && match UnixWait.satisfied caller machine with
                           | Some fired ->
                               fired
                               |> Set.exists (fun primitive ->
                                   match Parking.exclusiveQueueOf machine.Machine primitive with
                                   | Some queue -> Set.contains queue held
                                   | None -> false
                               )
                           | None -> false
                    )

                if heldBack then
                    cover SweepLabel.HeldByWoken

            runObserving smallBuffers observe ignore ignore case

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen caseGen) property

        // A third of what the fixed sample reached when these were added.
        coverage.Count SweepLabel.Woke |> shouldBeGreaterThan 1550
        coverage.Count SweepLabel.WokenUnfinished |> shouldBeGreaterThan 160
        coverage.Count SweepLabel.HeldByWoken |> shouldBeGreaterThan 7

    /// `UnixWait.finish` answers what the finishing function of each woken
    /// call's own family answers (`FinishOracle.agree`), at every step of the
    /// first property's interleavings: for every thread woken and not yet
    /// finished, and every thread a sweep of that step's system would wake, in
    /// the system the sweep answers. The run itself goes on through the
    /// families' functions, as the first property's does.
    [<Test>]
    let ``finish answers what each woken call's own finishing function answers, at every step of random interleavings``
        ()
        : unit
        =
        let property (cover : string -> unit) (case : Case) : unit =
            let observe (_ : Step) (world : World) : unit =
                let _, woken = UnixWait.wake world.Machine

                for pid in UnixSystem.processIds woken do
                    for KeyValue (thread, state) in UnixSystem.threads pid woken do
                        match UnixThreadState.park state with
                        | Some {
                                   State = ParkState.Woken _
                               } -> cover (FinishOracle.agree (Caller.make pid thread) woken)
                        | Some {
                                   State = ParkState.Asleep
                               }
                        | None -> ()

            runObserving smallBuffers observe ignore ignore case

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen caseGen) property

        let reached (prefix : string) : int =
            coverage.Reached
            |> List.sumBy (fun (label, count) -> if label.StartsWith prefix then count else 0)

        // A third of what the fixed sample reached when this was added, for
        // each kind of call the interleavings park a thread in often. A pipe's
        // `read` and `write` they park in seldom, and a `sigsuspend` never;
        // `TestUnixWaitFinish` reaches every kind.
        reached "Accept " |> shouldBeGreaterThan 478
        reached "ConnectionRead " |> shouldBeGreaterThan 417
        reached "ConnectionWrite " |> shouldBeGreaterThan 214
        reached "EpollWait " |> shouldBeGreaterThan 145
        reached "Flock " |> shouldBeGreaterThan 133
        reached "InotifyRead " |> shouldBeGreaterThan 204
        reached "Kevent " |> shouldBeGreaterThan 177
        reached "KqueuePoll " |> shouldBeGreaterThan 272
        reached "Poll " |> shouldBeGreaterThan 167
        reached "ConnectionWrite NeedsCopyIn" |> shouldBeGreaterThan 129
        reached "ConnectionWrite ProcessEnded" |> shouldBeGreaterThan 4

        coverage.Reached
        |> List.sumBy (fun (label, count) -> if label.EndsWith " refused" then count else 0)
        |> shouldBeGreaterThan 80

    /// A close looks only at the parked calls holding the description the
    /// closed descriptor names, and at none when no call holds it; it answers
    /// what a close looking at every parked call of the process answers. At
    /// every step of the first property's interleavings, for every descriptor
    /// of every process with a parked call.
    [<Test>]
    let ``close answers what a close examining every parked call answers, at every step of random interleavings``
        ()
        : unit
        =
        let caseName (value : 'a) : string =
            (fst (
                Reflection.FSharpValue.GetUnionFields (
                    value,
                    typeof<'a>,
                    System.Reflection.BindingFlags.Public
                    ||| System.Reflection.BindingFlags.NonPublic
                )
            ))
                .Name

        let property (cover : string -> unit) (case : Case) : unit =
            let observe (_ : Step) (world : World) : unit =
                for pid in UnixSystem.processIds world.Machine do
                    let view = Proc.view pid world.Machine

                    let parked =
                        view.Threads
                        |> Map.toList
                        |> List.choose (fun (thread, state) ->
                            state.Parked |> Option.map (fun park -> thread, park.Syscall)
                        )

                    if not parked.IsEmpty then
                        for KeyValue (fd, _) in fdsOf pid world.Machine do
                            let closingId =
                                FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors view)
                                |> Option.get

                            let holders =
                                parked
                                |> List.filter (fun (_, parked) ->
                                    List.contains closingId (ParkedSyscall.descriptions parked)
                                )

                            if holders.IsEmpty then
                                cover "unheld"

                            for _, holder in holders do
                                cover $"held %s{caseName holder}"

                            let watchedByNumber =
                                parked
                                |> List.exists (fun (_, parked) ->
                                    match parked with
                                    | ParkedSyscall.Poll poll ->
                                        poll.Entries
                                        |> List.exists (fun entry ->
                                            match entry with
                                            | ParkedPollEntry.Watched (watched, _, _) -> watched = fd
                                            | ParkedPollEntry.Ignored _ -> false
                                        )
                                    | ParkedSyscall.KqueuePoll poll ->
                                        poll.Entries |> List.exists (fun entry -> entry.Fd = fd)
                                    | ParkedSyscall.Kevent wait -> wait.Fd = fd
                                    | _ -> false
                                )

                            if watchedByNumber then
                                cover "watched by number"

                            let reference =
                                UnixDescriptor.tryCloseExamining UnixDescriptor.ParksExamined.Every fd view

                            UnixDescriptor.tryCloseExamining UnixDescriptor.ParksExamined.Holding fd view
                            |> shouldEqual reference

                            match reference with
                            | Error refusal -> cover $"refused %s{caseName refusal}"
                            | Ok (_, after) ->
                                let ended =
                                    parked
                                    |> List.exists (fun (thread, parked) ->
                                        UnixThreadTable.parkOf thread after.Threads
                                        |> Option.map (fun park -> park.Syscall)
                                        <> Some parked
                                    )

                                if ended then
                                    cover "ended a call"

            runObserving smallBuffers observe ignore ignore case

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 100) (Arb.fromGen caseGen) property

        // A third of what the fixed sample reached when this was added: closes
        // of a description each kind of parked call holds, of one a poll,
        // a Darwin poll or a `kevent` refers to by number, and of one no call
        // holds, closes that end a call, and each refusal the interleavings
        // reach. A pipe's `read` and `write` they park in seldom.
        coverage.Count "unheld" |> shouldBeGreaterThan 22000
        coverage.Count "watched by number" |> shouldBeGreaterThan 410
        coverage.Count "ended a call" |> shouldBeGreaterThan 700
        coverage.Count "held Accept" |> shouldBeGreaterThan 1650
        coverage.Count "held ConnectionRead" |> shouldBeGreaterThan 660
        coverage.Count "held ConnectionWrite" |> shouldBeGreaterThan 480
        coverage.Count "held EpollWait" |> shouldBeGreaterThan 470
        coverage.Count "held Flock" |> shouldBeGreaterThan 250
        coverage.Count "held InotifyRead" |> shouldBeGreaterThan 115
        coverage.Count "held Kevent" |> shouldBeGreaterThan 195
        coverage.Count "held Poll" |> shouldBeGreaterThan 34
        coverage.Count "held PipeRead" |> shouldBeGreaterThan 29
        coverage.Count "held PipeWrite" |> shouldBeGreaterThan 19
        coverage.Count "refused PolledDescriptor" |> shouldBeGreaterThan 34

        coverage.Count "refused DarwinFlockedDescriptorWithWaiter"
        |> shouldBeGreaterThan 158

        coverage.Count "refused DarwinWokenTransfer" |> shouldBeGreaterThan 47
        coverage.Count "refused DarwinEndedWriteSignal" |> shouldBeGreaterThan 19

    /// How many cases of `caseGen`'s fixed sample the oracle replays: every one
    /// the first property counts its coverage over.
    let private oracleCases : int = 1500

    /// The embedded reference the oracle holds the library to.
    let private oracleResource : string =
        "WoofWare.PosixKernel.Test.multiProcessOracle.answers.txt"

    /// What `case` answered, step by step: each step, what each call and finish
    /// in it answered, which threads each wake pass woke, how each ended
    /// process ended or that its end was refused, and after the step, each
    /// live process's descriptors with the kind of thing each names, and the
    /// kind of call each of its threads is parked in. Systems are left out, so
    /// the transcript says nothing about how the library holds its state.
    let private transcriptOf (case : Case) : string =
        let builder = System.Text.StringBuilder ()
        let log (line : string) : unit = builder.AppendLine line |> ignore
        log $"%A{case.Platform} %d{case.Processes} %b{case.Prepared}"

        // Case names rather than `%A`, which would make the oracle take
        // minutes: each call's answer is written in full already.
        let observe (_ : Step) (world : World) : unit =
            for pid in world.Live do
                let view = Machines.focus pid world.Machine |> Option.get
                builder.Append("  ").Append(ProcessId.toInt32 pid).Append (':') |> ignore

                for KeyValue (fd, target) in fdsOf pid view do
                    builder.Append(' ').Append(fd).Append('=').Append (UnionCaseName.ofValue target)
                    |> ignore

                builder.Append (';') |> ignore

                for KeyValue (thread, state) in Proc.threads pid view do
                    let parked =
                        match UnixThreadState.parkedIn state with
                        | None -> "running"
                        | Some parked -> UnionCaseName.ofValue parked

                    builder.Append(' ').Append(thread).Append('=').Append (parked) |> ignore

                builder.AppendLine () |> ignore

        runObserving smallBuffers observe ignore log case
        builder.ToString ()

    /// The transcript of each case of the fixed sample the oracle replays, in
    /// the order they are drawn.
    let private oracleTranscripts () : string list =
        let transcripts = ResizeArray<string> ()
        CoverageSample.replay oracleCases (Arb.fromGen caseGen) (fun case -> transcripts.Add (transcriptOf case))
        List.ofSeq transcripts

    let private sha256 (text : string) : string =
        System.Security.Cryptography.SHA256.HashData (System.Text.Encoding.UTF8.GetBytes text)
        |> System.Convert.ToHexString

    /// Each case's index and the hash of its transcript, as the reference
    /// records them.
    let private recordedOracle () : Map<int, string> =
        let assembly = System.Reflection.Assembly.GetExecutingAssembly ()

        use stream =
            match assembly.GetManifestResourceStream oracleResource with
            | null -> failwith $"embedded resource %s{oracleResource} not found"
            | stream -> stream

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.filter (fun line -> line <> "" && not (line.StartsWith '#'))
        |> Array.map (fun line ->
            match line.Split '\t' with
            | [| index ; hash |] -> int index, hash
            | _ -> failwith $"not a line of the oracle's reference: %s{line}"
        )
        |> Map.ofArray

    /// The oracle for how the library holds several processes: the fixed
    /// sample's interleavings, each run as the first property runs it, answer
    /// exactly what the reference records. A difference names the cases whose
    /// transcripts moved; set `POSIXKERNEL_ORACLE_DUMP` to a directory and run
    /// `Update multi-process oracle` on the commit that recorded the reference
    /// and on this one to compare them line by line.
    [<Test>]
    let ``the fixed sample's interleavings answer what the recorded reference says`` () : unit =
        let recorded = recordedOracle ()
        recorded.Count |> shouldEqual oracleCases

        let moved =
            oracleTranscripts ()
            |> List.mapi (fun index transcript -> index, sha256 transcript)
            |> List.filter (fun (index, hash) -> Map.tryFind index recorded <> Some hash)
            |> List.map fst

        moved |> shouldEqual []

    /// Rewrites the oracle's reference from the library as built, and, if
    /// `POSIXKERNEL_ORACLE_DUMP` names a directory, writes each case's
    /// transcript there as `<index>.txt`.
    [<Test ; Explicit>]
    let ``Update multi-process oracle`` () : unit =
        let transcripts = oracleTranscripts ()

        match System.Environment.GetEnvironmentVariable "POSIXKERNEL_ORACLE_DUMP" with
        | null
        | "" -> ()
        | directory ->
            System.IO.Directory.CreateDirectory directory |> ignore

            transcripts
            |> List.iteri (fun index transcript ->
                System.IO.File.WriteAllText (System.IO.Path.Combine (directory, $"%d{index}.txt"), transcript)
            )

        let lines =
            [
                "# TestMultiProcessFuzz's oracle: the SHA-256 of the transcript (transcriptOf) of each case of"
                "# caseGen's fixed sample (CoverageSample's seed, the first 1500 cases), as the library answered"
                "# them when this file was written. index<TAB>hash"
            ]
            @ (transcripts
               |> List.mapi (fun index transcript -> $"%d{index}\t%s{sha256 transcript}"))

        System.IO.File.WriteAllText (
            System.IO.Path.Combine (__SOURCE_DIRECTORY__, "multiProcessOracle", "answers.txt"),
            String.concat "\n" lines + "\n"
        )

    // ------------------------------------------------- the process-end oracle

    /// A way a process ends, which the process-end oracle takes in each process
    /// still on the machine at the end of each case of the fixed sample.
    [<RequireQualifiedAccess>]
    type private Ending =
        /// `exit_group(7)`.
        | ExitGroup
        /// `kill(2)` of `signal`, to the process itself.
        | Kill of signal : Signal
        /// `raise(3)` of SIGTERM.
        | Raise
        /// SIGTERM blocked, raised, and unblocked, each followed by the return
        /// to user mode, the last of which ends the process.
        | ReturnToUser
        /// Every thread but the leader exits, and then the leader, the last.
        | LastThread
        /// A write of one byte into a new pipe whose read end is closed, which
        /// raises SIGPIPE at its default.
        | BrokenPipe

    let private endings : Ending list =
        [
            Ending.ExitGroup
            Ending.Kill Signal.SIGKILL
            Ending.Kill Signal.SIGQUIT
            Ending.Raise
            Ending.ReturnToUser
            Ending.LastThread
            Ending.BrokenPipe
        ]

    /// What an `Ending` came to.
    [<RequireQualifiedAccess>]
    type private Ended =
        /// The process ended as `termination` says, and `kernel` is the system
        /// without it.
        | Ended of termination : ProcessTermination * kernel : UnixSystem<int, string>
        /// The process's end was refused, as `ProcessEndRefusal.describe` says.
        | EndRefused of reason : string
        /// A call on the way did not end the process: what it answered, and
        /// the system it left.
        | Carried of answer : string * kernel : UnixSystem<int, string>
        /// A call on the way was refused, as this says.
        | Refused of reason : string
        /// The process cannot take the ending: why.
        | Inapplicable of reason : string


    /// `fate`, a call's answer, as an `Ended`; or, if the process carries on
    /// and `next` says nothing of the outcome, `onwards` of the system it
    /// left.
    let private fateThen<'Outcome>
        (fate : ProcessFate<'Outcome, int, string>)
        (next : 'Outcome -> UnixSystem<int, string> -> Ended option)
        (onwards : UnixSystem<int, string> -> Ended)
        : Ended
        =
        match fate with
        | ProcessFate.ProcessEnded (ended, kernel) -> Ended.Ended (EndedProcess.termination ended, kernel)
        | ProcessFate.Continues (outcome, kernel) ->
            match next outcome kernel with
            | Some ended -> ended
            | None -> onwards kernel

    /// `fate`, a call's answer that ends the path whatever it is.
    let private fateOnly<'Outcome> (call : string) (fate : ProcessFate<'Outcome, int, string>) : Ended =
        fateThen
            fate
            (fun outcome kernel -> Some (Ended.Carried ($"%s{call}: %A{outcome}", kernel)))
            (fun _ -> failwith "unreachable")

    /// How the process `pid` of `machine` ends by `ending`, made by its
    /// lowest-named thread parked in nothing.
    let private endBy (ending : Ending) (pid : ProcessId) (machine : UnixSystem<int, string>) : Ended =
        let threads = Proc.threads pid machine

        let running =
            threads
            |> Map.filter (fun _ state -> (UnixThreadState.parkedIn state).IsNone)
            |> Map.keys
            |> List.ofSeq

        match running with
        | [] -> Ended.Inapplicable "no thread is running"
        | thread :: _ ->

        let caller = Caller.make pid thread
        let platform = UnixSystem.platform machine
        let numbering = SimulatedUnixPlatform.signalNumbering platform
        let signo (signal : Signal) : int = Signal.toRawSignoUnder numbering signal

        // The return to user mode of `caller`, which goes on to `onwards`
        // unless it ends the process or takes something else.
        let returning (onwards : UnixSystem<int, string> -> Ended) (kernel : UnixSystem<int, string>) : Ended =
            match UnixSignal.tryOnReturnToUser caller kernel with
            | Error (ReturnToUserRefusal.ProcessEnd refusal) -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
            | Error refusal -> Ended.Refused $"onReturnToUser: %A{refusal}"
            | Ok fate ->
                fateThen
                    fate
                    (fun outcome kernel ->
                        match outcome with
                        | ReturnToUserOutcome.Resumes None -> None
                        | other -> Some (Ended.Carried ($"onReturnToUser: %A{other}", kernel))
                    )
                    onwards

        // `pthread_sigmask(2)` of SIGTERM alone, and the return from it.
        let mask (block : bool) (onwards : UnixSystem<int, string> -> Ended) (kernel : UnixSystem<int, string>) =
            let how =
                if block then
                    MaskHow.block numbering
                else
                    MaskHow.unblock numbering

            let set = SignalMask.ofSignals numbering (Set.singleton Signal.SIGTERM)

            match UnixSignal.pthreadSigmask caller how (Some set) kernel with
            | Error errno -> Ended.Refused $"pthread_sigmask: %O{errno}"
            | Ok (_, kernel) -> returning onwards kernel

        match ending with
        | Ending.ExitGroup ->
            match UnixThreadLifecycle.tryExitGroup caller 7 machine with
            | Ok (ended, kernel) -> Ended.Ended (EndedProcess.termination ended, kernel)
            | Error refusal -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
        | Ending.Kill signal ->
            match UnixSignal.tryKill caller (ProcessId.toInt32 pid) (signo signal) machine with
            | Error (KillRefusal.ProcessEnd refusal) -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
            | Error refusal -> Ended.Refused $"kill: %A{refusal}"
            | Ok (Error errno) -> Ended.Refused $"kill: %O{errno}"
            | Ok (Ok fate) -> fateOnly "kill" fate
        | Ending.Raise ->
            match UnixSignal.tryPthreadKill caller thread (signo Signal.SIGTERM) machine with
            | Error (ThreadKillRefusal.ProcessEnd refusal) -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
            | Error refusal -> Ended.Refused $"pthread_kill: %A{refusal}"
            | Ok (Error errno) -> Ended.Refused $"pthread_kill: %O{errno}"
            | Ok (Ok fate) -> fateOnly "pthread_kill" fate
        | Ending.ReturnToUser ->
            machine
            |> mask
                true
                (fun kernel ->
                    match UnixSignal.tryPthreadKill caller thread (signo Signal.SIGTERM) kernel with
                    | Error (ThreadKillRefusal.ProcessEnd refusal) ->
                        Ended.EndRefused (ProcessEndRefusal.describe refusal)
                    | Error refusal -> Ended.Refused $"pthread_kill: %A{refusal}"
                    | Ok (Error errno) -> Ended.Refused $"pthread_kill: %O{errno}"
                    | Ok (Ok fate) ->
                        fateThen
                            fate
                            (fun outcome kernel ->
                                match outcome with
                                | KillOutcome.ProcessRuns -> None
                                | other -> Some (Ended.Carried ($"pthread_kill: %A{other}", kernel))
                            )
                            (returning (mask false (fun kernel -> Ended.Carried ("unblocked", kernel))))
                )
        | Ending.LastThread ->
            let leader = Proc.leader pid machine

            if running.Length <> threads.Count then
                Ended.Inapplicable "a thread is parked"
            else

            let exit (thread : int) (onwards : UnixSystem<int, string> -> Ended) (kernel : UnixSystem<int, string>) =
                match UnixThreadLifecycle.tryExitThread (Caller.make pid thread) 0 kernel with
                | Error (ThreadExitRefusal.ProcessEnd refusal) -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
                | Error refusal -> Ended.Refused $"exitThread %d{thread}: %A{refusal}"
                | Ok fate -> fateThen fate (fun () _ -> None) onwards

            let last =
                exit leader (fun kernel -> Ended.Carried ("the leader's exit left the process", kernel))

            List.foldBack exit (running |> List.filter ((<>) leader)) last machine
        | Ending.BrokenPipe ->
            match UnixPipe.tryPipe2 caller 0 UserBuffer.Mapped machine with
            | Error refusal -> Ended.Refused $"pipe2: %A{refusal}"
            | Ok (Pipe2Answer.Failed errno, _) -> Ended.Inapplicable $"pipe2: %O{errno}"
            | Ok (Pipe2Answer.Created (readFd, writeFd), kernel) ->

            match UnixDescriptor.tryClose caller readFd kernel with
            | Ok (SyscallAnswer.Completed 0L, kernel) ->
                match UnixReadWrite.tryWrite caller writeFd UserBuffer.Mapped 1UL kernel with
                | Error (WriteRefusal.ProcessEnd (_, refusal)) -> Ended.EndRefused (ProcessEndRefusal.describe refusal)
                | Error refusal -> Ended.Refused $"write: %A{refusal}"
                | Ok (CallProgress.Answered fate) -> fateOnly "write" fate
                | Ok (CallProgress.NeedsCopyIn paused) ->
                    match UnixReadWrite.tryWriteWithBytes (ImmutableArray.Create 0uy) paused with
                    | Error (WriteRefusal.ProcessEnd (_, refusal)) ->
                        Ended.EndRefused (ProcessEndRefusal.describe refusal)
                    | Error refusal -> Ended.Refused $"write: %A{refusal}"
                    | Ok fate -> fateOnly "write" fate
            | other -> Ended.Refused $"close: %A{other}"

    /// What `kernel` shows of itself, without saying how the library holds it:
    /// its processes, each one's descriptors with the description each names
    /// and the kind of thing that is, its threads with the kind of call each
    /// is parked in and whether that call could go on, and what a `poll` of
    /// each descriptor by a thread parked in nothing answers at once; every
    /// open file description with how many descriptors name it and how many
    /// calls hold it; and what the launched pipes have delivered.
    let private observed (log : string -> unit) (kernel : UnixSystem<int, string>) : unit =
        Machines.checkInvariants kernel |> Expect.empty (fun () -> "the system")
        let pids = UnixSystem.processIds kernel |> List.ofSeq
        log $"    processes %A{pids |> List.map ProcessId.toInt32}"

        for pid in pids do
            let registry = Proc.fileDescriptors pid kernel
            let threads = Proc.threads pid kernel

            let descriptors =
                FileDescriptorRegistry.fds registry
                |> Map.toList
                |> List.map (fun (fd, id) ->
                    let target =
                        match FileDescriptorRegistry.tryFindTarget fd registry with
                        | Some target -> UnionCaseName.ofValue target
                        | None -> "nothing"

                    $"%d{fd}=%O{id}:%s{target}"
                )
                |> String.concat " "

            log $"    %d{ProcessId.toInt32 pid}: %s{descriptors}"

            for KeyValue (thread, state) in threads do
                match UnixThreadState.parkedIn state with
                | None -> log $"      thread %d{thread} running"
                | Some parked ->
                    let satisfied = UnixWait.satisfied (Caller.make pid thread) kernel
                    log $"      thread %d{thread} %s{UnionCaseName.ofValue parked}, satisfied %A{satisfied}"

            let poller =
                threads
                |> Map.tryFindKey (fun _ state -> (UnixThreadState.parkedIn state).IsNone)

            match poller with
            | None -> ()
            | Some thread ->
                for fd in FileDescriptorRegistry.fds registry |> Map.keys do
                    let entry : PollEntry =
                        {
                            Fd = fd
                            Events = 0x0001s ||| 0x0004s
                        }

                    match UnixPoll.tryPoll (Caller.make pid thread) [ entry ] 0 kernel with
                    | Ok (outcome, _) -> log $"      poll %d{fd}: %A{outcome}"
                    | Error refusal -> log $"      poll %d{fd}: refused %s{UnionCaseName.ofValue refusal}"

        let openFiles = UnixSystem.openFiles kernel

        for KeyValue (id, description) in OpenFileTable.descriptions openFiles do
            log
                $"    %O{id} %s{UnionCaseName.ofValue description.Target}: %A{OpenFileTable.descriptorCount id openFiles} descriptors, %A{OpenFileTable.holdCount id openFiles} holds"

        let delivered = DeliveryLog.toList (UnixSystem.delivered kernel)

        let sum =
            (17, delivered)
            ||> List.fold (fun sum delivery ->
                Seq.fold (fun (sum : int) (b : byte) -> sum * 31 + int b) sum delivery.Bytes
            )

        log $"    delivered %d{delivered.Length}, checksum %d{sum}"

    /// How many cases of the fixed sample the process-end oracle replays.
    let private endingCases : int = 1500

    /// The embedded reference the process-end oracle holds the library to.
    let private endingResource : string =
        "WoofWare.PosixKernel.Test.multiProcessOracle.endings.txt"

    /// What each `Ending` came to in each process still on the machine at the
    /// end of `case`, and what the system it left shows (`observed`).
    let private endingsTranscriptOf (case : Case) : string =
        let builder = System.Text.StringBuilder ()
        let log (line : string) : unit = builder.AppendLine line |> ignore
        log $"%A{case.Platform} %d{case.Processes} %b{case.Prepared}"
        let last = ref None
        runObserving smallBuffers (fun _ world -> last.Value <- Some world) ignore ignore case

        match last.Value with
        | None -> log "  no steps"
        | Some (world : World) ->
            for pid in world.Live do
                let mutable exited = None

                for ending in endings do
                    log $"  %d{ProcessId.toInt32 pid} %A{ending}"

                    match endBy ending pid world.Machine with
                    | Ended.Ended (termination, kernel) ->
                        log $"    ends %A{termination}"
                        observed log kernel

                        // An ending that changes nothing outside the process before it
                        // ends it leaves the very system `exit_group` leaves.
                        match ending, exited with
                        | Ending.ExitGroup, _ -> exited <- Some kernel
                        | Ending.BrokenPipe, _ -> ()
                        | _, Some exited ->
                            kernel
                            |> Expect.equal (fun () -> $"%A{ending} of %O{pid}, against exit_group") exited
                        | _, None -> ()
                    | Ended.EndRefused reason -> log $"    end refused: %s{reason}"
                    | Ended.Carried (answer, kernel) ->
                        log $"    carries on: %s{answer}"
                        observed log kernel
                    | Ended.Refused reason -> log $"    refused: %s{reason}"
                    | Ended.Inapplicable reason -> log $"    inapplicable: %s{reason}"

        builder.ToString ()

    /// The process-end oracle's transcript of each case it replays, in the
    /// order they are drawn.
    let private endingsTranscripts () : string list =
        let transcripts = ResizeArray<string> ()

        CoverageSample.replay endingCases (Arb.fromGen caseGen) (fun case -> transcripts.Add (endingsTranscriptOf case))

        List.ofSeq transcripts

    /// Each case's index and the hash of its transcript, as the process-end
    /// oracle's reference records them.
    let private recordedEndings () : Map<int, string> =
        let assembly = System.Reflection.Assembly.GetExecutingAssembly ()

        use stream =
            match assembly.GetManifestResourceStream endingResource with
            | null -> failwith $"embedded resource %s{endingResource} not found"
            | stream -> stream

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.filter (fun line -> line <> "" && not (line.StartsWith '#'))
        |> Array.map (fun line ->
            match line.Split '\t' with
            | [| index ; hash |] -> int index, hash
            | _ -> failwith $"not a line of the process-end oracle's reference: %s{line}"
        )
        |> Map.ofArray

    /// The oracle for how a process ends: in the world each case of the fixed
    /// sample leaves, each process still on the machine ends by every `Ending`,
    /// and what each came to, and what the system it left shows, is exactly
    /// what the reference records. Besides, each ending that changes nothing
    /// outside the process before it ends it, every one but the broken pipe's,
    /// leaves the very system `exit_group` leaves. A difference names the cases whose
    /// transcripts moved; set `POSIXKERNEL_ORACLE_DUMP` to a directory and run
    /// `Update process-end oracle` on the commit that recorded the reference
    /// and on this one to compare them line by line.
    [<Test>]
    let ``every way a process ends, from the fixed sample's worlds, answers what the recorded reference says``
        ()
        : unit
        =
        let recorded = recordedEndings ()
        recorded.Count |> shouldEqual endingCases

        let moved =
            endingsTranscripts ()
            |> List.mapi (fun index transcript -> index, sha256 transcript)
            |> List.filter (fun (index, hash) -> Map.tryFind index recorded <> Some hash)
            |> List.map fst

        moved |> shouldEqual []

    /// Rewrites the process-end oracle's reference from the library as built,
    /// and, if `POSIXKERNEL_ORACLE_DUMP` names a directory, writes each case's
    /// transcript there as `ending-<index>.txt`.
    [<Test ; Explicit>]
    let ``Update process-end oracle`` () : unit =
        let transcripts = endingsTranscripts ()

        match System.Environment.GetEnvironmentVariable "POSIXKERNEL_ORACLE_DUMP" with
        | null
        | "" -> ()
        | directory ->
            System.IO.Directory.CreateDirectory directory |> ignore

            transcripts
            |> List.iteri (fun index transcript ->
                System.IO.File.WriteAllText (System.IO.Path.Combine (directory, $"ending-%d{index}.txt"), transcript)
            )

        let lines =
            [
                "# TestMultiProcessFuzz's process-end oracle: the SHA-256 of the transcript (endingsTranscriptOf) of"
                "# each case of caseGen's fixed sample (CoverageSample's seed, the first 1500 cases), as the library"
                "# answered them when this file was written. index<TAB>hash"
            ]
            @ (transcripts
               |> List.mapi (fun index transcript -> $"%d{index}\t%s{sha256 transcript}"))

        System.IO.File.WriteAllText (
            System.IO.Path.Combine (__SOURCE_DIRECTORY__, "multiProcessOracle", "endings.txt"),
            String.concat "\n" lines + "\n"
        )
