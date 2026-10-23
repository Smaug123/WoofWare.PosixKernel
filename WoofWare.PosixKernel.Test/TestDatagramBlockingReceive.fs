namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.Text
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Blocking receives on a UDP socket, held to a reference model of each
/// flavour's measured rules (`udp-sleepers.c`, plan section 2.16, which
/// `TestDatagramSleepersProbe` replays row by row): under Linux each datagram
/// and the ICMP error chooses the receive asleep that parked first, and no
/// other wakes; under Darwin every receive with something to take wakes, and
/// a close a receive slept through drains the socket.
///
/// The property makes random interleavings of receives parking, datagrams
/// and errors arriving, signals, wakes, finishes in any order, the leader's
/// own non-blocking receives and closes, under both flavours, and after each
/// asks the reference what the library must answer.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramBlockingReceive =

    type private World = UnixSystem<int, string>

    let private leader : int = 0

    // ------------------------------------------------------------ the reference

    /// What a sleeper's call is.
    [<RequireQualifiedAccess>]
    type private Kind =
        | Take
        | Peek
        | TakeFrom
        | PeekFrom

    let private peeks (kind : Kind) : bool =
        match kind with
        | Kind.Peek
        | Kind.PeekFrom -> true
        | Kind.Take
        | Kind.TakeFrom -> false

    [<RequireQualifiedAccess>]
    type private Standing =
        | Asleep
        | Woken

    type private Sleeper =
        {
            Kind : Kind
            /// Whether it sleeps through the dup.
            ThroughDup : bool
            Standing : Standing
            Ordinal : int
            /// Under Linux, whether an arrival has chosen it.
            Chosen : bool
            /// Whether SIGUSR1 is pending to it.
            Signalled : bool
            /// Under Darwin, whether a close has ended it.
            Ended : bool
        }

    /// What the reference says a thread's call answers: a datagram's text, an
    /// error, or that it sleeps (again).
    [<RequireQualifiedAccess>]
    type private Answer =
        | Datagram of text : string
        | Error of error : UnixError
        | Sleeps

    type private Reference =
        {
            Linux : bool
            Queue : string list
            Error : bool
            Sleepers : Map<int, Sleeper>
            NextOrdinal : int
            Drained : bool
        }

    /// What a receive of `kind` takes of the socket now, if anything.
    let private take (kind : Kind) (reference : Reference) : (Answer * Reference) option =
        let datagram () =
            match reference.Queue with
            | next :: rest ->
                Some (
                    Answer.Datagram next,
                    if peeks kind then
                        reference
                    else
                        { reference with
                            Queue = rest
                        }
                )
            | [] -> None

        let error () =
            if reference.Error then
                // Linux's peek takes the error too; Darwin's leaves it.
                let leaves = peeks kind && not reference.Linux

                Some (
                    Answer.Error UnixError.ECONNREFUSED,
                    { reference with
                        Error = leaves && reference.Error
                    }
                )
            else
                None

        if reference.Linux then
            match error () with
            | Some taken -> Some taken
            | None -> datagram ()
        else
            match datagram () with
            | Some taken -> Some taken
            | None -> error ()

    let private withSleeper (thread : int) (sleeper : Sleeper option) (reference : Reference) : Reference =
        { reference with
            Sleepers =
                match sleeper with
                | Some sleeper -> Map.add thread sleeper reference.Sleepers
                | None -> Map.remove thread reference.Sleepers
        }

    /// The reference with the Linux receive asleep that parked first, of those
    /// no arrival has chosen, chosen.
    let private choose (reference : Reference) : Reference =
        if not reference.Linux then
            reference
        else

        reference.Sleepers
        |> Map.toList
        |> List.filter (fun (_, sleeper) -> sleeper.Standing = Standing.Asleep && not sleeper.Chosen)
        |> List.sortBy (fun (_, sleeper) -> sleeper.Ordinal)
        |> List.tryHead
        |> function
            | None -> reference
            | Some (thread, sleeper) ->
                withSleeper
                    thread
                    (Some
                        { sleeper with
                            Chosen = true
                        })
                    reference

    /// A receive of `kind` by `thread`, made now.
    let private parkRef (thread : int) (kind : Kind) (throughDup : bool) (reference : Reference) : Answer * Reference =
        match take kind reference with
        | Some taken -> taken
        | None when reference.Drained -> Answer.Error UnixError.EBADF, reference
        | None ->
            Answer.Sleeps,
            { reference with
                NextOrdinal = reference.NextOrdinal + 1
            }
            |> withSleeper
                thread
                (Some
                    {
                        Kind = kind
                        ThroughDup = throughDup
                        Standing = Standing.Asleep
                        Ordinal = reference.NextOrdinal
                        Chosen = false
                        Signalled = false
                        Ended = false
                    })

    /// Which sleepers a wake wakes now.
    let private wokenRef (reference : Reference) : Set<int> =
        reference.Sleepers
        |> Map.filter (fun _ sleeper ->
            sleeper.Standing = Standing.Asleep
            && (sleeper.Signalled
                || sleeper.Ended
                || (if reference.Linux then
                        sleeper.Chosen
                    else
                        not reference.Queue.IsEmpty || reference.Error))
        )
        |> Map.keys
        |> Set.ofSeq

    let private wakeRef (reference : Reference) : Reference =
        (reference, wokenRef reference)
        ||> Set.fold (fun reference thread ->
            withSleeper
                thread
                (Some
                    { reference.Sleepers.[thread] with
                        Standing = Standing.Woken
                    })
                reference
        )

    /// The woken `thread`'s call, finished.
    let private finishRef (thread : int) (reference : Reference) : Answer * Reference =
        let sleeper = reference.Sleepers.[thread]
        let gone = withSleeper thread None reference

        let interrupted () = Answer.Error UnixError.EINTR, gone

        if sleeper.Ended then
            Answer.Error UnixError.EBADF, gone
        // Under Darwin a signal beats what there is to take; under Linux what
        // there is to take beats a signal.
        elif sleeper.Signalled && not reference.Linux then
            interrupted ()
        else

        match take sleeper.Kind gone with
        | Some taken -> taken
        | None when sleeper.Signalled -> interrupted ()
        | None ->
            Answer.Sleeps,
            { reference with
                NextOrdinal = reference.NextOrdinal + 1
            }
            |> withSleeper
                thread
                (Some
                    { sleeper with
                        Standing = Standing.Asleep
                        Ordinal = reference.NextOrdinal
                        Chosen = false
                    })

    // ------------------------------------------------------------ the library

    [<RequireQualifiedAccess>]
    type private Op =
        | Park of thread : int * kind : Kind * throughDup : bool
        | Arrive
        | RaiseError
        | Signal of thread : int
        | Wake
        | Finish of thread : int
        | LeaderTake
        | Close of dup : bool

    type private Run =
        {
            System : World
            Reference : Reference
            R : int option
            D : int option
            Socket : SocketId
            Port : uint16
            Peer : uint16
            Sent : int
            /// Each step's label, for coverage.
            Labels : string list
        }

    let private returned (thread : int) (system : World) : World =
        ReturnsToUser.untilResumed (Callers.thread thread system) system

    let private stepAs (thread : int) (call : Syscall<int, string>) (system : World) : SteppedCall<int, string> =
        match UnixSystem.tryStep (Callers.thread thread system) call system with
        | Ok stepped -> stepped
        | Error refusal -> failwith $"thread %d{thread}'s %A{call} was refused: %s{SyscallRefusal.describe refusal}"

    let private inet (system : World) (port : uint16) : CopiedArgument<ImmutableArray<byte>> =
        CopiedArgument.Readable (
            ImmutableArray.Create<byte> (
                CopyIn.blob
                    (UnixSystem.platform system)
                    SimulatedUnixPlatform.internetAddressFamily
                    (Ipv4Endpoint.ofParts Ipv4Address.loopback port)
            )
        )

    let private udp (system : World) : int * World =
        match stepAs leader (Syscall.Socket (SimulatedUnixPlatform.internetAddressFamily, 2, 0)) system with
        | SteppedCall.Socket (DescriptorAnswer.Returned fd, system) -> fd, returned leader system
        | other -> failwith $"socket: %A{other}"

    let private bindAt (fd : int) (port : uint16) (system : World) : World =
        match stepAs leader (Syscall.Bind (fd, inet system port, 16u)) system with
        | SteppedCall.Bind (BindAnswer.Bound _, system) -> returned leader system
        | other -> failwith $"bind: %A{other}"

    let private portOf (fd : int) (system : World) : uint16 =
        match stepAs leader (Syscall.GetSockName (fd, UserBuffer.Mapped, 16u)) system with
        | SteppedCall.GetSockName (GetSockNameAnswer.Reported (copied, _)) -> (CopyOut.endpoint copied).Port
        | other -> failwith $"getsockname: %A{other}"

    let private closeAs (fd : int) (system : World) : Result<World, string> =
        match UnixSystem.tryStep (Callers.thread leader system) (Syscall.Close fd) system with
        | Ok (SteppedCall.Close (SyscallAnswer.Completed 0L, system)) -> Ok (returned leader system)
        | Ok other -> failwith $"close: %A{other}"
        | Error refusal -> Error (SyscallRefusal.describe refusal)

    let private socketOf (fd : int) (system : World) : SocketId =
        match FileDescriptorRegistry.tryFindId fd (Lone.fileDescriptors system) with
        | Some id ->
            match OpenFileTable.tryFind id (UnixSystem.openFiles system) with
            | Some description ->
                match description.Target with
                | OpenFileTarget.Socket socket -> socket
                | target -> failwith $"fd %d{fd} names %A{target}"
            | None -> failwith $"fd %d{fd}'s description is gone"
        | None -> failwith $"fd %d{fd} is not open"

    let private errorPending (run : Run) : bool =
        DatagramReceiver.errorPending (UnixMachineState.datagramReceiver run.Socket (Kernel.machine run.System))

    let private usr1 (system : World) : int =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    let private boot (flavour : SimulatedUnixFlavour) : Run =
        let system =
            UnixSystem.initial<int, string> (HostPlatform.platformOf flavour)
            |> Launched.boot UnixSystem.pipedStandardStreams leader (CpuId 0)

        let system =
            match
                stepAs
                    leader
                    (Syscall.SigAction (usr1 system, Some (SignalDisposition.Catch (SignalCatch.ofHandler "h"))))
                    system
            with
            | SteppedCall.SigAction (SigactionAnswer.Completed _, system) -> returned leader system
            | other -> failwith $"sigaction: %A{other}"

        // The receiving socket, connected to a port nobody holds, so that a
        // send through it raises the ICMP error, and a datagram from a socket
        // bound to that port, made and closed for each, reaches it.
        let r, system = udp system
        let system = bindAt r 0us system
        let unheld, system = udp system
        let system = bindAt unheld 0us system
        let peer = portOf unheld system

        let system =
            match closeAs unheld system with
            | Ok system -> system
            | Error refusal -> failwith refusal

        let system =
            match stepAs leader (Syscall.Connect (r, inet system peer, 16u)) system with
            | SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) ->
                returned leader system
            | other -> failwith $"connect: %A{other}"

        let d, system =
            match stepAs leader (Syscall.Dup r) system with
            | SteppedCall.Dup (DescriptorAnswer.Returned fd, system) -> fd, returned leader system
            | other -> failwith $"dup: %A{other}"

        let system = system |> Threads.ensure 1 |> Threads.ensure 2 |> Threads.ensure 3

        {
            System = system
            Reference =
                {
                    Linux = (flavour = SimulatedUnixFlavour.Linux)
                    Queue = []
                    Error = false
                    Sleepers = Map.empty
                    NextOrdinal = 0
                    Drained = false
                }
            R = Some r
            D = Some d
            Socket = socketOf r system
            Port = portOf r system
            Peer = peer
            Sent = 0
            Labels = []
        }

    let private callOf (system : World) (kind : Kind) (fd : int) : Syscall<int, string> =
        let peek =
            MessageFlag.number (SimulatedUnixPlatform.flavour (UnixSystem.platform system)) MessageFlag.Peek
            |> Option.get

        match kind with
        | Kind.Take -> Syscall.Recv (fd, UserBuffer.Mapped, 16UL, 0)
        | Kind.Peek -> Syscall.Recv (fd, UserBuffer.Mapped, 16UL, peek)
        | Kind.TakeFrom ->
            Syscall.RecvFrom (fd, UserBuffer.Mapped, 16UL, 0, UserBuffer.Mapped, CopiedArgument.Readable 16u)
        | Kind.PeekFrom ->
            Syscall.RecvFrom (fd, UserBuffer.Mapped, 16UL, peek, UserBuffer.Mapped, CopiedArgument.Readable 16u)

    let private readAnswer (answer : ReadAnswer) : Answer =
        match answer with
        | ReadAnswer.Completed bytes -> Answer.Datagram (Encoding.ASCII.GetString (bytes.AsSpan ()))
        | ReadAnswer.Failed error -> Answer.Error error
        | ReadAnswer.Drawn _ -> failwith "a socket read drew entropy"

    let private recvFromAnswer (answer : RecvFromAnswer) : Answer =
        match answer with
        | RecvFromAnswer.Received (bytes, _, _) -> Answer.Datagram (Encoding.ASCII.GetString (bytes.AsSpan ()))
        | RecvFromAnswer.Failed error
        | RecvFromAnswer.FailedAfterReceiving (error, _, _) -> Answer.Error error

    /// What thread `thread`'s call answered, by `answer`, read from
    /// `interrupted` and `outcome`, and the system with the thread back in
    /// user mode if it returned.
    let private settled (thread : int) (outcome : Choice<Answer, unit, unit>) (system : World) : Answer * World =
        match outcome with
        | Choice1Of3 answer -> answer, returned thread system
        | Choice2Of3 () -> Answer.Sleeps, system
        | Choice3Of3 () ->
            match Interruptions.handled (Callers.thread thread system) system with
            | Ok (InterruptedCall.FailsWithEintr, system) -> Answer.Error UnixError.EINTR, system
            | other -> failwith $"thread %d{thread}'s interrupted call ended %A{other}"

    let private ofRead (outcome : ReadOutcome) : Choice<Answer, unit, unit> =
        match outcome with
        | ReadOutcome.Answered answer -> Choice1Of3 (readAnswer answer)
        | ReadOutcome.WouldBlock _ -> Choice2Of3 ()
        | ReadOutcome.Interrupted -> Choice3Of3 ()

    let private ofRecvFrom (outcome : RecvFromOutcome) : Choice<Answer, unit, unit> =
        match outcome with
        | RecvFromOutcome.Answered answer -> Choice1Of3 (recvFromAnswer answer)
        | RecvFromOutcome.WouldBlock _ -> Choice2Of3 ()
        | RecvFromOutcome.Interrupted -> Choice3Of3 ()

    /// The threads the library has asleep or woken in a datagram receive.
    let private parkedIn (system : World) : Map<int, ParkState> =
        Lone.threadMap system
        |> Map.toList
        |> List.choose (fun (thread, state) ->
            match UnixThreadState.park state with
            | Some ({
                        Syscall = ParkedSyscall.DatagramReceive _
                    } as park) -> Some (thread, park.State)
            | _ -> None
        )
        |> Map.ofList

    let private label (text : string) (run : Run) : Run =
        { run with
            Labels = text :: run.Labels
        }

    let private answerLabel (answer : Answer) : string =
        match answer with
        | Answer.Datagram _ -> "datagram"
        | Answer.Error error -> $"%O{error}"
        | Answer.Sleeps -> "sleeps"

    /// `run` after `op`, failing the test where the library and the reference
    /// part. An op that cannot be made now is skipped.
    let private apply (op : Op) (run : Run) : Run =
        let system = run.System
        let reference = run.Reference

        let agree (what : string) (library : Answer) (expected : Answer) =
            if library <> expected then
                failwith $"%s{what}: the library answered %A{library}, the reference %A{expected}"

        match op with
        | Op.Park (thread, kind, throughDup) ->
            let fd = if throughDup then run.D else run.R

            match fd with
            | None -> run
            | Some _ when reference.Sleepers.ContainsKey thread -> run
            | Some fd ->
                let expected, reference = parkRef thread kind throughDup reference

                let library, system =
                    match stepAs thread (callOf system kind fd) system with
                    | SteppedCall.Recv (outcome, system) -> settled thread (ofRead outcome) system
                    | SteppedCall.RecvFrom (outcome, system) -> settled thread (ofRecvFrom outcome) system
                    | other -> failwith $"the receive answered %A{other}"

                agree $"thread %d{thread}'s %A{kind}" library expected

                { run with
                    System = system
                    Reference = reference
                }
                |> label $"park %s{answerLabel library}"
        | Op.Arrive ->
            let text = $"d%d{run.Sent}"
            let sender, system = udp system
            let system = bindAt sender run.Peer system
            let bytes = ImmutableArray.Create<byte> (Encoding.ASCII.GetBytes text)

            let system =
                match
                    stepAs
                        leader
                        (Syscall.SendTo (
                            sender,
                            CopiedArgument.Readable bytes,
                            uint64 bytes.Length,
                            0,
                            inet system run.Port,
                            16u
                        ))
                        system
                with
                | SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed _), system)) ->
                    returned leader system
                | other -> failwith $"sendto: %A{other}"

            let system =
                match closeAs sender system with
                | Ok system -> system
                | Error refusal -> failwith refusal

            { run with
                System = system
                Sent = run.Sent + 1
                Reference =
                    choose
                        { reference with
                            Queue = reference.Queue @ [ text ]
                        }
            }
            |> label "arrive"
        | Op.RaiseError ->
            match run.R, run.D with
            | Some fd, _
            | None, Some fd ->
                let before = errorPending run

                let system =
                    match
                        stepAs
                            leader
                            (Syscall.Send (fd, CopiedArgument.Readable (ImmutableArray.Create 'x'B), 1UL, 0))
                            system
                    with
                    | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns _, system)) ->
                        returned leader system
                    | other -> failwith $"send: %A{other}"

                let raised =
                    { run with
                        System = system
                    }

                // Whether the send raised the error is the ICMP rules' (U1c),
                // not this test's: the reference takes it from the library.
                if errorPending raised && not before then
                    { raised with
                        Reference =
                            choose
                                { reference with
                                    Error = true
                                }
                    }
                    |> label "error raised"
                else
                    { raised with
                        Reference =
                            { reference with
                                Error = errorPending raised
                            }
                    }
                    |> label "error not raised"
            | None, None -> run
        | Op.Signal thread ->
            match reference.Sleepers.TryFind thread with
            | None -> run
            | Some sleeper ->
                let system =
                    match stepAs leader (Syscall.PthreadKill (thread, usr1 system)) system with
                    | SteppedCall.PthreadKill (ProcessFate.Continues (KillAnswer.Completed _, system)) ->
                        returned leader system
                    | other -> failwith $"pthread_kill: %A{other}"

                { run with
                    System = system
                    Reference =
                        withSleeper
                            thread
                            (Some
                                { sleeper with
                                    Signalled = true
                                })
                            reference
                }
                |> label "signal"
        | Op.Wake ->
            let expected = wokenRef reference
            let woken, system = UnixWait.wake system

            let library =
                woken |> List.map (fun (caller, _) -> Caller.thread caller) |> Set.ofList

            if library <> expected then
                failwith $"a wake woke %A{library}, where the reference wakes %A{expected}"

            { run with
                System = system
                Reference = wakeRef reference
            }
            |> label $"wake %d{library.Count}"
        | Op.Finish thread ->
            match reference.Sleepers.TryFind thread, Map.tryFind thread (parkedIn system) with
            | Some {
                       Standing = Standing.Woken
                   },
              Some (ParkState.Woken _) ->
                let expected, reference = finishRef thread reference

                let library, system =
                    let caller = Callers.thread thread system

                    // A length cell of real storage holds 16
                    // (`ParkedCall.ofPark`).
                    match UnixWait.finish caller (ParkedCall.ofThread caller system) system with
                    | FinishedCall.DatagramReceive (FinishedDatagramReceive.Read (outcome, system)) ->
                        settled thread (ofRead outcome) system
                    | FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (outcome, system)) ->
                        settled thread (ofRecvFrom outcome) system
                    | other -> failwith $"finishing thread %d{thread} answered %A{other}"

                agree $"finishing thread %d{thread}" library expected

                { run with
                    System = system
                    Reference = reference
                }
                |> label $"finish %s{answerLabel library}"
            | Some {
                       Standing = Standing.Asleep
                   },
              Some (ParkState.Asleep)
            | None, None -> run
            | standing, library ->
                failwith $"thread %d{thread} stands %A{standing} in the reference and %A{library} in the library"
        | Op.LeaderTake ->
            match run.R, run.D with
            | Some fd, _
            | None, Some fd ->
                let dontWait =
                    MessageFlag.number (SimulatedUnixPlatform.flavour (UnixSystem.platform system)) MessageFlag.DontWait
                    |> Option.get

                let expected, reference =
                    match take Kind.Take reference with
                    | Some taken -> taken
                    | None -> Answer.Error UnixError.EAGAIN, reference

                let library, system =
                    match stepAs leader (Syscall.Recv (fd, UserBuffer.Mapped, 16UL, dontWait)) system with
                    | SteppedCall.Recv (ReadOutcome.Answered answer, system) ->
                        readAnswer answer, returned leader system
                    | other -> failwith $"the leader's recv: %A{other}"

                agree "the leader's recv" library expected

                { run with
                    System = system
                    Reference = reference
                }
                |> label "leader take"
            | None, None -> run
        | Op.Close dup ->
            // The other descriptor stays open, so the socket does.
            match (if dup then run.D else run.R), (if dup then run.R else run.D) with
            | None, _
            | _, None -> run
            | Some fd, Some _ ->
                // Under Darwin a close a receive slept through drains the
                // socket, ending every receive on it, unless one has something
                // to answer besides the close, which it refuses.
                let live = reference.Sleepers |> Map.filter (fun _ sleeper -> not sleeper.Ended)

                let drains =
                    not reference.Linux
                    && live |> Map.exists (fun _ sleeper -> sleeper.ThroughDup = dup)

                let raced =
                    drains
                    && (not reference.Queue.IsEmpty
                        || reference.Error
                        || live |> Map.exists (fun _ sleeper -> sleeper.Signalled))

                match closeAs fd system with
                | Error refusal ->
                    if not raced then
                        failwith $"closing fd %d{fd} was refused: %s{refusal}"

                    run |> label "close refused"
                | Ok system ->
                    if raced then
                        failwith $"closing fd %d{fd} drained the socket while a receive had something to answer"

                    // A close that drains nothing, and every Linux close,
                    // leaves each receive as it was.
                    let reference =
                        if drains then
                            { reference with
                                Drained = true
                                Sleepers =
                                    reference.Sleepers
                                    |> Map.map (fun _ sleeper ->
                                        { sleeper with
                                            Ended = true
                                        }
                                    )
                            }
                        else
                            reference

                    { run with
                        System = system
                        Reference = reference
                        R = if dup then run.R else None
                        D = if dup then None else run.D
                    }
                    |> label (if drains then "close drains" else "close")

    let private opGen : Gen<Op> =
        let thread = Gen.choose (1, 3)

        let kind = Gen.elements [ Kind.Take ; Kind.Peek ; Kind.TakeFrom ; Kind.PeekFrom ]

        Gen.frequency
            [
                6,
                gen {
                    let! thread = thread
                    let! kind = kind
                    let! dup = Gen.elements [ false ; true ]
                    return Op.Park (thread, kind, dup)
                }
                2, Gen.constant Op.Arrive
                1, Gen.constant Op.RaiseError
                2, Gen.map Op.Signal thread
                6, Gen.constant Op.Wake
                8, Gen.map Op.Finish thread
                3, Gen.constant Op.LeaderTake
                1, Gen.map Op.Close (Gen.elements [ false ; true ])
            ]

    let private caseGen : Gen<SimulatedUnixFlavour * Op list> =
        gen {
            let! flavour = Gen.elements [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]
            let! length = Gen.choose (1, 40)
            let! ops = Gen.listOfLength length opGen
            return flavour, ops
        }

    [<Test>]
    let ``blocking receives wake, answer and drain as the reference model of each flavour says`` () : unit =
        let property (cover : string -> unit) ((flavour, ops) : SimulatedUnixFlavour * Op list) : unit =
            let run = (boot flavour, ops) ||> List.fold (fun run op -> apply op run)

            UnixSystem.checkInvariants run.System |> shouldEqual []

            for text in run.Labels do
                cover $"%O{flavour} %s{text}"

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 400) (Arb.fromGen caseGen) property

        let count (label : string) : int =
            coverage.Reached
            |> List.sumBy (fun (reached, count) -> if reached = label then count else 0)

        // Each floor is about a third of what the fixed sample reached when
        // this was written.
        for flavour in [ "Linux" ; "Darwin" ] do
            count $"%s{flavour} park sleeps" |> shouldBeGreaterThan 100
            count $"%s{flavour} finish datagram" |> shouldBeGreaterThan 10
            count $"%s{flavour} finish sleeps" |> shouldBeGreaterThan 4
            count $"%s{flavour} finish EINTR" |> shouldBeGreaterThan 6
            count $"%s{flavour} finish ECONNREFUSED" |> shouldBeGreaterThan 3
            count $"%s{flavour} error raised" |> shouldBeGreaterThan 35

        count "Darwin close drains" |> shouldBeGreaterThan 6
        count "Darwin finish EBADF" |> shouldBeGreaterThan 4
        count "Darwin park EBADF" |> shouldBeGreaterThan 3
