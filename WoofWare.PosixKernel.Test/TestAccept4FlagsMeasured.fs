namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Linux's `accept4(2)` flags, as `UnixConnection.accept` takes them: every row
/// of `docs/probes/accept4-flags`, measured on Linux 6.18.5 aarch64 and
/// embedded, replayed by running the probe's script against the model and
/// printing what it answers in the probe's words.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestAccept4FlagsMeasured =

    let private context : string = "TestAccept4FlagsMeasured"

    /// The probe's output, without its `uname` line.
    let private measured : string list =
        let name = "WoofWare.PosixKernel.Test.accept4Flags.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray
        |> List.tail

    let private run : FcntlWorld.Run =
        {
            Name = "linux root"
            Platform = SimulatedUnixPlatform.linuxArm64
            Caller = Owners.root
            Lines = []
        }

    [<Literal>]
    let private SockNonBlock : int = 0x800

    [<Literal>]
    let private SockCloseOnExec : int = 0x80000

    /// The probe's BAD words: an unknown bit, `INT_MIN`, and an unknown bit
    /// beside both flags.
    let private badFlags : int list =
        [ 1 ; Int32.MinValue ; SockNonBlock ||| SockCloseOnExec ||| 1 ]

    let private errorName (error : UnixError) : string =
        if error = UnixError.EBADF then "EBADF"
        elif error = UnixError.EINVAL then "EINVAL"
        elif error = UnixError.ENOTSOCK then "ENOTSOCK"
        elif error = UnixError.EOPNOTSUPP then "EOPNOTSUPP"
        elif error = UnixError.EAGAIN then "EAGAIN"
        else failwith $"%s{context}: no name for %O{error}"

    /// What the model says for a refusal where the probe printed an errno.
    let private refusedForLimit : string = "refused at the descriptor bound"

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (_, system) -> system
        | Error refusal -> failwith $"close(%d{fd}) was refused: %A{refusal}"

    /// The probe's `describe`: the answer, and for a new descriptor its flags,
    /// which it then closes.
    let private describe
        (outcome : Result<AcceptOutcome * UnixSystem<int, string>, AcceptRefusal>)
        (before : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        match outcome with
        | Error (AcceptRefusal.DescriptorLimit _) -> refusedForLimit, before
        | Error refusal -> failwith $"refused: %s{AcceptRefusal.describe refusal}"
        | Ok (AcceptOutcome.Failed error, system)
        | Ok (AcceptOutcome.DroppedConnection error, system) -> errorName error, system
        | Ok (AcceptOutcome.Accepted (fd, _), system) ->
            let nonBlocking =
                match UnixDescriptor.isNonBlocking (Callers.leader system) fd system with
                | Some true -> 1
                | Some false -> 0
                | None -> failwith $"the accepted descriptor %d{fd} is not open"

            let closeOnExec =
                match FcntlWorld.descriptorFlags fd system with
                | "ok 0x1" -> 1
                | "ok 0x0" -> 0
                | other -> failwith $"F_GETFD of %d{fd}: %s{other}"

            $"ok nonblock=%d{nonBlocking} cloexec=%d{closeOnExec}", close fd system
        | Ok (other, _) -> failwith $"unexpected %A{other}"

    /// `accept4(fd, NULL, NULL, flags)` by the leader.
    let private accept4 (fd : int) (flags : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        describe
            (UnixConnection.tryAccept (Callers.leader system) fd (UserBuffer.Unmapped 0UL) None flags system)
            system

    /// `accept4` with a mapped peer buffer and a length cell holding -1.
    let private accept4NegativeLength
        (fd : int)
        (flags : int)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        describe
            (UnixConnection.tryAccept (Callers.leader system) fd UserBuffer.Mapped (Some 0xFFFFFFFFu) flags system)
            system

    let private setNonBlocking (fd : int) (value : bool) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixDescriptor.setNonBlocking (Callers.leader system) fd value system |> snd

    /// The probe's `still_queued`: an accept through the listener made
    /// non-blocking for the call.
    let private stillQueued (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let was =
            UnixDescriptor.isNonBlocking (Callers.leader system) fd system
            |> Option.defaultWith (fun () -> failwith $"listener %d{fd} is not open")

        let answer, system = accept4 fd 0 (setNonBlocking fd true system)
        let system = setNonBlocking fd was system

        match answer with
        | "EAGAIN" -> "gone", system
        | answer when answer.StartsWith "ok" -> "still queued", system
        | answer -> answer, system

    /// A listener at `port` with one connection queued, and the client.
    let private queuedListener (port : uint16) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let listener, system = FcntlWorld.listener port false system

        let client, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        listener, FcntlWorld.connect client port system

    let private sectionA (system : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
        let file, system =
            FcntlWorld.openWith (FcntlWorld.opening FileAccessMode.ReadOnly) "f" system

        let datagram, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Default system

        let idle, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Default system

        let empty, system = FcntlWorld.listener 6000us true system
        let mutable system = system
        let mutable port = 6001us

        let row (format : string) (call : UnixSystem<int, string> -> string * UnixSystem<int, string>) : string =
            let answer, after = call system
            system <- after
            format + answer

        let lines =
            [
                for flags in badFlags do
                    let label = $"A flags 0x%08x{uint32 flags}"
                    yield row $"%s{label} closed fd     -> " (accept4 500 flags)
                    yield row $"%s{label} fd -1         -> " (accept4 -1 flags)
                    yield row $"%s{label} regular file  -> " (accept4 file flags)
                    yield row $"%s{label} datagram      -> " (accept4 datagram flags)
                    yield row $"%s{label} idle stream   -> " (accept4 idle flags)
                    yield row $"%s{label} empty nb lis. -> " (accept4 empty flags)

                    let queued, after = queuedListener port system
                    system <- after
                    port <- port + 1us
                    let answered = row $"%s{label} queued lis.   -> " (accept4 queued flags)
                    yield row $"%s{answered}; then " (stillQueued queued)

                    // still_queued took the connection; the probe connects a
                    // second client to the same listener.
                    let client, after =
                        NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

                    system <- FcntlWorld.connect client (port - 1us) after

                    let answered =
                        row $"%s{label} queued, len -1 -> " (accept4NegativeLength queued flags)

                    yield row $"%s{answered}; then " (stillQueued queued)

                let queued, after = queuedListener port system
                system <- after
                port <- port + 1us

                let answered =
                    row "A flags 0x00000000 queued, len -1 -> " (accept4NegativeLength queued 0)

                yield row $"%s{answered}; then " (stillQueued queued)
            ]

        lines, system

    let private sectionB (system : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
        let file, system =
            FcntlWorld.openWith (FcntlWorld.opening FileAccessMode.ReadOnly) "f" system

        let queued, system = queuedListener 7000us system
        let kept = Set.ofList [ 0 ; 1 ; 2 ; file ; queued ]

        let rec fill (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixDescriptor.tryDup (Callers.leader system) 0 system with
            | Ok (DescriptorAnswer.Returned _, system) -> fill system
            | Ok (other, _) -> failwith $"dup(0) while filling: %A{other}"
            | Error _ -> system

        let mutable system = fill system

        let row (format : string) (call : UnixSystem<int, string> -> string * UnixSystem<int, string>) : string =
            let answer, after = call system
            system <- after
            format + answer

        let lines =
            [
                for flags in [ 1 ; 0 ] do
                    yield row $"B full, flags 0x%x{flags} closed fd    -> " (accept4 2000 flags)
                    yield row $"B full, flags 0x%x{flags} regular file -> " (accept4 file flags)
                    yield row $"B full, flags 0x%x{flags} queued lis.  -> " (accept4 queued flags)

                let open' =
                    Lone.fileDescriptors system
                    |> FileDescriptorRegistry.fds
                    |> Map.keys
                    |> Seq.filter (fun fd -> not (Set.contains fd kept))
                    |> List.ofSeq

                system <- List.fold (fun system fd -> close fd system) system open'
                yield row "B after freeing one, queued: " (stillQueued queued)
            ]

        lines, system

    let private sectionC (system : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
        let words =
            [
                0, "0"
                SockNonBlock, "NONBLOCK"
                SockCloseOnExec, "CLOEXEC"
                SockNonBlock ||| SockCloseOnExec, "NONBLOCK|CLOEXEC"
            ]

        let mutable system = system
        let mutable port = 8000us

        let lines =
            [
                for nonBlocking in [ false ; true ] do
                    for word, name in words do
                        let listener, after = FcntlWorld.listener port nonBlocking system
                        port <- port + 1us

                        let client, after =
                            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp after

                        let after = FcntlWorld.connect client (port - 1us) after
                        let answer, after = accept4 listener word after
                        system <- after

                        let listenerNonBlocking =
                            match UnixDescriptor.isNonBlocking (Callers.leader system) listener system with
                            | Some true -> 1
                            | Some false -> 0
                            | None -> failwith "the listener is not open"

                        let kind = if nonBlocking then "non-blocking" else "blocking    "

                        yield
                            sprintf
                                "C %s listener, flags %-16s -> %s; listener nonblock=%d"
                                kind
                                name
                                answer
                                listenerNonBlocking
            ]

        lines, system

    let private sectionD (system : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
        let listener, system = FcntlWorld.listener 9000us false system

        let flags = SockNonBlock ||| SockCloseOnExec

        match
            UnixConnection.tryAccept (Callers.thread 1 system) listener (UserBuffer.Unmapped 0UL) None flags system
        with
        | Ok (AcceptOutcome.WouldBlock _, system) ->
            let client, system =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

            let system = FcntlWorld.connect client 9000us system |> Woken.thread 1
            let finished = UnixConnection.tryFinishAccept (Callers.thread 1 system) system
            let answer, system = describe finished system

            [
                $"D blocking listener, nothing queued, NONBLOCK|CLOEXEC -> %s{answer}; slept"
            ],
            system
        | answered ->
            let answer, system = describe answered system

            [
                $"D blocking listener, nothing queued, NONBLOCK|CLOEXEC -> %s{answer}; did not sleep"
            ],
            system

    /// The probe's script, run against the model.
    let private modelled : string list =
        let system = FcntlWorld.system run
        let a, system = sectionA system
        let b, system = sectionB system
        let c, system = sectionC system
        let d, _ = sectionD system
        a @ b @ c @ d

    /// Every row the model answers is the measured row. The rows it refuses
    /// are those where the descriptor limit decides the answer, which this
    /// kernel does not model, and they must be exactly the ones measured as
    /// `EMFILE`.
    [<Test>]
    let ``accept4's flags answer as measured on Linux`` () : unit =
        modelled.Length |> shouldEqual measured.Length

        let mutable refused = 0

        let mismatches =
            List.zip measured modelled
            |> List.choose (fun (measuredRow, modelledRow) ->
                if measuredRow = modelledRow then
                    None
                elif
                    measuredRow.EndsWith "-> EMFILE"
                    && modelledRow = measuredRow.Replace ("-> EMFILE", $"-> %s{refusedForLimit}")
                then
                    refused <- refused + 1
                    None
                else
                    Some $"measured: %s{measuredRow}\nmodelled: %s{modelledRow}"
            )

        mismatches |> shouldEqual []
        refused |> shouldEqual 2

    /// Darwin has no `accept4`: any flags at all are refused as a call the
    /// platform lacks, before the descriptor is looked at.
    [<Test>]
    let ``Darwin refuses accept4's flags`` () : unit =
        let system =
            FcntlWorld.system
                { run with
                    Platform = SimulatedUnixPlatform.macOsArm64
                }

        for flags in [ SockNonBlock ; SockCloseOnExec ; 1 ; Int32.MinValue ] do
            match UnixConnection.tryAccept (Callers.leader system) 500 UserBuffer.Mapped (Some 16u) flags system with
            | Error (AcceptRefusal.FlagsNotProvided SimulatedUnixFlavour.Darwin) -> ()
            | other -> failwith $"flags 0x%x{flags}: expected a refusal, got %A{other}"

            (fun () ->
                UnixConnection.accept (Callers.leader system) 500 UserBuffer.Mapped (Some 16u) flags system
                |> ignore
            )
            |> shouldFail<PlatformNotSupportedException>
