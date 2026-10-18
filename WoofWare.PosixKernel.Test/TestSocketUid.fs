namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The uid a socket carries (`SocketDescription.Uid`), replayed from
/// `docs/probes/socket-creator-uid`: the effective uid of the process that made
/// it, which a later change of that process's credentials leaves alone; and
/// for an accepted socket, the listener's on Darwin and the acceptor's
/// effective uid at accept(2) on Linux.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSocketUid =

    let private context : string = "TestSocketUid"

    let private uid (raw : uint32) : UserId = UserId.parseOrFail context raw
    let private gid (raw : uint32) : GroupId = GroupId.parseOrFail context raw

    /// The credentials a probe name stands for: root, or the uid in the name
    /// with group 20.
    let private credentialsOf (name : string) : Credentials =
        match name with
        | "root" -> Credentials.ofIds UserId.root (gid 0u) []
        | name -> Credentials.ofIds (uid (uint32 (name.Substring 1))) (gid 20u) []

    let private launchOn (platform : SimulatedUnixPlatform) (credentials : Credentials) : ProcessLaunch<int> =
        Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> Launched.credentials credentials
        |> ProcessLaunch.withCoreDumps CoreDumps.Suppressed

    /// A machine of `platform` whose one process has `credentials`, and its
    /// process ID.
    let private machine
        (platform : SimulatedUnixPlatform)
        (credentials : Credentials)
        : ProcessId * UnixSystem<int, string>
        =
        let system : UnixSystem<int, string> =
            UnixSystem.initial platform
            |> Launched.bootWith
                (Launched.credentials credentials
                 >> ProcessLaunch.withCoreDumps CoreDumps.Suppressed)
                UnixSystem.pipedStandardStreams
                0
                (CpuId 0)

        Lone.pid system, system

    /// `system` with a new process of `credentials`, and its process ID.
    let private withProcess
        (credentials : Credentials)
        (system : UnixSystem<int, string>)
        : ProcessId * UnixSystem<int, string>
        =
        match UnixSystem.tryLaunch (launchOn system.Machine.UnixPlatform credentials) system with
        | Ok launched -> launched
        | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

    let private step
        (pid : ProcessId)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : SteppedCall<int, string>
        =
        match UnixSystem.tryStep (Caller.make pid 0) call system with
        | Ok stepped -> stepped
        | Error refusal -> failwith $"%A{call} by %O{pid} was refused: %A{refusal}"

    let private tcpSocket
        (pid : ProcessId)
        (reuse : bool)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let platform = system.Machine.UnixPlatform

        let domain, kind, protocol =
            NewSocket.arguments platform SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp

        let fd, system =
            match step pid (Syscall.Socket (domain, kind, protocol)) system with
            | SteppedCall.Socket (Ok made) -> made
            | other -> failwith $"socket: %A{Stepped.view other}"

        if not reuse then
            fd, system
        else

        let call =
            Syscall.SetSockOpt (
                fd,
                SimulatedUnixPlatform.socketOptionLevel platform,
                SimulatedUnixPlatform.reuseAddressOption platform,
                CopiedArgument.Readable (OptionValue.ofInt 1),
                4u
            )

        match step pid call system with
        | SteppedCall.SetSockOpt (SetSockOptAnswer.Set, system) -> fd, system
        | other -> failwith $"setsockopt: %A{Stepped.view other}"

    let private bind
        (pid : ProcessId)
        (fd : int)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Result<BindAnswer * UnixSystem<int, string>, SyscallRefusal<int>>
        =
        let blob = CopyIn.inetCopy system.Machine.UnixPlatform endpoint

        match
            UnixSystem.tryStep
                (Caller.make pid 0)
                (Syscall.Bind (fd, CopiedArgument.Readable blob, uint32 blob.Length))
                system
        with
        | Ok (SteppedCall.Bind (answer, system)) -> Ok (answer, system)
        | Ok other -> failwith $"bind: %A{Stepped.view other}"
        | Error refusal -> Error refusal

    let private bound (pid : ProcessId) (fd : int) (endpoint : Ipv4Endpoint) (system : UnixSystem<int, string>) =
        match bind pid fd endpoint system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind of %s{Ipv4Endpoint.toString endpoint}: %A{other}"

    let private setEffective (pid : ProcessId) (effective : UserId) (system : UnixSystem<int, string>) =
        match step pid (Syscall.SetResUid (None, Some effective, None)) system with
        | SteppedCall.SetResUid (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"setresuid(-1, %O{effective}, -1): %A{Stepped.view other}"

    /// The socket `fd` of `pid` names.
    let private socketOf (pid : ProcessId) (fd : int) (system : UnixSystem<int, string>) : SocketDescription =
        match FileDescriptorRegistry.tryFind fd (UnixSystem.fileDescriptors pid system) with
        | Some description ->
            match description.Target with
            | OpenFileTarget.Socket socketId -> UnixMachineState.socket socketId system.Machine
            | other -> failwith $"fd %d{fd} is %A{other}"
        | None -> failwith $"fd %d{fd} is not open"

    let private port : uint16 = 40000us
    let private loopback : Ipv4Endpoint = Ipv4Endpoint.ofParts Ipv4Address.loopback port

    /// `pid` listens at the loopback port with a socket made under effective
    /// uid `listenerUid`, then accepts a connection from a client socket of
    /// its own under `acceptorUid`, changing its effective uid through root
    /// with Linux's `setresuid`; `None` leaves the process's uid as it is.
    /// The listener's descriptor, the accepted one, the client's, and the
    /// system.
    let private acceptRow
        (pid : ProcessId)
        (listenerUid : UserId option)
        (acceptorUid : UserId option)
        (system : UnixSystem<int, string>)
        : int * int * int * UnixSystem<int, string>
        =
        let system =
            listenerUid
            |> Option.fold (fun system effective -> setEffective pid effective system) system

        let listener, system = tcpSocket pid false system
        let system = bound pid listener loopback system

        let system =
            match step pid (Syscall.Listen (listener, 8)) system with
            | SteppedCall.Listen (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"listen: %A{Stepped.view other}"

        let system =
            match acceptorUid with
            | Some effective -> system |> setEffective pid UserId.root |> setEffective pid effective
            | None -> system

        let client, system = tcpSocket pid false system
        let blob = CopyIn.inetCopy system.Machine.UnixPlatform loopback

        let system =
            match step pid (Syscall.Connect (client, CopiedArgument.Readable blob, uint32 blob.Length)) system with
            | SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
            | other -> failwith $"connect: %A{Stepped.view other}"

        match step pid (Syscall.Accept (listener, UserBuffer.Mapped, 16u)) system with
        | SteppedCall.Accept (AcceptOutcome.Accepted (accepted, _, _), system) -> listener, accepted, client, system
        | other -> failwith $"accept: %A{Stepped.view other}"

    let private close (pid : ProcessId) (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match step pid (Syscall.Close fd) system with
        | SteppedCall.Close (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"close(%d{fd}): %A{Stepped.view other}"

    /// The probe's rows of `resource` whose first field is `tag`, split at
    /// their tabs.
    let private rows (resource : string) (tag : string) : string[] list =
        SocketLadder.resource resource
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line.StartsWith (tag + "\t", StringComparison.Ordinal))
        |> Array.map (fun line -> line.Split '\t')
        |> List.ofArray

    let private field (row : string[]) (name : string) : string =
        row
        |> Array.pick (fun f ->
            if f.StartsWith (name + "=", StringComparison.Ordinal) then
                Some (f.Substring (name.Length + 1))
            else
                None
        )

    // ------------------------------------------------------------- Linux

    [<Test>]
    let ``Linux: a socket keeps the effective uid it was made under through a later setresuid`` () : unit =
        // CREATE rows: /proc/net/tcp reports the uid the socket was made
        // under, whatever the process's effective uid became before it bound
        // and listened.
        let measured = rows "socket-creator-uid.linux.txt" "CREATE"
        measured.Length |> shouldEqual 3

        for row in measured do
            let made = (credentialsOf (field row "made")).EffectiveUser
            let later = (credentialsOf (field row "later")).EffectiveUser
            let pid, system = machine SimulatedUnixPlatform.linuxX64 (credentialsOf "root")
            let system = setEffective pid made system
            let fd, system = tcpSocket pid false system
            let system = system |> setEffective pid UserId.root |> setEffective pid later
            let system = bound pid fd loopback system

            (socketOf pid fd system).Uid
            |> shouldEqual (uid (uint32 (field row "proc-uid")))

            (Lone.proc system).Credentials.EffectiveUser |> shouldEqual later

    [<Test>]
    let ``Linux: an accepted socket carries the acceptor's effective uid at accept, not the listener's`` () : unit =
        // ACCEPT rows: /proc/net/tcp's uid for the listening socket and for
        // the one accept returned.
        let measured = rows "socket-creator-uid.linux.txt" "ACCEPT"
        measured.Length |> shouldEqual 3

        for row in measured do
            let listenerUid = (credentialsOf (field row "listener")).EffectiveUser
            let acceptorUid = (credentialsOf (field row "acceptor")).EffectiveUser
            let pid, system = machine SimulatedUnixPlatform.linuxX64 (credentialsOf "root")

            let listener, accepted, _, system =
                acceptRow pid (Some listenerUid) (Some acceptorUid) system

            (socketOf pid listener system).Uid
            |> shouldEqual (uid (uint32 (field row "listening")))

            (socketOf pid accepted system).Uid
            |> shouldEqual (uid (uint32 (field row "accepted")))

    // ------------------------------------------------------------- Darwin

    /// Darwin's ACCEPT rows, grouped by listener and acceptor: the binders'
    /// answers, and the control's.
    let private darwinAccepts : ((string * string) * (string[] list * string[] list)) list =
        rows "socket-creator-uid.darwin-root.txt" "ACCEPT"
        |> List.groupBy (fun row -> field row "listener", field row "acceptor")
        |> List.map (fun (key, group) -> key, group |> List.partition (fun row -> not (Array.contains "control" row)))

    [<Test>]
    let ``Darwin: an accepted socket carries the listener's uid, and binds beside it answer as measured`` () : unit =
        // A Darwin process keeps one set of IDs in this kernel, so the
        // listener and the acceptor are one uid here: the listener's, which
        // is what the measured answers show the accepted socket carries. Each
        // binder is a fresh process of its uid, binding the wildcard with
        // SO_REUSEADDR once the listening socket has closed.
        darwinAccepts.Length |> shouldEqual 3

        for (listenerName, _), (binders, _) in darwinAccepts do
            binders.Length |> shouldEqual 4

            for row in binders do
                let pid, system =
                    machine SimulatedUnixPlatform.macOsArm64 (credentialsOf listenerName)

                let listener, accepted, _, system = acceptRow pid None None system
                let system = close pid listener system

                (socketOf pid accepted system).Uid
                |> shouldEqual (credentialsOf listenerName).EffectiveUser

                let binderPid, system = withProcess (credentialsOf (field row "binder")) system
                let fd, system = tcpSocket binderPid true system

                let answered =
                    match bind binderPid fd (Ipv4Endpoint.ofParts Ipv4Address.any port) system with
                    | Ok (BindAnswer.Bound _, _) -> "-> ok"
                    | Ok (BindAnswer.Failed error, _) -> $"-> %A{error}"
                    | Error refusal -> $"refused: %A{refusal}"

                (String.Join ("\t", row), answered)
                |> shouldEqual (String.Join ("\t", row), row |> Array.find (fun f -> f.StartsWith "-> "))

    [<Test>]
    let ``Darwin: a bind of another uid beside an end whose socket has closed is refused`` () : unit =
        // The probe's control rows met the accepted end in TIME_WAIT
        // (`close-order.c`: the accepted end every time): EADDRINUSE beside an
        // end of uid 502, and admitted beside an end of root's, which no rule
        // explains. So a binder that is not root, of another uid, is refused
        // there; one of the end's uid, or root, is answered.
        let controls =
            darwinAccepts
            |> List.map (fun ((listener, _), (_, controls)) -> listener, (List.exactlyOne controls))

        controls
        |> List.map (fun (listener, row) -> listener, Array.find (fun (f : string) -> f.StartsWith "-> ") row)
        |> List.sort
        |> shouldEqual [ "root", "-> ok" ; "u502", "-> EADDRINUSE" ; "u502", "-> EADDRINUSE" ]

        for listenerName in [ "u502" ; "root" ] do
            let pid, system =
                machine SimulatedUnixPlatform.macOsArm64 (credentialsOf listenerName)

            let listener, accepted, client, system = acceptRow pid None None system
            // The accepted end closes first, and so goes to TIME_WAIT.
            let system = system |> close pid listener |> close pid accepted |> close pid client

            system.Machine.TimeWaits |> Map.count |> shouldEqual 1

            for binderName in [ "u501" ; listenerName ; "root" ] do
                let binderPid, system = withProcess (credentialsOf binderName) system
                let fd, system = tcpSocket binderPid true system

                match bind binderPid fd (Ipv4Endpoint.ofParts Ipv4Address.any port) system, binderName with
                | Error (SyscallRefusal.Bind (BindRefusal.TimeWait (TimeWaitRefusal.OtherUidClosedEnd (_, holder, binder)))),
                  "u501" ->
                    holder |> shouldEqual (credentialsOf listenerName).EffectiveUser
                    binder |> shouldEqual (uid 501u)
                | Ok (BindAnswer.Bound _, _), name when name <> "u501" -> ()
                | other, name -> failwith $"%s{listenerName}'s end, binder %s{name}: %A{other}"
