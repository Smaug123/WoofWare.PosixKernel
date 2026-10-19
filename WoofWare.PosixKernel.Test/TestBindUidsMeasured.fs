namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Darwin's `bind(2)` against a port another socket holds, replayed from
/// `docs/probes/darwin-root/bind-uids.c`, which measured it as root on Darwin
/// 27.0 between sockets of uids 501, 502, 504 and 0: each row's holder and
/// binder are processes of those uids on one machine, and every socket
/// carries the uid of the process that made it (`SocketDescription.Uid`).
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestBindUidsMeasured =

    /// One `BIND` row.
    type private Row =
        {
            Line : string
            Kind : SocketKind
            Holder : string
            HolderAddress : Ipv4Address
            HolderReuseAddress : bool
            HolderReusePort : bool
            Listening : bool
            Binder : string
            BinderAddress : Ipv4Address
            BinderReuseAddress : bool
            BinderReusePort : bool
            Answer : string
            Control : string
        }

    let private address (text : string) : Ipv4Address =
        match text with
        | "0.0.0.0" -> Ipv4Address.any
        | "127.0.0.1" -> Ipv4Address.loopback
        | other -> failwith $"unknown address %s{other}"

    let private rows : Row list =
        SocketLadder.resource "darwin-root.bind-uids.txt"
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line.StartsWith ("BIND\t", StringComparison.Ordinal))
        |> Array.map (fun line ->
            let fields =
                line.Split '\t'
                |> Array.choose (fun field ->
                    match field.IndexOf '=' with
                    | -1 -> None
                    | i when not (field.StartsWith "->") -> Some (field.Substring (0, i), field.Substring (i + 1))
                    | _ -> None
                )
                |> Map.ofArray

            let answer =
                line.Split '\t'
                |> Array.pick (fun field ->
                    if field.StartsWith "-> " then
                        Some (field.Substring 3)
                    else
                        None
                )

            {
                Line = line
                Kind =
                    (if fields.["proto"] = "tcp" then
                         SocketKind.Stream
                     else
                         SocketKind.Datagram)
                Holder = fields.["holder"]
                HolderAddress = address fields.["haddr"]
                HolderReuseAddress = fields.["hopts"].Contains 'A'
                HolderReusePort = fields.["hopts"].Contains 'P'
                Listening = fields.["hstate"] = "listen"
                Binder = fields.["binder"]
                BinderAddress = address fields.["baddr"]
                BinderReuseAddress = fields.["bopts"].Contains 'A'
                BinderReusePort = fields.["bopts"].Contains 'P'
                Answer = answer
                Control = fields.["control"]
            }
        )
        |> List.ofArray

    /// Whether Darwin consults the holder's owner for `row`: a binder that is
    /// not root, a holder of another uid, and not both addresses the wildcard.
    let private ownerConsulted (row : Row) : bool =
        row.Binder <> "root"
        && row.Holder <> row.Binder
        && (row.HolderAddress <> Ipv4Address.any || row.BinderAddress <> Ipv4Address.any)

    let private context : string = "TestBindUidsMeasured"

    /// The credentials the probe's processes took: root, or the uid in the
    /// name with group 20.
    let private credentialsOf (name : string) : Credentials =
        match name with
        | "root" -> Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []
        | name ->
            Credentials.ofIds
                (UserId.parseOrFail context (uint32 (name.Substring 1)))
                (GroupId.parseOrFail context 20u)
                []

    /// A Darwin machine of two processes, the first of `holder`'s
    /// credentials and the second of `binder`'s, and their process IDs.
    let private machine (holder : string) (binder : string) : ProcessId * ProcessId * UnixSystem<int, string> =
        let platform = SimulatedUnixPlatform.macOsArm64

        let first : UnixSystem<int, string> =
            UnixSystem.initial platform
            |> Launched.bootWith
                (Launched.credentials (credentialsOf holder))
                UnixSystem.pipedStandardStreams
                0
                (CpuId 0)

        let launch =
            Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Launched.credentials (credentialsOf binder)

        match UnixSystem.tryLaunch launch first with
        | Ok (binderPid, system) -> Lone.pid first, binderPid, system
        | Error refusal -> failwith $"launching the binder: %s{ProcessCreationRefusal.describe refusal}"

    /// `call`, made by the leader of `pid`, failing the test if it is refused.
    let private step
        (pid : ProcessId)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : SteppedCall<int, string>
        =
        match UnixSystem.tryStep (Caller.make pid 0) call system with
        | Ok stepped -> stepped
        | Error refusal -> failwith $"%A{call} by %O{pid} was refused: %A{refusal}"

    /// A socket of `kind`, made by `pid`, with `SO_REUSEADDR` if `reuse`.
    let private socketOf
        (pid : ProcessId)
        (kind : SocketKind)
        (reuse : bool)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let platform = UnixSystem.platform system

        let protocol =
            match kind with
            | SocketKind.Stream -> SocketProtocol.Tcp
            | _ -> SocketProtocol.Udp

        let domain, rawKind, rawProtocol =
            NewSocket.arguments platform SocketDomain.Inet kind protocol

        let fd, system =
            match step pid (Syscall.Socket (domain, rawKind, rawProtocol)) system with
            | SteppedCall.Socket (Ok made) -> made
            | other -> failwith $"socket by %O{pid}: %A{Stepped.view other}"

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
        | other -> failwith $"setsockopt by %O{pid}: %A{Stepped.view other}"

    /// `bind(2)` of `fd` at `endpoint`, made by `pid`.
    let private bindOf
        (pid : ProcessId)
        (fd : int)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : BindAnswer * UnixSystem<int, string>
        =
        let blob = CopyIn.inetCopy (UnixSystem.platform system) endpoint

        match step pid (Syscall.Bind (fd, CopiedArgument.Readable blob, uint32 blob.Length)) system with
        | SteppedCall.Bind (answer, system) -> answer, system
        | other -> failwith $"bind by %O{pid}: %A{Stepped.view other}"

    /// What the model answers for `row`, as the probe prints it: the holder's
    /// process makes its socket and binds it at its address and a port,
    /// listening if the row says so, then the binder's process makes a second
    /// socket and binds it at its own address and the same port.
    let private answer (row : Row) : string =
        let port = 40000us
        let holderPid, binderPid, system = machine row.Holder row.Binder

        let holder, system = socketOf holderPid row.Kind row.HolderReuseAddress system

        let system =
            match bindOf holderPid holder (Ipv4Endpoint.ofParts row.HolderAddress port) system with
            | BindAnswer.Bound _, system -> system
            | other -> failwith $"%s{row.Line}: the holder's bind answered %A{fst other}"

        let system =
            if row.Listening then
                match step holderPid (Syscall.Listen (holder, 8)) system with
                | SteppedCall.Listen (ListenAnswer.Listening _, system) -> system
                | other -> failwith $"%s{row.Line}: the holder's listen answered %A{Stepped.view other}"
            else
                system

        let binder, system = socketOf binderPid row.Kind row.BinderReuseAddress system

        match bindOf binderPid binder (Ipv4Endpoint.ofParts row.BinderAddress port) system with
        | BindAnswer.Bound _, _ -> "ok"
        | BindAnswer.Failed error, _ -> $"%A{error}"

    [<Test>]
    let ``every row's control bind succeeded, so only the holder stood in the way`` () : unit =
        rows.Length |> shouldEqual 960

        for row in rows do
            if row.Control <> "ok" then
                failwith $"control not ok: %s{row.Line}"

    [<Test>]
    let ``every row without SO_REUSEPORT answers as measured, between processes of the row's uids`` () : unit =
        // This kernel does not model SO_REUSEPORT, so its rows are left out.
        let replayed =
            rows
            |> List.filter (fun row -> not row.HolderReusePort && not row.BinderReusePort)

        replayed.Length |> shouldEqual 240

        // Among them, the rows where Darwin consults the holder's owner: a
        // binder that is not root meeting another uid's holder at addresses
        // that are not both the wildcard, EADDRINUSE even with SO_REUSEADDR.
        let consulted = replayed |> List.filter ownerConsulted
        consulted.Length |> shouldEqual 96

        for row in consulted do
            row.Answer |> shouldEqual "EADDRINUSE"

        let mismatches =
            [
                for row in replayed do
                    let actual = answer row

                    if actual <> row.Answer then
                        $"%s{row.Line}: model answered %s{actual}"
            ]

        if not mismatches.IsEmpty then
            failwith $"%d{mismatches.Length} rows differ:\n%s{String.Join ('\n', mismatches)}"
