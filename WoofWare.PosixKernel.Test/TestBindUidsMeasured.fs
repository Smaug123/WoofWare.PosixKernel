namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Darwin's `bind(2)` against a port another socket holds, replayed from
/// `docs/probes/darwin-root/bind-uids.c`, which measured it as root on Darwin
/// 27.0 between sockets of uids 501, 502, 504 and 0.
///
/// This kernel keeps no owner for a socket, so it answers as if every socket
/// were its binder's. That is right wherever Darwin does not consult the
/// owner: the holder is the binder's own uid, or the binder is root. Those
/// rows are replayed here. Where a binder that is not root meets a holder of
/// another uid at an overlapping address that is not the wildcard on both
/// sides, Darwin answers `EADDRINUSE` even with `SO_REUSEADDR`; the last test
/// pins those rows, which the model answers as if the holder were the
/// binder's own.
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
                Kind = (if fields.["proto"] = "tcp" then SocketKind.Stream else SocketKind.Datagram)
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

    /// What the model answers for `row`, as the probe prints it: the holder
    /// bound at its address and a port, listening if the row says so, then a
    /// second socket bound at its own address and the same port.
    let private answer (row : Row) : string =
        let platform = SimulatedUnixPlatform.macOsArm64
        let port = 40000us

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let protocol =
            match row.Kind with
            | SocketKind.Stream -> SocketProtocol.Tcp
            | _ -> SocketProtocol.Udp

        let holder, system = NewSocket.create SocketDomain.Inet row.Kind protocol system
        let system = ReuseAddress.set row.HolderReuseAddress holder system

        let system =
            match
                CopyIn.bind holder UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts row.HolderAddress port)) system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"%s{row.Line}: the holder's bind answered %A{other}"

        let system =
            if row.Listening then
                match UnixSocket.tryListen (Callers.leader system) holder 8 system with
                | Ok (ListenAnswer.Listening _, system) -> system
                | other -> failwith $"%s{row.Line}: the holder's listen answered %A{other}"
            else
                system

        let binder, system = NewSocket.create SocketDomain.Inet row.Kind protocol system
        let system = ReuseAddress.set row.BinderReuseAddress binder system

        match CopyIn.bind binder UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts row.BinderAddress port)) system with
        | Ok (BindAnswer.Bound _, _) -> "ok"
        | Ok (BindAnswer.Failed error, _) -> $"%A{error}"
        | Error refusal -> $"REFUSED (%s{BindRefusal.describe refusal})"

    [<Test>]
    let ``every row's control bind succeeded, so only the holder stood in the way`` () : unit =
        rows.Length |> shouldEqual 960

        for row in rows do
            if row.Control <> "ok" then
                failwith $"control not ok: %s{row.Line}"

    [<Test>]
    let ``every row where Darwin does not consult the holder's owner is replayed`` () : unit =
        // This kernel does not model SO_REUSEPORT, so its rows are left out.
        let replayed =
            rows
            |> List.filter (fun row -> not row.HolderReusePort && not row.BinderReusePort && not (ownerConsulted row))

        replayed.Length |> shouldEqual 144

        let mismatches =
            [
                for row in replayed do
                    let actual = answer row

                    if actual <> row.Answer then
                        $"%s{row.Line}: model answered %s{actual}"
            ]

        if not mismatches.IsEmpty then
            failwith (String.Join ("\n", mismatches))

    [<Test>]
    let ``where Darwin consults the holder's owner, SO_REUSEADDR does not get a binder past another uid's holder`` () : unit =
        let consulted =
            rows
            |> List.filter (fun row -> not row.HolderReusePort && not row.BinderReusePort && ownerConsulted row)

        consulted.Length |> shouldEqual 96

        for row in consulted do
            row.Answer |> shouldEqual "EADDRINUSE"
