namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// The socket table's index of its UDP sockets by port answers what a scan of
/// every socket in the table answers, whatever changes the table has been
/// through.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSocketTableIndex =

    /// One change to a table: a socket set under an identity, replacing
    /// whatever was there, or an identity removed, whether or not the table
    /// holds it.
    type private Change =
        | Set of socketId : SocketId * socket : SocketDescription
        | Remove of socketId : SocketId

    /// Few ports and few identities, so that sockets share ports and replace
    /// one another often.
    let private ports : uint16 list = [ 1us .. 3us ]

    let private genBinding : Gen<Ipv4Binding> =
        gen {
            let! address = Gen.elements [ Ipv4Address.any ; Ipv4Address.loopback ]
            let! port = Gen.elements ports

            return
                {
                    Endpoint = Ipv4Endpoint.ofParts address port
                    LockedAddress = None
                    LockedPort = false
                    PortHold = PortHold.Reserved
                }
        }

    /// Mostly bound, so that a socket replaced in place often moves between
    /// ports.
    let private genAddressing : Gen<SocketAddressing> =
        Gen.frequency
            [
                1, Gen.constant (SocketAddressing.Inet None)
                4, genBinding |> Gen.map (Some >> SocketAddressing.Inet)
                1, Gen.constant (SocketAddressing.Inet6DualMode None)
                2,
                genBinding
                |> Gen.map (DualModeBinding.Mapped >> Some >> SocketAddressing.Inet6DualMode)
                1, Gen.constant (SocketAddressing.Inet6V6Only None)
                1, Gen.constant (SocketAddressing.Unix None)
            ]

    /// Mostly datagram sockets, which are the ones the index files.
    let private genSocket : Gen<SocketDescription> =
        gen {
            let! addressing = genAddressing

            let! kind =
                Gen.frequency
                    [
                        4, Gen.constant SocketKind.Datagram
                        1, Gen.constant SocketKind.Stream
                        1, Gen.constant SocketKind.SeqPacket
                    ]

            return
                {
                    Addressing = addressing
                    Kind = kind
                    Protocol = SocketProtocol.Default
                    ReuseAddress = false
                    Options = SocketOptions.initial
                    Phase = SocketPhase.Idle
                    Uid = UserId.root
                }
        }

    let private genChange : Gen<Change> =
        let genId = Gen.choose (0, 5) |> Gen.map (int64 >> SocketId)

        Gen.frequency
            [
                3, Gen.map2 (fun socketId socket -> Change.Set (socketId, socket)) genId genSocket
                1, genId |> Gen.map Change.Remove
            ]

    let private apply (change : Change) (table : SocketTable) : SocketTable =
        match change with
        | Change.Set (socketId, socket) -> SocketTable.set socketId socket table
        | Change.Remove socketId -> SocketTable.remove socketId table

    let private applyToReference
        (change : Change)
        (reference : Map<SocketId, SocketDescription>)
        : Map<SocketId, SocketDescription>
        =
        match change with
        | Change.Set (socketId, socket) -> Map.add socketId socket reference
        | Change.Remove socketId -> Map.remove socketId reference

    /// The UDP sockets in `sockets` holding an IPv4 binding at `port`, by a
    /// scan of every one.
    let private scan (port : uint16) (sockets : Map<SocketId, SocketDescription>) : Set<SocketId> =
        sockets
        |> Map.filter (fun _ socket ->
            SocketTable.receivesDatagrams socket
            && (SocketAddressing.ipv4Binding socket.Addressing
                |> Option.exists (fun binding -> binding.Endpoint.Port = port))
        )
        |> Map.keys
        |> Set.ofSeq

    /// Every port the generator binds, and one it never does.
    let private asked : uint16 list = 0us :: 4us :: ports

    /// Which socket a change replaces or removes, if it is one the index
    /// files, and where.
    let private filedAt (socket : SocketDescription) : uint16 option =
        if SocketTable.receivesDatagrams socket then
            SocketAddressing.ipv4Binding socket.Addressing
            |> Option.map (fun binding -> binding.Endpoint.Port)
        else
            None

    /// The walks are a fixed sample rather than FsCheck's own, so that the
    /// coverage counted over them is the coverage the claim was checked over.
    /// A walk's changes are drawn independently, so a smaller walk is not a
    /// simpler one, and nothing is lost by having no shrinker.
    let private walks : Change list list =
        Gen.sampleWithSeed (Rnd 7UL) 50 1000 (Gen.listOf genChange) |> List.ofArray

    [<Test>]
    let ``the index answers what a scan answers after every change`` () : unit =
        // The walks are only worth something if they reach the states that
        // could go wrong: a filed socket rebound to another port in place,
        // replaced by a socket the index does not file, and removed.
        let mutable moved = 0
        let mutable unfiled = 0
        let mutable removed = 0

        for changes in walks do
            ((SocketTable.empty, Map.empty), changes)
            ||> List.fold (fun (table, reference) change ->
                match change with
                | Change.Set (socketId, socket) ->
                    match Map.tryFind socketId reference |> Option.bind filedAt, filedAt socket with
                    | Some before, Some after when before <> after -> moved <- moved + 1
                    | Some _, None -> unfiled <- unfiled + 1
                    | _ -> ()
                | Change.Remove socketId ->
                    if Map.tryFind socketId reference |> Option.bind filedAt |> Option.isSome then
                        removed <- removed + 1

                let table = apply change table
                let reference = applyToReference change reference

                if SocketTable.all table <> reference then
                    failwith $"after %A{change} the table holds %A{SocketTable.all table}, not %A{reference}"

                for port in asked do
                    let indexed = SocketTable.datagramSocketsAt port table
                    let scanned = scan port reference

                    if indexed <> scanned then
                        failwith $"after %A{change}, port %d{port}: the index answers %A{indexed}, a scan %A{scanned}"

                if not (SocketTable.indexFresh table) then
                    failwith $"after %A{change}, indexFresh says the index is stale"

                table, reference
            )
            |> ignore

        // The sample is fixed, and reached 1214, 2729 and 1500; each floor is
        // about half that, so a generator change that reshuffles the sample
        // keeps meeting it.
        if moved < 600 || unfiled < 1300 || removed < 750 then
            failwith $"the walks moved %d{moved}, unfiled %d{unfiled} and removed %d{removed} filed sockets"
