namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which ephemeral port ranges a Darwin machine can have, replayed from
/// `docs/probes/darwin-root/port-range.c`, which wrote each of
/// `net.inet.ip.portrange.first` and `last` as root on Darwin 27.0 and read
/// it back.
///
/// Darwin takes any value for either end and keeps it within 1024 to 65535,
/// so no Darwin machine's range starts below 1024; and it takes a low end
/// above the high end, searching downwards, which this kernel does not model.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPortRangeSysctlsMeasured =

    /// One `SET` row: the sysctl written, the value asked for, and the value
    /// read back.
    type private SetRow =
        {
            Name : string
            Asked : int
            ReadBack : int
        }

    let private setRows : SetRow list =
        SocketLadder.resource "darwin-root.port-range.txt"
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line.StartsWith ("SET\t", StringComparison.Ordinal))
        |> Array.map (fun line ->
            match line.Split '\t' with
            | [| _ ; name ; asked ; answer ; readBack |] ->
                if answer <> "-> ok" then
                    failwith $"the probe's write was refused: %s{line}"

                {
                    Name = name
                    Asked = int asked
                    ReadBack = int (readBack.Substring "readback=".Length)
                }
            | _ -> failwith $"unparsed row %s{line}"
        )
        |> List.ofArray

    let private attempt (platform : SimulatedUnixPlatform) (range : uint16 * uint16) =
        UnixSystem.initial<int, string> platform
        |> UnixBootImage.tryWithEphemeralPortRange range
        |> Result.map UnixBootImage.platform

    [<Test>]
    let ``the probe wrote every value it meant to, as root`` () : unit =
        let firsts = setRows |> List.filter (fun row -> row.Name = "net.inet.ip.portrange.first")
        firsts.Length |> shouldEqual 14

        // Every value below 1024 read back as 1024, and every value from 1024
        // to 65535 as itself, for first and last alike: the floor the replay
        // below holds the setter to.
        for row in setRows do
            if row.Name = "net.inet.ip.portrange.first" || row.Name = "net.inet.ip.portrange.last" then
                let kept = row.Asked >= 1024 && row.Asked <= 65535
                (row.Name, row.Asked, row.ReadBack = row.Asked) |> shouldEqual (row.Name, row.Asked, kept)

    [<Test>]
    let ``a Darwin range is admitted exactly when each end is a value its sysctl reads back as itself`` () : unit =
        let mutable replayed = 0

        for row in setRows do
            if row.Asked >= 1 && row.Asked <= 65535 then
                let asked = uint16 row.Asked

                // The other end at the far side of the range, which both
                // sysctls keep.
                let range =
                    match row.Name with
                    | "net.inet.ip.portrange.first" -> Some (asked, 65535us)
                    | "net.inet.ip.portrange.last" -> Some (1024us, asked)
                    | _ -> None

                match range with
                | None -> ()
                | Some range ->
                    replayed <- replayed + 1

                    match attempt SimulatedUnixPlatform.macOsArm64 range, row.ReadBack = row.Asked with
                    | Ok _, true -> ()
                    | Error (EphemeralPortRangeRefusal.BelowDarwinFloor (low, high)), false when (low, high) = range -> ()
                    | other, kept ->
                        failwith $"%s{row.Name}=%d{row.Asked} (read back %d{row.ReadBack}, kept %b{kept}) gave %A{other}"

        // first and last, each at the ten values it was written from 1 to 65535.
        replayed |> shouldEqual 20

    [<Test>]
    let ``Linux keeps its own floor`` () : unit =
        match attempt SimulatedUnixPlatform.linuxX64 (1us, 2000us) with
        | Ok _ -> ()
        | Error refusal -> failwith $"Linux refused (1, 2000): %s{EphemeralPortRangeRefusal.describe refusal}"

    [<Test>]
    let ``a descending range is Darwin's to search downwards, which is not modelled, and empty on Linux`` () : unit =
        attempt SimulatedUnixPlatform.macOsArm64 (40003us, 40000us)
        |> shouldEqual (Error (EphemeralPortRangeRefusal.Descending (40003us, 40000us)))

        attempt SimulatedUnixPlatform.linuxX64 (40003us, 40000us)
        |> shouldEqual (Error (EphemeralPortRangeRefusal.Empty (40003us, 40000us)))

        // A descending pair with an end below the floor is no Darwin range at
        // all, which `last` reads back as 1024 just as `first` does.
        attempt SimulatedUnixPlatform.macOsArm64 (2000us, 1us)
        |> shouldEqual (Error (EphemeralPortRangeRefusal.BelowDarwinFloor (2000us, 1us)))

        EphemeralPortRangeRefusal.kind (EphemeralPortRangeRefusal.Descending (40003us, 40000us))
        |> shouldEqual RefusalKind.Unmodelled

    [<Test>]
    let ``a Darwin machine narrowed to four ports hands its stream binds out in order from its low end`` () : unit =
        // The probe's ALLOC rows for first=B, last=B+3 (B = 40000): each of
        // five stream sockets bound at 0.0.0.0:0, kept open.
        let measured =
            SocketLadder.resource "darwin-root.port-range.txt"
            |> Array.map (fun line -> line.TrimEnd '\r')
            |> Array.find (fun line ->
                line.StartsWith ("ALLOC\troot\tfirst=B last=B+3 ", StringComparison.Ordinal)
                && line.Contains "\ttcp 0.0.0.0:0\t"
            )

        measured.EndsWith "-> 40000 40001 40002 40003 EADDRNOTAVAIL" |> shouldEqual true

        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
            |> UnixBootImage.tryWithEphemeralPortRange (40000us, 40003us)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let platform = SimulatedUnixPlatform.macOsArm64

        let ports, system =
            ((([] : uint16 list), system), [ 1..4 ])
            ||> List.fold (fun (ports, system) _ ->
                let fd, system = NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

                match
                    CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.any 0us)) system
                with
                | Ok (BindAnswer.Bound (SocketAddress.Inet endpoint), system) -> ports @ [ endpoint.Port ], system
                | other -> failwith $"bind of port 0 answered %A{other}"
            )

        ports |> shouldEqual [ 40000us ; 40001us ; 40002us ; 40003us ]

        // The fifth: Darwin answers EADDRNOTAVAIL, which this kernel refuses
        // to answer (`SimulatedUnixPlatform.ephemeralPortsExhausted`).
        let fd, system = NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.any 0us)) system with
        | Error _ -> ()
        | other -> failwith $"the fifth bind of port 0 answered %A{other}"
