namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which ranges Linux's `net.ipv4.ip_local_port_range` accepts, and which ports
/// an unprivileged process's searches take from a range of one port, replayed
/// from `docs/probes/local-port-range`.
///
/// This kernel holds `ip_unprivileged_port_start` at 1024
/// (`SimulatedUnixPlatform.privilegedPortCeiling`), the namespace default the
/// probe's section R wrote its ranges under; a range Linux accepts only once
/// that sysctl is lowered (sections O and B) is refused, as unmodelled.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestLocalPortRangeMeasured =

    let private lines () : string list =
        let name = "WoofWare.PosixKernel.Test.local-port-range.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private image () : UnixBootImage<int, string> =
        UnixSystem.initial SimulatedUnixPlatform.linuxX64

    /// A range as one write of two numbers, each a port, gives it.
    let private (|PortPair|_|) (text : string) : (uint16 * uint16) option =
        let m = Regex.Match (text, @"^([0-9]+) ([0-9]+)$")

        if m.Success then
            match UInt16.TryParse m.Groups.[1].Value, UInt16.TryParse m.Groups.[2].Value with
            | (true, low), (true, high) -> Some (low, high)
            | _ -> None
        else
            None

    let private rangeRow : Regex =
        Regex @"^R write ip_local_port_range ""(.*)"" -> (\S+) \| range=(\d+) (\d+) unprivileged_start=1024$"

    [<Test>]
    let ``withEphemeralPortRange admits exactly the ranges Linux's sysctl was measured to`` () : unit =
        let mutable replayed = 0

        for line in lines () do
            let m = rangeRow.Match line

            if m.Success then
                match m.Groups.[1].Value with
                | PortPair (low, high) ->
                    let measured = m.Groups.[2].Value

                    match measured, UnixBootImage.tryWithEphemeralPortRange (low, high) (image ()) with
                    | "OK", Ok _ -> ()
                    | "EINVAL", Error _ -> ()
                    | _, Ok _ -> failwith $"%s{line}: the model admits the range"
                    | _, Error refusal ->
                        failwith $"%s{line}: the model refuses it (%s{EphemeralPortRangeRefusal.describe refusal})"

                    replayed <- replayed + 1
                // A write the library's two ports cannot state: a negative
                // number, one past 65535, or not two numbers at all.
                | _ -> ()

        replayed |> shouldEqual 13

    /// The ranges that Linux accepted only once `ip_unprivileged_port_start`
    /// had been lowered to their low end or below it.
    let private lowered : Regex =
        Regex
            @"^(?:O\d write ip_local_port_range|B unprivileged_start ""\d+"" -> OK, range) ""(\d+ \d+)"" -> OK \| range=(\d+) (\d+) unprivileged_start=(\d+)$"

    [<Test>]
    let ``a range Linux accepts only below the unprivileged port start is refused as unmodelled`` () : unit =
        let mutable replayed = 0

        for line in lines () do
            let m = lowered.Match line

            if m.Success then
                let low = UInt16.Parse m.Groups.[2].Value
                let high = UInt16.Parse m.Groups.[3].Value

                if int low < int SimulatedUnixPlatform.privilegedPortCeiling then
                    match UnixBootImage.tryWithEphemeralPortRange (low, high) (image ()) with
                    | Error refusal ->
                        refusal
                        |> shouldEqual (EphemeralPortRangeRefusal.BelowUnprivilegedPortStart low)

                        EphemeralPortRangeRefusal.kind refusal |> shouldEqual RefusalKind.Unmodelled
                    | Ok _ -> failwith $"%s{line}: the model admits the range"

                    replayed <- replayed + 1

        // O1's 1-2000, O2's 500-2000 and 600-600, and B's 600-600, 600-601,
        // 1-1 and 80-80.
        replayed |> shouldEqual 7
