namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Runtime.InteropServices
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The host's own `gethostname(3)`, asked the same questions as a model
/// machine given the host's name, at every capacity around that name's length
/// and around Darwin's `MAXHOSTNAMELEN + 1`: the two must return the same and
/// leave the same bytes in the buffer.
///
/// Every row's destination is storage the test owns, with room either side,
/// so no row writes anywhere the test does not own: the rows that would
/// (Darwin's capacity of zero, and every unwritable destination) are held to
/// the recordings by `TestGetHostName` instead.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestGetHostNameAgainstHost =

    [<DllImport("libc", EntryPoint = "gethostname", SetLastError = true)>]
    extern int private gethostname(nativeint name, unativeint length)

    [<Literal>]
    let private Guard : int = 64

    [<Literal>]
    let private StorageBytes : int = 4096

    /// Call the host's `gethostname` with `capacity` into storage pre-filled
    /// with 0xAA, and report its return, its errno, and the bytes it changed,
    /// failing if it touched the guard before the buffer.
    let private host (capacity : int) : int * int * byte[] =
        let total = Guard + StorageBytes + Guard
        let storage = Marshal.AllocHGlobal total

        try
            Marshal.Copy (Array.create total 0xAAuy, 0, storage, total)
            let ret = gethostname (storage + nativeint Guard, unativeint capacity)
            let errno = if ret = 0 then 0 else Marshal.GetLastPInvokeError ()
            let after = Array.zeroCreate<byte> total
            Marshal.Copy (storage, after, 0, total)

            if Array.exists (fun b -> b <> 0xAAuy) after.[.. Guard - 1] then
                failwith $"the host's gethostname stored before its buffer at capacity %d{capacity}"

            let buffer = after.[Guard..]

            let changed =
                match Array.tryFindIndexBack (fun b -> b <> 0xAAuy) buffer with
                | Some last -> last + 1
                | None -> 0

            ret, errno, Array.sub buffer 0 changed
        finally
            Marshal.FreeHGlobal storage

    [<Test>]
    let ``the model answers every capacity as the host's gethostname does`` () : unit =
        let platform =
            match HostPlatform.flavour () with
            | Some flavour -> HostPlatform.platformOf flavour
            | None -> Assert.Ignore "the library models no such host"; failwith "unreachable"

        let name =
            let _, _, placed = host 1024
            let length = Array.IndexOf (placed, 0uy)

            if length < 0 then
                failwith "the host's name is not terminated in 1024 bytes"

            match UnixByteString.ofBytes (ImmutableArray.Create<byte> placed.[.. length - 1]) with
            | Ok name -> name
            | Error defect -> failwith $"unreachable: %s{UnixByteString.describe defect}"

        let system =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithHostName name
            |> Configured.expectOk HostNameRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let length = (UnixByteString.toBytes name).Length

        let capacities =
            [ 1 .. length + 3 ] @ [ 63 ; 64 ; 65 ; 66 ; 255 ; 256 ; 257 ; 258 ; 1024 ]
            |> List.filter (fun capacity -> capacity >= 1)
            |> List.distinct

        let mismatches =
            [
                for capacity in capacities do
                    let ret, errno, placed = host capacity

                    let expected =
                        match
                            UnixHostName.tryGetHostName
                                (Callers.thread 0 system)
                                UserBuffer.Mapped
                                (uint64 capacity)
                                system
                        with
                        | Ok (GetHostNameAnswer.Returned placed) -> Ok (0, 0, placed.ToArray ())
                        | Ok (GetHostNameAnswer.Failed (placed, error)) ->
                            Ok (-1, UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) error, placed.ToArray ())
                        | Error refusal -> Error (GetHostNameRefusal.describe refusal)

                    match expected with
                    | Ok expected when expected = (ret, errno, placed) -> ()
                    | other ->
                        yield $"capacity %d{capacity}: host %A{(ret, errno, placed)}, model %A{other}"
            ]

        mismatches |> shouldEqual []
