namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What a transfer into or out of a large regular file costs, as the bytes it
/// allocates: a write, a truncation or a read must cost in proportion to the
/// bytes it moves, not to the length of the file it moves them in.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFileContentsCost =

    let private sixteenMebibytes : int = 16 * 1024 * 1024

    /// A machine whose root holds `/f`, `length` bytes of 0xAB, open read-write
    /// as the returned descriptor.
    let private withFile (length : int) : int * UnixSystem<int, string> =
        let contents = ImmutableArray.CreateRange (Array.create length 0xABuy)

        let system = InotifyReplay.boot InotifyReplay.root [ "f", SeedEntry.file contents ]

        InotifyReplay.openFd (InotifyReplay.openFlags FileAccessMode.ReadWrite false false false) "/f" 0 system

    /// A whole `pwrite(2)` of `bytes` at `offset`, made once through the public
    /// protocol: `WriteOutcomes.admitThenPwrite` makes it twice and compares
    /// the two systems, which is a cost of the test rather than of the write.
    let private pwrite
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (offset : int64)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match
            UnixReadWrite.tryPwrite (Callers.leader system) fd UserBuffer.Mapped (uint64 bytes.Length) offset system
            |> CallProgress.resumeWith (fun paused -> UnixReadWrite.tryPwriteWithBytes bytes paused)
        with
        | Ok (WriteAnswer.Completed written, system) when written = int64 bytes.Length -> system
        | other -> failwith $"pwrite of %d{bytes.Length} bytes at %d{offset}: %A{other}"

    /// The bytes `f` allocates on this thread, beside what it answers.
    let private allocatedBy<'a> (f : unit -> 'a) : 'a * int64 =
        let before = GC.GetAllocatedBytesForCurrentThread ()
        let result = f ()
        result, GC.GetAllocatedBytesForCurrentThread () - before

    [<Test>]
    let ``appending to a large file allocates in proportion to the bytes appended`` () : unit =
        let fd, system = withFile sixteenMebibytes
        let page = ImmutableArray.CreateRange (Array.create 4096 0xCDuy)

        // A write that copied the file would allocate 16 MiB apiece.
        let system, allocated =
            allocatedBy (fun () ->
                (system, [ 0..7 ])
                ||> List.fold (fun system i ->
                    pwrite fd page (int64 sixteenMebibytes + int64 (i * page.Length)) system
                )
            )

        if allocated > 1024L * 1024L then
            failwith $"eight 4 KiB appends to a 16 MiB file allocated %d{allocated} bytes"

        match PReadUnchanged.pread fd UserBuffer.Mapped 8UL (int64 sixteenMebibytes - 4L) system with
        | Ok (ReadAnswer.Completed bytes) ->
            List.ofSeq bytes
            |> shouldEqual [ 0xABuy ; 0xABuy ; 0xABuy ; 0xABuy ; 0xCDuy ; 0xCDuy ; 0xCDuy ; 0xCDuy ]
        | other -> failwith $"pread: %A{other}"

    [<Test>]
    let ``a write into the middle of a large file allocates in proportion to the bytes written`` () : unit =
        let fd, system = withFile sixteenMebibytes
        let bytes = ImmutableArray.CreateRange [ 1uy ; 2uy ; 3uy ]

        let _, allocated =
            allocatedBy (fun () -> pwrite fd bytes (int64 (sixteenMebibytes / 2)) system)

        if allocated > 256L * 1024L then
            failwith $"a three-byte write into a 16 MiB file allocated %d{allocated} bytes"

    [<Test>]
    let ``extending a file by truncation allocates nothing in proportion to the new length`` () : unit =
        let fd, system = withFile 0

        let system, allocated =
            allocatedBy (fun () -> InotifyReplay.ftruncate fd (256L * 1024L * 1024L) system)

        if allocated > 1024L * 1024L then
            failwith $"ftruncate of an empty file to 256 MiB allocated %d{allocated} bytes"

        // And what the extension made reads as zero, anywhere in it.
        match PReadUnchanged.pread fd UserBuffer.Mapped 4UL (200L * 1024L * 1024L) system with
        | Ok (ReadAnswer.Completed bytes) -> List.ofSeq bytes |> shouldEqual [ 0uy ; 0uy ; 0uy ; 0uy ]
        | other -> failwith $"pread: %A{other}"

    [<Test>]
    let ``a short read from a large file allocates in proportion to the bytes read`` () : unit =
        let fd, system = withFile sixteenMebibytes

        let answer, allocated =
            allocatedBy (fun () -> PReadUnchanged.pread fd UserBuffer.Mapped 16UL (int64 (sixteenMebibytes / 3)) system)

        if allocated > 1024L * 1024L then
            failwith $"a 16-byte read from a 16 MiB file allocated %d{allocated} bytes"

        match answer with
        | Ok (ReadAnswer.Completed bytes) -> bytes.Length |> shouldEqual 16
        | other -> failwith $"pread: %A{other}"
