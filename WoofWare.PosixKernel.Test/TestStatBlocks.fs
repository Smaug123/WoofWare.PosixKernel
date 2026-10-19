namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Runtime.InteropServices
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// One change to a regular file's contents.
[<RequireQualifiedAccess>]
type FileAllocationOp =
    /// `pwrite(2)` of `count` bytes at `offset`.
    | Write of offset : int64 * count : int
    /// `ftruncate(2)` to `length`.
    | Truncate of length : int64
    /// `pwrite(2)` of `count` bytes at `offset` from a NULL buffer, which
    /// faults as it is copied and answers EFAULT.
    | FaultedWrite of offset : int64 * count : int

/// `st_blksize` and `st_blocks` as `stat` and `fstat` report them: the rows
/// `stat-blocks.c` measured (`docs/probes/stat-blocks/`), replayed on both
/// flavours; a regular file's against the pages a reference says its history
/// left allocated, and where it states none; and the same histories run
/// against this host's kernel.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestStatBlocks =

    let private context : string = "TestStatBlocks"

    let private linux : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64
    let private darwin : SimulatedUnixPlatform = SimulatedUnixPlatform.macOsArm64

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    // ------------------------------------------------------------ the model

    let private creating : OpenFlags =
        {
            Access = FileAccessMode.ReadWrite
            Create = true
            Exclusive = true
            Truncate = false
            NoFollow = false
            CloseOnExec = false
            Synchronous = false
            DataSynchronous = false
            Directory = false
        }

    let private systemOn
        (platform : SimulatedUnixPlatform)
        (fsType : EmulatedFileSystemType)
        : UnixSystem<int, string>
        =
        let image : UnixBootImage<int, string> = UnixSystem.initial platform

        image
        |> UnixBootImage.tryWithMount (Some (EmulatedMount.defaultOf fsType))
        |> Configured.expectOk MountRefusal.describe
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private defaultSystemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        systemOn platform (EmulatedFileSystemType.defaultFor (SimulatedUnixPlatform.flavour platform))

    let private payload (count : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Array.init count (fun i -> byte (i % 251 + 1)))

    let private create (path : string) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match Answered.openPath (UnixPath.parseOrFail context path) creating 0o644 system with
        | SyscallAnswer.Completed fd, system -> int fd, system
        | SyscallAnswer.Failed error, _ -> failwith $"creat %s{path}: %O{error}"

    let private applyToModel
        (fd : int)
        (system : UnixSystem<int, string>)
        (op : FileAllocationOp)
        : UnixSystem<int, string>
        =
        match op with
        | FileAllocationOp.Write (offset, count) ->
            match WriteOutcomes.admitThenPwrite 0 fd (payload count) offset system with
            | Ok (WriteAnswer.Completed written, system) when int written = count -> system
            | other -> failwith $"pwrite of %d{count} at %d{offset}: %A{other}"
        | FileAllocationOp.Truncate length ->
            match UnixDescriptor.tryFtruncate (Callers.leader system) fd length system with
            | Ok (SyscallAnswer.Completed _, system) -> system
            | other -> failwith $"ftruncate to %d{length}: %A{other}"
        | FileAllocationOp.FaultedWrite (offset, count) ->
            match
                UnixReadWrite.tryPwrite
                    (Callers.leader system)
                    fd
                    (UserBuffer.Unmapped 0UL)
                    (uint64 count)
                    offset
                    system
                |> CallProgress.resumeWith (fun paused -> UnixReadWrite.tryPwriteWithBytes ImmutableArray.Empty paused)
            with
            | Ok (WriteAnswer.Failed UnixError.EFAULT, system) -> system
            | other -> failwith $"pwrite of %d{count} at %d{offset} from NULL: %A{other}"

    let private reported (what : string) (answer : Result<FileStatusAnswer, 'refusal>) : FileStatus =
        match answer with
        | Ok (FileStatusAnswer.Reported status) -> status
        | other -> failwith $"%s{what}: expected a status, got %A{other}"

    let private fstatOf (fd : int) (system : UnixSystem<int, string>) : Result<FileStatusAnswer, FStatRefusal> =
        UnixPathResolution.tryFstat (Callers.leader system) fd system

    let private lstatOf (path : string) (system : UnixSystem<int, string>) : Result<FileStatusAnswer, StatRefusal> =
        UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.NoFollowFinal (PathArg.ofText path) system

    // ----------------------------------------------------------- reference

    /// The length a history leaves the file, and the indices of the 4096-byte
    /// pages it leaves allocated: a write of at least a byte fills every page
    /// it touches; a truncation frees every page from its new end on, even to
    /// the length the file had; and a faulted write makes the file at least
    /// its offset long and, on tmpfs, allocates the page holding the offset,
    /// even one that starts at the end of the file.
    let private reference (flavour : SimulatedUnixFlavour) (ops : FileAllocationOp list) : int64 * Set<int64> =
        ((0L, Set.empty), ops)
        ||> List.fold (fun (length, held) op ->
            match op with
            | FileAllocationOp.Write (_, 0) -> length, held
            | FileAllocationOp.Write (offset, count) ->
                let last = offset + int64 count
                let touched = set [ offset / 4096L .. (last - 1L) / 4096L ]
                max length last, Set.union held touched
            | FileAllocationOp.Truncate newLength ->
                newLength, held |> Set.filter (fun index -> index * 4096L < newLength)
            | FileAllocationOp.FaultedWrite (offset, _) ->
                match flavour with
                | SimulatedUnixFlavour.Linux -> max length offset, Set.add (offset / 4096L) held
                | SimulatedUnixFlavour.Darwin -> max length offset, held
        )

    /// What a history leaves `fstat` reporting as `(st_blksize, st_blocks)` on
    /// the flavour's default filesystem: on tmpfs 8 blocks per page
    /// allocated; on APFS 0 for a file of no bytes, and no `st_blocks` for any
    /// other.
    let private expected (flavour : SimulatedUnixFlavour) (ops : FileAllocationOp list) : int64 option * int64 option =
        let length, held = reference flavour ops

        match flavour with
        | SimulatedUnixFlavour.Linux -> Some 4096L, Some (8L * int64 held.Count)
        | SimulatedUnixFlavour.Darwin -> Some 4096L, (if length = 0L then Some 0L else None)

    let private modelAllocation (fd : int) (system : UnixSystem<int, string>) : int64 option * int64 option =
        let status = fstatOf fd system |> reported "fstat"
        status.IoBlockSize, status.AllocatedBlocks

    let private opGen : Gen<FileAllocationOp> =
        let position =
            Gen.frequency
                [
                    3, Gen.choose (0, 40000) |> Gen.map int64
                    3,
                    Gen.map2 (fun page delta -> int64 (page * 4096 + delta)) (Gen.choose (0, 80)) (Gen.choose (-1, 1))
                    1, Gen.choose (0, 400000) |> Gen.map int64
                ]
            |> Gen.map (max 0L)

        let count =
            Gen.frequency
                [
                    1, Gen.constant 0
                    3, Gen.choose (1, 9000)
                    2, Gen.elements [ 1 ; 4095 ; 4096 ; 4097 ; 8192 ]
                ]

        Gen.frequency
            [
                4, Gen.map2 (fun offset count -> FileAllocationOp.Write (offset, count)) position count
                1, Gen.map FileAllocationOp.Truncate position
                1, Gen.map2 (fun offset count -> FileAllocationOp.FaultedWrite (offset, max 1 count)) position count
            ]

    let private historyGen : Gen<FileAllocationOp list> =
        Gen.choose (0, 10) |> Gen.bind (fun n -> Gen.listOfLength n opGen)

    [<Test>]
    let ``a regular file reports 8 blocks for each page allocated, and Darwin none for a file of data`` () : unit =
        let property (ops : FileAllocationOp list) : unit =
            for platform in [ linux ; darwin ] do
                let flavour = SimulatedUnixPlatform.flavour platform
                let fd, system = create "/f" (defaultSystemOn platform)
                let system = List.fold (applyToModel fd) system ops

                let model = modelAllocation fd system

                if model <> expected flavour ops then
                    failwith $"%A{ops} on %O{flavour}: the reference says %A{expected flavour ops}, the model %A{model}"

                // `stat` of the path answers as `fstat` of the descriptor.
                let status = lstatOf "/f" system |> reported "lstat"
                (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual model

        Check.One (config, Prop.forAll (Arb.fromGen historyGen) property)

    // ------------------------------------------------- the measured outputs

    /// The rows of one `stat-blocks.c` output: each label (the tag and the
    /// object's name) with its `size`, `blksize` and `blocks`, or `None` for a
    /// row the call failed.
    let private measuredRows (flavour : SimulatedUnixFlavour) : Map<string, (int64 * int64 * int64) option> =
        let resource =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.stat-blocks.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.stat-blocks.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"no embedded resource %s{resource}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.choose (fun line ->
            match line.Split '\t' with
            | [| tag ; name ; size ; blksize ; blocks |] when
                size.StartsWith "size="
                && blksize.StartsWith "blksize="
                && blocks.StartsWith "blocks="
                ->
                let value (field : string) =
                    int64 (field.Substring (field.IndexOf '=' + 1))

                Some ($"%s{tag} %s{name}", Some (value size, value blksize, value blocks))
            | [| tag ; name ; failed |] when failed.StartsWith "err=" -> Some ($"%s{tag} %s{name}", None)
            | _ -> None
        )
        |> Map.ofArray

    let private measured (flavour : SimulatedUnixFlavour) (label : string) : (int64 * int64 * int64) option =
        match Map.tryFind label (measuredRows flavour) with
        | Some row -> row
        | None -> failwith $"the %O{flavour} output of stat-blocks.c has no row %s{label}"

    let private fields (status : FileStatus) : int64 * int64 option * int64 option =
        status.Size, status.IoBlockSize, status.AllocatedBlocks

    /// The fields of a status that must state both block fields.
    let private stated (status : FileStatus) : int64 * int64 * int64 =
        match status.IoBlockSize, status.AllocatedBlocks with
        | Some blksize, Some blocks -> status.Size, blksize, blocks
        | other -> failwith $"expected both block fields stated, got %A{other}"

    /// The model's regular file after `ops`, as `(size, blksize, blocks)`.
    let private modelFields
        (platform : SimulatedUnixPlatform)
        (ops : FileAllocationOp list)
        : int64 * int64 option * int64 option
        =
        let fd, system = create "/f" (defaultSystemOn platform)
        let system = List.fold (applyToModel fd) system ops
        fstatOf fd system |> reported $"fstat after %A{ops}" |> fields

    /// The model states what every reading measured, leaving `st_blocks`
    /// unstated only for a Darwin file holding bytes.
    let private agreesWithReadings
        (flavour : SimulatedUnixFlavour)
        (what : string)
        (model : int64 * int64 option * int64 option)
        (readings : (int64 * int64 * int64) option list)
        : unit
        =
        let size, blksize, blocks = model

        let blocksMayBeUnstated = flavour = SimulatedUnixFlavour.Darwin && size > 0L

        let agrees (reading : (int64 * int64 * int64) option) : bool =
            match reading with
            | None -> false
            | Some (s, b, n) ->
                size = s
                && blksize = Some b
                && (blocks = Some n || (blocks.IsNone && blocksMayBeUnstated))

        if not (List.forall agrees readings) then
            failwith $"%s{what} on %O{flavour}: measured %A{readings}, the model %A{model}"

    /// Each hole the probe made, by its name in the output, as the history
    /// that makes it; the probe's `fsync` changes nothing the model holds.
    let private holes : (string * FileAllocationOp list) list =
        let mib = 1048576L

        [
            "extend_to_1MiB", [ FileAllocationOp.Truncate mib ]
            "byte_at_4096", [ FileAllocationOp.Write (4096L, 1) ]
            "byte_at_65536", [ FileAllocationOp.Write (65536L, 1) ]
            "byte_at_1MiB", [ FileAllocationOp.Write (mib, 1) ]
            "byte_at_64MiB", [ FileAllocationOp.Write (64L * mib, 1) ]
            "4096_then_extend_to_1MiB", [ FileAllocationOp.Write (0L, 4096) ; FileAllocationOp.Truncate mib ]
            "4096_then_byte_at_1MiB", [ FileAllocationOp.Write (0L, 4096) ; FileAllocationOp.Write (mib, 1) ]
        ]

    /// The suffixes the probe read each hole under: at once, after `fsync`,
    /// after it had waited, and by path once it had closed.
    let private holeReadings : string list =
        [
            ""
            "_fsync"
            "_after_45s"
            "_fsync_after_45s"
            "_closed"
            "_fsync_closed"
        ]

    [<Test>]
    let ``every hole the probe made reports what each kernel did, at every reading`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            for name, ops in holes do
                let readings =
                    holeReadings
                    |> List.map (fun suffix -> measured flavour $"HOLE %s{name}%s{suffix}")

                agreesWithReadings flavour name (modelFields platform ops) readings

    [<Test>]
    let ``a dense file of 16 MiB reports a block per 512 bytes on Linux`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform
            let model = modelFields platform [ FileAllocationOp.Write (0L, 16 * 1048576) ]
            agreesWithReadings flavour "dense_16MiB" model [ measured flavour "FILE dense_16MiB" ]

    [<Test>]
    let ``a file grown by one-byte appends reports its pages on Linux, and Darwin, which allocated ahead, none``
        ()
        : unit
        =
        // The model's file is the same however the bytes came, so one write
        // stands for the probe's 300000 appends.
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform
            let model = modelFields platform [ FileAllocationOp.Write (0L, 300000) ]

            let readings =
                [ "pwrite" ; "write" ]
                |> List.collect (fun call ->
                    [ 0..2 ]
                    |> List.collect (fun trial ->
                        [
                            measured flavour $"APPEND %s{call}_trial_%d{trial}_end"
                            measured flavour $"APPEND %s{call}_trial_%d{trial}_end_fsync"
                        ]
                    )
                )

            agreesWithReadings flavour "300000 one-byte appends" model readings

            // Not vacuous on Darwin: some trial allocated more than its pages.
            if flavour = SimulatedUnixFlavour.Darwin then
                readings
                |> List.exists (fun reading -> reading <> Some (300000L, 4096L, 592L))
                |> shouldEqual true

    [<Test>]
    let ``a symbolic link reports the blocks its target takes`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform
            let mutable system = defaultSystemOn platform

            for length in [ 126 ; 127 ; 128 ; 129 ; 1000 ; 1022 ; 1023 ; 1024 ; 4095 ] do
                let path = $"/link_%d{length}"

                match measured flavour $"LINK target_%d{length}" with
                | None -> ()
                | Some row ->
                    match Eager.trySymlink (PathArg.ofText (String ('a', length))) (PathArg.ofText path) system with
                    | Ok (SyscallAnswer.Completed _, after) -> system <- after
                    | other -> failwith $"symlink of %d{length} bytes on %O{flavour}: %A{other}"

                    lstatOf path system |> reported "lstat" |> stated |> shouldEqual row

    [<Test>]
    let ``a directory reports no blocks however many names it holds`` () : unit =
        // Measured at 5000 and 20000 names, and by stat-fields.c at 0, 100 and
        // 1000.
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            let fresh = defaultSystemOn platform

            let _, system =
                Answered.mkdir (Callers.leader fresh) (PathArg.ofText "/d") 0o755 fresh

            let system =
                (system, [ 1..50 ])
                ||> List.fold (fun system i ->
                    let fd, system = create $"/d/f%d{i}" system

                    match UnixDescriptor.tryClose (Callers.leader system) fd system with
                    | Ok (SyscallAnswer.Completed _, system) -> system
                    | other -> failwith $"close: %A{other}"
                )

            let status = lstatOf "/d" system |> reported "lstat /d"

            for names in [ 5000 ; 20000 ] do
                match measured flavour $"DIR names_%d{names}" with
                | Some (_, blksize, blocks) ->
                    (status.IoBlockSize, status.AllocatedBlocks)
                    |> shouldEqual (Some blksize, Some blocks)
                | None -> failwith $"the probe could not stat a directory of %d{names} names"

    [<Test>]
    let ``a fresh file and a device report a block size and no blocks`` () : unit =
        // Measured by stat-fields.c: 4096 and 0 for a fresh regular file on
        // both, and for Linux's /dev/null.
        for platform in [ linux ; darwin ] do
            let fd, system = create "/f" (defaultSystemOn platform)
            let status = fstatOf fd system |> reported "fstat"

            (status.IoBlockSize, status.AllocatedBlocks)
            |> shouldEqual (Some 4096L, Some 0L)

        let status =
            lstatOf "/dev/null" (defaultSystemOn linux) |> reported "lstat /dev/null"

        (status.IoBlockSize, status.AllocatedBlocks)
        |> shouldEqual (Some 4096L, Some 0L)

    [<Test>]
    let ``a write whose buffer faults leaves what each kernel did`` () : unit =
        let shapes =
            [
                "empty", 0L, []
                "dense", 4096L, [ FileAllocationOp.Write (0L, 4096) ]
                "dense", 5000L, [ FileAllocationOp.Write (0L, 5000) ]
                "extended", 20000L, [ FileAllocationOp.Truncate 20000L ]
            ]

        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            for shape, size, setup in shapes do
                for offset in [ 0L ; 1000L ; 4096L ; 5000L ; 8192L ; 12288L ; 100000L ] do
                    for count in [ 1 ; 10000 ] do
                        let name = $"%s{shape}_%d{size}_at_%d{offset}_count_%d{count}"

                        // A NULL buffer and a PROT_NONE page measured alike;
                        // the model is given NULL.
                        let readings =
                            [ "null" ; "protnone" ]
                            |> List.collect (fun buffer ->
                                [
                                    measured flavour $"FAULT %s{name}_%s{buffer}_ret=-1_errno=14"
                                    measured flavour $"FAULT %s{name}_%s{buffer}_fsync"
                                ]
                            )

                        let model =
                            modelFields platform (setup @ [ FileAllocationOp.FaultedWrite (offset, count) ])

                        agreesWithReadings flavour name model readings

    [<Test>]
    let ``what a faulted write allocated past the end goes as each kernel's did`` () : unit =
        let step (text : string) : FileAllocationOp =
            let n = int64 (text.Substring 1)

            match text.[0] with
            | 'w' -> FileAllocationOp.Write (0L, int n)
            | 'f' -> FileAllocationOp.FaultedWrite (n, 1)
            | 't' -> FileAllocationOp.Truncate n
            | 'p' -> FileAllocationOp.Write (n, 1)
            | other -> failwith $"no history step starts %c{other}"

        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            let histories =
                measuredRows flavour
                |> Map.keys
                |> Seq.filter (fun label -> label.StartsWith "HISTORY ")
                |> List.ofSeq

            histories.Length |> shouldEqual 14

            for label in histories do
                let ops =
                    label.Substring("HISTORY ".Length).Split ' ' |> Array.map step |> List.ofArray

                agreesWithReadings flavour label (modelFields platform ops) [ measured flavour label ]

    // ---------------------------------------------------------------- pipes

    let private pipeOn (system : UnixSystem<int, string>) : (int * int) * UnixSystem<int, string> =
        match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
        | Ok (Pipe2Answer.Created (readFd, writeFd), system) -> (readFd, writeFd), system
        | other -> failwith $"pipe2: %A{other}"

    let private writePipe (fd : int) (count : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match
            WriteOutcomes.admitThenWriteAs (Caller.make (Lone.pid system) 0) fd UserBuffer.Mapped (payload count) system
            |> WriteOutcomes.returned
        with
        | Ok (WriteAnswer.Completed written, system) when int written = count -> system
        | other -> failwith $"write of %d{count} to a pipe: %A{other}"

    let private readPipe (fd : int) (count : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixReadWrite.tryRead (Callers.leader system) fd UserBuffer.Mapped (uint64 count) system with
        | Ok (ReadOutcome.Answered (ReadAnswer.Completed _), system) -> system
        | other -> failwith $"read of %d{count} from a pipe: %A{other}"

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed _, system) -> system
        | other -> failwith $"close %d{fd}: %A{other}"

    let private pipeFields (fd : int) (system : UnixSystem<int, string>) : int64 * int64 * int64 =
        fstatOf fd system |> reported $"fstat %d{fd}" |> stated

    /// The probe's pipe readings the model can repeat, each with what the
    /// model reports for it. The probe's writes are non-blocking, and each
    /// here is one the probe recorded as complete.
    let private pipeReadings (platform : SimulatedUnixPlatform) : (string * (int64 * int64 * int64)) list =
        let system = defaultSystemOn platform

        let (r, w), system = pipeOn system

        let empty =
            [
                "PIPE read_end_empty", pipeFields r system
                "PIPE write_end_empty", pipeFields w system
            ]

        let system = writePipe w 100 system

        let holding100 =
            [
                "PIPE read_end_holding_100", pipeFields r system
                "PIPE write_end_holding_100", pipeFields w system
            ]

        let system = writePipe w 20000 system

        let holding20100 =
            [
                "PIPE read_end_holding_20100", pipeFields r system
                "PIPE write_end_holding_20100", pipeFields w system
            ]

        let system = readPipe r 70000 system
        let drained = [ "PIPE read_end_drained", pipeFields r system ]
        let system = close w system
        let writerClosed = [ "PIPE read_end_drained_writer_closed", pipeFields r system ]
        let system = close r system

        let (r, w), system = pipeOn system
        let system = writePipe w 16384 system
        let oneWrite = [ "PIPE one_write_16384", pipeFields r system ]
        let system = system |> close r |> close w

        let (r, w), system = pipeOn system
        let system = writePipe w 100 system |> close r

        let readerClosed100 =
            [ "PIPE write_end_holding_100_reader_closed", pipeFields w system ]

        let system = close w system

        let (r, w), system = pipeOn system
        let system = writePipe w 20000 system |> close r

        let readerClosed =
            [ "PIPE write_end_holding_20000_reader_closed", pipeFields w system ]

        let system = close w system

        let (r, w), system = pipeOn system
        let system = writePipe w 20000 system |> close w

        let writerClosedHolding =
            [ "PIPE read_end_holding_20000_writer_closed", pipeFields r system ]

        List.concat
            [
                empty
                holding100
                holding20100
                drained
                writerClosed
                oneWrite
                readerClosed100
                readerClosed
                writerClosedHolding
            ]

    [<Test>]
    let ``a pipe reports what each kernel did as its buffer grows and its ends close`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            for label, model in pipeReadings platform do
                if measured flavour label <> Some model then
                    failwith $"%s{label} on %O{flavour}: measured %A{measured flavour label}, the model %A{model}"

    // ------------------------------------------------------------------ NFS

    [<Test>]
    let ``nothing on an NFS mount states a block size or blocks, and the device filesystem does`` () : unit =
        for platform in [ linux ; darwin ] do
            let fd, system = create "/f" (systemOn platform EmulatedFileSystemType.Nfs)
            let system = applyToModel fd system (FileAllocationOp.Write (0L, 5000))

            match Eager.trySymlink (PathArg.ofText "f") (PathArg.ofText "/l") system with
            | Ok (SyscallAnswer.Completed _, system) ->
                for status in
                    [
                        fstatOf fd system |> reported "fstat /f"
                        lstatOf "/f" system |> reported "lstat /f"
                        lstatOf "/l" system |> reported "lstat /l"
                    ] do
                    (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual (None, None)
            | other -> failwith $"symlink on %O{platform}: %A{other}"

        let system = systemOn linux EmulatedFileSystemType.Nfs
        let status = lstatOf "/dev/null" system |> reported "lstat /dev/null"

        (status.IoBlockSize, status.AllocatedBlocks)
        |> shouldEqual (Some 4096L, Some 0L)

    // ------------------------------------------------------------- the host

    let private hostPwrite (fd : int) (offset : int64) (count : int) : unit =
        if HostCalls.lseek (fd, offset, 0) <> offset then
            failwith $"host lseek to %d{offset} failed: errno %d{Marshal.GetLastPInvokeError ()}"

        let bytes = (payload count).AsSpan().ToArray ()

        if HostCalls.write (fd, bytes, unativeint count) <> nativeint count then
            failwith $"host write of %d{count} failed: errno %d{Marshal.GetLastPInvokeError ()}"

    [<Test>]
    let ``a regular file's history agrees with this host's kernel`` () : unit =
        HostStat.onMeasuredHost (fun flavour ->
            let hostBase =
                match HostFileSystemType.directoryOfDefaultType flavour with
                | Some directory -> directory
                | None ->
                    Assert.Ignore
                        $"this %O{flavour} host has no %O{EmulatedFileSystemType.defaultFor flavour} directory to measure"

                    failwith "unreachable: Assert.Ignore throws"

            let platform = HostPlatform.platformOf flavour

            let property (ops : FileAllocationOp list) : unit =
                let unique = Guid.NewGuid().ToString "N"
                let path = Path.Combine (hostBase, $"posixkernel-blocks-%s{unique}")
                File.Create(path).Dispose ()
                // O_RDWR, which is 2 on both.
                let hostFd = HostCalls.openFile (path, 2, 0)

                if hostFd < 0 then
                    failwith $"host open of %s{path} failed: errno %d{Marshal.GetLastPInvokeError ()}"

                try
                    let fd, system = create "/f" (defaultSystemOn platform)

                    (system, ops)
                    ||> List.fold (fun system op ->
                        match op with
                        | FileAllocationOp.Write (offset, count) ->
                            if count > 0 then
                                hostPwrite hostFd offset count
                        | FileAllocationOp.Truncate length ->
                            if HostCalls.ftruncate (hostFd, length) <> 0 then
                                failwith $"host ftruncate failed: errno %d{Marshal.GetLastPInvokeError ()}"
                        | FileAllocationOp.FaultedWrite (offset, count) ->
                            if HostCalls.lseek (hostFd, offset, 0) <> offset then
                                failwith $"host lseek to %d{offset} failed: errno %d{Marshal.GetLastPInvokeError ()}"

                            if HostCalls.writePointer (hostFd, 0n, unativeint count) <> -1n then
                                failwith $"host write of %d{count} from NULL did not fail"

                        let system = applyToModel fd system op

                        // A field the model leaves unstated is the one answer no
                        // host reading can check: it says the host's answer
                        // depends on what the model does not follow.
                        let blksize, blocks = modelAllocation fd system
                        let host = HostStat.fstat flavour hostFd

                        let agrees (model : int64 option) (host : int64 option) : bool = model.IsNone || model = host

                        if not (agrees blksize host.IoBlockSize && agrees blocks host.AllocatedBlocks) then
                            failwith
                                $"%A{ops}, after %A{op}: this %O{flavour} host reports (%A{host.IoBlockSize}, %A{host.AllocatedBlocks}), the model (%A{blksize}, %A{blocks})"

                        system
                    )
                    |> ignore<UnixSystem<int, string>>
                finally
                    HostCalls.close hostFd |> ignore<int>
                    File.Delete path

            Check.One (config.WithMaxTest 100, Prop.forAll (Arb.fromGen historyGen) property)
        )
