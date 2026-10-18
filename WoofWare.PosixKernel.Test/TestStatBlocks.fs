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

/// `st_blksize` and `st_blocks` as `stat` and `fstat` report them: the rows
/// `stat-blocks.c` measured (`docs/probes/stat-blocks/`), replayed on both
/// flavours; a regular file's against the pages a reference says its history
/// left holding data; and the same histories run against this host's kernel.
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
        match Answered.openPath creating (UnixPath.parseOrFail context path) 0o644 system with
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

    let private inodeOf (fd : int) (system : UnixSystem<int, string>) : InodeNumber =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.File (inode, _)) -> inode
        | other -> failwith $"fd %d{fd} is %A{other}, not a regular file"

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
    /// pages it leaves holding data: a write of at least a byte fills every
    /// page it touches, and a truncation empties every page wholly past its
    /// new end.
    let private reference (ops : FileAllocationOp list) : int64 * Set<int64> =
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
        )

    /// What a history leaves `fstat` reporting as `(st_blksize, st_blocks)`
    /// on the flavour's default filesystem, or `None` where `fstat` refuses:
    /// on tmpfs 8 per page holding data; on APFS the same, but only for a file
    /// with no hole.
    let private expected (flavour : SimulatedUnixFlavour) (ops : FileAllocationOp list) : (int64 * int64) option =
        let length, held = reference ops
        let blocks = 8L * int64 held.Count

        match flavour with
        | SimulatedUnixFlavour.Linux -> Some (4096L, blocks)
        | SimulatedUnixFlavour.Darwin ->
            let pages = (length + 4095L) / 4096L

            if int64 held.Count = pages then
                Some (4096L, blocks)
            else
                None

    let private modelAllocation
        (flavour : SimulatedUnixFlavour)
        (fd : int)
        (system : UnixSystem<int, string>)
        : (int64 * int64) option
        =
        match fstatOf fd system with
        | Ok (FileStatusAnswer.Reported status) -> Some (status.IoBlockSize, status.AllocatedBlocks)
        | Error (FStatRefusal.HoleOnApfs inode) when flavour = SimulatedUnixFlavour.Darwin ->
            inode |> shouldEqual (inodeOf fd system)
            None
        | other -> failwith $"fstat on %O{flavour}: %A{other}"

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
            ]

    let private historyGen : Gen<FileAllocationOp list> =
        Gen.choose (0, 10) |> Gen.bind (fun n -> Gen.listOfLength n opGen)

    [<Test>]
    let ``a regular file reports 8 blocks for each page holding data, and Darwin refuses a hole`` () : unit =
        let property (ops : FileAllocationOp list) : unit =
            for platform in [ linux ; darwin ] do
                let flavour = SimulatedUnixPlatform.flavour platform
                let fd, system = create "/f" (defaultSystemOn platform)
                let system = List.fold (applyToModel fd) system ops

                let model = modelAllocation flavour fd system

                if model <> expected flavour ops then
                    failwith $"%A{ops} on %O{flavour}: the reference says %A{expected flavour ops}, the model %A{model}"

                // `stat` of the path answers as `fstat` of the descriptor.
                match lstatOf "/f" system, model with
                | Ok (FileStatusAnswer.Reported status), Some allocation ->
                    (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual allocation
                | Error (StatRefusal.HoleOnApfs inode), None -> inode |> shouldEqual (inodeOf fd system)
                | other -> failwith $"%A{ops} on %O{flavour}: stat answered %A{other}"

        Check.One (config, Prop.forAll (Arb.fromGen historyGen) property)

    [<Test>]
    let ``Darwin's refusal of a hole is unmodelled, and the public stat raises it`` () : unit =
        let fd, system = create "/f" (defaultSystemOn darwin)
        let system = applyToModel fd system (FileAllocationOp.Write (8192L, 1))
        let inode = inodeOf fd system

        StatRefusal.kind (StatRefusal.HoleOnApfs inode)
        |> shouldEqual RefusalKind.Unmodelled

        FStatRefusal.kind (FStatRefusal.HoleOnApfs inode)
        |> shouldEqual RefusalKind.Unmodelled

        Assert.Throws<UnmodelledException> (fun () ->
            UnixPathResolution.fstat (Callers.leader system) fd system
            |> ignore<FileStatusAnswer>
        )
        |> ignore<UnmodelledException>

        Assert.Throws<UnmodelledException> (fun () ->
            UnixPathResolution.stat (Callers.leader system) SymlinkPolicy.Follow (PathArg.ofText "/f") system
            |> ignore<FileStatusAnswer>
        )
        |> ignore<UnmodelledException>

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

    let private fields (status : FileStatus) : int64 * int64 * int64 =
        status.Size, status.IoBlockSize, status.AllocatedBlocks

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
    let ``every hole the probe made reports what each kernel did, or Darwin refuses one that moved`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform

            for name, ops in holes do
                let fd, system = create "/f" (defaultSystemOn platform)
                let system = List.fold (applyToModel fd) system ops

                let readings =
                    holeReadings
                    |> List.map (fun suffix -> measured flavour $"HOLE %s{name}%s{suffix}")

                match fstatOf fd system with
                | Ok (FileStatusAnswer.Reported status) ->
                    for reading in readings do
                        if reading <> Some (fields status) then
                            failwith
                                $"%s{name} on %O{flavour}: measured %A{readings}, the model reports %A{fields status}"
                // Every hole here has data before or after it, or is one
                // `ftruncate` made, which stayed at 0 but need not have.
                | Error (FStatRefusal.HoleOnApfs _) when flavour = SimulatedUnixFlavour.Darwin -> ()
                | other -> failwith $"%s{name} on %O{flavour}: %A{other}"

    [<Test>]
    let ``a dense file of 16 MiB reports a block per 512 bytes`` () : unit =
        for platform in [ linux ; darwin ] do
            let flavour = SimulatedUnixPlatform.flavour platform
            let fd, system = create "/f" (defaultSystemOn platform)
            let system = applyToModel fd system (FileAllocationOp.Write (0L, 16 * 1048576))

            Some (fstatOf fd system |> reported "fstat" |> fields)
            |> shouldEqual (measured flavour "FILE dense_16MiB")

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

                    Some (lstatOf path system |> reported "lstat" |> fields)
                    |> shouldEqual (Some row)

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
                    (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual (blksize, blocks)
                | None -> failwith $"the probe could not stat a directory of %d{names} names"

    [<Test>]
    let ``a fresh file and a device report a block size and no blocks`` () : unit =
        // Measured by stat-fields.c: 4096 and 0 for a fresh regular file on
        // both, and for Linux's /dev/null.
        for platform in [ linux ; darwin ] do
            let fd, system = create "/f" (defaultSystemOn platform)
            let status = fstatOf fd system |> reported "fstat"
            (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual (4096L, 0L)

        let status =
            lstatOf "/dev/null" (defaultSystemOn linux) |> reported "lstat /dev/null"

        (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual (4096L, 0L)

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
        fstatOf fd system |> reported $"fstat %d{fd}" |> fields

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
    let ``every inode on an NFS mount is refused, and the device filesystem answers`` () : unit =
        for platform in [ linux ; darwin ] do
            let fd, system = create "/f" (systemOn platform EmulatedFileSystemType.Nfs)
            let inode = inodeOf fd system

            fstatOf fd system |> shouldEqual (Error (FStatRefusal.OnNfsMount inode))
            lstatOf "/f" system |> shouldEqual (Error (StatRefusal.OnNfsMount inode))

            match Eager.trySymlink (PathArg.ofText "f") (PathArg.ofText "/l") system with
            | Ok (SyscallAnswer.Completed _, system) ->
                match lstatOf "/l" system with
                | Error (StatRefusal.OnNfsMount _) -> ()
                | other -> failwith $"lstat of a symbolic link on NFS on %O{platform}: %A{other}"
            | other -> failwith $"symlink: %A{other}"

            StatRefusal.kind (StatRefusal.OnNfsMount inode)
            |> shouldEqual RefusalKind.Unmodelled

        let system = systemOn linux EmulatedFileSystemType.Nfs
        let status = lstatOf "/dev/null" system |> reported "lstat /dev/null"
        (status.IoBlockSize, status.AllocatedBlocks) |> shouldEqual (4096L, 0L)

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

                        let system = applyToModel fd system op

                        // A Darwin refusal is the one answer no host reading
                        // can check: it says the host's answer will move.
                        match modelAllocation flavour fd system with
                        | None -> ()
                        | Some model ->
                            let host = HostStat.fstat flavour hostFd

                            if (host.IoBlockSize, host.AllocatedBlocks) <> model then
                                failwith
                                    $"%A{ops}, after %A{op}: this %O{flavour} host reports (%d{host.IoBlockSize}, %d{host.AllocatedBlocks}), the model %A{model}"

                        system
                    )
                    |> ignore<UnixSystem<int, string>>
                finally
                    HostCalls.close hostFd |> ignore<int>
                    File.Delete path

            Check.One (config.WithMaxTest 100, Prop.forAll (Arb.fromGen historyGen) property)
        )
