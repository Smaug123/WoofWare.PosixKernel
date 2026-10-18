namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which calls move a file's access time, held to `docs/probes/atime`, which
/// made each call on a fresh file whose times it first put in a chosen state,
/// and recorded whether `st_atime` moved.
///
/// The model's Linux root filesystem is a tmpfs mounted `noatime` (its
/// `statfs(2)` says so), so the Linux rows replayed are the probe's
/// `tmpfs-noatime` ones; its Darwin root filesystem is an APFS volume with its
/// default options, so the Darwin rows are those of a Mac's data volume.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestAccessTime =

    let private context : string = "TestAccessTime"

    // ------------------------------------------------------------ the probe's rows

    /// One row of the probe: the state its target was put in, the call, what
    /// the call returned (or -errno), and whether the target's atime moved.
    type private Row =
        {
            State : string
            Op : string
            Ret : int64
            Moved : bool
        }

    let private rowsOf (resource : string) (label : string) : Row list =
        use stream = Assembly.GetExecutingAssembly().GetManifestResourceStream resource

        if isNull stream then
            failwith $"%s{context}: no embedded resource %s{resource}"

        use reader = new StreamReader (stream)

        let field (fields : string array) (key : string) : string =
            match fields |> Array.tryFind (fun f -> f.StartsWith (key + "=")) with
            | Some f -> f.Substring (key.Length + 1)
            | None -> failwith $"%s{context}: no %s{key}= in %A{fields}"

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.filter (fun line -> not (line.StartsWith "#"))
        |> Array.map (fun line -> line.Split ' ')
        |> Array.filter (fun fields -> fields.[0] = label)
        |> Array.map (fun fields ->
            {
                State = fields.[1]
                Op = fields.[2]
                Ret = int64 (field fields "ret")
                Moved = field fields "moved" = "1"
            }
        )
        |> List.ofArray

    let private linuxRows : Lazy<Row list> =
        lazy (rowsOf "WoofWare.PosixKernel.Test.atime.linux.txt" "tmpfs-noatime")

    let private darwinRows : Lazy<Row list> =
        lazy (rowsOf "WoofWare.PosixKernel.Test.atime.darwin-data.txt" "apfs-data")

    // ------------------------------------------------------------ the probe's cell

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private uid (n : uint32) : UserId = UserId.parseOrFail context n
    let private gid (n : uint32) : GroupId = GroupId.parseOrFail context n

    /// The probe's caller: uid 1000 on Linux, uid 501 on Darwin.
    let private credentialsFor (platform : SimulatedUnixPlatform) : Credentials =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> Credentials.ofIds (uid 1000u) (gid 1000u) []
        | SimulatedUnixFlavour.Darwin -> Credentials.ofIds (uid 501u) (gid 20u) []

    let private bootTime : UnixTimestamp =
        UnixTimestamp.createOrFail context 1_790_000_000L 0

    /// How long the probe slept between steps.
    let private nap : int64 = 30_000_000L

    /// What the probe's consecutive calls took, at least: enough that a write
    /// after a creation leaves the file's mtime after its atime.
    let private tick : int64 = 1_000L

    let private flags (platform : SimulatedUnixPlatform) (create : bool) : int =
        match SimulatedUnixPlatform.flavour platform, create with
        | _, false -> 0
        // O_WRONLY | O_CREAT | O_EXCL.
        | SimulatedUnixFlavour.Linux, true -> 0x1 ||| 0x40 ||| 0x80
        | SimulatedUnixFlavour.Darwin, true -> 0x1 ||| 0x200 ||| 0x800

    let private writeOnly : int = 0x1

    /// An address no call can copy into or out of, in the user half on both.
    let private protNone : UserBuffer = UserBuffer.Unmapped 0x0000_7000_0000_0000UL

    let private kernelHalf : UserBuffer = UserBuffer.Unmapped 0xFFFF_FFFF_FFFF_F000UL

    let private timespec (seconds : int64) (nanoseconds : int64) : TimespecFields =
        {
            Seconds = seconds
            Nanoseconds = nanoseconds
        }

    type private Cell =
        {
            Platform : SimulatedUnixPlatform
            System : UnixSystem<int, string>
        }

    let private leader (cell : Cell) : Caller<int> = Callers.leader cell.System

    let private step (cell : Cell) (call : Syscall<int, string>) : SteppedCall<int, string> =
        UnixSystem.step (leader cell) call cell.System

    /// A stepped call's case and its first field, without the system.
    let private brief (stepped : SteppedCall<int, string>) : string =
        match Stepped.view stepped with
        | case, first :: _ -> $"%s{case} %A{first}"
        | case, [] -> case

    let private advance (nanoseconds : int64) (cell : Cell) : Cell =
        { cell with
            System = UnixSystem.advanceClock nanoseconds cell.System
        }

    let private path (text : string) : PathArgumentBytes = PathArg.ofText text

    let private openFile (cell : Cell) (target : string) (word : int) : int * Cell =
        match step cell (Syscall.Open (path target, word, 0o644)) with
        | SteppedCall.Open (OpenOutcome.Answered (DescriptorAnswer.Returned fd), system) ->
            fd,
            { cell with
                System = system
            }
        | other -> failwith $"%s{context}: open(%s{target}) answered %s{brief other}"

    let private close (fd : int) (cell : Cell) : Cell =
        match step cell (Syscall.Close fd) with
        | SteppedCall.Close (SyscallAnswer.Completed _, system) ->
            { cell with
                System = system
            }
        | other -> failwith $"%s{context}: close(%d{fd}) answered %s{brief other}"

    let private pwrite (fd : int) (bytes : byte array) (offset : int64) (cell : Cell) : Cell =
        let data = ImmutableArray.CreateRange bytes

        match step cell (Syscall.PWrite (fd, CopiedArgument.Readable data, uint64 bytes.Length, offset)) with
        | SteppedCall.PWrite (WriteAnswer.Completed _, system) ->
            { cell with
                System = system
            }
        | other -> failwith $"%s{context}: pwrite(%d{fd}) answered %s{brief other}"

    let private status (cell : Cell) (policy : SymlinkPolicy) (target : string) : FileStatus =
        match step cell (Syscall.Stat (policy, path target)) with
        | SteppedCall.Stat (FileStatusAnswer.Reported status) -> status
        | other -> failwith $"%s{context}: stat(%s{target}) answered %s{brief other}"

    let private numbering (platform : SimulatedUnixPlatform) : RawErrnoNumbering =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> RawErrnoNumbering.Linux
        | SimulatedUnixFlavour.Darwin -> RawErrnoNumbering.Darwin

    let private failed (cell : Cell) (error : UnixError) : int64 =
        -(int64 (UnixError.toRawErrnoUnder (numbering cell.Platform) error))

    let private syscallRet (cell : Cell) (answer : SyscallAnswer) : int64 =
        match answer with
        | SyscallAnswer.Completed n -> n
        | SyscallAnswer.Failed error -> failed cell error

    let private readRet (cell : Cell) (answer : ReadAnswer) : int64 =
        match answer with
        | ReadAnswer.Completed bytes -> int64 bytes.Length
        | ReadAnswer.Failed error -> failed cell error
        | ReadAnswer.Drawn _ -> failwith $"%s{context}: a file read drew from the entropy pool"

    /// The probe's fixture in `/w`, which the caller owns: `f` (4096 bytes),
    /// `e` (empty), `d` holding `x`, and `l -> f`, each made as the probe made
    /// it, a little apart.
    let private fixture (platform : SimulatedUnixPlatform) : Cell =
        let credentials = credentialsFor platform

        let owner : InodeOwner =
            {
                User = credentials.EffectiveUser
                Group = credentials.EffectiveGroup
            }

        let seed =
            Map.ofList
                [
                    name "w", SeedEntry.Directory (Map.empty, PermissionBits.parseOrFail context 0o755, Some owner)
                ]

        let image =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithBootTime bootTime
            |> Configured.expectOk BootTimeRefusal.describe

        let system =
            match UnixBootImage.tryWithFileSystem bootTime (InodeOwner.ofProcess Owners.root) seed image with
            | Ok image ->
                Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0) image
            | Error fault -> failwith $"%s{context}: could not seed: %A{fault}"

        let cell =
            {
                Platform = platform
                System = system
            }
            |> advance nap

        let fd, cell = openFile cell "/w/f" (flags platform true)
        let cell = advance tick cell |> pwrite fd (Array.create 4096 (byte 'x')) 0L
        let cell = close fd cell |> advance tick
        let fd, cell = openFile cell "/w/e" (flags platform true)
        let cell = close fd cell |> advance tick

        let cell =
            match step cell (Syscall.MkDir (path "/w/d", 0o755)) with
            | SteppedCall.MkDir (SyscallAnswer.Completed _, system) ->
                { cell with
                    System = system
                }
            | other -> failwith $"%s{context}: mkdir answered %s{brief other}"

        let fd, cell = openFile (advance tick cell) "/w/d/x" (flags platform true)
        let cell = close fd cell |> advance tick

        match step cell (Syscall.Symlink (path "f", path "/w/l")) with
        | SteppedCall.Symlink (SyscallAnswer.Completed _, system) ->
            { cell with
                System = system
            }
            |> advance tick
        | other -> failwith $"%s{context}: symlink answered %s{brief other}"

    // ------------------------------------------------------------ the calls

    /// The object whose atime a row reports, and whether it is stat'd without
    /// following a link.
    let private targetOf (op : string) : string * SymlinkPolicy =
        match op with
        | "getdents"
        | "getdents-eof"
        | "lookup"
        | "read-dir" -> "/w/d", SymlinkPolicy.Follow
        | "readlink"
        | "readlink-efault"
        | "follow"
        | "lstat" -> "/w/l", SymlinkPolicy.NoFollowFinal
        | "empty-read" -> "/w/e", SymlinkPolicy.Follow
        | "dev-null" -> "/dev/null", SymlinkPolicy.Follow
        | "dev-urandom" -> "/dev/urandom", SymlinkPolicy.Follow
        | _ -> "/w/f", SymlinkPolicy.Follow

    /// The calls this kernel has, on this flavour; the probe's others (readv,
    /// mmap, execve, sendfile, a getdents into a bad buffer, O_NOATIME) it
    /// does not model, and Darwin's /dev it refuses.
    let private modelled (platform : SimulatedUnixPlatform) (op : string) : bool =
        match op, SimulatedUnixPlatform.flavour platform with
        | ("readv1" | "mmap" | "mmap-touch" | "exec" | "sendfile" | "getdents-efault" | "noatime-read"), _ -> false
        | ("cfr" | "dev-null" | "dev-urandom"), SimulatedUnixFlavour.Darwin -> false
        | _ -> true

    /// Read `d` to its end, one entry at a time, through `fd`.
    let rec private readToEnd (fd : int) (cell : Cell) : int64 * Cell =
        match step cell (Syscall.ReadDirectoryEntry fd) with
        | SteppedCall.ReadDirectoryEntry (ReadDirectoryAnswer.Entry _, system) ->
            let ret, cell =
                readToEnd
                    fd
                    { cell with
                        System = system
                    }

            ret + 1L, cell
        | SteppedCall.ReadDirectoryEntry (ReadDirectoryAnswer.EndOfDirectory, system) ->
            0L,
            { cell with
                System = system
            }
        | other -> failwith $"%s{context}: readdir answered %s{brief other}"

    /// Make the row's call; what it returned, where the model's answer is the
    /// probe's number (`None` for getdents, whose count is of bytes).
    /// `held` is the descriptor `getdents-eof`'s first call was made through.
    let private call (op : string) (held : int option) (cell : Cell) : int64 option * int option * Cell =
        let readFrom (target : string) (prepare : int -> Cell -> Cell) (make : int -> Syscall<int, string>) =
            let fd, cell = openFile cell target 0
            let cell = prepare fd cell

            let ret, cell =
                match step cell (make fd) with
                | SteppedCall.Read (ReadOutcome.Answered answer, system) ->
                    readRet cell answer,
                    { cell with
                        System = system
                    }
                | SteppedCall.PRead (answer, system) ->
                    readRet cell answer,
                    { cell with
                        System = system
                    }
                | other -> failwith $"%s{context}: %s{op} answered %s{brief other}"

            Some ret, None, close fd cell

        let seek (offset : int64) (whence : int) (fd : int) (cell : Cell) : Cell =
            match step cell (Syscall.LSeek (fd, offset, whence)) with
            | SteppedCall.LSeek (SyscallAnswer.Completed _, system) ->
                { cell with
                    System = system
                }
            | other -> failwith $"%s{context}: lseek answered %s{brief other}"

        let none _ cell = cell
        let mapped = UserBuffer.Mapped

        match op with
        | "read1" -> readFrom "/w/f" none (fun fd -> Syscall.Read (fd, mapped, 1UL))
        | "read0" -> readFrom "/w/f" none (fun fd -> Syscall.Read (fd, mapped, 0UL))
        | "readeof" -> readFrom "/w/f" (seek 0L 2) (fun fd -> Syscall.Read (fd, mapped, 16UL))
        | "pread1" -> readFrom "/w/f" none (fun fd -> Syscall.PRead (fd, mapped, 1UL, 0L))
        | "empty-read" -> readFrom "/w/e" none (fun fd -> Syscall.Read (fd, mapped, 16UL))
        | "read-efault" -> readFrom "/w/f" none (fun fd -> Syscall.Read (fd, protNone, 16UL))
        | "pread-efault" -> readFrom "/w/f" none (fun fd -> Syscall.PRead (fd, protNone, 16UL, 0L))
        | "readeof-efault" -> readFrom "/w/f" (seek 0L 2) (fun fd -> Syscall.Read (fd, protNone, 16UL))
        | "read-efault-kernel" -> readFrom "/w/f" none (fun fd -> Syscall.Read (fd, kernelHalf, 16UL))
        | "pread0" -> readFrom "/w/f" none (fun fd -> Syscall.PRead (fd, mapped, 0UL, 0L))
        | "preadeof" -> readFrom "/w/f" none (fun fd -> Syscall.PRead (fd, mapped, 16UL, 4096L))
        | "read-at-max" -> readFrom "/w/f" (seek Int64.MaxValue 0) (fun fd -> Syscall.Read (fd, mapped, 16UL))
        | "pread-at-max" -> readFrom "/w/f" none (fun fd -> Syscall.PRead (fd, mapped, 16UL, Int64.MaxValue))
        | "read-big" -> readFrom "/w/f" none (fun fd -> Syscall.Read (fd, mapped, 0x80000000UL))
        | "read-dir" -> readFrom "/w/d" none (fun fd -> Syscall.Read (fd, mapped, 16UL))
        | "dev-null" -> readFrom "/dev/null" none (fun fd -> Syscall.Read (fd, mapped, 16UL))
        | "dev-urandom" ->
            let fd, cell = openFile cell "/dev/urandom" 0

            match step cell (Syscall.Read (fd, mapped, 16UL)) with
            | SteppedCall.Read (ReadOutcome.Answered (ReadAnswer.Drawn _), system) ->
                Some 16L,
                None,
                close
                    fd
                    { cell with
                        System = system
                    }
            | other -> failwith $"%s{context}: %s{op} answered %s{brief other}"
        | "getdents" ->
            let fd, cell = openFile cell "/w/d" 0
            let _, cell = readToEnd fd cell
            None, None, close fd cell
        | "getdents-eof" ->
            let fd, cell =
                match held with
                | Some fd -> fd, cell
                | None -> openFile cell "/w/d" 0

            let _, cell = readToEnd fd cell
            None, Some fd, cell
        | "readlink"
        | "readlink-efault" ->
            let buffer = if op = "readlink" then mapped else protNone

            match step cell (Syscall.ReadLink (path "/w/l", buffer, 4096)) with
            | SteppedCall.ReadLink (ReadLinkAnswer.Reported bytes) -> Some (int64 bytes.Length), None, cell
            | SteppedCall.ReadLink (ReadLinkAnswer.Failed error) -> Some (failed cell error), None, cell
            | other -> failwith $"%s{context}: %s{op} answered %s{brief other}"
        | "follow"
        | "follow-target"
        | "lstat"
        | "lookup" ->
            let policy, target =
                match op with
                | "lstat" -> SymlinkPolicy.NoFollowFinal, "/w/l"
                | "lookup" -> SymlinkPolicy.Follow, "/w/d/x"
                | _ -> SymlinkPolicy.Follow, "/w/l"

            status cell policy target |> ignore
            Some 0L, None, cell
        | "open" ->
            let fd, cell = openFile cell "/w/f" 0
            Some 0L, None, close fd cell
        | "write" ->
            let fd, cell = openFile cell "/w/f" writeOnly
            Some 1L, None, pwrite fd [| byte 'y' |] 0L cell |> close fd
        | "utime-atime" ->
            let flavour = SimulatedUnixPlatform.flavour cell.Platform

            let times =
                TimesArgument.Fields (
                    timespec 0L (TimestampChangeRules.utimeNow flavour),
                    timespec 0L (TimestampChangeRules.utimeOmit flavour)
                )

            match
                step
                    cell
                    (Syscall.UTimensAt (
                        AtDirectory.atFdCwd flavour,
                        NullablePathArgument.NotNull (path "/w/f"),
                        times,
                        0
                    ))
            with
            | SteppedCall.UTimensAt (answer, system) ->
                Some (syscallRet cell answer),
                None,
                { cell with
                    System = system
                }
            | other -> failwith $"%s{context}: %s{op} answered %s{brief other}"
        | "cfr" ->
            let source, cell = openFile cell "/w/f" 0
            // O_WRONLY | O_CREAT | O_TRUNC, on Linux, the one flavour with the call.
            let destination, cell = openFile cell "/w/out" (0x1 ||| 0x40 ||| 0x200)

            match step cell (Syscall.CopyFileRange (source, destination, 1UL, 0)) with
            | SteppedCall.CopyFileRange (answer, system) ->
                Some (syscallRet cell answer),
                None,
                { cell with
                    System = system
                }
                |> close destination
                |> close source
            | other -> failwith $"%s{context}: %s{op} answered %s{brief other}"
        | _ -> failwith $"%s{context}: no model of the probe's call %s{op}"

    /// `utimensat(2)` of `target`, setting atime and mtime to the given whole
    /// seconds, as the probe's states do.
    let private setTimes
        (target : string)
        (policy : SymlinkPolicy)
        (access : int64)
        (modification : int64)
        (cell : Cell)
        =
        let flavour = SimulatedUnixPlatform.flavour cell.Platform

        let noFollow =
            match policy, flavour with
            | SymlinkPolicy.NoFollowFinal, SimulatedUnixFlavour.Linux -> 0x100
            | SymlinkPolicy.NoFollowFinal, SimulatedUnixFlavour.Darwin -> 0x20
            | _, _ -> 0

        let times = TimesArgument.Fields (timespec access 0L, timespec modification 0L)

        match
            step
                cell
                (Syscall.UTimensAt (
                    AtDirectory.atFdCwd flavour,
                    NullablePathArgument.NotNull (path target),
                    times,
                    noFollow
                ))
        with
        | SteppedCall.UTimensAt (SyscallAnswer.Completed _, system) ->
            { cell with
                System = system
            }
        | other -> failwith $"%s{context}: utimensat(%s{target}) answered %s{brief other}"

    let private nowSeconds (cell : Cell) : int64 =
        UnixTimestamp.seconds (UnixClock.gettimeofday (leader cell) cell.System)

    /// The row's target in the row's state, and the descriptor a
    /// `getdents-eof` first call was made through; `None` where the probe
    /// skipped the state.
    let private inState (row : Row) (cell : Cell) : (int option * Cell) option =
        let target, policy = targetOf row.Op
        let onDevice = target.StartsWith "/dev"

        match row.State with
        | "created" -> Some (None, advance nap cell)
        | "written" ->
            if onDevice || target = "/w/l" then
                None
            else
                let cell = advance nap cell

                let cell =
                    if target = "/w/d" then
                        let fd, cell = openFile cell "/w/d/y" (flags cell.Platform true)
                        close fd cell
                    else
                        let size = (status cell SymlinkPolicy.Follow target).Size
                        let fd, cell = openFile cell target writeOnly
                        pwrite fd [| byte 'z' |] size cell |> close fd

                Some (None, advance nap cell)
        | "read" ->
            let _, held, cell = call row.Op None (advance nap cell)
            Some (held, advance nap cell)
        | "read-older" ->
            if onDevice then
                None
            else
                let _, held, cell = call row.Op None (advance nap cell)
                let now = nowSeconds cell
                Some (held, setTimes target policy (now - 7200L) (now - 3600L) cell |> advance nap)
        | state ->
            if onDevice then
                None
            else
                let now = nowSeconds cell

                let access, modification =
                    match state with
                    | "future" -> now + 3600L, now - 3600L
                    | "equal" -> now - 3600L, now - 3600L
                    | "older" -> now - 7200L, now - 3600L
                    | past when past.StartsWith "past-" ->
                        let hours = int64 (past.Substring 5)
                        now - hours * 3600L, now - hours * 3600L - 3600L
                    | _ -> failwith $"%s{context}: unknown state %s{state}"

                Some (None, setTimes target policy access modification cell |> advance nap)

    /// What the model does for `row`: whether the target's atime moved, and
    /// what the call returned where the two are comparable; `None` where the
    /// probe made no such row.
    let private replay (platform : SimulatedUnixPlatform) (row : Row) : (bool * int64 option) option =
        match inState row (fixture platform) with
        | None -> None
        | Some (held, cell) ->

        let target, policy = targetOf row.Op
        let before = status cell policy target
        let ret, _, cell = call row.Op held cell
        let after = status cell policy target
        Some (before.AccessTime <> after.AccessTime, ret)

    let private replayAll (platform : SimulatedUnixPlatform) (rows : Row list) : unit =
        let modelledRows = rows |> List.filter (fun row -> modelled platform row.Op)

        // The probe's own call set, so a renamed call cannot silently drop out.
        modelledRows |> List.length |> shouldBeGreaterThan 300

        let mismatches =
            modelledRows
            |> List.choose (fun row ->
                match replay platform row with
                | None ->
                    Some $"%s{row.State} %s{row.Op}: the probe ran it, but the model's cell cannot make the state"
                | Some (moved, ret) ->
                    let retMismatch =
                        match ret with
                        | Some ret when ret <> row.Ret -> Some $"returned %d{ret}, measured %d{row.Ret}"
                        | _ -> None

                    match moved = row.Moved, retMismatch with
                    | true, None -> None
                    | movedOk, _ ->
                        let flag = if movedOk then "" else " (MOVED DIFFERS)"
                        let retText = Option.defaultValue "" retMismatch

                        Some
                            $"%s{row.State} %s{row.Op}: atime moved %b{moved}, measured %b{row.Moved}%s{flag} %s{retText}"
            )

        if not mismatches.IsEmpty then
            failwith $"%s{context}: %d{mismatches.Length} rows differ:\n%s{String.Join ('\n', mismatches)}"

    /// Every Linux row the model can make, from the probe's tmpfs mounted
    /// `noatime`: nothing but `utimensat(2)` moves an access time.
    [<Test>]
    let ``Linux moves an access time where a noatime tmpfs does`` () : unit =
        replayAll SimulatedUnixPlatform.linuxArm64 linuxRows.Value

    /// Every Darwin row the model can make, from a Mac's data volume: a read
    /// of at least one byte moves the atime of a file whose atime is before
    /// its mtime, and so does a directory read that returns an entry; nothing
    /// else does but `utimensat(2)`.
    [<Test>]
    let ``Darwin moves an access time where an APFS volume with its default options does`` () : unit =
        replayAll SimulatedUnixPlatform.macOsArm64 darwinRows.Value

    /// A fresh APFS disk image with its default options answered every row
    /// exactly as the Mac's data volume did, so the data volume's rows are
    /// APFS's rather than that volume's.
    [<Test>]
    let ``a fresh APFS image with its default options moves exactly what the data volume does`` () : unit =
        let image =
            rowsOf "WoofWare.PosixKernel.Test.atime.darwin-image-default.txt" "apfs-image-default"
            |> List.map (fun row -> row.State, row.Op, row.Moved)

        darwinRows.Value
        |> List.map (fun row -> row.State, row.Op, row.Moved)
        |> shouldEqual image

    // ------------------------------------------------------------ the rule, generated

    /// A file's times before a read, relative to now, and the read.
    type private ReadCase =
        {
            Darwin : bool
            /// Seconds from now, and nanoseconds, of the atime and the mtime.
            Access : int64 * int
            Modification : int64 * int
            Count : uint64
            Offset : int64
            Positioned : bool
        }

    let private readCaseGen : Gen<ReadCase> =
        // Around now, and around each other, to the nanosecond.
        let time =
            Gen.zip (Gen.elements [ -100_000L ; -86_401L ; -3_600L ; -1L ; 0L ; 1L ; 3_600L ]) (Gen.choose (0, 2))

        gen {
            let! darwin = Gen.elements [ false ; true ]
            let! access = time
            let! modification = Gen.oneof [ time ; Gen.constant access ]
            let! count = Gen.elements [ 0UL ; 1UL ; 16UL ; 4096UL ; 5000UL ]
            let! offset = Gen.elements [ 0L ; 100L ; 4095L ; 4096L ; 10_000L ]
            let! positioned = Gen.elements [ false ; true ]

            return
                {
                    Darwin = darwin
                    Access = access
                    Modification = modification
                    Count = count
                    Offset = offset
                    Positioned = positioned
                }
        }

    /// Against a naive statement of each mount's rule: a read through `read`
    /// or `pread` of a regular file moves its atime to now exactly when the
    /// count is not zero and, on Darwin's APFS, the atime is before the mtime
    /// (never on Linux's noatime tmpfs), and moves no other time of any inode.
    [<Test>]
    let ``a read moves the access time exactly as the mount's rule says`` () : unit =
        let property (case : ReadCase) : unit =
            let platform =
                if case.Darwin then
                    SimulatedUnixPlatform.macOsArm64
                else
                    SimulatedUnixPlatform.linuxArm64

            let cell = fixture platform
            let now = UnixClock.gettimeofday (leader cell) cell.System
            let fileStatus = status cell SymlinkPolicy.Follow "/w/f"

            let at (seconds : int64, nanoseconds : int) : UnixTimestamp =
                UnixTimestamp.createOrFail context (UnixTimestamp.seconds now + seconds) nanoseconds

            let times : InodeTimes =
                {
                    Access = at case.Access
                    Modification = at case.Modification
                    StatusChange = now
                    Birth = bootTime
                }

            let cell =
                { cell with
                    System =
                        Kernel.mapMachine
                            (fun machine ->
                                { machine with
                                    CommittedFileSystem =
                                        CommittedFileSystem.initial (
                                            GraphMutators.setTimes fileStatus.Inode times machine.FileSystem
                                        )
                                }
                            )
                            cell.System
                }

            let before = UnixSystem.fileSystem cell.System
            let fd, cell = openFile cell "/w/f" 0
            let cell = advance 5_000L cell
            let readAt = UnixClock.gettimeofday (leader cell) cell.System

            let system =
                if case.Positioned then
                    match step cell (Syscall.PRead (fd, UserBuffer.Mapped, case.Count, case.Offset)) with
                    | SteppedCall.PRead (_, system) -> system
                    | other -> failwith $"%s{context}: pread answered %s{brief other}"
                else
                    let cell =
                        match step cell (Syscall.LSeek (fd, case.Offset, 0)) with
                        | SteppedCall.LSeek (SyscallAnswer.Completed _, system) ->
                            { cell with
                                System = system
                            }
                        | other -> failwith $"%s{context}: lseek answered %s{brief other}"

                    match step cell (Syscall.Read (fd, UserBuffer.Mapped, case.Count)) with
                    | SteppedCall.Read (ReadOutcome.Answered _, system) -> system
                    | other -> failwith $"%s{context}: read answered %s{brief other}"

            let moves = case.Count > 0UL && case.Darwin && times.Access < times.Modification

            let expected =
                VirtualFileSystem.inodes before
                |> Map.map (fun inode entry ->
                    if inode = fileStatus.Inode && moves then
                        { entry.Times with
                            Access = readAt
                        }
                    else
                        entry.Times
                )

            VirtualFileSystem.inodes (UnixSystem.fileSystem system)
            |> Map.map (fun _ entry -> entry.Times)
            |> shouldEqual expected

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen readCaseGen) property)
