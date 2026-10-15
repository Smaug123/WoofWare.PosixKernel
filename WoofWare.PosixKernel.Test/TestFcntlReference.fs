namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which of `O_SYNC` and `O_DSYNC` an `open(2)` of the descriptor-table
/// property asks for. `O_DSYNC` alone is not among them: the library refuses
/// it.
[<RequireQualifiedAccess>]
type FcntlSyncRequest =
    | Neither
    /// `O_SYNC`, which on Linux is both of its bits.
    | Sync
    /// `O_SYNC|O_DSYNC`, the same word as `Sync` on Linux.
    | SyncAndDataSync

/// A non-blocking `flock(2)` of the descriptor-table property.
[<RequireQualifiedAccess>]
type FcntlFlockOp =
    /// `LOCK_SH|LOCK_NB`.
    | Shared
    /// `LOCK_EX|LOCK_NB`.
    | Exclusive
    /// `LOCK_UN`.
    | Unlock

/// One step of the descriptor-table property.
[<RequireQualifiedAccess>]
type FcntlOp =
    /// `open(2)` of the file `f`, with the access mode, `O_CLOEXEC`, `O_SYNC`
    /// and `O_DSYNC`, `O_NOFOLLOW` and `O_TRUNC` as asked.
    | Open of
        access : FileAccessMode *
        closeOnExec : bool *
        synchronous : FcntlSyncRequest *
        noFollow : bool *
        truncate : bool
    /// `open(2)` of the directory `d` with `O_RDONLY|O_DIRECTORY`, as
    /// `opendir(3)` opens one, with `O_CLOEXEC`, `O_SYNC` and `O_DSYNC` as
    /// asked.
    | OpenDirectory of closeOnExec : bool * synchronous : FcntlSyncRequest
    /// `pipe2(2)`, with `O_NONBLOCK` and `O_CLOEXEC` as asked.
    | Pipe of nonBlocking : bool * closeOnExec : bool
    | Dup of fd : int
    /// `F_DUPFD`, or with `closeOnExec` `F_DUPFD_CLOEXEC`.
    | DupFd of fd : int * minimum : int * closeOnExec : bool
    | GetFd of fd : int
    | SetFd of fd : int * word : int
    | GetFl of fd : int
    | SetFl of fd : int * word : int
    | Dup2 of oldFd : int * newFd : int
    | Dup3 of oldFd : int * newFd : int * closeOnExec : bool * stray : bool
    /// A one-byte `write(2)`.
    | Write of fd : int
    /// A one-byte `pwrite(2)` at offset 0.
    | Pwrite of fd : int
    | Ftruncate of fd : int * length : int64
    | Flock of fd : int * operation : FcntlFlockOp
    | Close of fd : int

/// `fcntl(2)`, `dup2(2)` and `dup3(2)`, and the calls that change what
/// `F_GETFL` reports (`open(2)`, `write(2)`, `pwrite(2)`, `ftruncate(2)` and
/// `flock(2)`), against a reference descriptor table written out again from
/// the measurements: each descriptor names a description and carries its own
/// flags, each description carries the status flags, and the flag words are
/// spelled in each flavour's numbering independently of the library's tables.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFcntlReference =

    let private context : string = "TestFcntlReference"

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    /// Whether `status` holds only what `flavour`'s kernel keeps on a
    /// description.
    let private statusIsOf (flavour : SimulatedUnixFlavour) (status : OpenFileStatus) : bool =
        match flavour, status with
        | SimulatedUnixFlavour.Linux, OpenFileStatus.Linux _
        | SimulatedUnixFlavour.Darwin, OpenFileStatus.Darwin _ -> true
        | SimulatedUnixFlavour.Linux, OpenFileStatus.Darwin _
        | SimulatedUnixFlavour.Darwin, OpenFileStatus.Linux _ -> false

    [<RequireQualifiedAccess>]
    type private Kind =
        | File
        | Directory
        | PipeRead
        | PipeWrite

    [<RequireQualifiedAccess>]
    type private Lock =
        | Shared
        | Exclusive

    /// Each description's facts, kept under both flavours alike; `statusWord`
    /// reports each only under the flavour whose `F_GETFL` does.
    type private Description =
        {
            Kind : Kind
            /// For a pipe's write end made by `Pipe`, its read end's description;
            /// a launched output stream's reader never goes.
            Reader : int option
            /// What `flock` contends on: the file, the directory, or a pipe
            /// (both of whose ends are one).
            Object : int
            Access : int
            NonBlocking : bool
            Synchronous : bool
            DataSynchronous : bool
            NoFollow : bool
            /// Whether `open` was given `O_DIRECTORY`.
            OpenedDirectory : bool
            Written : bool
            /// Whether a lock has ever been granted to it.
            Flocked : bool
            Lock : Lock option
        }

    /// What a call came to: an answer, a refusal at the descriptor bound, or
    /// any other refusal.
    [<RequireQualifiedAccess>]
    type private Outcome =
        | Answered of SyscallAnswer
        | RefusedAtBound of DescriptorLimitRefusal
        | Refused

    type private Reference =
        {
            Darwin : bool
            Platform : SimulatedUnixPlatform
            /// Each descriptor: its description, and FD_CLOEXEC and FD_CLOFORK.
            Fds : Map<int, int * bool * bool>
            Descriptions : Map<int, Description>
            Next : int
            /// The `Object` the next pipe gets.
            NextObject : int
        }

    /// The `Object` of the file `f`.
    let private fileObject : int = 0
    /// The `Object` of the directory `d`.
    let private directoryObject : int = 1

    // Each flavour's numbering, written out from the headers and the probe's
    // HEADER rows rather than read from the library.
    let private nonBlockBit (r : Reference) : int = if r.Darwin then 0x4 else 0x800
    let private appendBit (r : Reference) : int = if r.Darwin then 0x8 else 0x400
    let private asyncBit (r : Reference) : int = if r.Darwin then 0x40 else 0x2000
    let private syncBit (r : Reference) : int = if r.Darwin then 0x80 else 0x100000
    let private dsyncBit (r : Reference) : int = if r.Darwin then 0x400000 else 0x1000
    let private cloexecBit (r : Reference) : int = if r.Darwin then 0x1000000 else 0x80000

    let private x64 (r : Reference) : bool =
        SimulatedUnixPlatform.architecture r.Platform = SimulatedUnixArchitecture.X64

    let private largeFileBit (r : Reference) : int = if x64 r then 0x8000 else 0x20000
    let private directBit (r : Reference) : int = if x64 r then 0x4000 else 0x10000
    let private noAtimeBit (r : Reference) : int = 0x40000
    let private noFollowBit (r : Reference) : int = if x64 r then 0x20000 else 0x8000
    let private directoryBit (r : Reference) : int = if x64 r then 0x10000 else 0x4000

    let private unmodelled (r : Reference) : int =
        if r.Darwin then
            appendBit r ||| asyncBit r
        else
            appendBit r ||| asyncBit r ||| directBit r ||| noAtimeBit r

    let private statusWord (r : Reference) (d : Description) : int =
        let bit (set : bool) (value : int) = if set then value else 0

        let madeByOpen =
            match d.Kind with
            | Kind.File
            | Kind.Directory -> true
            | Kind.PipeRead
            | Kind.PipeWrite -> false

        d.Access
        ||| bit d.NonBlocking (nonBlockBit r)
        ||| bit d.Synchronous (syncBit r)
        ||| bit d.DataSynchronous (dsyncBit r)
        ||| bit (not r.Darwin && madeByOpen) (largeFileBit r)
        ||| bit (not r.Darwin && d.NoFollow) (noFollowBit r)
        ||| bit (not r.Darwin && d.OpenedDirectory) (directoryBit r)
        ||| bit (r.Darwin && d.Written) 0x10000
        ||| bit (r.Darwin && d.Flocked) 0x4000

    let private bound (r : Reference) : int =
        SimulatedUnixPlatform.descriptorBound r.Platform

    let private lowestFreeFrom (minimum : int) (r : Reference) : int =
        Seq.initInfinite (fun i -> minimum + i)
        |> Seq.find (fun fd -> not (Map.containsKey fd r.Fds))

    /// Whether some descriptor names the description `description`: a lock
    /// goes with the last of them.
    let private isLive (description : int) (r : Reference) : bool =
        r.Fds |> Map.exists (fun _ (named, _, _) -> named = description)

    let private withDescription (description : int) (d : Description) (r : Reference) : Reference =
        { r with
            Descriptions = Map.add description d r.Descriptions
        }

    /// What `open(2)` keeps of `synchronous`: on Linux, `O_SYNC` is both of
    /// its bits.
    let private synchronisation (r : Reference) (synchronous : FcntlSyncRequest) : bool * bool =
        match synchronous with
        | FcntlSyncRequest.Neither -> false, false
        | FcntlSyncRequest.Sync -> true, not r.Darwin
        | FcntlSyncRequest.SyncAndDataSync -> true, true

    let private add (description : Description) (fd : int) (cloexec : bool) (r : Reference) : Reference =
        { r with
            Fds = Map.add fd (r.Next, cloexec, false) r.Fds
            Descriptions = Map.add r.Next description r.Descriptions
            Next = r.Next + 1
        }

    /// What the reference answers for `op`. Every descriptor a call would make
    /// must lie below the bound; one that would not is refused, naming the
    /// lowest it could have had.
    let private step (op : FcntlOp) (r : Reference) : Outcome * Reference =
        let ok (value : int) =
            Outcome.Answered (SyscallAnswer.Completed (int64 value))

        let failed (error : UnixError) =
            Outcome.Answered (SyscallAnswer.Failed error)

        let atBound (descriptor : int) =
            Outcome.RefusedAtBound
                {
                    Descriptor = descriptor
                    Bound = bound r
                }

        let fresh (kind : Kind) (object : int) (access : int) =
            {
                Kind = kind
                Reader = None
                Object = object
                Access = access
                NonBlocking = false
                Synchronous = false
                DataSynchronous = false
                NoFollow = false
                OpenedDirectory = false
                Written = false
                Flocked = false
                Lock = None
            }

        let duplicate (oldFd : int) (newFd : int) (cloexec : bool) (r : Reference) =
            let description, _, _ = r.Fds.[oldFd]

            { r with
                Fds = Map.add newFd (description, cloexec, false) r.Fds
            }

        match op with
        | FcntlOp.Open _
        | FcntlOp.OpenDirectory _ when lowestFreeFrom 0 r >= bound r -> atBound (lowestFreeFrom 0 r), r
        | FcntlOp.Open (access, cloexec, synchronous, noFollow, truncate) ->
            let fd = lowestFreeFrom 0 r

            let access =
                match access with
                | FileAccessMode.ReadOnly -> 0
                | FileAccessMode.WriteOnly -> 1
                | FileAccessMode.ReadWrite -> 2

            let synchronous, dataSynchronous = synchronisation r synchronous

            ok fd,
            add
                { fresh Kind.File fileObject access with
                    Synchronous = synchronous
                    DataSynchronous = dataSynchronous
                    NoFollow = noFollow
                    // `f` always exists, so `O_TRUNC` always truncates a file
                    // that was there.
                    Written = truncate
                }
                fd
                cloexec
                r
        | FcntlOp.OpenDirectory (cloexec, synchronous) ->
            let fd = lowestFreeFrom 0 r
            let synchronous, dataSynchronous = synchronisation r synchronous

            ok fd,
            add
                { fresh Kind.Directory directoryObject 0 with
                    Synchronous = synchronous
                    DataSynchronous = dataSynchronous
                    OpenedDirectory = true
                }
                fd
                cloexec
                r
        | FcntlOp.Pipe _ when lowestFreeFrom (lowestFreeFrom 0 r + 1) r >= bound r ->
            atBound (lowestFreeFrom (lowestFreeFrom 0 r + 1) r), r
        | FcntlOp.Pipe (nonBlocking, cloexec) ->
            let readFd = lowestFreeFrom 0 r
            let object = r.NextObject

            let r =
                add
                    { fresh Kind.PipeRead object 0 with
                        NonBlocking = nonBlocking
                    }
                    readFd
                    cloexec
                    { r with
                        NextObject = object + 1
                    }

            let writeFd = lowestFreeFrom 0 r
            let readDescription = r.Next - 1

            ok readFd,
            add
                { fresh Kind.PipeWrite object 1 with
                    NonBlocking = nonBlocking
                    Reader = Some readDescription
                }
                writeFd
                cloexec
                r
        | FcntlOp.Dup fd ->
            if not (Map.containsKey fd r.Fds) then
                failed UnixError.EBADF, r
            elif lowestFreeFrom 0 r >= bound r then
                atBound (lowestFreeFrom 0 r), r
            else
                let newFd = lowestFreeFrom 0 r
                ok newFd, duplicate fd newFd false r
        | FcntlOp.DupFd (fd, minimum, cloexec) ->
            if not (Map.containsKey fd r.Fds) then
                failed UnixError.EBADF, r
            elif minimum < 0 then
                failed UnixError.EINVAL, r
            elif lowestFreeFrom minimum r >= bound r then
                atBound (lowestFreeFrom minimum r), r
            else
                let newFd = lowestFreeFrom minimum r
                ok newFd, duplicate fd newFd cloexec r
        | FcntlOp.GetFd fd ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (_, cloexec, clofork) -> ok ((if cloexec then 1 else 0) ||| (if clofork then 2 else 0)), r
        | FcntlOp.SetFd (fd, word) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                ok 0,
                { r with
                    Fds = Map.add fd (description, word &&& 1 <> 0, r.Darwin && word &&& 2 <> 0) r.Fds
                }
        | FcntlOp.GetFl fd ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) -> ok (statusWord r r.Descriptions.[description]), r
        | FcntlOp.SetFl (fd, word) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some _ when word &&& unmodelled r <> 0 -> Outcome.Refused, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                let d =
                    if r.Darwin then
                        { d with
                            NonBlocking = word &&& nonBlockBit r <> 0
                            Synchronous = word &&& syncBit r <> 0
                            DataSynchronous = word &&& dsyncBit r <> 0
                        }
                    else
                        { d with
                            NonBlocking = word &&& nonBlockBit r <> 0
                        }

                ok 0,
                { r with
                    Descriptions = Map.add description d r.Descriptions
                }
        | FcntlOp.Dup2 (oldFd, newFd) ->
            if newFd < 0 || not (Map.containsKey oldFd r.Fds) then
                failed UnixError.EBADF, r
            elif oldFd = newFd then
                ok newFd, r
            elif newFd >= bound r then
                atBound newFd, r
            else
                ok newFd, duplicate oldFd newFd false r
        | FcntlOp.Dup3 (oldFd, newFd, cloexec, stray) ->
            if r.Darwin then
                Outcome.Refused, r
            elif stray then
                failed UnixError.EINVAL, r
            elif oldFd = newFd then
                failed UnixError.EINVAL, r
            elif newFd < 0 || not (Map.containsKey oldFd r.Fds) then
                failed UnixError.EBADF, r
            elif newFd >= bound r then
                atBound newFd, r
            else
                ok newFd, duplicate oldFd newFd cloexec r
        | FcntlOp.Write fd ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                match d.Kind with
                | Kind.PipeRead
                | Kind.Directory -> failed UnixError.EBADF, r
                | Kind.File when d.Access = 0 -> failed UnixError.EBADF, r
                | Kind.PipeWrite when d.Reader |> Option.exists (fun reader -> not (isLive reader r)) ->
                    // No reader: EPIPE, with SIGPIPE ignored, and nothing moved.
                    failed UnixError.EPIPE, r
                | Kind.File
                | Kind.PipeWrite ->
                    ok 1,
                    withDescription
                        description
                        { d with
                            Written = true
                        }
                        r
        | FcntlOp.Pwrite fd ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                match d.Kind with
                // Unseekable and unwritable at once: Darwin lets
                // unwritability win.
                | Kind.PipeRead when r.Darwin -> failed UnixError.EBADF, r
                | Kind.PipeRead
                | Kind.PipeWrite -> failed UnixError.ESPIPE, r
                | Kind.File
                | Kind.Directory when d.Access = 0 -> failed UnixError.EBADF, r
                | Kind.File
                | Kind.Directory ->
                    ok 1,
                    withDescription
                        description
                        { d with
                            Written = true
                        }
                        r
        | FcntlOp.Ftruncate (_, length) when length < 0L -> failed UnixError.EINVAL, r
        | FcntlOp.Ftruncate (fd, _) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                match d.Kind with
                | Kind.PipeRead
                | Kind.PipeWrite -> failed UnixError.EINVAL, r
                | Kind.File
                | Kind.Directory when d.Access = 0 -> failed UnixError.EINVAL, r
                | Kind.File
                | Kind.Directory ->
                    ok 0,
                    withDescription
                        description
                        { d with
                            Written = true
                        }
                        r
        | FcntlOp.Flock (fd, operation) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                let acquire (wanted : Lock) : Outcome * Reference =
                    let conflicts =
                        r.Descriptions
                        |> Map.exists (fun other o ->
                            other <> description
                            && o.Object = d.Object
                            && isLive other r
                            && (
                                match wanted, o.Lock with
                                | _, None -> false
                                | Lock.Exclusive, Some _ -> true
                                | Lock.Shared, Some held -> held = Lock.Exclusive
                            )
                        )

                    // Linux gives up the old lock before it asks for the new
                    // one, so a conversion it cannot grant leaves none.
                    let released =
                        { d with
                            Lock = None
                        }

                    if conflicts then
                        failed UnixError.EAGAIN, withDescription description released r
                    else
                        ok 0,
                        withDescription
                            description
                            { released with
                                Lock = Some wanted
                                Flocked = true
                            }
                            r

                match d.Kind, operation with
                | Kind.PipeRead, _
                | Kind.PipeWrite, _ when r.Darwin -> Outcome.Refused, r
                | _, FcntlFlockOp.Unlock ->
                    ok 0,
                    withDescription
                        description
                        { d with
                            Lock = None
                        }
                        r
                // A conversion, which this library refuses under Darwin.
                | _, _ when r.Darwin && d.Lock.IsSome -> Outcome.Refused, r
                | _, FcntlFlockOp.Shared -> acquire Lock.Shared
                | _, FcntlFlockOp.Exclusive -> acquire Lock.Exclusive
        | FcntlOp.Close fd ->
            if Map.containsKey fd r.Fds then
                ok 0,
                { r with
                    Fds = Map.remove fd r.Fds
                }
            else
                failed UnixError.EBADF, r

    let private system (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let seed =
            Map.ofList
                [
                    DirectoryEntryName.parseOrFail context "f",
                    SeedEntry.File (ImmutableArray<byte>.Empty, PermissionBits.parseOrFail context 0o666, None)
                    DirectoryEntryName.parseOrFail context "d",
                    SeedEntry.Directory (Map.empty, PermissionBits.parseOrFail context 0o755, None)
                ]

        let image = UnixSystem.initial platform

        match
            UnixBootImage.tryWithFileSystem (UnixTimestamp.ofMillisecondsSinceEpoch 0L) Owners.linuxDefault seed image
        with
        | Ok image ->
            let system =
                (Launched.bootWith (Launched.credentials Owners.root) UnixSystem.pipedStandardStreams 0 (CpuId 0)) image

            // SIGPIPE ignored, so that a write with no reader answers EPIPE.
            system
            |> Lone.mapProc (fun proc ->
                { proc with
                    Signals =
                        SignalState.setDisposition
                            (Lone.UnixSystemState.signalNumbering system)
                            Signal.SIGPIPE
                            SignalDisposition.Ignore
                            proc.Signals
                }
            )
        | Error fault -> failwith $"could not build the system: %A{fault}"

    /// The library's answer to `op`.
    let private library
        (r : Reference)
        (op : FcntlOp)
        (system : UnixSystem<int, string>)
        : Outcome * UnixSystem<int, string>
        =
        let platform = r.Platform

        let ofFcntl (result : Result<SyscallAnswer * UnixSystem<int, string>, FcntlRefusal>) =
            match result with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error (FcntlRefusal.UnmodelledStatusFlags _) -> Outcome.Refused, system
            | Error (FcntlRefusal.DescriptorLimit refusal) -> Outcome.RefusedAtBound refusal, system
            | Error refusal -> failwith $"fcntl refused: %s{FcntlRefusal.describe refusal}"

        let openPath (flags : OpenFlags) (path : string) : Outcome * UnixSystem<int, string> =
            match OpenFlagWords.openPath flags (PathArg.ofText path) 0o644 system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error (OpenRefusal.DescriptorLimit refusal) -> Outcome.RefusedAtBound refusal, system
            | Error refusal -> failwith $"open refused: %A{refusal}"

        // As `OpenFlagWords.encode` reads them: Linux's word holds both of
        // `O_SYNC`'s bits whenever `Synchronous` is set.
        let synchronised (synchronous : FcntlSyncRequest) (flags : OpenFlags) : OpenFlags =
            match synchronous with
            | FcntlSyncRequest.Neither -> flags
            | FcntlSyncRequest.Sync ->
                { flags with
                    Synchronous = true
                    DataSynchronous = not r.Darwin
                }
            | FcntlSyncRequest.SyncAndDataSync ->
                { flags with
                    Synchronous = true
                    DataSynchronous = true
                }

        let thread = Lone.leader system

        match op with
        | FcntlOp.Open (access, cloexec, synchronous, noFollow, truncate) ->
            let flags =
                { FcntlWorld.opening access with
                    CloseOnExec = cloexec
                    NoFollow = noFollow
                    Truncate = truncate
                }
                |> synchronised synchronous

            openPath flags "f"
        | FcntlOp.OpenDirectory (cloexec, synchronous) ->
            let flags =
                { FcntlWorld.opening FileAccessMode.ReadOnly with
                    CloseOnExec = cloexec
                    Directory = true
                }
                |> synchronised synchronous

            openPath flags "d"
        | FcntlOp.Pipe (nonBlocking, cloexec) ->
            let flags =
                (if nonBlocking then nonBlockBit r else 0)
                ||| (if cloexec then cloexecBit r else 0)

            match UnixPipe.tryPipe2 (Callers.leader system) flags UserBuffer.Mapped system with
            | Ok (Pipe2Answer.Created (readFd, _), system) ->
                Outcome.Answered (SyscallAnswer.Completed (int64 readFd)), system
            | Error (Pipe2Refusal.DescriptorLimit refusal) -> Outcome.RefusedAtBound refusal, system
            | other -> failwith $"pipe2: %A{other}"
        | FcntlOp.Dup fd ->
            match UnixDescriptor.tryDup (Callers.leader system) fd system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error refusal -> Outcome.RefusedAtBound refusal, system
        | FcntlOp.DupFd (fd, minimum, cloexec) ->
            let command =
                if cloexec then
                    FcntlWorld.dupFdCloexec platform
                else
                    FcntlWorld.DupFd

            ofFcntl (UnixDescriptor.tryFcntl (Callers.leader system) fd command minimum system)
        | FcntlOp.GetFd fd -> ofFcntl (UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.GetFd 0 system)
        | FcntlOp.SetFd (fd, word) ->
            ofFcntl (UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.SetFd word system)
        | FcntlOp.GetFl fd -> ofFcntl (UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.GetFl 0 system)
        | FcntlOp.SetFl (fd, word) ->
            ofFcntl (UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.SetFl word system)
        | FcntlOp.Dup2 (oldFd, newFd) ->
            match UnixDescriptor.tryDup2 (Callers.leader system) oldFd newFd system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error (Dup2Refusal.DescriptorLimit refusal) -> Outcome.RefusedAtBound refusal, system
            | Error refusal -> failwith $"dup2 refused: %s{Dup2Refusal.describe refusal}"
        | FcntlOp.Dup3 (oldFd, newFd, cloexec, stray) ->
            let flags = (if cloexec then cloexecBit r else 0) ||| (if stray then 0x800 else 0)

            match UnixDescriptor.tryDup3 (Callers.leader system) oldFd newFd flags system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error (Dup3Refusal.NotProvided _) -> Outcome.Refused, system
            | Error (Dup3Refusal.DescriptorLimit refusal) -> Outcome.RefusedAtBound refusal, system
            | Error refusal -> failwith $"dup3 refused: %s{Dup3Refusal.describe refusal}"
        | FcntlOp.Write fd ->
            match WriteOutcomes.admitThenWrite thread fd UserBuffer.Mapped (ImmutableArray.Create 1uy) system with
            | Ok (WriteStep.Returns (WriteAnswer.Completed n, system))
            | Ok (WriteStep.ReturnsRaising (WriteAnswer.Completed n, _, system)) ->
                Outcome.Answered (SyscallAnswer.Completed n), system
            | Ok (WriteStep.Returns (WriteAnswer.Failed error, system))
            | Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed error, _, system)) ->
                Outcome.Answered (SyscallAnswer.Failed error), system
            | other -> failwith $"write: %A{other}"
        | FcntlOp.Pwrite fd ->
            match WriteOutcomes.admitThenPwrite thread fd (ImmutableArray.Create 1uy) 0L system with
            | Ok (WriteAnswer.Completed n, system) -> Outcome.Answered (SyscallAnswer.Completed n), system
            | Ok (WriteAnswer.Failed error, system) -> Outcome.Answered (SyscallAnswer.Failed error), system
            | Error refusal -> failwith $"pwrite refused: %A{refusal}"
        | FcntlOp.Ftruncate (fd, length) ->
            match UnixDescriptor.tryFtruncate (Callers.leader system) fd length system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error refusal -> failwith $"ftruncate refused: %s{TruncationRefusal.describe refusal}"
        | FcntlOp.Flock (fd, operation) ->
            let word =
                match operation with
                | FcntlFlockOp.Shared -> 1 ||| 4
                | FcntlFlockOp.Exclusive -> 2 ||| 4
                | FcntlFlockOp.Unlock -> 8

            match UnixDescriptor.tryFlock (Callers.thread thread system) fd word system with
            | Ok (SyscallOutcome.Answered answer, system) -> Outcome.Answered answer, system
            | Ok (other, _) -> failwith $"a non-blocking flock answered %A{other}"
            | Error (FLockRefusal.DarwinPipe _)
            | Error FLockRefusal.DarwinConversion -> Outcome.Refused, system
            | Error refusal -> failwith $"flock refused: %s{FLockRefusal.describe refusal}"
        | FcntlOp.Close fd ->
            match UnixDescriptor.tryClose (Callers.leader system) fd system with
            | Ok (answer, system) -> Outcome.Answered answer, system
            | Error refusal -> failwith $"close refused: %s{CloseRefusal.describe refusal}"

    /// Which descriptors `fds` name a description in common: the partition the
    /// library and the reference must agree on.
    let private partition (fds : Map<int, 'a>) : Set<Set<int>> =
        fds
        |> Map.toList
        |> List.groupBy snd
        |> List.map (fun (_, members) -> members |> List.map fst |> Set.ofList)
        |> Set.ofList

    let private wordGen (platform : SimulatedUnixPlatform) : Gen<int> =
        let darwin = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin

        let modelled =
            if darwin then
                [ 0x4 ; 0x80 ; 0x400000 ]
            else
                [ 0x800 ; 0x100000 ; 0x1000 ]

        // Bits the flavour's F_SETFL ignores: the access mode, O_CREAT,
        // O_LARGEFILE or Darwin's FWASWRITTEN and FHASLOCK, and a few
        // undefined ones.
        let ignored =
            if darwin then
                [ 1 ; 2 ; 3 ; 0x200 ; 0x4000 ; 0x10000 ; 0x40000000 ]
            else
                [ 1 ; 2 ; 3 ; 0x40 ; 0x8000 ; 0x20000 ; 0x10000 ; 0x4000000 ]

        let unmodelled =
            if darwin then
                [ 0x8 ; 0x40 ]
            else
                [ 0x400 ; 0x2000 ; 0x40000 ; 0x4000 ; 0x10000 ]

        gen {
            let! modelledBits = Gen.subListOf modelled
            let! ignoredBits = Gen.subListOf ignored
            let! stray = Gen.frequency [ 9, Gen.constant [] ; 1, Gen.subListOf unmodelled ]
            return List.fold (|||) 0 (modelledBits @ ignoredBits @ stray)
        }

    let private opGen (platform : SimulatedUnixPlatform) : Gen<FcntlOp> =
        let bound = SimulatedUnixPlatform.descriptorBound platform
        // Around the bound, so that F_DUPFD and dup2 put descriptors just below
        // it and then reach it.
        let nearBound =
            Gen.elements [ bound - 3 ; bound - 2 ; bound - 1 ; bound ; bound + 1 ]

        let fd =
            Gen.frequency
                [
                    12, Gen.choose (0, 12)
                    1, Gen.elements [ -1 ; 40 ; System.Int32.MinValue ]
                    2, nearBound
                ]

        let bool = Gen.elements [ true ; false ]

        let access =
            Gen.elements
                [
                    FileAccessMode.ReadOnly
                    FileAccessMode.WriteOnly
                    FileAccessMode.ReadWrite
                ]

        let synchronous =
            Gen.elements
                [
                    FcntlSyncRequest.Neither
                    FcntlSyncRequest.Sync
                    FcntlSyncRequest.SyncAndDataSync
                ]

        let flockOp =
            Gen.elements [ FcntlFlockOp.Shared ; FcntlFlockOp.Exclusive ; FcntlFlockOp.Unlock ]

        Gen.frequency
            [
                3,
                gen {
                    let! a = access
                    let! c = bool
                    let! s = synchronous
                    let! n = bool
                    let! t = Gen.frequency [ 3, Gen.constant false ; 1, Gen.constant true ]
                    return FcntlOp.Open (a, c, s, n, t)
                }
                1, Gen.map2 (fun c s -> FcntlOp.OpenDirectory (c, s)) bool synchronous
                2, Gen.map2 (fun n c -> FcntlOp.Pipe (n, c)) bool bool
                2, Gen.map FcntlOp.Dup fd
                3,
                Gen.map3
                    (fun f m c -> FcntlOp.DupFd (f, m, c))
                    fd
                    (Gen.frequency
                        [
                            8, Gen.choose (0, 14)
                            1, Gen.elements [ -1 ; System.Int32.MinValue ]
                            3, nearBound
                        ])
                    bool
                3, Gen.map FcntlOp.GetFd fd
                3, Gen.map2 (fun f w -> FcntlOp.SetFd (f, w)) fd (Gen.elements [ 0 ; 1 ; 2 ; 3 ; -1 ; 4 ; 0x80000 ])
                3, Gen.map FcntlOp.GetFl fd
                3, Gen.map2 (fun f w -> FcntlOp.SetFl (f, w)) fd (wordGen platform)
                4, Gen.map2 (fun o n -> FcntlOp.Dup2 (o, n)) fd fd
                2,
                Gen.map3
                    (fun (o, n) c s -> FcntlOp.Dup3 (o, n, c, s))
                    (Gen.zip fd fd)
                    bool
                    (Gen.frequency [ 5, Gen.constant false ; 1, Gen.constant true ])
                2, Gen.map FcntlOp.Write fd
                1, Gen.map FcntlOp.Pwrite fd
                1,
                Gen.map2
                    (fun f l -> FcntlOp.Ftruncate (f, l))
                    fd
                    (Gen.frequency [ 8, Gen.map int64 (Gen.choose (0, 4)) ; 1, Gen.constant -1L ])
                3, Gen.map2 (fun f o -> FcntlOp.Flock (f, o)) fd flockOp
                3, Gen.map FcntlOp.Close fd
            ]

    [<Test>]
    let ``every descriptor-table call answers as the reference does, and leaves the same table and statuses of its flavour``
        ()
        : unit
        =
        let property (cover : string -> unit) (platform : SimulatedUnixPlatform, ops : FcntlOp list) : unit =
            let mutable system = system platform
            let darwin = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin

            // The launched standard streams, as the reference sees them: each
            // its own pipe end, the first read and the others write, and each
            // its own pipe.
            let stream (kind : Kind) (object : int) (access : int) : Description =
                {
                    Kind = kind
                    Reader = None
                    Object = object
                    Access = access
                    NonBlocking = false
                    Synchronous = false
                    DataSynchronous = false
                    NoFollow = false
                    OpenedDirectory = false
                    Written = false
                    Flocked = false
                    Lock = None
                }

            let mutable reference =
                {
                    Darwin = darwin
                    Platform = platform
                    Fds = Map.ofList [ 0, (0, false, false) ; 1, (1, false, false) ; 2, (2, false, false) ]
                    Descriptions =
                        Map.ofList
                            [
                                0, stream Kind.PipeRead 2 0
                                1, stream Kind.PipeWrite 3 1
                                2, stream Kind.PipeWrite 4 1
                            ]
                    Next = 3
                    NextObject = 5
                }

            for i, op in List.indexed ops do
                let where () : string = $"%O{platform}, op %d{i} (%A{op})"
                let expected, after = step op reference
                let actual, afterSystem = library reference op system

                if actual <> expected then
                    failwith $"%s{where ()}: expected %A{expected}, got %A{actual}"

                cover (
                    match op, actual with
                    | _, Outcome.Refused -> "refused"
                    | FcntlOp.DupFd _, Outcome.RefusedAtBound _ -> "F_DUPFD at the bound"
                    | FcntlOp.Dup2 _, Outcome.RefusedAtBound _ -> "dup2 at the bound"
                    | _, Outcome.RefusedAtBound _ -> "at the bound"
                    | FcntlOp.Dup2 (o, n), Outcome.Answered (SyscallAnswer.Completed _) when
                        o <> n && Map.containsKey n reference.Fds
                        ->
                        "dup2 onto an open descriptor"
                    | FcntlOp.DupFd (_, m, _), Outcome.Answered (SyscallAnswer.Completed fd) when fd > int64 m ->
                        "F_DUPFD past a taken minimum"
                    | _, Outcome.Answered (SyscallAnswer.Failed error) -> $"%O{error}"
                    | op, Outcome.Answered (SyscallAnswer.Completed _) -> UnionCaseName.ofValue op
                )

                reference <- after
                system <- afterSystem

                // The whole table, through the queries a client has.
                let registry = Lone.fileDescriptors system
                let libraryFds = FileDescriptorRegistry.fds registry

                libraryFds
                |> Map.keys
                |> Set.ofSeq
                |> Expect.equal where (reference.Fds |> Map.keys |> Set.ofSeq)

                partition libraryFds
                |> Expect.equal where (partition (reference.Fds |> Map.map (fun _ (d, _, _) -> d)))

                for fd in Map.keys reference.Fds do
                    let _, cloexec, clofork = reference.Fds.[fd]

                    (fd, FileDescriptorRegistry.tryFindFlags fd registry)
                    |> Expect.equal
                        where
                        (fd,
                         Some (
                             if darwin then
                                 DescriptorFlags.Darwin (closeOnExec = cloexec, closeOnFork = clofork)
                             else
                                 DescriptorFlags.Linux (closeOnExec = cloexec)
                         ))

                // Every descriptor's status word, whether or not the step
                // asked for one.
                for fd in Map.keys reference.Fds do
                    let description, _, _ = reference.Fds.[fd]

                    match UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.GetFl 0 system with
                    | Ok (answer, _) ->
                        answer
                        |> Expect.equal
                            (fun () -> $"%s{where ()}, F_GETFL of %d{fd}")
                            (SyscallAnswer.Completed (int64 (statusWord reference reference.Descriptions.[description])))
                    | Error refusal ->
                        failwith $"%s{where ()}: F_GETFL of %d{fd} refused: %s{FcntlRefusal.describe refusal}"

                // Every description's status is its machine's flavour's.
                for KeyValue (id, description) in OpenFileTable.descriptions system.Machine.OpenFiles do
                    if not (statusIsOf (SimulatedUnixPlatform.flavour platform) description.Status) then
                        failwith
                            $"%s{where ()}: description %O{id}'s status %A{description.Status} is not %O{platform}'s"

                UnixSystem.checkInvariants system |> Expect.empty where

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! ops = Gen.listOf (opGen platform)
                return platform, ops
            }

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 1000) (Arb.fromGen gen) property

        for label in
            [
                "refused"
                "F_DUPFD at the bound"
                "dup2 at the bound"
                "dup2 onto an open descriptor"
                "F_DUPFD past a taken minimum"
                "EBADF"
                "EINVAL"
                "SetFl"
                "Dup3"
                "Write"
                "Pwrite"
                "Ftruncate"
                "Flock"
                "OpenDirectory"
                "EAGAIN"
                "ESPIPE"
            ] do
            if coverage.Count label = 0 then
                failwith $"the property never reached %s{label}; reached %A{coverage.Reached |> List.sort}"
