namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `fcntl(2)`, `dup2(2)` and `dup3(2)`, and the calls that change what
/// `F_GETFL` reports (`open(2)`, `write(2)`, `pwrite(2)`, `ftruncate(2)` and
/// `flock(2)`), made through `UnixSystem.tryStep` against a reference
/// descriptor table written out again from the measurements: each descriptor
/// names a description and carries its own flags, each description carries
/// the status flags, and the flag words are spelled in each flavour's
/// numbering independently of the library's tables.
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
            /// For a pipe's write end made by `pipe2`, its read end's
            /// description; a launched output stream's reader never goes.
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

    /// The file every `open(2)` of a file names.
    let private filePath : PathArgumentBytes = PathArg.ofText "f"
    /// The directory every `open(2)` of a directory names.
    let private directoryPath : PathArgumentBytes = PathArg.ofText "d"

    let private isDarwin (platform : SimulatedUnixPlatform) : bool =
        SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin

    /// Whether `command` is `F_DUPFD` or `F_DUPFD_CLOEXEC` in `platform`'s
    /// numbering.
    let private isDupFd (platform : SimulatedUnixPlatform) (command : int) : bool =
        command = FcntlWorld.DupFd || command = FcntlWorld.dupFdCloexec platform

    let private statusWord (r : Reference) (d : Description) : int =
        let bit (set : bool) (value : int) : int = if set then value else 0

        // A flag the flavour may not number at all, looked up only when set.
        let flag (set : bool) (meaning : OpenFlagBit) : int =
            if set then OpenFlagWords.bitOf r.Platform meaning else 0

        let madeByOpen =
            match d.Kind with
            | Kind.File
            | Kind.Directory -> true
            | Kind.PipeRead
            | Kind.PipeWrite -> false

        d.Access
        ||| flag d.NonBlocking (OpenFlagBit.Unmodelled UnmodelledOpenFlag.NonBlocking)
        ||| flag d.Synchronous OpenFlagBit.Synchronous
        ||| flag d.DataSynchronous OpenFlagBit.DataSynchronous
        ||| flag (not r.Darwin && madeByOpen) (OpenFlagBit.Unmodelled UnmodelledOpenFlag.LargeFile)
        ||| flag (not r.Darwin && d.NoFollow) OpenFlagBit.NoFollow
        ||| flag (not r.Darwin && d.OpenedDirectory) OpenFlagBit.Directory
        // Darwin's FWASWRITTEN and FHASLOCK, which only F_GETFL reports
        // (`fcntl-dup.c`, WRITTEN rows).
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

    let private add (description : Description) (fd : int) (cloexec : bool) (r : Reference) : Reference =
        { r with
            Fds = Map.add fd (r.Next, cloexec, false) r.Fds
            Descriptions = Map.add r.Next description r.Descriptions
            Next = r.Next + 1
        }

    /// Fails unless the flag word `word` holds no bit outside `known`: this
    /// test generates no other, so the reference models no other.
    let private requireGenerated (call : string) (known : int) (word : int) : unit =
        if word &&& ~~~known <> 0 then
            failwith $"%s{call} with 0x%x{word} is not generated by TestFcntlReference"

    /// What the reference answers for `call`. Every descriptor a call would
    /// make must lie below the bound; one that would not is refused, naming
    /// the lowest it could have had.
    let private step (call : Syscall<int, string>) (r : Reference) : Outcome * Reference =
        let p = r.Platform
        let flag (meaning : OpenFlagBit) : int = OpenFlagWords.bitOf p meaning

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

        match call with
        | Syscall.Open _ when lowestFreeFrom 0 r >= bound r -> atBound (lowestFreeFrom 0 r), r
        | Syscall.Open (path, flags, _) ->
            let fd = lowestFreeFrom 0 r
            let has (meaning : OpenFlagBit) : bool = flags &&& flag meaning <> 0

            let shared =
                flag OpenFlagBit.CloseOnExec
                ||| flag OpenFlagBit.Synchronous
                ||| flag OpenFlagBit.DataSynchronous

            let description =
                if path = filePath then
                    requireGenerated
                        "open of f"
                        (3 ||| shared ||| flag OpenFlagBit.NoFollow ||| flag OpenFlagBit.Truncate)
                        flags

                    { fresh Kind.File fileObject (flags &&& 3) with
                        NoFollow = has OpenFlagBit.NoFollow
                        // `f` always exists, so `O_TRUNC` always truncates a
                        // file that was there.
                        Written = has OpenFlagBit.Truncate
                    }
                elif path = directoryPath then
                    requireGenerated "open of d" (flag OpenFlagBit.Directory ||| shared) flags

                    { fresh Kind.Directory directoryObject 0 with
                        OpenedDirectory = has OpenFlagBit.Directory
                    }
                else
                    failwith $"an open of %A{path} is not generated by TestFcntlReference"

            ok fd,
            add
                { description with
                    Synchronous = has OpenFlagBit.Synchronous
                    DataSynchronous = has OpenFlagBit.DataSynchronous
                }
                fd
                (has OpenFlagBit.CloseOnExec)
                r
        | Syscall.Pipe2 _ when lowestFreeFrom (lowestFreeFrom 0 r + 1) r >= bound r ->
            atBound (lowestFreeFrom (lowestFreeFrom 0 r + 1) r), r
        | Syscall.Pipe2 (_, flags) ->
            requireGenerated "pipe2" (OpenFlagWords.nonBlock p ||| OpenFlagWords.closeOnExec p) flags
            let nonBlocking = flags &&& OpenFlagWords.nonBlock p <> 0
            let readFd = lowestFreeFrom 0 r
            let object = r.NextObject

            let r =
                add
                    { fresh Kind.PipeRead object 0 with
                        NonBlocking = nonBlocking
                    }
                    readFd
                    (flags &&& OpenFlagWords.closeOnExec p <> 0)
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
                (flags &&& OpenFlagWords.closeOnExec p <> 0)
                r
        | Syscall.Dup fd ->
            if not (Map.containsKey fd r.Fds) then
                failed UnixError.EBADF, r
            elif lowestFreeFrom 0 r >= bound r then
                atBound (lowestFreeFrom 0 r), r
            else
                let newFd = lowestFreeFrom 0 r
                ok newFd, duplicate fd newFd false r
        | Syscall.Fcntl (fd, command, minimum) when isDupFd p command ->
            if not (Map.containsKey fd r.Fds) then
                failed UnixError.EBADF, r
            elif minimum < 0 then
                failed UnixError.EINVAL, r
            elif lowestFreeFrom minimum r >= bound r then
                atBound (lowestFreeFrom minimum r), r
            else
                let newFd = lowestFreeFrom minimum r
                ok newFd, duplicate fd newFd (command <> FcntlWorld.DupFd) r
        | Syscall.Fcntl (fd, FcntlWorld.GetFd, _) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (_, cloexec, clofork) -> ok ((if cloexec then 1 else 0) ||| (if clofork then 2 else 0)), r
        | Syscall.Fcntl (fd, FcntlWorld.SetFd, word) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) ->
                ok 0,
                { r with
                    Fds = Map.add fd (description, word &&& 1 <> 0, r.Darwin && word &&& 2 <> 0) r.Fds
                }
        | Syscall.Fcntl (fd, FcntlWorld.GetFl, _) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some (description, _, _) -> ok (statusWord r r.Descriptions.[description]), r
        | Syscall.Fcntl (fd, FcntlWorld.SetFl, word) ->
            match Map.tryFind fd r.Fds with
            | None -> failed UnixError.EBADF, r
            | Some _ when word &&& FcntlWorld.unmodelledStatusFlags p <> 0 -> Outcome.Refused, r
            | Some (description, _, _) ->
                let d = r.Descriptions.[description]

                let d =
                    if r.Darwin then
                        { d with
                            NonBlocking = word &&& OpenFlagWords.nonBlock p <> 0
                            Synchronous = word &&& flag OpenFlagBit.Synchronous <> 0
                            DataSynchronous = word &&& flag OpenFlagBit.DataSynchronous <> 0
                        }
                    else
                        { d with
                            NonBlocking = word &&& OpenFlagWords.nonBlock p <> 0
                        }

                ok 0,
                { r with
                    Descriptions = Map.add description d r.Descriptions
                }
        | Syscall.Fcntl (_, command, _) -> failwith $"fcntl command %d{command} is not generated by TestFcntlReference"
        | Syscall.Dup2 (oldFd, newFd) ->
            if newFd < 0 || not (Map.containsKey oldFd r.Fds) then
                failed UnixError.EBADF, r
            elif oldFd = newFd then
                ok newFd, r
            elif newFd >= bound r then
                atBound newFd, r
            else
                ok newFd, duplicate oldFd newFd false r
        | Syscall.Dup3 (oldFd, newFd, flags) ->
            if r.Darwin then
                Outcome.Refused, r
            elif flags &&& ~~~(OpenFlagWords.closeOnExec p) <> 0 then
                failed UnixError.EINVAL, r
            elif oldFd = newFd then
                failed UnixError.EINVAL, r
            elif newFd < 0 || not (Map.containsKey oldFd r.Fds) then
                failed UnixError.EBADF, r
            elif newFd >= bound r then
                atBound newFd, r
            else
                ok newFd, duplicate oldFd newFd (flags &&& OpenFlagWords.closeOnExec p <> 0) r
        | Syscall.Write (fd, _, _) ->
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
        | Syscall.PWrite (fd, _, _, _) ->
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
        | Syscall.FTruncate (_, length) when length < 0L -> failed UnixError.EINVAL, r
        | Syscall.FTruncate (fd, _) ->
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
        | Syscall.FLock (fd, operation) ->
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

                // LOCK_SH|LOCK_NB, LOCK_EX|LOCK_NB and LOCK_UN, which both
                // flavours number alike.
                match d.Kind, operation with
                | Kind.PipeRead, _
                | Kind.PipeWrite, _ when r.Darwin -> Outcome.Refused, r
                | _, 8 ->
                    ok 0,
                    withDescription
                        description
                        { d with
                            Lock = None
                        }
                        r
                // A conversion, which this library refuses under Darwin.
                | _, _ when r.Darwin && d.Lock.IsSome -> Outcome.Refused, r
                | _, 5 -> acquire Lock.Shared
                | _, 6 -> acquire Lock.Exclusive
                | _, operation -> failwith $"flock with 0x%x{operation} is not generated by TestFcntlReference"
        | Syscall.Close fd ->
            if Map.containsKey fd r.Fds then
                ok 0,
                { r with
                    Fds = Map.remove fd r.Fds
                }
            else
                failed UnixError.EBADF, r
        | other -> failwith $"%s{UnionCaseName.ofValue other} is not generated by TestFcntlReference"

    /// The name a call that completed is counted under.
    let private kindOf (platform : SimulatedUnixPlatform) (call : Syscall<int, string>) : string =
        match call with
        | Syscall.Open (path, _, _) when path = directoryPath -> "open of a directory"
        | Syscall.Open _ -> "open"
        | Syscall.Pipe2 _ -> "pipe2"
        | Syscall.Dup _ -> "dup"
        | Syscall.Fcntl (_, command, _) when isDupFd platform command -> "F_DUPFD"
        | Syscall.Fcntl (_, FcntlWorld.GetFd, _) -> "F_GETFD"
        | Syscall.Fcntl (_, FcntlWorld.SetFd, _) -> "F_SETFD"
        | Syscall.Fcntl (_, FcntlWorld.GetFl, _) -> "F_GETFL"
        | Syscall.Fcntl (_, FcntlWorld.SetFl, _) -> "F_SETFL"
        | Syscall.Fcntl (_, command, _) -> failwith $"fcntl command %d{command} is not generated by TestFcntlReference"
        | Syscall.Dup2 _ -> "dup2"
        | Syscall.Dup3 _ -> "dup3"
        | Syscall.Write _ -> "write"
        | Syscall.PWrite _ -> "pwrite"
        | Syscall.FTruncate _ -> "ftruncate"
        | Syscall.FLock _ -> "flock"
        | Syscall.Close _ -> "close"
        | other -> failwith $"%s{UnionCaseName.ofValue other} is not generated by TestFcntlReference"

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

    let private ofWrite (answer : WriteAnswer) : SyscallAnswer =
        match answer with
        | WriteAnswer.Completed written -> SyscallAnswer.Completed written
        | WriteAnswer.Failed error -> SyscallAnswer.Failed error

    /// The library's answer to `call`, made by the process's leader through
    /// `UnixSystem.tryStep`.
    let private library
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Outcome * UnixSystem<int, string>
        =
        match UnixSystem.tryStep (Callers.leader system) call system with
        | Ok (SteppedCall.Open (SyscallOutcome.Answered answer, after))
        | Ok (SteppedCall.Dup (answer, after))
        | Ok (SteppedCall.Fcntl (answer, after))
        | Ok (SteppedCall.Dup2 (answer, after))
        | Ok (SteppedCall.Dup3 (answer, after))
        | Ok (SteppedCall.FTruncate (answer, after))
        | Ok (SteppedCall.FLock (SyscallOutcome.Answered answer, after))
        | Ok (SteppedCall.Close (answer, after)) -> Outcome.Answered answer, after
        | Ok (SteppedCall.Pipe2 (Pipe2Answer.Created (readFd, _), after)) ->
            Outcome.Answered (SyscallAnswer.Completed (int64 readFd)), after
        | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns answer, after)))
        | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.ReturnsRaising (answer, _), after)))
        | Ok (SteppedCall.PWrite (answer, after)) -> Outcome.Answered (ofWrite answer), after
        | Ok stepped -> failwith $"%A{call} answered %A{stepped}"
        | Error (SyscallRefusal.Open (OpenRefusal.DescriptorLimit refusal))
        | Error (SyscallRefusal.Pipe2 (Pipe2Refusal.DescriptorLimit refusal))
        | Error (SyscallRefusal.Dup refusal)
        | Error (SyscallRefusal.Fcntl (FcntlRefusal.DescriptorLimit refusal))
        | Error (SyscallRefusal.Dup2 (Dup2Refusal.DescriptorLimit refusal))
        | Error (SyscallRefusal.Dup3 (Dup3Refusal.DescriptorLimit refusal)) -> Outcome.RefusedAtBound refusal, system
        | Error (SyscallRefusal.Fcntl (FcntlRefusal.UnmodelledStatusFlags _))
        | Error (SyscallRefusal.Dup3 (Dup3Refusal.NotProvided _))
        | Error (SyscallRefusal.FLock (FLockRefusal.DarwinPipe _))
        | Error (SyscallRefusal.FLock FLockRefusal.DarwinConversion) -> Outcome.Refused, system
        | Error refusal -> failwith $"%A{call} was refused: %s{SyscallRefusal.describe refusal}"

    /// What the same `write(2)` or `pwrite(2)` as `call` answers through the
    /// call's own functions, held to the call made a step at a time
    /// (`WriteOutcomes.admitThenWrite` and `admitThenPwrite`): the answer
    /// `library` must also give. `None` for any other call.
    let private writtenThroughSteps
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : (Outcome * UnixSystem<int, string>) option
        =
        match call with
        | Syscall.Write (fd, CopiedArgument.Readable bytes, _) ->
            match WriteOutcomes.admitThenWrite (Lone.leader system) fd UserBuffer.Mapped bytes system with
            | Ok (WriteStep.Returns (answer, after))
            | Ok (WriteStep.ReturnsRaising (answer, _, after)) -> Some (Outcome.Answered (ofWrite answer), after)
            | other -> failwith $"write: %A{other}"
        | Syscall.PWrite (fd, CopiedArgument.Readable bytes, _, offset) ->
            match WriteOutcomes.admitThenPwrite (Lone.leader system) fd bytes offset system with
            | Ok (answer, after) -> Some (Outcome.Answered (ofWrite answer), after)
            | Error refusal -> failwith $"pwrite refused: %A{refusal}"
        | _ -> None

    /// Which descriptors `fds` name a description in common: the partition the
    /// library and the reference must agree on.
    let private partition (fds : Map<int, 'a>) : Set<Set<int>> =
        fds
        |> Map.toList
        |> List.groupBy snd
        |> List.map (fun (_, members) -> members |> List.map fst |> Set.ofList)
        |> Set.ofList

    let private wordGen (platform : SimulatedUnixPlatform) : Gen<int> =
        let darwin = isDarwin platform

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

    let private callGen (platform : SimulatedUnixPlatform) : Gen<Syscall<int, string>> =
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

        // Which of `O_SYNC` and `O_DSYNC` an `open(2)` asks for, as
        // `OpenFlags.Synchronous` and `DataSynchronous`: neither, `O_SYNC`
        // (which on Linux is both of its bits), or `O_SYNC|O_DSYNC`. `O_DSYNC`
        // alone is not among them: the library refuses it.
        let synchronous =
            Gen.elements [ false, false ; true, not (isDarwin platform) ; true, true ]

        let opening (path : PathArgumentBytes) (flags : OpenFlags) : Syscall<int, string> =
            Syscall.Open (path, OpenFlagWords.encode platform flags, 0o644)

        // LOCK_SH|LOCK_NB, LOCK_EX|LOCK_NB and LOCK_UN.
        let flockWord = Gen.elements [ 1 ||| 4 ; 2 ||| 4 ; 8 ]

        // Every write and pwrite is of one byte, and every pwrite at offset 0.
        let oneByte = CopiedArgument.Readable (ImmutableArray.Create 1uy)

        Gen.frequency
            [
                3,
                gen {
                    let! a = access
                    let! c = bool
                    let! s, d = synchronous
                    let! n = bool
                    let! t = Gen.frequency [ 3, Gen.constant false ; 1, Gen.constant true ]

                    return
                        opening
                            filePath
                            { FcntlWorld.opening a with
                                CloseOnExec = c
                                Synchronous = s
                                DataSynchronous = d
                                NoFollow = n
                                Truncate = t
                            }
                }
                // As `opendir(3)` opens one: `O_RDONLY|O_DIRECTORY`.
                1,
                Gen.map2
                    (fun c (s, d) ->
                        opening
                            directoryPath
                            { FcntlWorld.opening FileAccessMode.ReadOnly with
                                CloseOnExec = c
                                Directory = true
                                Synchronous = s
                                DataSynchronous = d
                            }
                    )
                    bool
                    synchronous
                2,
                Gen.map2
                    (fun n c ->
                        Syscall.Pipe2 (
                            UserBuffer.Mapped,
                            (if n then OpenFlagWords.nonBlock platform else 0)
                            ||| (if c then OpenFlagWords.closeOnExec platform else 0)
                        )
                    )
                    bool
                    bool
                2, Gen.map Syscall.Dup fd
                3,
                Gen.map3
                    (fun f m c ->
                        Syscall.Fcntl (
                            f,
                            (if c then
                                 FcntlWorld.dupFdCloexec platform
                             else
                                 FcntlWorld.DupFd),
                            m
                        )
                    )
                    fd
                    (Gen.frequency
                        [
                            8, Gen.choose (0, 14)
                            1, Gen.elements [ -1 ; System.Int32.MinValue ]
                            3, nearBound
                        ])
                    bool
                3, Gen.map (fun f -> Syscall.Fcntl (f, FcntlWorld.GetFd, 0)) fd
                3,
                Gen.map2
                    (fun f w -> Syscall.Fcntl (f, FcntlWorld.SetFd, w))
                    fd
                    (Gen.elements [ 0 ; 1 ; 2 ; 3 ; -1 ; 4 ; 0x80000 ])
                3, Gen.map (fun f -> Syscall.Fcntl (f, FcntlWorld.GetFl, 0)) fd
                3, Gen.map2 (fun f w -> Syscall.Fcntl (f, FcntlWorld.SetFl, w)) fd (wordGen platform)
                4, Gen.map2 (fun o n -> Syscall.Dup2 (o, n)) fd fd
                // `O_CLOEXEC`, and now and then `O_NONBLOCK`, which `dup3`
                // refuses.
                2,
                Gen.map3
                    (fun (o, n) c s ->
                        Syscall.Dup3 (
                            o,
                            n,
                            (if c then OpenFlagWords.closeOnExec platform else 0)
                            ||| (if s then OpenFlagWords.nonBlock platform else 0)
                        )
                    )
                    (Gen.zip fd fd)
                    bool
                    (Gen.frequency [ 5, Gen.constant false ; 1, Gen.constant true ])
                2, Gen.map (fun f -> Syscall.Write (f, oneByte, 1UL)) fd
                1, Gen.map (fun f -> Syscall.PWrite (f, oneByte, 1UL, 0L)) fd
                1,
                Gen.map2
                    (fun f l -> Syscall.FTruncate (f, l))
                    fd
                    (Gen.frequency [ 8, Gen.map int64 (Gen.choose (0, 4)) ; 1, Gen.constant -1L ])
                3, Gen.map2 (fun f o -> Syscall.FLock (f, o)) fd flockWord
                3, Gen.map Syscall.Close fd
            ]

    [<Test>]
    let ``every descriptor-table call answers as the reference does, and leaves the same table and statuses of its flavour``
        ()
        : unit
        =
        let property
            (cover : string -> unit)
            (platform : SimulatedUnixPlatform, calls : Syscall<int, string> list)
            : unit
            =
            let mutable system = system platform
            let darwin = isDarwin platform

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

            for i, call in List.indexed calls do
                let where () : string = $"%O{platform}, call %d{i} (%A{call})"
                let expected, after = step call reference
                let actual, afterSystem = library call system

                if actual <> expected then
                    failwith $"%s{where ()}: expected %A{expected}, got %A{actual}"

                match writtenThroughSteps call system with
                | Some (throughSteps, afterSteps) when throughSteps <> actual || afterSteps <> afterSystem ->
                    failwith
                        $"%s{where ()}: UnixSystem.tryStep answered %A{actual}, and the call's own functions %A{throughSteps}, or left another system"
                | Some _
                | None -> ()

                cover (
                    match call, actual with
                    | _, Outcome.Refused -> "refused"
                    | Syscall.Fcntl (_, command, _), Outcome.RefusedAtBound _ when isDupFd platform command ->
                        "F_DUPFD at the bound"
                    | Syscall.Dup2 _, Outcome.RefusedAtBound _ -> "dup2 at the bound"
                    | _, Outcome.RefusedAtBound _ -> "at the bound"
                    | Syscall.Dup2 (o, n), Outcome.Answered (SyscallAnswer.Completed _) when
                        o <> n && Map.containsKey n reference.Fds
                        ->
                        "dup2 onto an open descriptor"
                    | Syscall.Fcntl (_, command, m), Outcome.Answered (SyscallAnswer.Completed fd) when
                        isDupFd platform command && fd > int64 m
                        ->
                        "F_DUPFD past a taken minimum"
                    | _, Outcome.Answered (SyscallAnswer.Failed error) -> $"%O{error}"
                    | call, Outcome.Answered (SyscallAnswer.Completed _) -> kindOf platform call
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

                // Every descriptor's status word, whether or not the call
                // asked for one.
                for fd in Map.keys reference.Fds do
                    let description, _, _ = reference.Fds.[fd]

                    match
                        UnixSystem.tryStep (Callers.leader system) (Syscall.Fcntl (fd, FcntlWorld.GetFl, 0)) system
                    with
                    | Ok (SteppedCall.Fcntl (answer, _)) ->
                        answer
                        |> Expect.equal
                            (fun () -> $"%s{where ()}, F_GETFL of %d{fd}")
                            (SyscallAnswer.Completed (int64 (statusWord reference reference.Descriptions.[description])))
                    | Ok stepped -> failwith $"%s{where ()}: F_GETFL of %d{fd} answered %A{stepped}"
                    | Error refusal ->
                        failwith $"%s{where ()}: F_GETFL of %d{fd} refused: %s{SyscallRefusal.describe refusal}"

                // Every description's status is its machine's flavour's.
                for KeyValue (id, description) in OpenFileTable.descriptions system.Machine.OpenFiles do
                    if not (statusIsOf (SimulatedUnixPlatform.flavour platform) description.Status) then
                        failwith
                            $"%s{where ()}: description %O{id}'s status %A{description.Status} is not %O{platform}'s"

                UnixSystem.checkInvariants system |> Expect.empty where

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! calls = Gen.listOf (callGen platform)
                return platform, calls
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
                "F_SETFL"
                "dup3"
                "write"
                "pwrite"
                "ftruncate"
                "flock"
                "open of a directory"
                "EAGAIN"
                "ESPIPE"
            ] do
            if coverage.Count label = 0 then
                failwith $"the property never reached %s{label}; reached %A{coverage.Reached |> List.sort}"
