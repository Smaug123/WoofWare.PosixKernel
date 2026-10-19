namespace WoofWare.PosixKernel.Test

open System.Collections.Generic
open FsCheck
open FsCheck.FSharp
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyReplay

/// The operations that `TestInotifyDelivery` runs against its reference, and
/// `TestInotifyDeliveryAgainstHost` against the host's kernel, in random
/// sequences over one starting tree: how a sequence is drawn, the syscall each
/// operation makes, and what the model answers it.
///
/// Every path is relative to the root of the tree, which is the process's
/// working directory.
module internal InotifyDeliveryOps =

    let private dirs : string list = [ "." ; "a" ; "a/s" ; "b" ]
    let private names : string list = [ "x" ; "y" ; "s" ; "a" ]

    let private join (dir : string) (entry : string) : string =
        if dir = "." then entry else $"%s{dir}/%s{entry}"

    /// Every path an operation names: each directory of the pool, and each
    /// name in each of them.
    let paths : string list =
        dirs
        @ [
            for dir in dirs do
                for entry in names -> join dir entry
        ]
        |> List.distinct

    /// The tree every sequence starts from: the directories "a", "a/s" and
    /// "b", and the files "a/x" and "b/y".
    let seed : (string * SeedEntry) list =
        [
            "a", directory 0o755 [ "s", directory 0o755 [] ; "x", file "x" ]
            "b", directory 0o755 [ "y", file "y" ]
        ]

    /// How a path names its final component.
    [<RequireQualifiedAccess>]
    type Form =
        | Plain
        /// The path with "/." appended.
        | Dot
        /// The path with "/" appended.
        | Slash

    [<RequireQualifiedAccess>]
    type Times =
        | Both
        | AccessOnly
        | ModificationOnly

    /// One operation of a sequence. A path is an index into `paths`, and an
    /// instance one of the sequence's two inotify instances.
    [<RequireQualifiedAccess>]
    type Op =
        /// `open(2)` of the path for writing, creating it, exclusively if
        /// `exclusive`; then a close of the descriptor it answers.
        | Create of path : int * exclusive : bool
        /// `open(2)` of the path for writing, with `O_TRUNC`; then a close of
        /// the descriptor it answers.
        | OpenTruncate of path : int
        | MkDir of path : int
        | RmDir of path : int
        | Unlink of path : int
        | Link of existing : int * path : int
        /// A symbolic link at the path, holding `target`.
        | Symlink of target : string * path : int
        | Rename of source : int * destination : int
        | Chmod of path : int * form : Form * mode : int
        /// `chown` to the tree's owner, or to neither ID.
        | Chown of path : int * neither : bool
        | Utimes of path : int * times : Times
        /// `inotify_add_watch(2)`, with `IN_DONT_FOLLOW` if `dontFollow`.
        | AddWatch of instance : int * path : int * mask : uint32 * dontFollow : bool
        | RmWatch of instance : int * wd : int
        /// `open(2)` of the path, kept: read-only, or for reading and writing.
        | Open of path : int * readOnly : bool
        /// Through the kept descriptor `slot` (0 the newest, and back from
        /// there, modulo how many are kept): a write of `count` bytes.
        | Write of slot : int * count : int
        | Ftruncate of slot : int
        | Fchmod of slot : int * mode : int
        | Close of slot : int
        /// `openat(2)` of "." from the kept descriptor `slot`, for reading,
        /// with `O_DIRECTORY`, kept: the directory that descriptor is onto,
        /// reached by ".", which it may be after the directory's removal.
        | OpenDotAt of slot : int

    /// Every event a watch in a sequence may ask for.
    let eventBits : uint32 list =
        [ modify ; attrib ; movedFrom ; movedTo ; create ; delete ; 0x400u ; 0x800u ]

    /// `IN_EXCL_UNLINK`.
    let exclUnlink : uint32 = 0x04000000u

    /// `IN_MOVE_SELF`.
    let moveSelf : uint32 = 0x800u

    /// `IN_DONT_FOLLOW`.
    let private dontFollowBit : uint32 = 0x02000000u

    let private opGen (targets : string list) : Gen<Op> =
        let path = Gen.choose (0, paths.Length - 1)

        let mask =
            gen {
                let! events =
                    Gen.subListOf eventBits
                    |> Gen.map (List.fold (|||) 0u)
                    |> Gen.filter (fun mask -> mask <> 0u)

                let! excl = Gen.elements [ false ; true ]
                return events ||| (if excl then exclUnlink else 0u)
            }

        let slot = Gen.choose (0, 7)

        Gen.frequency
            [
                4, Gen.map2 (fun p e -> Op.Create (p, e)) path (Gen.elements [ true ; false ])
                2, Gen.map Op.OpenTruncate path
                3, Gen.map Op.MkDir path
                2, Gen.map Op.RmDir path
                3, Gen.map Op.Unlink path
                2, Gen.map2 (fun e p -> Op.Link (e, p)) path path
                1, Gen.map2 (fun t p -> Op.Symlink (t, p)) (Gen.elements targets) path
                4, Gen.map2 (fun s d -> Op.Rename (s, d)) path path
                4,
                Gen.map3
                    (fun p f m -> Op.Chmod (p, f, m))
                    path
                    (Gen.elements [ Form.Plain ; Form.Plain ; Form.Dot ; Form.Slash ])
                    (Gen.elements [ 0o755 ; 0o700 ])
                2, Gen.map2 (fun p n -> Op.Chown (p, n)) path (Gen.elements [ false ; false ; true ])
                2,
                Gen.map2
                    (fun p t -> Op.Utimes (p, t))
                    path
                    (Gen.elements [ Times.Both ; Times.AccessOnly ; Times.ModificationOnly ])
                5,
                gen {
                    let! instance = Gen.choose (0, 1)
                    let! p = path
                    let! m = mask
                    let! dontFollow = Gen.elements [ false ; false ; false ; true ]
                    return Op.AddWatch (instance, p, m, dontFollow)
                }
                1, Gen.map2 (fun i w -> Op.RmWatch (i, w)) (Gen.choose (0, 1)) (Gen.choose (1, 6))
                4, Gen.map2 (fun p r -> Op.Open (p, r)) path (Gen.elements [ false ; false ; true ])
                5, Gen.map2 (fun s c -> Op.Write (s, c)) slot (Gen.elements [ 0 ; 1 ; 1 ; 3 ])
                2, Gen.map Op.Ftruncate slot
                2, Gen.map2 (fun s m -> Op.Fchmod (s, m)) slot (Gen.elements [ 0o755 ; 0o700 ])
                2, Gen.map Op.Close slot
                1, Gen.map Op.OpenDotAt slot
            ]

    /// A descriptor opened through a name that something then happens to,
    /// and a change through it: the name unlinked, renamed away, renamed over,
    /// given again by a link or a fresh file, its directory removed, or left
    /// alone. A slot of 0 is the newest kept descriptor, which this opened if
    /// the open succeeded.
    let private episodeGen : Gen<Op list> =
        gen {
            let path = Gen.choose (0, paths.Length - 1)
            let! p = path
            let! q = path
            let! readOnly = Gen.elements [ false ; false ; true ]

            let! meanwhile =
                Gen.elements
                    [
                        [ Op.Unlink p ]
                        [ Op.Rename (p, q) ]
                        [ Op.Rename (q, p) ]
                        [ Op.Unlink p ; Op.Link (q, p) ]
                        [ Op.Unlink p ; Op.Create (p, false) ]
                        [ Op.RmDir p ]
                        []
                    ]

            let! change = Gen.elements [ Op.Write (0, 1) ; Op.Ftruncate 0 ; Op.Fchmod (0, 0o700) ]
            return [ Op.Create (p, false) ; Op.Open (p, readOnly) ] @ meanwhile @ [ change ]
        }

    /// A directory opened through a name that something then happens to,
    /// opened again by "." from that descriptor, and a mode change through
    /// either: the name removed, renamed away, renamed over, or left alone.
    /// A slot of 0 is the newest kept descriptor, 1 the one before it.
    let private directoryEpisodeGen : Gen<Op list> =
        gen {
            let path = Gen.choose (0, paths.Length - 1)
            let! p = path
            let! q = path

            let! meanwhile =
                Gen.elements
                    [
                        [ Op.RmDir p ]
                        [ Op.RmDir p ]
                        [ Op.Rename (p, q) ; Op.RmDir q ]
                        [ Op.Rename (q, p) ]
                        [ Op.Rename (p, q) ]
                        []
                    ]

            let! through = Gen.elements [ 0 ; 0 ; 1 ]
            let! mode = Gen.elements [ 0o755 ; 0o700 ]

            return
                [ Op.MkDir p ; Op.Open (p, true) ]
                @ meanwhile
                @ [ Op.OpenDotAt 0 ; Op.Fchmod (through, mode) ]
        }

    /// A file with two names, watched itself, opened through one or both or
    /// one twice, then its names unlinked or renamed over in some order and
    /// its descriptors closed: when it goes for inotify depends on which
    /// names the descriptors hold. Or a directory, watched, opened, removed
    /// and closed.
    let private selfEpisodeGen : Gen<Op list> =
        gen {
            let path = Gen.choose (0, paths.Length - 1)
            let! p = path
            let! q = path
            let! other = path
            let! instance = Gen.choose (0, 1)
            let! events = Gen.elements [ 0xC00u ; 0x400u ; 0x4u ; List.fold (|||) 0u eventBits ]

            let! opens =
                Gen.elements [ [] ; [ p ] ; [ q ] ; [ p ; q ] ; [ p ; p ] ; [ q ; p ; q ] ]
                |> Gen.map (List.map (fun opened -> Op.Open (opened, false)))

            let! removals =
                Gen.elements
                    [
                        [ Op.Unlink p ; Op.Unlink q ]
                        [ Op.Unlink q ; Op.Unlink p ]
                        [ Op.Unlink p ; Op.Rename (other, q) ]
                        [
                            Op.Unlink q
                            Op.Link (p, q)
                            Op.Open (q, false)
                            Op.Unlink p
                            Op.Unlink q
                        ]
                    ]

            let! closes = Gen.listOfLength 4 (Gen.map Op.Close (Gen.choose (0, 3)))
            let! directory = Gen.frequency [ 3, Gen.constant false ; 1, Gen.constant true ]

            if directory then
                return
                    [
                        Op.MkDir p
                        Op.AddWatch (instance, p, events, false)
                        Op.Open (p, true)
                        Op.RmDir p
                        Op.Close 0
                    ]
            else
                return
                    [
                        Op.Create (p, false)
                        Op.Link (p, q)
                        Op.AddWatch (instance, p, events, false)
                    ]
                    @ opens
                    @ removals
                    @ closes
        }

    /// A symbolic link to one of `targets`, made at a path and watched for
    /// every event, itself (`IN_DONT_FOLLOW`) or what it names; then a mode
    /// change through the path, which follows the link, or the link unlinked
    /// or renamed, which does not.
    let private linkEpisodeGen (targets : string list) : Gen<Op list> =
        gen {
            let path = Gen.choose (0, paths.Length - 1)
            let! p = path
            let! q = path
            let! target = Gen.elements targets
            let! instance = Gen.choose (0, 1)
            let! dontFollow = Gen.elements [ true ; false ]

            let! change = Gen.elements [ Op.Chmod (p, Form.Plain, 0o700) ; Op.Unlink p ; Op.Rename (p, q) ]

            return
                [
                    Op.Symlink (target, p)
                    Op.AddWatch (instance, p, List.fold (|||) 0u eventBits, dontFollow)
                    change
                ]
        }

    /// A sequence of operations, each symbolic link's target one of
    /// `targets`. Half the sequences open by watching every directory of the
    /// pool, on both instances, for every event, half of those with
    /// `IN_EXCL_UNLINK`, so that most changes reach a watch; every sequence
    /// ends with a `linkEpisodeGen`, so that `IN_DONT_FOLLOW` meets a link.
    let caseGen (targets : string list) : Gen<Op list> =
        gen {
            let! opening = Gen.elements [ true ; false ]
            let! excl = Gen.elements [ 0u ; exclUnlink ]
            let! length = Gen.choose (10, 40)

            let! ops =
                Gen.listOfLength
                    length
                    (Gen.frequency
                        [
                            6, Gen.map List.singleton (opGen targets)
                            2, episodeGen
                            1, directoryEpisodeGen
                            1, selfEpisodeGen
                        ])
                |> Gen.map List.concat

            let! linkEpisode = linkEpisodeGen targets

            let watchAll =
                [
                    for instance in 0..1 do
                        for dir in dirs do
                            Op.AddWatch (
                                instance,
                                List.findIndex ((=) dir) paths,
                                List.fold (|||) 0u eventBits ||| excl,
                                false
                            )
                ]

            return (if opening then watchAll else []) @ ops @ linkEpisode
        }

    /// The index, oldest first, of the kept descriptor `slot` picks among
    /// `count`: the newest for 0, and back from there.
    let slotIndex (slot : int) (count : int) : int = count - 1 - slot % count

    /// Linux's `AT_FDCWD`.
    let linuxAtFdCwd : int = -100

    /// The syscall `op` makes on `platform`, whose inotify instances are `fds`
    /// and whose kept descriptors are `kept`, oldest first; a `Chown` gives
    /// the path to `owner`. `None` for a call through a kept descriptor when
    /// none is kept, which is not made. A `Create` or an `OpenTruncate` is
    /// the open, which `answer` follows with a close.
    let syscallOf
        (platform : SimulatedUnixPlatform)
        (owner : InodeOwner)
        (fds : int list)
        (kept : int list)
        (op : Op)
        : Syscall<int, string> option
        =
        let path (i : int) = PathArg.ofText paths.[i]
        let word (flags : OpenFlags) : int = OpenFlagWords.encode platform flags

        match op with
        | Op.Create (i, exclusive) ->
            Some (Syscall.Open (path i, word (openFlags FileAccessMode.WriteOnly true exclusive false), 0o644))
        | Op.OpenTruncate i ->
            Some (Syscall.Open (path i, word (openFlags FileAccessMode.WriteOnly false false true), 0o644))
        | Op.MkDir i -> Some (Syscall.MkDir (path i, 0o755))
        | Op.RmDir i -> Some (Syscall.RmDir (path i))
        | Op.Unlink i -> Some (Syscall.Unlink (path i))
        | Op.Link (existing, i) -> Some (Syscall.Link (path existing, path i))
        | Op.Symlink (target, i) -> Some (Syscall.Symlink (PathArg.ofText target, path i))
        | Op.Rename (source, destination) -> Some (Syscall.Rename (path source, path destination))
        | Op.Chmod (i, form, mode) ->
            let text =
                match form with
                | Form.Plain -> paths.[i]
                | Form.Dot -> paths.[i] + "/."
                | Form.Slash -> paths.[i] + "/"

            Some (Syscall.ChMod (PathArg.ofText text, mode))
        | Op.Chown (i, neither) ->
            let id = if neither then None else Some owner.User
            let gid = if neither then None else Some owner.Group
            Some (Syscall.ChOwn (path i, id, gid))
        | Op.Utimes (i, times) ->
            let access, modification =
                match times with
                | Times.Both -> timespec 1L 0L, timespec 2L 0L
                | Times.AccessOnly -> timespec 1L 0L, timespec 0L utimeOmit
                | Times.ModificationOnly -> timespec 0L utimeOmit, timespec 2L 0L

            Some (
                Syscall.UTimensAt (
                    linuxAtFdCwd,
                    NullablePathArgument.NotNull (path i),
                    TimesArgument.Fields (access, modification),
                    0
                )
            )
        | Op.AddWatch (instance, i, mask, dontFollow) ->
            Some (Syscall.InotifyAddWatch (fds.[instance], path i, mask ||| (if dontFollow then dontFollowBit else 0u)))
        | Op.RmWatch (instance, wd) -> Some (Syscall.InotifyRmWatch (fds.[instance], wd))
        | Op.Open (i, readOnly) ->
            let access =
                if readOnly then
                    FileAccessMode.ReadOnly
                else
                    FileAccessMode.ReadWrite

            Some (Syscall.Open (path i, word (openFlags access false false false), 0))
        | Op.Write _
        | Op.Ftruncate _
        | Op.Fchmod _
        | Op.Close _
        | Op.OpenDotAt _ ->

        match kept with
        | [] -> None
        | kept ->

        let slotOf (slot : int) = kept.[slotIndex slot kept.Length]

        match op with
        | Op.Write (slot, count) ->
            let bytes =
                System.Collections.Immutable.ImmutableArray.CreateRange (Array.create count (byte 'w'))

            Some (Syscall.Write (slotOf slot, CopiedArgument.Readable bytes, uint64 count))
        | Op.Ftruncate slot -> Some (Syscall.FTruncate (slotOf slot, 0L))
        | Op.Fchmod (slot, mode) -> Some (Syscall.FChMod (slotOf slot, mode))
        | Op.Close slot -> Some (Syscall.Close (slotOf slot))
        | Op.OpenDotAt slot ->
            let flags =
                { openFlags FileAccessMode.ReadOnly false false false with
                    Directory = true
                }

            Some (Syscall.OpenAt (slotOf slot, PathArg.ofText ".", word flags, 0))
        | other -> failwith $"%A{other} is not a call through a kept descriptor"

    /// The `SyscallAnswer` the call `stepped` answers, and the system after it.
    /// An open must return, and a write must return and raise no signal.
    let private answerOf
        (syscall : Syscall<int, string>)
        (stepped : SteppedCall<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        if UnionCaseName.ofValue stepped <> UnionCaseName.ofValue syscall then
            failwith $"Syscall.%s{UnionCaseName.ofValue syscall} answered SteppedCall.%s{UnionCaseName.ofValue stepped}"

        match stepped with
        | SteppedCall.MkDir (answer, after)
        | SteppedCall.RmDir (answer, after)
        | SteppedCall.Unlink (answer, after)
        | SteppedCall.Link (answer, after)
        | SteppedCall.Symlink (answer, after)
        | SteppedCall.Rename (answer, after)
        | SteppedCall.ChMod (answer, after)
        | SteppedCall.ChOwn (answer, after)
        | SteppedCall.UTimensAt (answer, after)
        | SteppedCall.InotifyAddWatch (answer, after)
        | SteppedCall.InotifyRmWatch (answer, after)
        | SteppedCall.FTruncate (answer, after)
        | SteppedCall.FChMod (answer, after)
        | SteppedCall.Close (answer, after) -> answer, after
        | SteppedCall.Open (SyscallOutcome.Answered answer, after) -> answer, after
        | SteppedCall.Open (outcome, _) -> failwith $"expected an open that returns, got %A{outcome}"
        | SteppedCall.OpenAt (SyscallOutcome.Answered answer, after) -> answer, after
        | SteppedCall.OpenAt (outcome, _) -> failwith $"expected an open that returns, got %A{outcome}"
        | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed written), after), _) ->
            SyscallAnswer.Completed written, after
        | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Failed error), after), _) ->
            SyscallAnswer.Failed error, after
        | SteppedCall.Write (ProcessFate.Continues (outcome, _), _) ->
            failwith $"expected a write that returns and raises no signal, got %A{outcome}"
        | SteppedCall.Write (ProcessFate.ProcessEnded (ended, _), _) ->
            failwith $"expected a write that returns and raises no signal, but it ended the process: %A{ended}"
        | other -> failwith $"SteppedCall.%s{UnionCaseName.ofValue other} answers no call the property makes"

    /// Fails the test unless `stepped`, what `UnixSystem.tryStep` answered for
    /// the `write(2)` of `bytes` through `fd` in `system`, is what the same
    /// write answers through the call's own functions, held to it made a step
    /// at a time (`WriteOutcomes.admitThenWriteDeliveringAs`), leaving the same
    /// system and delivering the same bytes.
    let private requireWrittenAlike
        (fd : int)
        (bytes : System.Collections.Immutable.ImmutableArray<byte>)
        (stepped : SteppedCall<int, string>)
        (system : UnixSystem<int, string>)
        : unit
        =
        let throughSteps =
            WriteOutcomes.admitThenWriteDeliveringAs (Callers.thread 0 system) fd UserBuffer.Mapped bytes system
            |> Result.map (fun (step, delivery) ->
                let fate =
                    match step with
                    | WriteStep.Returns (answer, after) -> ProcessFate.Continues (WriteOutcome.Returns answer, after)
                    | WriteStep.ReturnsRaising (answer, signal, after) ->
                        ProcessFate.Continues (WriteOutcome.ReturnsRaising (answer, signal), after)
                    | WriteStep.ProcessEnded (ended, after) -> ProcessFate.ProcessEnded (ended, after)
                    | WriteStep.WouldBlock (condition, after) ->
                        ProcessFate.Continues (WriteOutcome.WouldBlock condition, after)
                    | WriteStep.Interrupted after -> ProcessFate.Continues (WriteOutcome.Interrupted, after)

                fate, delivery
            )

        match stepped, throughSteps with
        | SteppedCall.Write (fate, delivery), Ok steps when (fate, delivery) = steps -> ()
        | _ ->
            let answered (fate : ProcessFate<WriteOutcome<int>, int, string>, delivery : Delivery option) : string =
                match fate with
                | ProcessFate.Continues (outcome, _) -> $"%A{outcome}, delivering %A{delivery}"
                | ProcessFate.ProcessEnded (ended, _) -> $"%A{ended}, delivering %A{delivery}"

            let viaStep =
                match stepped with
                | SteppedCall.Write (fate, delivery) -> answered (fate, delivery)
                | other -> $"SteppedCall.%s{UnionCaseName.ofValue other}"

            failwith
                $"write(%d{fd}): UnixSystem.tryStep answered %s{viaStep}, and the call's own functions %A{Result.map answered throughSteps}, or left another system"

    /// What the model answers `syscall`, the call `syscallOf` resolved `op`
    /// to, made through `UnixSystem.tryStep`, and the system after it. For a
    /// `Create` or an `OpenTruncate` that opens a descriptor, the answer of
    /// the close of it that follows. Fails the test if the model refuses the
    /// call, or if a write answers otherwise than the same write made a step
    /// at a time (`WriteOutcomes.admitThenWrite`).
    let answer
        (op : Op)
        (syscall : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        match UnixSystem.tryStep (Callers.leader system) syscall system with
        | Error refusal -> failwith $"%A{op}: refused: %s{SyscallRefusal.describe refusal}"
        | Ok stepped ->

        match op with
        | Op.Create _
        | Op.OpenTruncate _ ->
            match answerOf syscall stepped with
            | SyscallAnswer.Completed fd, after ->
                let close = Syscall.Close (int fd)

                match UnixSystem.tryStep (Callers.leader after) close after with
                | Ok (SteppedCall.Close (SyscallAnswer.Completed 0L, after)) -> SyscallAnswer.Completed 0L, after
                | Ok other -> failwith $"close(%d{fd}) answered %A{answerOf close other |> fst}"
                | Error refusal -> failwith $"close(%d{fd}) was refused: %s{SyscallRefusal.describe refusal}"
            | answered -> answered
        | Op.Write _ ->
            match syscall with
            | Syscall.Write (fd, CopiedArgument.Readable bytes, _) -> requireWrittenAlike fd bytes stepped system
            | other -> failwith $"%A{op} made %A{other}, which is not a write from readable memory"

            answerOf syscall stepped
        | _ -> answerOf syscall stepped

    /// Numbers each cookie by the order it first appears in.
    type Cookies () =
        let seen = Dictionary<uint32, uint32> ()

        member _.Ordinal (cookie : uint32) : uint32 =
            if cookie = 0u then
                0u
            else
                match seen.TryGetValue cookie with
                | true, ordinal -> ordinal
                | false, _ ->
                    let ordinal = uint32 seen.Count + 1u
                    seen.[cookie] <- ordinal
                    ordinal

    /// What a queued record carries, as a test counts its coverage.
    [<RequireQualifiedAccess>]
    type RecordLabel =
        /// `IN_CREATE`.
        | Create
        /// `IN_DELETE`.
        | Delete
        /// `IN_MOVED_TO`.
        | Moved
        /// `IN_ATTRIB` under a name, at the watch on its directory.
        | AttribNamed
        /// `IN_ATTRIB` at the inode's own watch.
        | AttribSelf
        /// `IN_MODIFY`.
        | Modify
        /// `IN_ISDIR`.
        | Directory
        /// `IN_IGNORED`.
        | Ignored
        /// `IN_DELETE_SELF`.
        | DeleteSelf
        /// `IN_MOVE_SELF`.
        | MoveSelf

    /// Every label a record of `mask` naming `entry` ("" for none) carries.
    let recordLabels (mask : uint32) (entry : string) : RecordLabel list =
        [
            if mask &&& create <> 0u then
                RecordLabel.Create
            if mask &&& delete <> 0u then
                RecordLabel.Delete
            if mask &&& movedTo <> 0u then
                RecordLabel.Moved
            if mask &&& attrib <> 0u && entry <> "" then
                RecordLabel.AttribNamed
            if mask &&& attrib <> 0u && entry = "" then
                RecordLabel.AttribSelf
            if mask &&& modify <> 0u then
                RecordLabel.Modify
            if mask &&& 0x40000000u <> 0u then
                RecordLabel.Directory
            if mask &&& 0x8000u <> 0u then
                RecordLabel.Ignored
            if mask &&& 0x400u <> 0u then
                RecordLabel.DeleteSelf
            if mask &&& moveSelf <> 0u then
                RecordLabel.MoveSelf
        ]
