namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What a `write(2)` or `pwrite(2)` to a regular file leaves behind when the
/// copy from the caller's buffer faults: the call answers EFAULT, having
/// already done some of what a write does to the file.
///
/// Every row of `docs/probes/faulting-file-write` is replayed against a model
/// booted like the machine that measured it, and the faulting write is held to
/// the successful one it falls short of.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFaultingFileWrite =

    let private context : string = "TestFaultingFileWrite"

    /// The writers a probe row names.
    [<RequireQualifiedAccess>]
    type private Writer =
        /// The file's owner, uid 1000 with gid 1000, on Linux.
        | Owner
        /// uid 1001 with gid 1000, not the file's owner, on Linux.
        | NonOwner
        /// uid 0, on Linux.
        | Root
        /// Darwin's measuring user, uid 501 with gid 20, the file's owner.
        | DarwinOwner

    /// One row of a probe output.
    type private Row =
        {
            Writer : Writer
            /// Whether the file's group is one the writer is in.
            GroupIn : bool
            Size : int
            /// `write` or `pwrite`.
            Call : string
            Offset : int64
            /// `mapped`, `null`, `protnone`, `past48` or `top`.
            Buffer : string
            Count : int
            Before : int
            /// What the probe printed after the arrow.
            Result : string
        }

    let private rowPattern : Regex =
        Regex
            @"^writer=(\S+) group=(in|out) size=(\d+) call=(write|pwrite) offset=(\d+) buffer=(\S+) count=(\d+) before=([0-7]+) -> (.*)$"

    let private recorded (resource : string) : Row list =
        let logicalName = $"WoofWare.PosixKernel.Test.faulting-file-write.%s{resource}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream logicalName with
            | null -> failwith $"no embedded resource %s{logicalName}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray
        |> List.filter (fun line -> not (line.StartsWith "#" || line.StartsWith "uname:"))
        |> List.choose (fun line ->
            let m = rowPattern.Match line

            if not m.Success then
                failwith $"%s{resource}: unexpected line %s{line}"

            let result = m.Groups.[9].Value

            if result = "unsettable" then
                None
            else

            Some
                {
                    Writer =
                        match m.Groups.[1].Value with
                        | "uid1000" -> Writer.Owner
                        | "uid1001" -> Writer.NonOwner
                        | "root" -> Writer.Root
                        | "self" -> Writer.DarwinOwner
                        | other -> failwith $"%s{resource}: unexpected writer %s{other}"
                    GroupIn = m.Groups.[2].Value = "in"
                    Size = int m.Groups.[3].Value
                    Call = m.Groups.[4].Value
                    Offset = int64 m.Groups.[5].Value
                    Buffer = m.Groups.[6].Value
                    Count = int m.Groups.[7].Value
                    Before = Convert.ToInt32 (m.Groups.[8].Value, 8)
                    Result = result
                }
        )

    let private user (uid : uint32) : UserId = UserId.parseOrFail context uid
    let private group (gid : uint32) : GroupId = GroupId.parseOrFail context gid

    let private credentialsOf (writer : Writer) : Credentials =
        match writer with
        | Writer.Owner -> Credentials.ofIds (user 1000u) (group 1000u) []
        | Writer.NonOwner -> Credentials.ofIds (user 1001u) (group 1000u) []
        | Writer.Root -> Credentials.ofIds UserId.root (group 0u) []
        | Writer.DarwinOwner -> Credentials.ofIds (user 501u) (group 20u) []

    /// The file's owner, as the probe's setup left it.
    let private ownerOf (writer : Writer) (groupIn : bool) : InodeOwner =
        match writer with
        | Writer.DarwinOwner ->
            {
                User = user 501u
                Group = group (if groupIn then 20u else 0u)
            }
        | Writer.Owner
        | Writer.NonOwner
        | Writer.Root ->
            {
                User = user 1000u
                Group = group (if groupIn then 1000u else 2000u)
            }

    /// The address each of the probe's buffers names.
    let private bufferOf (name : string) : UserBuffer =
        match name with
        | "mapped" -> UserBuffer.Mapped
        | "null" -> UserBuffer.Unmapped 0UL
        // Any address below the user limit that no mapping backs.
        | "protnone" -> UserBuffer.Unmapped 0x0000_7000_0000_0000UL
        | "past48" -> UserBuffer.Unmapped (1UL <<< 48)
        | "top" -> UserBuffer.Unmapped (UInt64.MaxValue - 4095UL)
        | other -> failwith $"unexpected buffer %s{other}"

    /// What a write or pwrite left: the probe's fields, as the model reports
    /// them, and the file's contents.
    type private Observed =
        {
            Answer : WriteAnswer
            Mode : int
            Size : int64
            Position : int64
            AccessTimeMoved : bool
            ModificationTimeMoved : bool
            ChangeTimeMoved : bool
            /// `fcntl(fd, F_GETFL)`.
            Flags : int64
            /// Linux: the inotify records' masks, in order. Darwin: `None`.
            Events : uint32 list option
            Contents : byte[]
        }

    let private inotifyNames : (uint32 * string) list =
        [
            0x1u, "IN_ACCESS"
            0x2u, "IN_MODIFY"
            0x4u, "IN_ATTRIB"
            0x8u, "IN_CLOSE_WRITE"
            0x10u, "IN_CLOSE_NOWRITE"
            0x20u, "IN_OPEN"
        ]

    /// `observed` as the probe prints it.
    let private render (observed : Observed) : string =
        let ret, errno =
            match observed.Answer with
            | WriteAnswer.Completed count -> count, 0
            // EFAULT is 14 in both flavours' numberings.
            | WriteAnswer.Failed UnixError.EFAULT -> -1L, 14
            | WriteAnswer.Failed other -> failwith $"unexpected error %O{other}"

        let moved (b : bool) = if b then "moved" else "same"

        let events =
            match observed.Events with
            | None -> "-"
            | Some [] -> "none"
            | Some masks ->
                masks
                |> List.collect (fun mask ->
                    let named = inotifyNames |> List.filter (fun (bit, _) -> mask &&& bit <> 0u)
                    let rest = named |> List.fold (fun m (bit, _) -> m &&& ~~~bit) mask
                    (named |> List.map snd) @ (if rest = 0u then [] else [ $"0x%x{rest}" ])
                )
                |> String.concat "|"

        let mode = Convert.ToString(observed.Mode, 8).PadLeft (5, '0')

        $"ret=%d{ret} errno=%d{errno} mode=%s{mode} size=%d{observed.Size} pos=%d{observed.Position} atime=%s{moved observed.AccessTimeMoved} mtime=%s{moved observed.ModificationTimeMoved} ctime=%s{moved observed.ChangeTimeMoved} flags=0x%x{observed.Flags} events=%s{events}"

    /// How a call ended: what it left, or the refusal's message.
    [<RequireQualifiedAccess>]
    type private Ended =
        | Observed of Observed
        | Refused of string

    /// The probe's row on a model: a file of `size` bytes `'h'` with mode
    /// `before`, owned by `owner`, at `/f`, opened for reading and writing by a
    /// process of `credentials`, which (on Linux) watches it with inotify; then,
    /// a second later, `call` of `count` bytes at `offset` through `buffer`,
    /// whose bytes are "WORLD..." when it is mapped.
    let private run
        (platform : SimulatedUnixPlatform)
        (owner : InodeOwner)
        (credentials : Credentials)
        (size : int)
        (before : int)
        (call : string)
        (offset : int64)
        (buffer : UserBuffer)
        (count : int)
        : Ended
        =
        let seed =
            Map.ofList
                [
                    DirectoryEntryName.parseOrFail context "f",
                    SeedEntry.File (
                        ImmutableArray.CreateRange (Array.create size (byte 'h')),
                        PermissionBits.parseOrFail context before,
                        Some owner
                    )
                ]

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.fileSystem
                (UnixTimestamp.ofMillisecondsSinceEpoch 0L)
                {
                    User = UserId.root
                    Group = group 0u
                }
                seed
            |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let caller = Callers.leader system
        let linux = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Linux

        let fd, system =
            InotifyReplay.openFd (InotifyReplay.openFlags FileAccessMode.ReadWrite false false false) "/f" 0 system

        let instance, system =
            if linux then
                let instance, system = InotifyReplay.init1 InotifyReplay.nonblock system

                let _, system =
                    InotifyReplay.watch instance "/f" InotifyReplay.modelledEvents system

                Some instance, system
            else
                None, system

        let system =
            if call = "write" then
                match UnixDescriptor.lseek caller fd offset 0 system with
                | SyscallAnswer.Completed _, system -> system
                | other -> failwith $"lseek: %A{other}"
            else
                system

        let system = UnixSystem.advanceClock 1_000_000_000L system

        let stat (system : UnixSystem<int, string>) : FileStatus =
            match UnixPathResolution.fstat caller fd system with
            | FileStatusAnswer.Reported status -> status
            | other -> failwith $"fstat: %A{other}"

        let statBefore = stat system

        let bytes =
            ImmutableArray.CreateRange (Array.init count (fun i -> byte "WORLD".[i % 5]))

        let answered : Result<WriteAnswer * UnixSystem<int, string>, string> =
            if call = "write" then
                UnixReadWrite.tryWrite caller fd buffer (uint64 count) system
                |> CallProgress.resumeWith (fun paused -> UnixReadWrite.tryWriteWithBytes bytes paused)
                |> Result.map (fun fate ->
                    match fate with
                    | ProcessFate.Continues (WriteOutcome.Returns answer, system) -> answer, system
                    | other -> failwith $"write: %A{other}"
                )
                |> Result.mapError WriteRefusal.describe
            else
                UnixReadWrite.tryPwrite caller fd buffer (uint64 count) offset system
                |> CallProgress.resumeWith (fun paused -> UnixReadWrite.tryPwriteWithBytes bytes paused)
                |> Result.mapError PWriteRefusal.describe

        match answered with
        | Error message -> Ended.Refused message
        | Ok (answer, system) ->

        let statAfter = stat system

        let position =
            match UnixDescriptor.lseek caller fd 0L 1 system with
            | SyscallAnswer.Completed position, _ -> position
            | other -> failwith $"lseek: %A{other}"

        let flags =
            // `F_GETFL` is 3 in both flavours' numberings.
            match UnixDescriptor.tryFcntl caller fd 3 0 system with
            | Ok (SyscallAnswer.Completed flags, _) -> flags
            | other -> failwith $"fcntl: %A{other}"

        let events, system =
            match instance with
            | None -> None, system
            | Some instance ->
                let records, system = InotifyReplay.drainRecords instance system
                Some (records |> List.map (fun record -> record.Mask)), system

        let contents =
            match UnixReadWrite.pread caller fd UserBuffer.Mapped (uint64 statAfter.Size) 0L system with
            | ReadAnswer.Completed read, _ -> read.AsSpan().ToArray ()
            | other -> failwith $"pread: %A{other}"

        Ended.Observed
            {
                Answer = answer
                Mode = statAfter.Mode &&& 0o7777
                Size = statAfter.Size
                Position = position
                AccessTimeMoved = statAfter.AccessTime <> statBefore.AccessTime
                ModificationTimeMoved = statAfter.ModificationTime <> statBefore.ModificationTime
                ChangeTimeMoved = statAfter.StatusChangeTime <> statBefore.StatusChangeTime
                Flags = flags
                Events = events
                Contents = contents
            }

    let private replay (resource : string) (platform : SimulatedUnixPlatform) : unit =
        let rows = recorded resource
        rows |> List.isEmpty |> shouldEqual false

        let mismatches =
            rows
            |> List.choose (fun row ->
                let ended =
                    run
                        platform
                        (ownerOf row.Writer row.GroupIn)
                        (credentialsOf row.Writer)
                        row.Size
                        row.Before
                        row.Call
                        row.Offset
                        (bufferOf row.Buffer)
                        row.Count

                let modelled =
                    match ended with
                    | Ended.Observed observed -> render observed
                    | Ended.Refused message -> $"refused: %s{message}"

                if modelled = row.Result then
                    None
                else
                    Some $"%A{row}\n  measured %s{row.Result}\n  modelled %s{modelled}"
            )

        if not (List.isEmpty mismatches) then
            let shown = mismatches |> List.truncate 10 |> String.concat "\n"
            failwith $"%s{resource}: %d{mismatches.Length} of %d{rows.Length} rows differ, for example:\n%s{shown}"

    [<Test>]
    let ``Linux tmpfs: every measured row`` () =
        replay "linux-6.18.5-aarch64-tmpfs.txt" SimulatedUnixPlatform.linuxArm64

    [<Test>]
    let ``Linux ext4: every measured row`` () =
        replay "linux-6.18.5-aarch64-ext4.txt" SimulatedUnixPlatform.linuxArm64

    [<Test>]
    let ``Darwin APFS: every measured row`` () =
        replay "darwin-27.0.0-arm64-apfs.txt" SimulatedUnixPlatform.macOsArm64

    /// A writer the property chooses among.
    type private Standing =
        | OwnerInGroup
        | OwnerOutsideGroup
        | NonOwnerInGroup
        | NonOwnerOutsideGroup
        | Privileged
        | PrivilegedOwner

    let private standingOf (standing : Standing) : InodeOwner * Credentials =
        let owner (gid : uint32) : InodeOwner =
            {
                User = user 1000u
                Group = group gid
            }

        match standing with
        | OwnerInGroup -> owner 1000u, Credentials.ofIds (user 1000u) (group 1000u) []
        | OwnerOutsideGroup -> owner 2000u, Credentials.ofIds (user 1000u) (group 1000u) []
        | NonOwnerInGroup -> owner 1000u, Credentials.ofIds (user 1001u) (group 1000u) []
        | NonOwnerOutsideGroup -> owner 2000u, Credentials.ofIds (user 1001u) (group 1000u) []
        | Privileged -> owner 1000u, Credentials.ofIds UserId.root (group 0u) []
        | PrivilegedOwner ->
            {
                User = UserId.root
                Group = group 0u
            },
            Credentials.ofIds UserId.root (group 0u) []

    [<Test>]
    let ``A faulting write does what the successful write does before its copy`` () =
        let gen =
            gen {
                let! linux = Gen.elements [ true ; false ]

                let! standing =
                    Gen.elements
                        [
                            OwnerInGroup
                            OwnerOutsideGroup
                            NonOwnerInGroup
                            NonOwnerOutsideGroup
                            Privileged
                            PrivilegedOwner
                        ]

                let! size = Gen.choose (0, 40)
                let! offset = Gen.choose (0, 60)
                let! count = Gen.choose (1, 20)
                // Every mode a writer other than the owner can open for writing.
                let! mode = Gen.choose (0, 0o7777) |> Gen.map (fun mode -> mode ||| 0o666)
                let! call = Gen.elements [ "write" ; "pwrite" ]
                let! address = Gen.elements [ 0UL ; 0x1000UL ; 0x0000_7000_0000_0000UL ]
                return linux, standing, size, int64 offset, count, mode, call, address
            }

        let property
            (
                linux : bool,
                standing : Standing,
                size : int,
                offset : int64,
                count : int,
                mode : int,
                call : string,
                address : uint64
            )
            : unit
            =
            let platform =
                if linux then
                    SimulatedUnixPlatform.linuxArm64
                else
                    SimulatedUnixPlatform.macOsArm64

            let owner, credentials = standingOf standing

            let go (buffer : UserBuffer) =
                run platform owner credentials size mode call offset buffer count

            let succeeded = go UserBuffer.Mapped
            let faulted = go (UserBuffer.Unmapped address)

            let measured =
                linux
                || (
                    match standing with
                    | OwnerInGroup
                    | OwnerOutsideGroup -> true
                    | NonOwnerInGroup
                    | NonOwnerOutsideGroup
                    | Privileged
                    | PrivilegedOwner -> false
                )

            match succeeded, faulted with
            // Darwin is measured for an unprivileged owner alone.
            | _, Ended.Refused _ when not measured -> ()
            | _, Ended.Observed observed when not measured ->
                failwith $"Darwin answered an unmeasured writer's faulting write: %s{render observed}"
            | Ended.Refused _, Ended.Refused _ -> ()
            | Ended.Observed succeeded, Ended.Observed faulted ->
                faulted.Answer |> shouldEqual (WriteAnswer.Failed UnixError.EFAULT)
                // The set-ID bits are stripped as by the write that succeeds.
                faulted.Mode |> shouldEqual succeeded.Mode
                // The file reaches the offset, and no further, and holds no
                // byte of the buffer.
                let length = max size (int offset)
                faulted.Size |> shouldEqual (int64 length)

                faulted.Contents
                |> shouldEqual (Array.init length (fun i -> if i < size then byte 'h' else 0uy))

                faulted.Position |> shouldEqual (if call = "write" then offset else 0L)
                faulted.AccessTimeMoved |> shouldEqual false
                // The description is not marked written, as no byte moved.
                faulted.Flags |> shouldEqual (succeeded.Flags &&& ~~~0x10000L)
                // Linux moves both times before the copy, and Darwin only for a
                // write that reaches past the end of the file.
                let moves = linux || offset + int64 count > int64 size
                faulted.ModificationTimeMoved |> shouldEqual moves
                faulted.ChangeTimeMoved |> shouldEqual moves
                // `IN_ATTRIB` for the stripped bits, and no `IN_MODIFY`.
                let attrib = 0x4u

                let expected =
                    succeeded.Events
                    |> Option.map (fun masks -> masks |> List.filter (fun mask -> mask &&& attrib <> 0u))

                faulted.Events |> shouldEqual expected
            | succeeded, faulted ->
                failwith $"the write that succeeds ended %A{succeeded}, the faulting one %A{faulted}"

        Prop.forAll (Arb.fromGen gen) property |> Check.QuickThrowOnFailure

    [<Test>]
    let ``Darwin refuses a faulting write by root, which is unmeasured`` () =
        for (owner, credentials), call in
            List.allPairs [ standingOf Privileged ; standingOf PrivilegedOwner ] [ "write" ; "pwrite" ] do
            match
                run SimulatedUnixPlatform.macOsArm64 owner credentials 5 0o644 call 0L (UserBuffer.Unmapped 0UL) 5
            with
            | Ended.Refused _ -> ()
            | Ended.Observed observed -> failwith $"%s{call} answered %s{render observed}"

    [<Test>]
    let ``Darwin refuses a faulting write by a non-owner, which is unmeasured`` () =
        let owner, credentials = standingOf NonOwnerInGroup

        for call in [ "write" ; "pwrite" ] do
            match
                run SimulatedUnixPlatform.macOsArm64 owner credentials 5 0o666 call 0L (UserBuffer.Unmapped 0UL) 5
            with
            | Ended.Refused _ -> ()
            | Ended.Observed observed -> failwith $"%s{call} answered %s{render observed}"
