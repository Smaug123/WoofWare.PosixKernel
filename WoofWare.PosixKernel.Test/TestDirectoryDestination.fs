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

/// The buffer a directory read stores into, given to `readDirectoryEntry` as
/// a `UserBuffer` with the record's place in the call: the rows
/// `getdents-fault.c` measured (`docs/probes/getdents-fault`), replayed on
/// both flavours through a client that fills a buffer the way the process's
/// call does, and a property that a destination changes only what the
/// kernel would store.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDirectoryDestination =

    let private context : string = "TestDirectoryDestination"
    let private epoch : UnixTimestamp = UnixTimestamp.ofMillisecondsSinceEpoch 0L

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform =
        match flavour with
        | SimulatedUnixFlavour.Linux -> SimulatedUnixPlatform.linuxArm64
        | SimulatedUnixFlavour.Darwin -> SimulatedUnixPlatform.macOsArm64

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    /// Who ran the probe: uid 65534 in the Linux container, uid 501 (group 20)
    /// on Darwin.
    let private credentialsOf (flavour : SimulatedUnixFlavour) : Credentials =
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            Credentials.ofIds (UserId.parseOrFail context 65534u) (GroupId.parseOrFail context 65534u) []
        | SimulatedUnixFlavour.Darwin ->
            Credentials.ofIds (UserId.parseOrFail context 501u) (GroupId.parseOrFail context 20u) []

    let private file : SeedEntry =
        SeedEntry.File (ImmutableArray.Empty, PermissionBits.parseOrFail context 0o644, None)

    /// What the probe made: `dir` holding `a` to `e`, and a regular file `f`.
    let private seed : Map<DirectoryEntryName, SeedEntry> =
        Map.ofList
            [
                name "dir",
                SeedEntry.Directory (
                    [ "a" ; "b" ; "c" ; "d" ; "e" ]
                    |> List.map (fun n -> name n, file)
                    |> Map.ofList,
                    PermissionBits.parseOrFail context 0o755,
                    None
                )
                name "f", file
                name "big",
                SeedEntry.Directory (
                    [ 0..39 ] |> List.map (fun i -> name $"n%02d{i}", file) |> Map.ofList,
                    PermissionBits.parseOrFail context 0o755,
                    None
                )
            ]

    let private systemOn (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        let credentials = credentialsOf flavour
        let image : UnixBootImage<int, string> = UnixSystem.initial (platformOf flavour)

        match UnixBootImage.tryWithFileSystem epoch (InodeOwner.ofProcess credentials) seed image with
        | Ok image ->
            Launched.bootWith
                (Launched.credentials credentials
                 >> ProcessLaunch.withCurrentDirectory (AbsoluteUnixPath.parseOrFail context "/"))
                UnixSystem.pipedStandardStreams
                0
                (CpuId 0)
                image
        | Error fault -> failwith $"could not build the probe's directory: %A{fault}"

    let private openAt (path : string) (directory : bool) (system : UnixSystem<int, string>) =
        let flags : OpenFlags =
            {
                Access =
                    if directory then
                        FileAccessMode.ReadOnly
                    else
                        FileAccessMode.ReadWrite
                Create = false
                Exclusive = false
                Truncate = false
                NoFollow = false
                CloseOnExec = false
                Synchronous = false
                DataSynchronous = false
                NonBlocking = false
                Directory = directory
            }

        match Answered.openPath (UnixPath.parseOrFail context path) flags 0 system with
        | DescriptorAnswer.Returned fd, system -> fd, system
        | DescriptorAnswer.Failed error, _ -> failwith $"open(%s{path}) answered %O{error}"

    // ------------------------------------------------------ a filling client

    /// `d_reclen` of a record naming `entryName`: `struct linux_dirent64` on
    /// Linux, whose name starts at byte 19, and Darwin's `struct direntry`,
    /// whose fixed part is 24 bytes; each NUL-terminated and padded to 8.
    let private recordLength (flavour : SimulatedUnixFlavour) (entryName : PathComponent) : int =
        let length = (PathComponent.toByteString entryName |> UnixByteString.toBytes).Length

        let header =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 19
            | SimulatedUnixFlavour.Darwin -> 24

        (header + length + 1 + 7) &&& ~~~7

    /// The bytes of a record the kernel stores: on Linux up to its name's
    /// NUL, and not the padding after it; on Darwin the whole record.
    let private storedLength (flavour : SimulatedUnixFlavour) (entryName : PathComponent) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 19 + (PathComponent.toByteString entryName |> UnixByteString.toBytes).Length + 1
        | SimulatedUnixFlavour.Darwin -> recordLength flavour entryName

    /// Which bytes of the process's buffer it can write.
    [<RequireQualifiedAccess>]
    type private Writable =
        | All
        /// Those from `low` up to, not including, `high`.
        | Range of low : int * high : int

    /// What the process's directory read returned, as this library's client
    /// works it out.
    [<RequireQualifiedAccess>]
    type private Batch =
        | Returned of bytes : int
        | Failed of error : UnixError
        | Refused

    /// One `getdents64` or `getdirentries64` into a buffer of `capacity` bytes
    /// of which `writable` the process can write, made the way a client makes
    /// it: a record at a time, asking with `Mapped` and, where the bytes the
    /// answer stores into are not all writable, again from the same system
    /// with `Unmapped address`.
    let private batch
        (flavour : SimulatedUnixFlavour)
        (fd : int)
        (capacity : int)
        (writable : Writable)
        (address : uint64)
        (system : UnixSystem<int, string>)
        : Batch * UnixSystem<int, string>
        =
        let covers (low : int) (high : int) : bool =
            match writable with
            | Writable.All -> true
            | Writable.Range (from, until) -> low >= high || (from <= low && high <= until)

        // Darwin's status word, in the last four bytes of a buffer of 1024
        // bytes or more, which hold no record.
        let statusWordWritable, recordCapacity =
            match flavour with
            | SimulatedUnixFlavour.Darwin when capacity >= 1024 -> covers (capacity - 4) capacity, capacity - 4
            | SimulatedUnixFlavour.Darwin
            | SimulatedUnixFlavour.Linux -> true, capacity

        let ask (destination : UserBuffer) (place : DirectoryBatchPlace) (system : UnixSystem<int, string>) =
            UnixNamespace.tryReadDirectoryEntry (Callers.leader system) fd destination place system

        let rec go (used : int) (system : UnixSystem<int, string>) : Batch * UnixSystem<int, string> =
            let place =
                if used = 0 then
                    DirectoryBatchPlace.First
                else
                    DirectoryBatchPlace.Following

            let faulted () =
                match ask (UserBuffer.Unmapped address) place system with
                | Ok (ReadDirectoryAnswer.Failed error, after) -> Batch.Failed error, after
                | Ok (ReadDirectoryAnswer.Stopped, after)
                | Ok (ReadDirectoryAnswer.EndOfDirectory, after) -> Batch.Returned used, after
                | Ok (ReadDirectoryAnswer.Entry record, _) -> failwith $"a read through no storage returned %A{record}"
                | Error _ -> Batch.Refused, system

            match ask UserBuffer.Mapped place system with
            | Error _ -> Batch.Refused, system
            | Ok (ReadDirectoryAnswer.Failed error, after) -> Batch.Failed error, after
            | Ok (ReadDirectoryAnswer.Stopped, _) -> failwith "a read through storage stopped"
            | Ok (ReadDirectoryAnswer.EndOfDirectory, after) ->
                if statusWordWritable then
                    Batch.Returned used, after
                else
                    faulted ()
            | Ok (ReadDirectoryAnswer.Entry record, after) ->
                let length = recordLength flavour record.Name

                if used + length > recordCapacity then
                    // Does not fit: the client's own business, except that a
                    // Darwin call that stored records through a status word
                    // it cannot write is one no call here answers.
                    if used > 0 && not statusWordWritable then
                        Batch.Refused, system
                    else
                        Batch.Returned used, system
                elif covers used (used + storedLength flavour record.Name) then
                    go (used + length) after
                else
                    faulted ()

        go 0 system

    /// How many entries reading the rest of `fd` through storage yields, and
    /// how that reading ends: `EOF`, or the errno's name.
    let private rest (flavour : SimulatedUnixFlavour) (fd : int) (system : UnixSystem<int, string>) : int * string =
        let rec go (count : int) (system : UnixSystem<int, string>) =
            match
                UnixNamespace.tryReadDirectoryEntry
                    (Callers.leader system)
                    fd
                    UserBuffer.Mapped
                    DirectoryBatchPlace.First
                    system
            with
            | Ok (ReadDirectoryAnswer.Entry _, after) -> go (count + 1) after
            | Ok (ReadDirectoryAnswer.EndOfDirectory, _) -> count, "EOF"
            | Ok (ReadDirectoryAnswer.Failed error, _) -> count, error.ToString ()
            | other -> failwith $"reading on through storage: %A{other}"

        go 0 system

    let private accessTime (path : string) (system : UnixSystem<int, string>) : UnixTimestamp =
        match
            UnixPathResolution.tryStat
                (Callers.leader system)
                SymlinkPolicy.Follow
                (PathArg.ofText path)
                UserBuffer.Mapped
                system
        with
        | Ok (FileStatusAnswer.Reported status) -> status.AccessTime
        | other -> failwith $"stat(%s{path}) answered %A{other}"

    let private descriptorAccessTime (fd : int) (system : UnixSystem<int, string>) : UnixTimestamp =
        match UnixPathResolution.tryFstat (Callers.leader system) fd UserBuffer.Mapped system with
        | Ok (FileStatusAnswer.Reported status) -> status.AccessTime
        | other -> failwith $"fstat(%d{fd}) answered %A{other}"

    let private advance (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixSystem.advanceClock 10_000_000L system

    // ------------------------------------------------------- the measured rows

    type private Row =
        {
            Case : string
            Destination : string
            Returned : int
            Errno : string
            Then : (int * string) option
            Atime : string option
        }

    let private rowsOf (flavour : SimulatedUnixFlavour) : Row list =
        let resource =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.getdents-fault.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.getdents-fault.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"no embedded resource %s{resource}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.choose (fun line ->
            let m =
                Regex.Match (
                    line,
                    @"^(\S+)\s+dest=(\S+)\s*: r=(-?\d+) errno=(\S+)(?: pos=\S+)?(?: then=(\d+):(\S*))?(?: atime=(\S+))?"
                )

            if m.Success then
                Some
                    {
                        Case = m.Groups.[1].Value
                        Destination = m.Groups.[2].Value
                        Returned = int m.Groups.[3].Value
                        Errno = m.Groups.[4].Value
                        Then =
                            if m.Groups.[5].Success then
                                // The probe ends the names with `<ERRNO>`
                                // where reading on failed.
                                let names = m.Groups.[6].Value
                                let ending = Regex.Match (names, @"<(\w+)>$")

                                let terminal = if ending.Success then ending.Groups.[1].Value else "EOF"

                                Some (int m.Groups.[5].Value, terminal)
                            else
                                None
                        Atime =
                            if m.Groups.[7].Success then
                                Some m.Groups.[7].Value
                            else
                                None
                    }
            else
                None
        )
        |> List.ofArray

    let private measured (row : Row) : Batch =
        if row.Returned >= 0 then
            Batch.Returned row.Returned
        else
            match UnixError.all |> List.tryFind (fun error -> error.ToString () = row.Errno) with
            | Some error -> Batch.Failed error
            | None -> failwith $"a row names errno %s{row.Errno}, which UnixError does not have"

    /// The rows this library does not model, each the client's business: a
    /// count too small for one record, and how many records a devfs call
    /// takes, which can be fewer than its buffer holds (`devfs-96`).
    let private notModelled (flavour : SimulatedUnixFlavour) (row : Row) : bool =
        row.Case = "count-1" || row.Case = "devfs-96"

    /// What the client sees for one row, and what reading on afterwards
    /// yields, and whether the access time it watched moved.
    let private replay (flavour : SimulatedUnixFlavour) (row : Row) : Batch * (int * string) option * string option =
        let system = systemOn flavour
        let recordSize = recordLength flavour (PathComponent.Name (name "a"))

        let writable =
            match row.Destination with
            | "ok" -> Writable.All
            | "null"
            | "prot_none"
            | "high" -> Writable.Range (0, 0)
            | "edge" ->
                match row.Case with
                | "partial-R1"
                | "devfs-partial"
                | "end-partial" -> Writable.Range (0, recordSize)
                | "partial-R1+8" -> Writable.Range (0, recordSize + 8)
                | "partial-R1+R2"
                | "partial-R1+R2-512" -> Writable.Range (0, 2 * recordSize)
                | "partial-R1+R2+R3" -> Writable.Range (0, 3 * recordSize)
                | "end-mostly" -> Writable.Range (0, 4096 - 24)
                | "end-last-byte" -> Writable.Range (0, 4095)
                | "start-tail" -> Writable.Range (0, 4092)
                | "big-tail-1024" -> Writable.Range (0, 1020)
                | "end-prefix"
                | "start-prefix" -> Writable.Range (4092, 4096)
                | first when first.StartsWith "first-" -> Writable.Range (0, int (first.Substring 6))
                | other -> failwith $"no edge case %s{other}"
            | other -> failwith $"no destination %s{other}"

        // The address the probe passed for each destination; the one for
        // its PROT_NONE page differs from run to run, and any address naming
        // no storage stands for it.
        let address =
            match row.Destination with
            | "prot_none" -> 0x1_0000_0000UL
            | "high" -> 0xFFFF_FFFF_FFFF_F000UL
            | "edge" -> 0x2_0000_0000UL
            | _ -> 0UL

        // The count the probe passed: `<case>-<count>` for the rows that
        // vary it, and 4096 otherwise.
        let capacity =
            let varies =
                row.Case.Contains "-null-"
                || List.contains row.Case [ "partial-R1+R2-512" ; "removed-32" ; "devfs-32" ; "devfs-96" ]

            match row.Case.Split '-' |> Array.last |> Int32.TryParse with
            | true, count when varies -> count
            | _ -> 4096

        let thenOf (fd : int) (after : UnixSystem<int, string>) : (int * string) option =
            row.Then |> Option.map (fun _ -> rest flavour fd after)

        let readFresh (path : string) (prepare : int -> UnixSystem<int, string> -> UnixSystem<int, string>) =
            let fd, system = openAt path true system
            let system = prepare fd system
            let outcome, after = batch flavour fd capacity writable address system
            outcome, thenOf fd after, None

        let toEnd (fd : int) (system : UnixSystem<int, string>) =
            match batch flavour fd 65536 Writable.All 0UL system with
            | Batch.Returned _, after -> after
            | other, _ -> failwith $"reading to the end: %A{other}"

        // A call that fails before it reaches the buffer, made directly
        // through the measured destination.
        let direct (fd : int) (system : UnixSystem<int, string>) =
            let destination =
                match row.Destination with
                | "ok" -> UserBuffer.Mapped
                | _ -> UserBuffer.Unmapped address

            match
                UnixNamespace.tryReadDirectoryEntry
                    (Callers.leader system)
                    fd
                    destination
                    DirectoryBatchPlace.First
                    system
            with
            | Ok (ReadDirectoryAnswer.Failed error, _) -> Batch.Failed error, None, None
            | other -> failwith $"%s{row.Case} dest=%s{row.Destination}: expected an errno, got %A{other}"

        match row.Case with
        | "closed-fd" -> direct 999 system
        | "regular-file" ->
            let fd, system = openAt "f" false system
            direct fd system
        | "start"
        | "start-null-512"
        | "start-tail"
        | "start-prefix"
        | "partial-R1"
        | "partial-R1+8"
        | "partial-R1+R2"
        | "partial-R1+R2+R3" -> readFresh "dir" (fun _ system -> system)
        | first when first.StartsWith "first-" -> readFresh "dir" (fun _ system -> system)
        | "after-first" ->
            // The probe's first read was of 64 bytes, the least Darwin takes:
            // two records on each flavour.
            readFresh
                "dir"
                (fun fd system ->
                    match batch flavour fd 64 Writable.All 0UL system with
                    | Batch.Returned bytes, after when bytes = 2 * recordSize -> after
                    | other, _ -> failwith $"the first read of 64 bytes: %A{other}"
                )
        | "partial-R1+R2-512" -> readFresh "dir" (fun _ system -> system)
        | "removed-32" ->
            let _, system =
                Answered.mkdir (Callers.leader system) (PathArg.ofText "gone") 0o755 system

            let fd, system = openAt "gone" true system

            let _, system =
                Answered.rmdir (Callers.leader system) (UnixPath.parseOrFail context "gone") system

            let outcome, after = batch flavour fd capacity writable address system
            outcome, thenOf fd after, None
        | resumed when resumed.StartsWith "resumed-" ->
            readFresh
                "dir"
                (fun fd system ->
                    match batch flavour fd (2 * recordSize) Writable.All 0UL system with
                    | Batch.Returned bytes, after when bytes = 2 * recordSize -> after
                    | other, _ -> failwith $"the first read of two records: %A{other}"
                )
        | "end"
        | "end-partial"
        | "end-mostly"
        | "end-last-byte"
        | "end-prefix" -> readFresh "dir" toEnd
        | "big-1024" ->
            let fd, system = openAt "big" true system
            let outcome, after = batch flavour fd 1024 Writable.All 0UL system
            outcome, thenOf fd after, None
        | "big-tail-1024" ->
            let fd, system = openAt "big" true system
            let outcome, after = batch flavour fd 1024 (Writable.Range (0, 1020)) address system
            outcome, thenOf fd after, None
        | "removed-atime"
        | "removed-atime-again" ->
            // A removed directory whose access time is before its
            // modification time, which APFS moves on a read.
            let _, system =
                Answered.mkdir (Callers.leader system) (PathArg.ofText "gone") 0o755 system

            let system = advance system

            let _, system =
                Answered.openPath
                    (UnixPath.parseOrFail context "gone/x")
                    { DirectoryReading.flags with
                        Directory = false
                        Create = true
                    }
                    0o644
                    system

            let _, system =
                Answered.unlink (Callers.leader system) (UnixPath.parseOrFail context "gone/x") system

            let fd, system = openAt "gone" true system

            let _, system =
                Answered.rmdir (Callers.leader system) (UnixPath.parseOrFail context "gone") system

            let system = advance system

            let system =
                if row.Case = "removed-atime-again" then
                    snd (batch flavour fd 4096 writable address system) |> advance
                else
                    system

            let before = descriptorAccessTime fd system
            let outcome, after = batch flavour fd 4096 writable address system

            let moved =
                if descriptorAccessTime fd after = before then
                    "kept"
                else
                    "moved"

            outcome, None, Some moved
        | "devfs-resumed" ->
            let fd, system = openAt "/dev" true system

            let system =
                match batch flavour fd 32 Writable.All 0UL system with
                | Batch.Returned 32, after -> after
                | other, _ -> failwith $"the first read of one /dev record: %A{other}"

            let before = accessTime "/dev" system
            let system = advance system
            let outcome, after = batch flavour fd 4096 writable address system
            let moved = if accessTime "/dev" after = before then "kept" else "moved"
            outcome, None, Some moved
        | "removed-first"
        | "removed-again" ->
            let _, system =
                Answered.mkdir (Callers.leader system) (PathArg.ofText "gone") 0o755 system

            let fd, system = openAt "gone" true system

            let _, system =
                Answered.rmdir (Callers.leader system) (UnixPath.parseOrFail context "gone") system

            let first, system = batch flavour fd 4096 writable address system

            if row.Case = "removed-first" then
                first, None, None
            else
                let again, after = batch flavour fd 4096 writable address system
                again, thenOf fd after, None
        | endNull when endNull.StartsWith "end-null-" -> readFresh "dir" toEnd
        | "removed" ->
            let _, system =
                Answered.mkdir (Callers.leader system) (PathArg.ofText "gone") 0o755 system

            let fd, system = openAt "gone" true system

            let _, system =
                Answered.rmdir (Callers.leader system) (UnixPath.parseOrFail context "gone") system

            let outcome, after = batch flavour fd 4096 writable address system
            outcome, thenOf fd after, None
        | "atime" ->
            match flavour with
            | SimulatedUnixFlavour.Darwin ->
                // An access time before the modification time, which APFS
                // moves on a read.
                let system = advance system

                let _, system =
                    Answered.openPath
                        (UnixPath.parseOrFail context "dir/new")
                        { DirectoryReading.flags with
                            Directory = false
                            Create = true
                        }
                        0o644
                        system

                let fd, system = openAt "dir" true system
                let before = accessTime "dir" system
                let system = advance system
                let outcome, after = batch flavour fd 4096 writable address system
                let moved = if accessTime "dir" after = before then "kept" else "moved"
                outcome, None, Some moved
            | SimulatedUnixFlavour.Linux ->
                // The probe's tmpfs was mounted strictatime, which this
                // library's tmpfs (noatime) is not; the devtmpfs at /dev is
                // relatime, and moves an access time equal to the directory's
                // modification time, as each is at boot.
                let fd, system = openAt "/dev" true system
                let before = accessTime "/dev" system
                let system = advance system
                let outcome, after = batch flavour fd 4096 writable address system
                let moved = if accessTime "/dev" after = before then "kept" else "moved"
                outcome, None, Some moved
        | "devfs-start"
        | "devfs-partial"
        | "devfs-32" ->
            let fd, system = openAt "/dev" true system
            let outcome, _ = batch flavour fd capacity writable address system
            outcome, None, None
        | "devfs-end" ->
            let fd, system = openAt "/dev" true system
            let outcome, _ = batch flavour fd 4096 writable address (toEnd fd system)
            outcome, None, None
        | "devfs-atime"
        | "devfs-atime-end" ->
            let fd, system = openAt "/dev" true system

            let system =
                if row.Case = "devfs-atime-end" then
                    toEnd fd system
                else
                    system

            let before = accessTime "/dev" system
            let system = advance system
            let outcome, after = batch flavour fd 4096 writable address system
            let moved = if accessTime "/dev" after = before then "kept" else "moved"
            outcome, None, Some moved
        | other -> failwith $"no case %s{other}"

    /// Rows the model refuses rather than answers: Darwin's faults after a
    /// record has been stored, through the status word after records, and
    /// on a description earlier calls have read from.
    let private refused (flavour : SimulatedUnixFlavour) (row : Row) : bool =
        flavour = SimulatedUnixFlavour.Darwin
        && (row.Case.StartsWith "partial-"
            || row.Case = "devfs-partial"
            || row.Case = "big-tail-1024"
            || row.Case = "after-first" && row.Destination <> "ok"
            || row.Case.StartsWith "resumed-")

    /// Rows whose directory this library does not reproduce entry for entry
    /// (`/dev`, and the directory an `atime` row adds to): the kind of
    /// answer is compared, not its size.
    let private sizeIgnored (row : Row) : bool =
        (row.Case.StartsWith "devfs-" || row.Case = "atime") && row.Returned > 0

    [<TestCaseSource(nameof flavours)>]
    let ``every modelled row answers as the kernel did`` (flavour : SimulatedUnixFlavour) : unit =
        let rows = rowsOf flavour
        let modelled = rows |> List.filter (notModelled flavour >> not)

        let mismatches =
            modelled
            |> List.choose (fun row ->
                let outcome, afterwards, atime = replay flavour row

                let expected =
                    if refused flavour row then
                        Batch.Refused
                    elif sizeIgnored row then
                        match outcome with
                        | Batch.Returned bytes when bytes > 0 -> outcome
                        | _ -> measured row
                    else
                        measured row

                let agrees =
                    outcome = expected
                    && (row.Then.IsNone || refused flavour row || afterwards = row.Then)
                    && (row.Atime.IsNone || atime = row.Atime)

                if agrees then
                    None
                else
                    Some
                        $"%s{row.Case} dest=%s{row.Destination}: measured %A{measured row} then %A{row.Then} atime %A{row.Atime}; model %A{outcome} then %A{afterwards} atime %A{atime}"
            )

        mismatches |> shouldEqual []

        // Every row was read: the probe prints this many per flavour.
        let expectedRows =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 62
            | SimulatedUnixFlavour.Darwin -> 83

        rows.Length |> shouldEqual expectedRows

        // Both sides are reached: an EFAULT only the buffer caused, a fault
        // the batch survives or is refused for, and an errno that beat it.
        modelled
        |> List.exists (fun row -> row.Destination <> "ok" && row.Errno = "EFAULT")
        |> shouldEqual true

        modelled
        |> List.exists (fun row -> row.Destination = "edge")
        |> shouldEqual true

        modelled
        |> List.exists (fun row -> row.Destination <> "ok" && row.Errno <> "EFAULT" && row.Errno <> "0")
        |> shouldEqual true

    [<TestCaseSource(nameof flavours)>]
    let ``a directory on NFS is refused through a buffer it cannot write`` (flavour : SimulatedUnixFlavour) : unit =
        let image : UnixBootImage<int, string> =
            UnixSystem.initial (platformOf flavour)
            |> UnixBootImage.tryWithMount (Some EmulatedMount.Nfs)
            |> Configured.expectOk MountRefusal.describe

        let credentials = credentialsOf flavour

        let system =
            match UnixBootImage.tryWithFileSystem epoch (InodeOwner.ofProcess credentials) seed image with
            | Ok image ->
                Launched.bootWith
                    (Launched.credentials credentials
                     >> ProcessLaunch.withCurrentDirectory (AbsoluteUnixPath.parseOrFail context "/"))
                    UnixSystem.pipedStandardStreams
                    0
                    (CpuId 0)
                    image
            | Error fault -> failwith $"could not build the directory: %A{fault}"

        let fd, system = openAt "dir" true system

        match
            UnixNamespace.tryReadDirectoryEntry
                (Callers.leader system)
                fd
                (UserBuffer.Unmapped 0UL)
                DirectoryBatchPlace.First
                system
        with
        | Error (ReadDirectoryRefusal.UnmeasuredDestinationFault _) -> ()
        | other -> failwith $"expected a refusal, got %A{other}"

        match
            UnixNamespace.tryReadDirectoryEntry
                (Callers.leader system)
                fd
                UserBuffer.Mapped
                DirectoryBatchPlace.First
                system
        with
        | Ok (ReadDirectoryAnswer.Entry _, _) -> ()
        | other -> failwith $"expected an entry, got %A{other}"

    // ------------------------------------------------------------ the property

    /// A directory read from a generated state: which directory, how many
    /// entries were read first, and whether it was then removed.
    type private Scenario =
        {
            Flavour : SimulatedUnixFlavour
            Names : string list
            ReadFirst : int
            Removed : bool
            Devfs : bool
            Destination : UserBuffer
            Place : DirectoryBatchPlace
        }

    let private scenarioGen : Gen<Scenario> =
        gen {
            let! flavour = Gen.elements flavours
            let! count = Gen.choose (0, 4)
            let names = [ "n0" ; "n1" ; "n2" ; "n3" ] |> List.truncate count
            let! readFirst = Gen.choose (0, count + 3)
            let! devfs = Gen.frequency [ 4, Gen.constant false ; 1, Gen.constant true ]

            let! removed =
                if devfs then
                    Gen.constant false
                else
                    Gen.elements [ false ; true ]

            let! destination =
                Gen.frequency
                    [
                        2, Gen.constant UserBuffer.Mapped
                        4, Gen.elements [ 0UL ; 0x1000UL ; UInt64.MaxValue ] |> Gen.map UserBuffer.Unmapped
                        1, Gen.constant UserBuffer.Opaque
                        1, Gen.constant UserBuffer.Addressless
                    ]

            let! place = Gen.elements [ DirectoryBatchPlace.First ; DirectoryBatchPlace.Following ]

            return
                {
                    Flavour = flavour
                    Names = names
                    ReadFirst = readFirst
                    Removed = removed
                    Devfs = devfs
                    Destination = destination
                    Place = place
                }
        }

    /// The scenario's system, with the descriptor it reads.
    let private prepared (scenario : Scenario) : int * UnixSystem<int, string> =
        let system = systemOn scenario.Flavour

        let path, system =
            if scenario.Devfs then
                "/dev", system
            else
                let _, system =
                    Answered.mkdir (Callers.leader system) (PathArg.ofText "t") 0o755 system

                let system =
                    (system, scenario.Names)
                    ||> List.fold (fun system n ->
                        let fd, system =
                            match
                                Answered.openPath
                                    (UnixPath.parseOrFail context $"t/%s{n}")
                                    { DirectoryReading.flags with
                                        Directory = false
                                        Create = true
                                    }
                                    0o644
                                    system
                            with
                            | DescriptorAnswer.Returned fd, system -> fd, system
                            | other -> failwith $"creating t/%s{n}: %A{other}"

                        snd (UnixDescriptor.close (Callers.leader system) fd system)
                    )

                "t", system

        let fd, system = openAt path true system

        let system =
            (system, [ 1 .. scenario.ReadFirst ])
            ||> List.fold (fun system _ ->
                match
                    UnixNamespace.tryReadDirectoryEntry
                        (Callers.leader system)
                        fd
                        UserBuffer.Mapped
                        DirectoryBatchPlace.First
                        system
                with
                | Ok (_, after) -> after
                | Error refusal -> failwith $"reading ahead: %s{ReadDirectoryRefusal.describe refusal}"
            )

        let system =
            if scenario.Removed then
                (system, scenario.Names)
                ||> List.fold (fun system n ->
                    snd (Answered.unlink (Callers.leader system) (UnixPath.parseOrFail context $"t/%s{n}") system)
                )
                |> fun system -> snd (Answered.rmdir (Callers.leader system) (UnixPath.parseOrFail context "t") system)
            else
                system

        advance system |> fun system -> fd, system

    /// What a read answers through `scenario.Destination`, by what it answered
    /// through storage and the system that answer left (`stored`). `None` is
    /// a refusal.
    let private reference
        (scenario : Scenario)
        (stored : ReadDirectoryAnswer * UnixSystem<int, string>)
        : (ReadDirectoryAnswer * UnixSystem<int, string>) option
        =
        let answer, after = stored
        let faulty = scenario.Destination <> UserBuffer.Mapped

        match answer with
        | _ when not faulty -> Some stored
        | ReadDirectoryAnswer.Failed _ -> Some stored
        | ReadDirectoryAnswer.Stopped -> failwith "a read through storage stopped"
        | ReadDirectoryAnswer.EndOfDirectory when scenario.Flavour = SimulatedUnixFlavour.Linux -> Some stored
        | ReadDirectoryAnswer.EndOfDirectory
        | ReadDirectoryAnswer.Entry _ ->
            match scenario.Destination, scenario.Flavour, scenario.Place with
            | UserBuffer.Opaque, _, _
            | UserBuffer.Addressless, _, _ -> None
            // APFS's status word after the records a call stored, at the end
            // of the directory: EFAULT, the position where the records left it.
            | UserBuffer.Unmapped _, SimulatedUnixFlavour.Darwin, DirectoryBatchPlace.Following when
                not scenario.Devfs
                && not scenario.Removed
                && (
                    match answer with
                    | ReadDirectoryAnswer.EndOfDirectory -> true
                    | _ -> false
                )
                ->
                Some (ReadDirectoryAnswer.Failed UnixError.EFAULT, after)
            | _, SimulatedUnixFlavour.Darwin, DirectoryBatchPlace.Following -> None
            // A record, or a removed directory, on an APFS description read
            // from before, short of its end: Darwin skips an entry by an
            // amount of its own. devfs keeps its position.
            | _, SimulatedUnixFlavour.Darwin, DirectoryBatchPlace.First when
                not scenario.Devfs
                && scenario.ReadFirst > 0
                && ((scenario.Removed && scenario.ReadFirst < List.length scenario.Names + 2)
                    || (
                        match answer with
                        | ReadDirectoryAnswer.Entry _ -> true
                        | _ -> false
                    ))
                ->
                None
            | _, SimulatedUnixFlavour.Linux, place ->
                // The entry stays next; the access time moves all the same.
                let faulted =
                    match place with
                    | DirectoryBatchPlace.First -> ReadDirectoryAnswer.Failed UnixError.EFAULT
                    | DirectoryBatchPlace.Following -> ReadDirectoryAnswer.Stopped

                Some (faulted, after)
            | _, SimulatedUnixFlavour.Darwin, DirectoryBatchPlace.First ->
                Some (ReadDirectoryAnswer.Failed UnixError.EFAULT, after)

    [<Test>]
    let ``a destination changes only what the kernel would store`` () : unit =
        let mutable faults = 0
        let mutable refusals = 0

        let property (scenario : Scenario) : unit =
            let fd, system = prepared scenario
            let caller = Callers.leader system

            let throughStorage =
                UnixNamespace.tryReadDirectoryEntry caller fd UserBuffer.Mapped scenario.Place system

            let seen =
                UnixNamespace.tryReadDirectoryEntry caller fd scenario.Destination scenario.Place system

            match throughStorage with
            | Error _ -> seen |> Result.map fst |> Result.isError |> shouldEqual true
            | Ok stored ->

            match reference scenario stored, seen with
            | None, Error _ -> refusals <- refusals + 1
            | None, Ok answer -> failwith $"%A{scenario}: expected a refusal, got %A{fst answer}"
            | Some (expected, _), Error refusal ->
                failwith $"%A{scenario}: expected %A{expected}, refused: %s{ReadDirectoryRefusal.describe refusal}"
            | Some (expected, expectedAfter), Ok (answer, after) ->
                answer |> shouldEqual expected

                match expected, fst stored with
                | ReadDirectoryAnswer.Failed UnixError.EFAULT, ReadDirectoryAnswer.Failed _ -> ()
                | ReadDirectoryAnswer.Failed UnixError.EFAULT, _
                | ReadDirectoryAnswer.Stopped, _ ->
                    faults <- faults + 1
                    // What the read would have returned through storage is
                    // still next, unless it removed directory moved to its end.
                    let next (system : UnixSystem<int, string>) =
                        UnixNamespace.tryReadDirectoryEntry caller fd UserBuffer.Mapped DirectoryBatchPlace.First system
                        |> Result.map fst

                    if scenario.Removed then
                        after |> shouldEqual (snd stored)
                    else
                        next after |> shouldEqual (Ok (fst stored))

                    // The access time is the one a successful read leaves,
                    // except on Darwin's APFS, where a fault moves nothing.
                    let path =
                        if scenario.Devfs then "/dev"
                        else if scenario.Removed then ""
                        else "t"

                    if path <> "" then
                        let expectedTime =
                            match scenario.Flavour, scenario.Devfs with
                            | SimulatedUnixFlavour.Darwin, false -> accessTime path system
                            | _ -> accessTime path (snd stored)

                        accessTime path after |> shouldEqual expectedTime
                | _ -> after |> shouldEqual expectedAfter

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 1000, Prop.forAll (Arb.fromGen scenarioGen) property)

        faults |> shouldBeGreaterThan 100
        refusals |> shouldBeGreaterThan 50
