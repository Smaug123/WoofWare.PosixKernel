namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// APFS takes a name as reaching the entry bound under any canonically
/// equivalent spelling of it, where Linux's filesystems compare bytes. This
/// library cannot decide canonical equivalence, so on Darwin it refuses
/// wherever the answer could depend on it, and answers as Linux does wherever
/// it cannot.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestNameEquivalence =

    let private boot (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private darwin : UnixSystem<int, string> = boot SimulatedUnixPlatform.macOsArm64

    let private linux : UnixSystem<int, string> = boot SimulatedUnixPlatform.linuxArm64

    let private byteString (bytes : byte list) : UnixByteString =
        match UnixByteString.ofBytes (ImmutableArray.CreateRange bytes) with
        | Ok value -> value
        | Error defect -> failwith $"test bytes %s{UnixByteString.describe defect}"

    let private arg (bytes : byte list) : PathArgumentBytes =
        PathArgumentBytes.Bytes (byteString bytes)

    let private ascii (text : string) : byte list =
        Encoding.ASCII.GetBytes text |> List.ofArray

    let private hexOf (bytes : byte list) : string =
        bytes |> List.map (fun b -> b.ToString "x2") |> String.concat ""

    let private bytesOfName (name : DirectoryEntryName) : byte list =
        DirectoryEntryName.toByteString name |> UnixByteString.toBytes |> List.ofSeq

    let private bytesOfHex (hex : string) : byte list =
        [ for i in 0..2 .. hex.Length - 2 -> Convert.ToByte (hex.Substring (i, 2), 16) ]

    let private openFlags (create : bool) (exclusive : bool) : OpenFlags =
        {
            Access = FileAccessMode.WriteOnly
            Create = create
            Exclusive = exclusive
            Truncate = false
            NoFollow = false
            CloseOnExec = false
            Synchronous = false
            DataSynchronous = false
            Directory = false
        }

    /// "é" as one precomposed code point, U+00E9.
    let private nfc : byte list = [ 0xC3uy ; 0xA9uy ]

    /// "é" as "e" and U+0301 COMBINING ACUTE ACCENT.
    let private nfd : byte list = [ 0x65uy ; 0xCCuy ; 0x81uy ]

    [<Test>]
    let ``Darwin refuses an exclusive create of the NFD spelling of a name bound in NFC`` () : unit =
        let system =
            match OpenFlagWords.openPath (openFlags true true) (arg nfc) 0o644 darwin with
            | Ok (SyscallAnswer.Completed _, system) -> system
            | other -> failwith $"creating the NFC spelling: expected a descriptor, got %A{other}"

        // Measured on APFS (`docs/probes/name-equivalence`): EEXIST, since the
        // NFD spelling reaches the entry bound in NFC.
        match OpenFlagWords.openPath (openFlags true true) (arg nfd) 0o644 system with
        | Error (OpenRefusal.Path (PathRefusal.UndecidedNameEquivalence (_, name, bound))) ->
            DirectoryEntryName.toByteString name |> shouldEqual (byteString nfd)
            DirectoryEntryName.toByteString bound |> shouldEqual (byteString nfc)
        | Ok (answer, _) -> failwith $"expected a refusal, got %A{answer}"
        | Error refusal -> failwith $"expected the lookup to be refused, got %s{OpenRefusal.describe refusal}"

    [<Test>]
    let ``Linux creates the NFD spelling of a name bound in NFC as a second name`` () : unit =
        let created (system : UnixSystem<int, string>) (name : byte list) : UnixSystem<int, string> =
            match OpenFlagWords.openPath (openFlags true true) (arg name) 0o644 system with
            | Ok (SyscallAnswer.Completed _, system) -> system
            | other -> failwith $"creating %s{hexOf name}: expected a descriptor, got %A{other}"

        let system = created (created linux nfc) nfd

        let names =
            match DirectoryReading.openDirectory (UnixPath.parseOrFail "test" "/") system with
            | Ok fd, system -> fst (DirectoryReading.drain fd system)
            | Error error, _ -> failwith $"opening the root: %O{error}"
            |> List.map (fun record ->
                DirectoryStreamName.toByteString record.Name
                |> UnixByteString.toBytes
                |> List.ofSeq
            )

        names |> shouldContain nfc
        names |> shouldContain nfd

    let private seedName (bytes : byte list) : DirectoryEntryName =
        match DirectoryEntryName.ofByteString (byteString bytes) with
        | Ok name -> name
        | Error error -> failwith $"test name: %s{DirectoryEntryName.describe error}"

    let private seedOf (names : byte list list) : Map<DirectoryEntryName, SeedEntry> =
        names
        |> List.map (fun name -> seedName name, SeedEntry.file ImmutableArray.Empty)
        |> Map.ofList

    let private seeded
        (platform : SimulatedUnixPlatform)
        (seed : Map<DirectoryEntryName, SeedEntry>)
        : Result<UnixBootImage<int, string>, FileSystemSeedFault>
        =
        UnixSystem.initial platform
        |> UnixBootImage.tryWithFileSystem (UnixTimestamp.ofMillisecondsSinceEpoch 0L) Owners.linuxDefault seed

    [<Test>]
    let ``a Darwin seed holding two names that might be one is refused, in any directory`` () : unit =
        let kelvin = [ 0xE2uy ; 0x84uy ; 0xAAuy ]
        let han = [ 0xE4uy ; 0xB8uy ; 0xADuy ]

        let refusedPair (seed : Map<DirectoryEntryName, SeedEntry>) : (byte list * byte list) option =
            match seeded SimulatedUnixPlatform.macOsArm64 seed with
            | Ok _ -> None
            | Error (FileSystemSeedFault.SeedNamesPossiblyEquivalent (first, second, SimulatedUnixFlavour.Darwin)) ->
                Some (bytesOfName first, bytesOfName second)
            | Error fault -> failwith $"expected the pair to be refused, got %s{FileSystemSeedFault.describe fault}"

        // Two spellings of one name: APFS holds one at a time.
        // The pair comes in byte order, which puts the decomposed spelling's
        // "e" first.
        refusedPair (seedOf [ nfc ; nfd ]) |> shouldEqual (Some (nfd, nfc))

        refusedPair (seedOf [ ascii "K" ; kelvin ])
        |> shouldEqual (Some (ascii "K", kelvin))

        refusedPair (Map.ofList [ seedName (ascii "d"), SeedEntry.directory (seedOf [ nfc ; nfd ]) ])
        |> shouldEqual (Some (nfd, nfc))

        // Two names beyond ASCII that APFS would hold as two: refused all the
        // same, since telling them apart needs Unicode's tables.
        refusedPair (seedOf [ nfc ; han ]) |> shouldEqual (Some (nfc, han))

        // Names the rule can tell apart.
        refusedPair (seedOf [ nfc ; ascii "e" ; ascii "k" ; kelvin ; ascii "x" ])
        |> shouldEqual None

        // One per directory is fine, however many directories.
        refusedPair (Map.ofList [ seedName nfc, SeedEntry.directory (seedOf [ han ]) ])
        |> shouldEqual None

        // Linux compares bytes, so both spellings are two names.
        match seeded SimulatedUnixPlatform.linuxX64 (seedOf [ nfc ; nfd ]) with
        | Ok _ -> ()
        | Error fault -> failwith $"Linux refused the seed: %s{FileSystemSeedFault.describe fault}"

    [<Test>]
    let ``a seeded Darwin filesystem matches names as one a process built`` () : unit =
        let system =
            match seeded SimulatedUnixPlatform.macOsArm64 (seedOf [ nfc ]) with
            | Ok image -> image |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            | Error fault -> failwith $"Darwin refused the seed: %s{FileSystemSeedFault.describe fault}"

        match UnixPathResolution.tryStat SymlinkPolicy.Follow (arg ([ byte '/' ] @ nfd)) system with
        | Error (StatRefusal.Path (PathRefusal.UndecidedNameEquivalence _)) -> ()
        | other -> failwith $"expected the NFD spelling's lookup to be refused, got %A{other}"

    [<Test>]
    let ``checkInvariants reports a directory holding two names that might be one, where names match by equivalence``
        ()
        : unit
        =
        // The graph primitives compare bytes, so they bind both spellings; a
        // walk is what refuses the second.
        let bothSpellings (matching : EntryNameMatching) : VirtualFileSystem * InodeNumber =
            let vfs =
                VirtualFileSystem.empty matching (UnixTimestamp.ofMillisecondsSinceEpoch 0L) Owners.linuxDefault

            let root = VirtualFileSystem.root vfs

            let bind (name : byte list) (vfs : VirtualFileSystem) : VirtualFileSystem =
                match
                    GraphMutators.createFile
                        root
                        (seedName name)
                        (PermissionBits.parseOrFail "test" 0o644)
                        Owners.linuxDefault
                        (UnixTimestamp.ofMillisecondsSinceEpoch 0L)
                        ImmutableArray.Empty
                        vfs
                with
                | Ok (_, vfs) -> vfs
                | Error error -> failwith $"binding %s{hexOf name}: %O{error}"

            vfs |> bind nfc |> bind nfd, root

        let vfs, root = bothSpellings EntryNameMatching.CanonicalEquivalence

        VirtualFileSystem.checkInvariants Set.empty vfs
        |> shouldEqual
            [
                VirtualFileSystemDefect.PossiblyEquivalentNames (root, seedName nfd, seedName nfc)
            ]

        let vfs, _ = bothSpellings EntryNameMatching.Bytes
        VirtualFileSystem.checkInvariants Set.empty vfs |> shouldEqual []

    // ------------------------------------------------------- the probe, replayed

    /// Raised by a replayed row's call that this library refuses, carrying the
    /// refusal's description.
    exception RowRefused of string

    let private answered<'a, 'refusal> (describe : 'refusal -> string) (result : Result<'a, 'refusal>) : 'a =
        match result with
        | Ok value -> value
        | Error refusal -> raise (RowRefused (describe refusal))

    let private errnoOf (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed _ -> "OK"
        | SyscallAnswer.Failed error -> string<UnixError> error

    let private completed (answer : SyscallAnswer * UnixSystem<int, string>) : UnixSystem<int, string> =
        match answer with
        | SyscallAnswer.Completed _, system -> system
        | other -> failwith $"expected a success, got %A{other}"

    /// A fresh system of `platform`'s whose current directory is an empty
    /// directory, as each of the probe's rows starts in one.
    let private rowSystem (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        system
        |> Answered.mkdir (arg (ascii "r")) 0o755
        |> completed
        |> Answered.chdir (arg (ascii "r"))
        |> completed

    let private create (name : byte list) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let answer, system =
            OpenFlagWords.openPath (openFlags true true) (arg name) 0o644 system
            |> answered OpenRefusal.describe

        errnoOf answer, system

    let private statOf (policy : SymlinkPolicy) (path : byte list) (system : UnixSystem<int, string>) =
        UnixPathResolution.tryStat policy (arg path) system
        |> answered StatRefusal.describe

    /// `stat(path)`, as the probe prints it: `same` if it reaches `expected`.
    let private statAnswer (path : byte list) (expected : InodeNumber) (system : UnixSystem<int, string>) : string =
        match statOf SymlinkPolicy.Follow path system with
        | FileStatusAnswer.Reported status -> if status.Inode = expected then "same" else "other"
        | FileStatusAnswer.Failed error -> string<UnixError> error

    let private inodeOf (path : byte list) (system : UnixSystem<int, string>) : InodeNumber =
        match statOf SymlinkPolicy.NoFollowFinal path system with
        | FileStatusAnswer.Reported status -> status.Inode
        | FileStatusAnswer.Failed error -> failwith $"lstat(%s{hexOf path}): %O{error}"

    /// The current directory's names, without "." and "..".
    let private namesHere (system : UnixSystem<int, string>) : byte list list =
        match DirectoryReading.openDirectory (UnixPath.parseOrFail "test" ".") system with
        | Ok fd, system ->
            fst (DirectoryReading.drain fd system)
            |> List.map (fun record ->
                DirectoryStreamName.toByteString record.Name
                |> UnixByteString.toBytes
                |> List.ofSeq
            )
            |> List.filter (fun name -> name <> ascii "." && name <> ascii "..")
        | Error error, _ -> failwith $"opening the current directory: %O{error}"

    let private listed (names : string list) : string =
        match List.sort names with
        | [] -> "(empty)"
        | names -> String.concat "," names

    let private lookupRow (what : string) (first : byte list) (second : byte list) (system : UnixSystem<int, string>) =
        let prefix = $"L\t%s{what}\t%s{hexOf first}\t%s{hexOf second}"

        match create first system with
        | "OK", system ->
            let looked = statAnswer second (inodeOf first system) system
            let excl, system = create second system
            let names = namesHere system |> List.map hexOf |> listed
            $"%s{prefix}\tstat=%s{looked}\texcl=%s{excl}\tnames=%s{names}"
        | failed, _ -> $"%s{prefix}\tcreate-first=%s{failed}"

    let private interiorRow
        (what : string)
        (first : byte list)
        (second : byte list)
        (system : UnixSystem<int, string>)
        =
        let system =
            UnixNamespace.tryMkdir (arg first) 0o755 system
            |> answered PathRefusal.describe
            |> completed

        let inner = first @ ascii "/x"

        match create inner system with
        | "OK", system ->
            let looked = statAnswer (second @ ascii "/x") (inodeOf inner system) system
            $"I\t%s{what}\t%s{hexOf first}\t%s{hexOf second}\tstat(second/x)=%s{looked}"
        | failed, _ -> failwith $"creating %s{hexOf inner}: %s{failed}"

    let private operationRow
        (what : string)
        (first : byte list)
        (second : byte list)
        (operation : string)
        (system : UnixSystem<int, string>)
        =
        let firstIsDirectory =
            match operation with
            | "rmdir(second)"
            | "rename(firstdir,second)"
            | "chdir(second)" -> true
            | _ -> false

        let system =
            if firstIsDirectory then
                UnixNamespace.tryMkdir (arg first) 0o755 system
                |> answered PathRefusal.describe
                |> completed
            else
                match create first system with
                | "OK", system -> system
                | failed, _ -> failwith $"creating %s{hexOf first}: %s{failed}"

        let system =
            match create (ascii "src") system with
            | "OK", system -> system
            | failed, _ -> failwith $"creating src: %s{failed}"

        let firstInode = inodeOf first system
        let sourceInode = inodeOf (ascii "src") system

        let which (inode : InodeNumber) : string =
            if inode = firstInode then "first"
            elif inode = sourceInode then "src"
            else "other"

        let answer, extra, system =
            match operation with
            | "mkdir(second)" ->
                let answer, system =
                    UnixNamespace.tryMkdir (arg second) 0o755 system
                    |> answered PathRefusal.describe

                answer, "", system
            | "link(src,second)" ->
                let answer, system =
                    UnixNamespace.tryLinkEager (arg (ascii "src")) (arg second) system
                    |> answered LinkRefusal.describe

                answer, "", system
            | "symlink(t,second)" ->
                let answer, system =
                    UnixNamespace.trySymlinkEager (arg (ascii "t")) (arg second) system
                    |> answered SymlinkRefusal.describe

                answer, "", system
            | "unlink(second)" ->
                let answer, system =
                    UnixNamespace.tryUnlink (arg second) system |> answered RemovalRefusal.describe

                answer, "", system
            | "rmdir(second)" ->
                let answer, system =
                    UnixNamespace.tryRmdir (arg second) system |> answered RemovalRefusal.describe

                answer, "", system
            | "rename(src,second)"
            | "rename(first,second)"
            | "rename(firstdir,second)"
            | "rename(second,moved)" ->
                let source, destination =
                    match operation with
                    | "rename(src,second)" -> ascii "src", second
                    | "rename(second,moved)" -> second, ascii "moved"
                    | _ -> first, second

                let answer, system =
                    UnixNamespace.tryRenameEager (arg source) (arg destination) system
                    |> answered RenameRefusal.describe

                answer, "", system
            | "chdir(second)" ->
                match UnixPathResolution.tryChdir (arg second) system |> answered PathRefusal.describe with
                | SyscallAnswer.Completed _ as answer, moved ->
                    let here =
                        match statOf SymlinkPolicy.Follow (ascii ".") moved with
                        | FileStatusAnswer.Reported status -> status.Inode
                        | FileStatusAnswer.Failed error -> failwith $"stat(.): %O{error}"

                    let back =
                        UnixPathResolution.tryChdir (arg (ascii "..")) moved
                        |> answered PathRefusal.describe
                        |> completed

                    answer, $"\tcwd=%s{which here}", back
                | answer, system -> answer, "", system
            | "open(second,O_CREAT)" ->
                match
                    OpenFlagWords.openPath (openFlags true false) (arg second) 0o644 system
                    |> answered OpenRefusal.describe
                with
                | SyscallAnswer.Completed fd as answer, system ->
                    let opened =
                        match UnixPathResolution.tryFstat (int fd) system |> answered FStatRefusal.describe with
                        | FileStatusAnswer.Reported status -> which status.Inode
                        | FileStatusAnswer.Failed error -> failwith $"fstat: %O{error}"

                    answer, $"\topened=%s{opened}", system
                | answer, system -> answer, "", system
            | other -> failwith $"the probe's operation %s{other} is not one this replay makes"

        let kinds =
            namesHere system
            |> List.map (fun name ->
                let kind =
                    match which (inodeOf name system) with
                    | "other" -> "new"
                    | kind -> kind

                $"%s{hexOf name}=%s{kind}"
            )
            |> listed

        $"O\t%s{what}\t%s{hexOf first}\t%s{hexOf second}\t%s{operation}=%s{errnoOf answer}%s{extra}\tnames=%s{kinds}"

    /// The line this library prints for the probe's row `measured`, made on a
    /// fresh directory of `system`'s, or the refusal it gives instead.
    let private replayRow (system : UnixSystem<int, string>) (measured : string) : Result<string, string> =
        let system = rowSystem system

        try
            match measured.Split '\t' |> List.ofArray with
            | "L" :: what :: first :: second :: _ -> lookupRow what (bytesOfHex first) (bytesOfHex second) system |> Ok
            | [ "B" ; what ; name ; _ ] ->
                let created, _ = create (bytesOfHex name) system
                Ok $"B\t%s{what}\t%s{name}\tcreate=%s{created}"
            | "I" :: what :: first :: second :: _ ->
                interiorRow what (bytesOfHex first) (bytesOfHex second) system |> Ok
            | "O" :: what :: first :: second :: answer :: _ ->
                let operation = answer.Substring (0, answer.IndexOf '=')
                operationRow what (bytesOfHex first) (bytesOfHex second) operation system |> Ok
            | _ -> failwith $"unrecognised probe line: %s{measured}"
        with RowRefused why ->
            Error why

    /// The probe's row's identity: its kind, label and names.
    let private keyOf (line : string) : string =
        line.Split '\t'
        |> Array.takeWhile (fun field -> not (field.Contains '='))
        |> String.concat "\t"

    let private measuredRows (resource : string) : string list =
        let assembly = Assembly.GetExecutingAssembly ()

        use stream =
            match assembly.GetManifestResourceStream $"WoofWare.PosixKernel.Test.%s{resource}" with
            | null -> failwith $"embedded resource %s{resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (fun line -> line.TrimEnd '\r')
        // The Linux file holds tmpfs's run and then ext4's, which agree.
        |> Array.takeWhile (fun line -> line <> "=====")
        |> Array.filter (fun line -> not (line.StartsWith '#'))
        |> List.ofArray

    /// Every row prints as measured, except exactly those in `refused`, which
    /// this library refuses.
    let private replay (system : UnixSystem<int, string>) (resource : string) (refused : Set<string>) : unit =
        let rows = measuredRows resource
        let keys = rows |> List.map keyOf |> Set.ofList

        let stale = Set.difference refused keys

        if not stale.IsEmpty then
            failwith $"rows listed as refused that the probe did not measure: %A{stale}"

        let failures =
            rows
            |> List.choose (fun measured ->
                let key = keyOf measured

                match replayRow system measured, Set.contains key refused with
                | Ok printed, false when printed = measured -> None
                | Ok printed, false -> Some $"measured: %s{measured}\n   model: %s{printed}"
                | Ok printed, true -> Some $"expected a refusal, but the model printed: %s{printed}"
                | Error _, true -> None
                | Error why, false -> Some $"measured: %s{measured}\n refused: %s{why}"
            )

        if not failures.IsEmpty then
            failwith (String.concat "\n" failures)

    /// The Darwin rows whose second spelling APFS took as the first, and so
    /// whose answers depend on canonical equivalence.
    let private darwinEquivalent : string list =
        [
            "L\tNFC then NFD\tc3a9\t65cc81"
            "L\tNFD then NFC\t65cc81\tc3a9"
            "L\tNFC then NFD, within a name\t636166c3a92e747874\t63616665cc812e747874"
            "L\tmark order\t61cc81cca7\t61cca7cc81"
            "L\tHangul syllable then jamo\teab080\te18480e185a1"
            "L\tHangul jamo then syllable\te18480e185a1\teab080"
            "L\tK then KELVIN SIGN\t4b\te284aa"
            "L\tKELVIN SIGN then K\te284aa\t4b"
            "L\t; then GREEK QUESTION MARK\t3b\tcdbe"
            "L\tGREEK QUESTION MARK then ;\tcdbe\t3b"
            "L\t` then GREEK VARIA\t60\te1bfaf"
            "L\tGREEK VARIA then `\te1bfaf\t60"
            "L\taKb then a KELVIN SIGN b\t614b62\t61e284aa62"
            "L\tOHM SIGN then OMEGA\te284a6\tcea9"
            "L\tOMEGA then OHM SIGN\tcea9\te284a6"
            "L\tANGSTROM SIGN then A RING\te284ab\tc385"
            "L\tA RING then A + RING\tc385\t41cc8a"
            "L\tCJK COMPATIBILITY IDEOGRAPH-F900 then U+8C48\tefa480\te8b188"
            "I\tNFC directory through NFD\tc3a9\t65cc81"
            "I\tK directory through KELVIN SIGN\t4b\te284aa"
            "O\tmkdir\tc3a9\t65cc81"
            "O\tlink\tc3a9\t65cc81"
            "O\tsymlink\tc3a9\t65cc81"
            "O\tunlink\tc3a9\t65cc81"
            "O\trmdir\tc3a9\t65cc81"
            "O\tchdir\tc3a9\t65cc81"
            "O\topen O_CREAT\tc3a9\t65cc81"
            "O\trename onto\tc3a9\t65cc81"
            "O\trename from\tc3a9\t65cc81"
            "O\trename to its other spelling\tc3a9\t65cc81"
            "O\trename to its other spelling\t65cc81\tc3a9"
            "O\trename a directory to its other spelling\tc3a9\t65cc81"
            "O\trename to its other spelling\t4b\te284aa"
            "O\trename to its other spelling\te284aa\t4b"
            "O\tunlink\t4b\te284aa"
            "O\tlink\t4b\te284aa"
        ]

    /// The Darwin rows APFS answered as two names, which this library refuses
    /// all the same: both names decompose to something beyond ASCII, and
    /// telling such names apart needs Unicode's tables.
    let private darwinMightBeEquivalent : string list =
        [
            "L\tanother letter\tc3a9\tc3a8"
            "L\tanother case, non-ASCII\tc389\tc3a9"
            "L\tvulgar half then 1 fraction-slash 2\tc2bd\t31e2818432"
        ]

    [<Test>]
    let ``Darwin answers every probe row as case-sensitive APFS did, or refuses where equivalence decides it``
        ()
        : unit
        =
        replay darwin "name-equivalence.darwin.txt" (Set.ofList (darwinEquivalent @ darwinMightBeEquivalent))

    [<Test>]
    let ``Linux answers every probe row as tmpfs did`` () : unit =
        replay linux "name-equivalence.linux.txt" Set.empty

    // ------------------------------------------------- generated directories

    /// The pieces names are built from: ASCII; the three code points whose
    /// canonical decomposition is ASCII; letters precomposed, and the mark that
    /// decomposes them; a canonical singleton beyond ASCII and its target; a
    /// letter with no decomposition; a compatibility ligature, which is not
    /// canonically equivalent to the letters it looks like; and bytes that are
    /// not UTF-8, two of which make U+0301 when they meet.
    let private pieces : byte list list =
        [
            ascii "a"
            ascii "e"
            ascii "f"
            ascii "i"
            ascii "K"
            ascii "k"
            ascii ";"
            ascii "`"
            [ 0xE2uy ; 0x84uy ; 0xAAuy ] // U+212A KELVIN SIGN
            [ 0xCDuy ; 0xBEuy ] // U+037E GREEK QUESTION MARK
            [ 0xE1uy ; 0xBFuy ; 0xAFuy ] // U+1FEF GREEK VARIA
            [ 0xC3uy ; 0xA9uy ] // U+00E9
            [ 0xC3uy ; 0xA1uy ] // U+00E1
            [ 0xCCuy ; 0x81uy ] // U+0301 COMBINING ACUTE ACCENT
            [ 0xE2uy ; 0x84uy ; 0xA6uy ] // U+2126 OHM SIGN
            [ 0xCEuy ; 0xA9uy ] // U+03A9
            [ 0xE4uy ; 0xB8uy ; 0xADuy ] // U+4E2D
            [ 0xEFuy ; 0xACuy ; 0x81uy ] // U+FB01, the "fi" ligature
            [ 0xFFuy ]
            [ 0xE9uy ] // Latin-1's "é"
            [ 0xCCuy ]
            [ 0x81uy ]
        ]

    /// The spellings canonically equivalent to `piece`, itself among them, by
    /// this test's own reading of the Unicode Character Database.
    let private respellings (piece : byte list) : byte list list =
        let groups =
            [
                [ ascii "K" ; [ 0xE2uy ; 0x84uy ; 0xAAuy ] ]
                [ ascii ";" ; [ 0xCDuy ; 0xBEuy ] ]
                [ ascii "`" ; [ 0xE1uy ; 0xBFuy ; 0xAFuy ] ]
                [ [ 0xC3uy ; 0xA9uy ] ; ascii "e" @ [ 0xCCuy ; 0x81uy ] ]
                [ [ 0xC3uy ; 0xA1uy ] ; ascii "a" @ [ 0xCCuy ; 0x81uy ] ]
                [ [ 0xE2uy ; 0x84uy ; 0xA6uy ] ; [ 0xCEuy ; 0xA9uy ] ]
            ]

        groups |> List.tryFind (List.contains piece) |> Option.defaultValue [ piece ]

    /// A name as the pieces it is spelled from.
    let private spelledGen : Gen<byte list list> =
        Gen.choose (1, 3)
        |> Gen.bind (fun count -> Gen.listOfLength count (Gen.elements pieces))

    /// `spelled` respelled, each piece as any spelling canonically equivalent
    /// to it.
    let private respelledGen (spelled : byte list list) : Gen<byte list list> =
        spelled
        |> List.map (fun piece -> Gen.elements (respellings piece))
        |> Gen.sequenceToList

    /// The name to look up beside the names `spelled`: one of them, one of
    /// them spelled another way, or any name.
    let private lookedUpGen (spelled : byte list list list) : Gen<byte list list> =
        match spelled with
        | [] -> spelledGen
        | spelled ->
            Gen.frequency
                [
                    1, Gen.elements spelled
                    2, Gen.elements spelled |> Gen.bind respelledGen
                    2, spelledGen
                ]

    let private strictUtf8 : UTF8Encoding = UTF8Encoding (false, true)

    /// The text `bytes` spell, by .NET's strict decoder rather than the
    /// library's.
    let private decoded (bytes : byte list) : string option =
        try
            Some (strictUtf8.GetString (Array.ofList bytes))
        with :? DecoderFallbackException ->
            None

    /// The canonical decomposition, by the host's Unicode tables.
    let private nfdOf (text : string) : string = text.Normalize NormalizationForm.FormD

    let private beyondAscii (text : string) : bool =
        nfdOf text |> Seq.exists (fun c -> int c >= 0x80)

    let private equivalent (left : byte list) (right : byte list) : bool =
        match decoded left, decoded right with
        | Some left, Some right -> nfdOf left = nfdOf right
        | _ -> false

    /// The rule the library states, by the host's tables rather than its own:
    /// two different names might be equivalent when they are, or when both
    /// decompose to something beyond ASCII.
    let private possiblyEquivalent (left : byte list) (right : byte list) : bool =
        left <> right
        && match decoded left, decoded right with
           | Some l, Some r -> nfdOf l = nfdOf r || (beyondAscii l && beyondAscii r)
           | _ -> false

    let private entryName (bytes : byte list) : DirectoryEntryName =
        match DirectoryEntryName.ofByteString (byteString bytes) with
        | Ok name -> name
        | Error error -> failwith $"test name %s{hexOf bytes}: %s{DirectoryEntryName.describe error}"

    [<Test>]
    let ``a lookup by canonical equivalence is bound exactly, free of every equivalent, or undecided as the rule says``
        ()
        : unit
        =
        let gen =
            gen {
                let! count = Gen.choose (0, 5)
                let! spelled = Gen.listOfLength count spelledGen
                let! lookedUp = lookedUpGen spelled
                return spelled |> List.map List.concat |> List.distinct, List.concat lookedUp
            }

        let property (cover : string -> unit) (entries : byte list list, name : byte list) : unit =
            let directory =
                entries
                |> List.mapi (fun i bytes -> entryName bytes, InodeNumber (int64 i + 1L))
                |> Map.ofList

            let firstPossiblyEquivalent =
                directory
                |> Map.toSeq
                |> Seq.map fst
                |> Seq.tryFind (fun bound -> possiblyEquivalent (bytesOfName bound) name)

            let answer =
                EntryNameMatching.lookUp EntryNameMatching.CanonicalEquivalence (entryName name) directory

            let fail (why : string) : unit =
                failwith $"looking up %s{hexOf name} among %A{List.map hexOf entries}: %s{why}, got %A{answer}"

            match answer with
            | EntryLookup.Bound inode ->
                cover "bound"

                if Map.tryFind (entryName name) directory <> Some inode then
                    fail "expected the entry bound under exactly those bytes"
            | EntryLookup.Free ->
                if entries |> List.exists (equivalent name) then
                    fail "an equivalent name is bound, so the name is not free"

                if firstPossiblyEquivalent.IsSome || List.contains name entries then
                    fail "expected an answer other than free"

                if not entries.IsEmpty then
                    cover "free beside other names"

                if decoded name |> Option.exists beyondAscii && not entries.IsEmpty then
                    cover "free, beyond ASCII"

                if (decoded name).IsNone && not entries.IsEmpty then
                    cover "free, not UTF-8"
            | EntryLookup.Undecided bound ->
                if List.contains name entries then
                    fail "the name is bound under exactly its bytes"

                if Some bound <> firstPossiblyEquivalent then
                    fail $"expected the first entry that might be equivalent, %A{firstPossiblyEquivalent}"

                if equivalent (bytesOfName bound) name then
                    cover "undecided, equivalent"
                else
                    cover "undecided, not equivalent"

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 2000) (Arb.fromGen gen) property

        for label in
            [
                "bound"
                "free beside other names"
                "free, beyond ASCII"
                "free, not UTF-8"
                "undecided, equivalent"
                "undecided, not equivalent"
            ] do
            if coverage.Count label < 50 then
                failwith $"the fixed sample reached %s{label} only %d{coverage.Count label} times"

    /// One call a generated history makes in a directory of its own.
    [<RequireQualifiedAccess>]
    type private Step =
        | Create of name : byte list
        | Stat of name : byte list
        | Unlink of name : byte list
        | Rename of source : byte list * destination : byte list

    let private namesOf (step : Step) : byte list list =
        match step with
        | Step.Create name
        | Step.Stat name
        | Step.Unlink name -> [ name ]
        | Step.Rename (source, destination) -> [ source ; destination ]

    let private stepsGen : Gen<Step list> =
        let rec go (count : int) (spelled : byte list list list) (acc : Step list) : Gen<Step list> =
            if count = 0 then
                Gen.constant (List.rev acc)
            else
                gen {
                    let! first = lookedUpGen spelled
                    let! second = lookedUpGen spelled

                    let! kind =
                        Gen.frequency
                            [
                                4, Gen.constant 0
                                3, Gen.constant 1
                                1, Gen.constant 2
                                2, Gen.constant 3
                            ]

                    let step =
                        match kind with
                        | 0 -> Step.Create (List.concat first)
                        | 1 -> Step.Stat (List.concat first)
                        | 2 -> Step.Unlink (List.concat first)
                        | _ -> Step.Rename (List.concat first, List.concat second)

                    return! go (count - 1) (first :: spelled) (step :: acc)
                }

        Gen.choose (1, 10) |> Gen.bind (fun count -> go count [] [])

    /// The directory a real filesystem holds: each name as it was bound, with
    /// the number of the file it names.
    type private Reference =
        {
            Entries : (byte list * int) list
            NextFile : int
        }

    /// What the real filesystem answers for `step`, and its directory after:
    /// case-sensitive APFS on Darwin, which takes a name as reaching the entry
    /// bound under any canonically equivalent spelling; tmpfs on Linux, which
    /// compares bytes.
    let private referenceStep (darwin : bool) (step : Step) (reference : Reference) : string * Reference =
        let find (name : byte list) : (byte list * int) option =
            reference.Entries
            |> List.tryFind (fun (bound, _) -> bound = name || (darwin && equivalent bound name))

        let bindable (name : byte list) : bool = not darwin || (decoded name).IsSome

        match step with
        | Step.Create name ->
            match find name with
            | Some _ -> "EEXIST", reference
            | None when not (bindable name) -> "EILSEQ", reference
            | None ->
                "OK",
                {
                    Entries = (name, reference.NextFile) :: reference.Entries
                    NextFile = reference.NextFile + 1
                }
        | Step.Stat name ->
            match find name with
            | Some (_, file) -> $"OK %d{file}", reference
            | None -> "ENOENT", reference
        | Step.Unlink name ->
            match find name with
            | Some (bound, _) ->
                "OK",
                { reference with
                    Entries = reference.Entries |> List.filter (fun (other, _) -> other <> bound)
                }
            | None -> "ENOENT", reference
        | Step.Rename (source, destination) ->
            match find source with
            | None -> "ENOENT", reference
            | Some (sourceBound, file) ->

            match find destination with
            // Measured: a rename onto another spelling of its own name changes
            // nothing on case-sensitive APFS.
            | Some (_, other) when other = file -> "OK", reference
            // Measured: the displaced entry's spelling is kept.
            | Some (destinationBound, _) ->
                "OK",
                { reference with
                    Entries =
                        (destinationBound, file)
                        :: (reference.Entries
                            |> List.filter (fun (bound, _) -> bound <> sourceBound && bound <> destinationBound))
                }
            | None when not (bindable destination) -> "EILSEQ", reference
            | None ->
                "OK",
                { reference with
                    Entries =
                        (destination, file)
                        :: (reference.Entries |> List.filter (fun (bound, _) -> bound <> sourceBound))
                }

    /// What the library answers for `step`, with each file named by the
    /// reference's number for it, or `None` if it refuses.
    let private modelStep
        (files : Map<InodeNumber, int>)
        (nextFile : int)
        (step : Step)
        (system : UnixSystem<int, string>)
        : (string * Map<InodeNumber, int> * UnixSystem<int, string>) option
        =
        try
            match step with
            | Step.Create name ->
                match create name system with
                | "OK", system -> Some ("OK", Map.add (inodeOf name system) nextFile files, system)
                | answer, system -> Some (answer, files, system)
            | Step.Stat name ->
                match statOf SymlinkPolicy.NoFollowFinal name system with
                | FileStatusAnswer.Reported status -> Some ($"OK %d{Map.find status.Inode files}", files, system)
                | FileStatusAnswer.Failed error -> Some (string<UnixError> error, files, system)
            | Step.Unlink name ->
                let answer, system =
                    UnixNamespace.tryUnlink (arg name) system |> answered RemovalRefusal.describe

                Some (errnoOf answer, files, system)
            | Step.Rename (source, destination) ->
                let answer, system =
                    UnixNamespace.tryRenameEager (arg source) (arg destination) system
                    |> answered RenameRefusal.describe

                Some (errnoOf answer, files, system)
        with RowRefused _ ->
            None

    let private historyProperty (platform : SimulatedUnixPlatform) (cover : string -> unit) (steps : Step list) : unit =
        let darwin = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin

        let rec run
            (steps : Step list)
            (reference : Reference)
            (files : Map<InodeNumber, int>)
            (system : UnixSystem<int, string>)
            : unit
            =
            match steps with
            | [] -> ()
            | step :: rest ->
                let expected, after = referenceStep darwin step reference

                let mightDecide =
                    namesOf step
                    |> List.exists (fun name ->
                        reference.Entries
                        |> List.exists (fun (bound, _) -> possiblyEquivalent bound name)
                    )

                let fail (why : string) : unit =
                    failwith
                        $"%A{step} in %A{reference.Entries |> List.map (fst >> hexOf)}: %s{why} (the filesystem answers %s{expected})"

                match modelStep files reference.NextFile step system with
                | None ->
                    if not mightDecide then
                        fail "refused, though no name it looks up might be equivalent to a bound one"

                    let decides =
                        namesOf step
                        |> List.exists (fun name ->
                            reference.Entries
                            |> List.exists (fun (bound, _) -> bound <> name && equivalent bound name)
                        )

                    cover (
                        if decides then
                            "refused, equivalence decides"
                        else
                            "refused, might be equivalent"
                    )

                    run rest reference files system
                | Some (answer, files, system) ->
                    if answer <> expected then
                        fail $"answered %s{answer}"

                    let listedNames = namesHere system |> List.sort
                    let referenceNames = after.Entries |> List.map fst |> List.sort

                    if listedNames <> referenceNames then
                        fail
                            $"the directory then holds %A{List.map hexOf listedNames}, not %A{List.map hexOf referenceNames}"

                    match UnixSystem.checkInvariants system with
                    | [] -> ()
                    | defects -> fail $"the system is defective: %A{defects}"

                    cover (
                        if mightDecide then
                            "answered, might be equivalent"
                        else
                            "answered"
                    )

                    let besideBeyondAscii =
                        reference.Entries
                        |> List.exists (fun (bound, _) -> decoded bound |> Option.exists beyondAscii)

                    if besideBeyondAscii && not mightDecide then
                        cover "answered beside a name beyond ASCII"

                    run rest after files system

        run
            steps
            {
                Entries = []
                NextFile = 0
            }
            Map.empty
            (rowSystem (boot platform))

    [<Test>]
    let ``a Darwin history answers as case-sensitive APFS wherever it answers, and refuses only where equivalence might decide``
        ()
        : unit
        =
        let coverage =
            CoverageSample.check
                (Config.QuickThrowOnFailure.WithMaxTest 300)
                (Arb.fromGen stepsGen)
                (historyProperty SimulatedUnixPlatform.macOsArm64)

        for label in
            [
                "answered"
                "answered beside a name beyond ASCII"
                "refused, equivalence decides"
                "refused, might be equivalent"
            ] do
            if coverage.Count label < 50 then
                failwith $"the fixed sample reached %s{label} only %d{coverage.Count label} times"

    [<Test>]
    let ``a Linux history answers as tmpfs, comparing bytes, and is never refused`` () : unit =
        let coverage =
            CoverageSample.check
                (Config.QuickThrowOnFailure.WithMaxTest 300)
                (Arb.fromGen stepsGen)
                (historyProperty SimulatedUnixPlatform.linuxArm64)

        coverage.Count "refused, equivalence decides" |> shouldEqual 0
        coverage.Count "refused, might be equivalent" |> shouldEqual 0
        coverage.Count "answered, might be equivalent" |> shouldBeGreaterThan 50
