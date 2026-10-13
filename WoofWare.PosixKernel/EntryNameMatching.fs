namespace WoofWare.PosixKernel

open System

/// How a filesystem decides which entry of a directory a name looked up in it
/// reaches.
[<RequireQualifiedAccess>]
type internal EntryNameMatching =
    /// A name reaches only the entry bound under exactly its bytes, as on
    /// Linux's tmpfs and ext4.
    | Bytes
    /// A name reaches the entry bound under any canonically equivalent Unicode
    /// spelling of it, as on APFS, in its case-sensitive variant as in its
    /// case-insensitive one: "é" spelled as U+00E9 and as "e" followed by
    /// U+0301 reach one entry, and so do "K" and U+212A KELVIN SIGN. The
    /// directory keeps the spelling the entry was bound under, which is what
    /// `readdir` reports, and never holds two spellings of one name.
    /// Compatibility equivalents, such as U+FB01 and "fi", are different names
    /// under case-sensitivity, and a name that is not valid UTF-8 reaches only
    /// the entry bound under exactly its bytes.
    ///
    /// This library holds no Unicode tables, so it cannot always decide whether
    /// two names are canonically equivalent: a lookup it cannot decide is
    /// `EntryLookup.Undecided`.
    | CanonicalEquivalence

/// What looking a name up in a directory finds.
[<RequireQualifiedAccess>]
type internal EntryLookup =
    /// The directory binds the name to `inode`.
    | Bound of inode : InodeNumber
    /// The name reaches no entry of the directory.
    | Free
    /// The directory binds no entry under exactly the name's bytes, but binds
    /// `bound`, which might be a canonically equivalent spelling of the name.
    /// Whether the name reaches `bound`'s entry or is free is beyond this
    /// library, which cannot decide canonical equivalence.
    | Undecided of bound : DirectoryEntryName

[<RequireQualifiedAccess>]
module internal EntryNameMatching =

    // The code points outside ASCII whose full canonical decomposition is
    // ASCII, each with that decomposition. Only through one of these can a name
    // holding a code point outside ASCII be canonically equivalent to a name of
    // ASCII alone.
    //
    // Derived from the Unicode Character Database 16.0.0 (Python 3.14.7's
    // `unicodedata`, in this repository's devshell) by
    //   [hex(c) for c in range(0x80, 0x110000)
    //    if not 0xD800 <= c <= 0xDFFF
    //    and all(ord(d) < 0x80 for d in unicodedata.normalize("NFD", chr(c)))]
    // which lists exactly these three, each decomposing to a single character.
    // A canonical decomposition never changes once its character is assigned
    // (Unicode's normalization stability policy), and all three were assigned
    // in Unicode 1.1, so a filesystem built on an older version of the database
    // decomposes them the same way. APFS decomposes all three, as the probe in
    // `docs/probes/name-equivalence` measured on Darwin 27.0.
    let private asciiDecompositions : Map<int, byte> =
        Map.ofList [ 0x037E, byte ';' ; 0x1FEF, byte '`' ; 0x212A, byte 'K' ]

    let private isAscii (bytes : ReadOnlySpan<byte>) : bool =
        bytes.IndexOfAnyInRange (0x80uy, 0xFFuy) < 0

    /// What this library can say about a name's canonical decomposition.
    [<RequireQualifiedAccess>]
    type private Decomposition =
        /// The name is not valid UTF-8, so it spells no Unicode text and is
        /// equivalent to no other name.
        | NotUtf8
        /// The decomposition is these bytes, all ASCII.
        | Ascii of bytes : byte[]
        /// The decomposition holds a code point outside ASCII, and this library
        /// knows nothing else about it.
        | BeyondAscii

    let private decompositionOf (name : DirectoryEntryName) : Decomposition =
        let bytes = UnixByteString.toBytes (DirectoryEntryName.toByteString name)

        // An ASCII name is its own decomposition.
        if isAscii (bytes.AsSpan ()) then
            Decomposition.Ascii (bytes.AsSpan().ToArray ())
        else

        match DirectoryEntryName.tryToString name with
        | None -> Decomposition.NotUtf8
        | Some text ->
            let decomposed =
                text.EnumerateRunes ()
                |> Seq.map (fun rune ->
                    if rune.Value < 0x80 then
                        Some (byte rune.Value)
                    else
                        Map.tryFind rune.Value asciiDecompositions
                )
                |> List.ofSeq

            if List.forall Option.isSome decomposed then
                Decomposition.Ascii (decomposed |> List.choose id |> Array.ofList)
            else
                Decomposition.BeyondAscii

    /// Whether a name whose decomposition is `target` might reach the entry
    /// bound under `bound`, a different byte string: false only where the two
    /// are certainly not canonically equivalent.
    let private mightReach (target : Decomposition) (bound : DirectoryEntryName) : bool =
        let boundBytes = UnixByteString.toBytes (DirectoryEntryName.toByteString bound)

        // The common case, settled without decoding or allocating: an ASCII
        // entry is its own decomposition.
        if isAscii (boundBytes.AsSpan ()) then
            match target with
            | Decomposition.Ascii target -> boundBytes.AsSpan().SequenceEqual (ReadOnlySpan<byte> target)
            | Decomposition.BeyondAscii
            | Decomposition.NotUtf8 -> false
        else

        match target, decompositionOf bound with
        | Decomposition.NotUtf8, _
        | _, Decomposition.NotUtf8 -> false
        | Decomposition.Ascii target, Decomposition.Ascii bound -> target = bound
        | Decomposition.Ascii _, Decomposition.BeyondAscii
        | Decomposition.BeyondAscii, Decomposition.Ascii _ -> false
        // Both decompositions hold a code point outside ASCII, and deciding
        // whether they are the same needs the tables this library lacks.
        | Decomposition.BeyondAscii, Decomposition.BeyondAscii -> true

    /// Look `name` up among `entries`, a directory's names, as a filesystem
    /// comparing names by `matching` does.
    ///
    /// A name bound under exactly its bytes is always `Bound`, under either
    /// matching: a filesystem comparing by canonical equivalence holds no two
    /// equivalent names in one directory, so no other entry can be the one it
    /// reaches.
    let lookUp
        (matching : EntryNameMatching)
        (name : DirectoryEntryName)
        (entries : Map<DirectoryEntryName, InodeNumber>)
        : EntryLookup
        =
        match Map.tryFind name entries with
        | Some inode -> EntryLookup.Bound inode
        | None ->

        match matching with
        | EntryNameMatching.Bytes -> EntryLookup.Free
        | EntryNameMatching.CanonicalEquivalence ->

        match decompositionOf name with
        // Measured on APFS: looking up a name that is not UTF-8 answers ENOENT
        // even beside a name some lenient decoding would take it for (Latin-1
        // "\xE9" beside "é", CESU-8 beside the emoji it encodes, an overlong
        // "e" beside "e").
        | Decomposition.NotUtf8 -> EntryLookup.Free
        | target ->

        match entries |> Map.tryFindKey (fun bound _ -> mightReach target bound) with
        | Some bound -> EntryLookup.Undecided bound
        | None -> EntryLookup.Free

    /// Two names among `names` that might be canonically equivalent, if any
    /// are, in the order `names` gives them. Which pair, when there are
    /// several, depends only on that order.
    ///
    /// A directory of a filesystem comparing names by canonical equivalence
    /// holds no such pair: this library binds no name whose lookup was
    /// `EntryLookup.Undecided`, and boots no seed holding such a pair.
    let firstPossiblyEquivalentPair
        (names : DirectoryEntryName seq)
        : (DirectoryEntryName * DirectoryEntryName) option
        =
        // Two distinct names might be equivalent exactly when their
        // decompositions are the same ASCII bytes, or both hold a code point
        // beyond ASCII; so grouping by decomposition finds every pair.
        names
        |> Seq.choose (fun name ->
            match decompositionOf name with
            | Decomposition.NotUtf8 -> None
            | Decomposition.Ascii bytes -> Some (Some (List.ofArray bytes), name)
            | Decomposition.BeyondAscii -> Some (None, name)
        )
        |> Seq.groupBy fst
        |> Seq.tryPick (fun (_, group) ->
            match group |> Seq.map snd |> Seq.truncate 2 |> List.ofSeq with
            | [ first ; second ] -> Some (first, second)
            | _ -> None
        )
