namespace WoofWare.PosixKernel

open System
open System.Collections.Immutable

/// <summary>
/// How a filesystem decides which entry is returned when looking up a name within a directory.
/// </summary>
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

/// What this library can say about the canonical decomposition of a name,
/// which is all it knows of the names the name might be canonically
/// equivalent to.
[<RequireQualifiedAccess>]
type internal NameDecomposition =
    /// The name is not valid UTF-8, so it spells no Unicode text and is
    /// equivalent to no other name.
    | NotUtf8
    /// The decomposition is these bytes, all ASCII.
    | Ascii of decomposition : UnixByteString
    /// The decomposition holds a code point outside ASCII. `trailing` is the
    /// decomposition of the longest suffix of the name whose code points each
    /// decompose to ASCII, and `leading` that of the longest such prefix.
    | BeyondAscii of trailing : UnixByteString * leading : UnixByteString

[<RequireQualifiedAccess>]
module internal NameDecomposition =

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

    /// Whether every byte of `name` is ASCII.
    let isAsciiName (name : DirectoryEntryName) : bool =
        isAscii ((UnixByteString.toBytes (DirectoryEntryName.toByteString name)).AsSpan ())

    /// What this library can say about the canonical decomposition of `name`.
    let ofName (name : DirectoryEntryName) : NameDecomposition =
        let bytes = DirectoryEntryName.toByteString name

        // An ASCII name is its own decomposition.
        if isAscii ((UnixByteString.toBytes bytes).AsSpan ()) then
            NameDecomposition.Ascii bytes
        else

        match DirectoryEntryName.tryToString name with
        | None -> NameDecomposition.NotUtf8
        | Some text ->
            // Each code point as the ASCII code point it decomposes to, or
            // `ValueNone` where its decomposition goes beyond ASCII.
            let decomposed : byte voption[] =
                [|
                    for rune in text.EnumerateRunes () do
                        if rune.Value < 0x80 then
                            ValueSome (byte rune.Value)
                        else
                            match Map.tryFind rune.Value asciiDecompositions with
                            | Some ascii -> ValueSome ascii
                            | None -> ValueNone
                |]

            let ascii (decomposed : byte voption[]) : UnixByteString =
                let bytes = decomposed |> Array.map (fun (b : byte voption) -> b.Value)

                match UnixByteString.ofBytes (ImmutableArray.Create<byte> bytes) with
                | Ok ascii -> ascii
                | Error defect ->
                    failwith
                        $"NameDecomposition.ofName: \"%s{DirectoryEntryName.toEscaped name}\" decomposes to bytes that are no byte string (%s{UnixByteString.describe defect}), though a name holds no NUL and decomposing adds none (this is a bug in this library)."

            match Array.tryFindIndex ValueOption.isNone decomposed with
            | None -> NameDecomposition.Ascii (ascii decomposed)
            | Some first ->
                let last = Array.findIndexBack ValueOption.isNone decomposed
                NameDecomposition.BeyondAscii (ascii decomposed.[last + 1 ..], ascii decomposed.[.. first - 1])

    let private begins (whole : UnixByteString) (prefix : UnixByteString) : bool =
        (UnixByteString.toBytes whole).AsSpan().StartsWith ((UnixByteString.toBytes prefix).AsSpan ())

    // Two names are canonically equivalent exactly when their full canonical
    // decompositions are the same. This library cannot compute a decomposition
    // that goes beyond ASCII, but it can say how one begins and ends:
    //
    // * Every ASCII code point is a starter (canonical combining class 0), so
    //   canonical reordering never moves one, nor moves anything across one.
    //   Checked against the same database by
    //     [c for c in range(0x80) if unicodedata.combining(chr(c))]
    //   which is empty.
    // * The only code points outside ASCII whose decomposition ends in ASCII
    //   are the three in `asciiDecompositions`:
    //     [hex(c) for c in range(0x80, 0x110000)
    //      if not 0xD800 <= c <= 0xDFFF
    //      and ord(unicodedata.normalize("NFD", chr(c))[-1]) < 0x80]
    //   lists exactly those three.
    //
    // So a name's `trailing` is exactly its decomposition's longest ASCII
    // suffix: the code point before that suffix decomposes to something ending
    // beyond ASCII, and reordering leaves beyond ASCII whatever it puts there.
    // A name's `leading` is a prefix of its decomposition's longest ASCII
    // prefix, which may be longer, since a decomposition may begin with ASCII
    // ("é" decomposes to "e" and U+0301). Two equivalent names have one
    // decomposition, so their `trailing`s are the same, and their `leading`s
    // are both prefixes of one string, so one begins the other.

    /// Whether names that decompose as `left` and `right` might be canonically
    /// equivalent: false only where they certainly are not.
    let mightBeEquivalent (left : NameDecomposition) (right : NameDecomposition) : bool =
        match left, right with
        | NameDecomposition.NotUtf8, _
        | _, NameDecomposition.NotUtf8 -> false
        | NameDecomposition.Ascii left, NameDecomposition.Ascii right -> left = right
        | NameDecomposition.Ascii _, NameDecomposition.BeyondAscii _
        | NameDecomposition.BeyondAscii _, NameDecomposition.Ascii _ -> false
        | NameDecomposition.BeyondAscii (leftTrailing, leftLeading),
          NameDecomposition.BeyondAscii (rightTrailing, rightLeading) ->
            leftTrailing = rightTrailing
            && (begins leftLeading rightLeading || begins rightLeading leftLeading)

/// A name beside its decomposition, as `NamesBeyondAscii` holds it. Sorted by
/// the decomposition first, so that a key whose `Name` is `None` sorts before
/// every name with the same decomposition.
type private DecomposedName =
    {
        Decomposition : NameDecomposition
        Name : DirectoryEntryName option
    }

/// The names of one directory that hold a byte beyond ASCII and are valid
/// UTF-8, each beside its decomposition, sorted so that a lookup by canonical
/// equivalence finds one that a name might be equivalent to by descending a
/// tree rather than by looking through them all.
type internal NamesBeyondAscii =
    private
        {
            /// Each member's `Name` is `Some`.
            Members : ImmutableSortedSet<DecomposedName>
        }

[<RequireQualifiedAccess>]
module internal NamesBeyondAscii =

    let empty : NamesBeyondAscii =
        {
            Members = ImmutableSortedSet.Create<DecomposedName> ComparisonIdentity.Structural<DecomposedName>
        }

    /// The member `name` is held as, if it is held: a name of ASCII alone is
    /// not, since a lookup finds it by its bytes, nor is one that is not
    /// UTF-8, which is equivalent to no other.
    let private memberFor (name : DirectoryEntryName) : DecomposedName option =
        if NameDecomposition.isAsciiName name then
            None
        else

        match NameDecomposition.ofName name with
        | NameDecomposition.NotUtf8 -> None
        | decomposition ->
            Some
                {
                    Decomposition = decomposition
                    Name = Some name
                }

    let add (name : DirectoryEntryName) (names : NamesBeyondAscii) : NamesBeyondAscii =
        match memberFor name with
        | None -> names
        | Some added ->
            {
                Members = names.Members.Add added
            }

    let remove (name : DirectoryEntryName) (names : NamesBeyondAscii) : NamesBeyondAscii =
        match memberFor name with
        | None -> names
        | Some removed ->
            {
                Members = names.Members.Remove removed
            }

    /// One of `names` that a name decomposing as `decomposition` might be
    /// canonically equivalent to, by `NameDecomposition.mightBeEquivalent`, if
    /// any is. Logarithmic in the number of names, once for each byte of the
    /// decomposition's `leading`.
    let tryFindPossiblyEquivalent
        (decomposition : NameDecomposition)
        (names : NamesBeyondAscii)
        : DirectoryEntryName option
        =
        // If any member might be equivalent to `decomposition`, the least
        // member at or after one of these starts is such a member. A member
        // decomposing to the same ASCII sorts at that decomposition, the one
        // start. A member beyond ASCII with the same `trailing` sorts by its
        // `leading`: if that begins `decomposition`'s `leading`, it is a
        // start, and every member from that start up to this one has that
        // same decomposition; otherwise it begins with `decomposition`'s
        // `leading`, and every member from the start that is `decomposition`
        // itself up to this one has a `leading` sorting between the two,
        // which begins with `decomposition`'s `leading` too.
        let starts : NameDecomposition seq =
            match decomposition with
            | NameDecomposition.NotUtf8 -> Seq.empty
            | NameDecomposition.Ascii _ -> Seq.singleton decomposition
            | NameDecomposition.BeyondAscii (trailing, leading) ->
                seq {
                    for length in 0 .. UnixByteString.length leading do
                        NameDecomposition.BeyondAscii (trailing, UnixByteString.slice 0 length leading)
                }

        let leastFrom (start : NameDecomposition) : DecomposedName option =
            // No member's `Name` is `None`, so this is the bitwise complement
            // of the index of the least member after the start.
            let index =
                ~~~(names.Members.IndexOf
                        {
                            Decomposition = start
                            Name = None
                        })

            if index < names.Members.Count then
                Some names.Members.[index]
            else
                None

        if names.Members.IsEmpty then
            None
        else

        starts
        |> Seq.tryPick (fun start ->
            match leastFrom start with
            | Some found when NameDecomposition.mightBeEquivalent decomposition found.Decomposition -> found.Name
            | Some _
            | None -> None
        )

[<RequireQualifiedAccess>]
module internal EntryNameMatching =

    /// The name spelled as `decomposition`, if that is ASCII.
    let private asciiSpelling (decomposition : NameDecomposition) : DirectoryEntryName option =
        match decomposition with
        | NameDecomposition.Ascii decomposed ->
            match DirectoryEntryName.ofByteString decomposed with
            | Ok spelled -> Some spelled
            | Error defect ->
                failwith
                    $"EntryNameMatching: \"%s{UnixByteString.toEscaped decomposed}\" is a name's decomposition but no name (%s{DirectoryEntryName.describe defect}), though decomposing adds no separator and makes no dot (this is a bug in this library)."
        | NameDecomposition.BeyondAscii _
        | NameDecomposition.NotUtf8 -> None

    /// Look `name` up among `entries`, a directory's names, as a filesystem
    /// comparing names by `matching` does. `beyondAscii` must be built from
    /// those same names. The only name of ASCII alone that a name might be
    /// equivalent to is the one spelled as its decomposition, and
    /// `beyondAscii` finds any other without looking through them all, so a
    /// lookup stays logarithmic in the directory's size.
    ///
    /// A name bound under exactly its bytes is always `Bound`, under either
    /// matching: a filesystem comparing by canonical equivalence holds no two
    /// equivalent names in one directory, so no other entry can be the one it
    /// reaches.
    let lookUp
        (matching : EntryNameMatching)
        (name : DirectoryEntryName)
        (entries : Map<DirectoryEntryName, InodeNumber>)
        (beyondAscii : NamesBeyondAscii)
        : EntryLookup
        =
        match Map.tryFind name entries with
        | Some inode -> EntryLookup.Bound inode
        | None ->

        match matching with
        | EntryNameMatching.Bytes -> EntryLookup.Free
        | EntryNameMatching.CanonicalEquivalence ->

        match NameDecomposition.ofName name with
        // Measured on APFS: looking up a name that is not UTF-8 answers ENOENT
        // even beside a name some lenient decoding would take it for (Latin-1
        // "\xE9" beside "é", CESU-8 beside the emoji it encodes, an overlong
        // "e" beside "e").
        | NameDecomposition.NotUtf8 -> EntryLookup.Free
        | decomposition ->

        // The name's own bytes, if they are ASCII, have already missed.
        match asciiSpelling decomposition with
        | Some spelled when Map.containsKey spelled entries -> EntryLookup.Undecided spelled
        | Some _
        | None ->

        match NamesBeyondAscii.tryFindPossiblyEquivalent decomposition beyondAscii with
        | Some bound -> EntryLookup.Undecided bound
        | None -> EntryLookup.Free

    /// Two names among `names`, which must be distinct, that might be
    /// canonically equivalent, if any are, in the order `names` gives them.
    /// Which pair, when there are several, depends only on that order.
    ///
    /// A directory of a filesystem comparing names by canonical equivalence
    /// holds no such pair: this library binds no name whose lookup was
    /// `EntryLookup.Undecided`, and boots no seed holding such a pair.
    let firstPossiblyEquivalentPair
        (names : DirectoryEntryName seq)
        : (DirectoryEntryName * DirectoryEntryName) option
        =
        // Each name looked up among those before it, as `lookUp` would look it
        // up, so that a directory of n names is checked in O(n log n).
        let rec firstFrom
            (earlier : Set<DirectoryEntryName>)
            (beyondAscii : NamesBeyondAscii)
            (names : DirectoryEntryName list)
            : (DirectoryEntryName * DirectoryEntryName) option
            =
            match names with
            | [] -> None
            | name :: later ->
                let decomposition = NameDecomposition.ofName name

                match asciiSpelling decomposition with
                | Some spelled when Set.contains spelled earlier -> Some (spelled, name)
                | Some _
                | None ->

                match NamesBeyondAscii.tryFindPossiblyEquivalent decomposition beyondAscii with
                | Some bound -> Some (bound, name)
                | None -> firstFrom (Set.add name earlier) (NamesBeyondAscii.add name beyondAscii) later

        firstFrom Set.empty NamesBeyondAscii.empty (List.ofSeq names)
