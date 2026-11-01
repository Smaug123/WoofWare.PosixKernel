namespace WoofWare.PosixKernel

open System
open System.Buffers
open System.Collections.Immutable
open System.Text
open System.Text.Unicode

/// <summary>
/// Why a sequence of bytes is not a <c>UnixByteString</c>.
/// </summary>
[<RequireQualifiedAccess>]
type UnixByteStringDefect =
    /// <summary>
    /// A NUL at this byte index.
    /// </summary>
    /// <remarks>
    /// A Unix kernel takes its strings NUL-terminated across the `char*`
    /// boundary, so a NUL cannot appear within one: everything after it would be
    /// invisible to the kernel.
    /// </remarks>
    | ContainsNul of index : int

/// Shared by `UnixByteString`'s own members and by its module.
module private UnixByteStringInternal =
    /// `Unchecked.defaultof<UnixByteString>` and C# `default` carry a
    /// *default* `ImmutableArray`, whose underlying array is null, and
    /// `.Length` on that throws rather than answering 0. Every read of the bytes
    /// goes through here, so the failure names the cause instead of surfacing as a
    /// bare `NullReferenceException` from somewhere further in. It throws
    /// `ArgumentException`, naming no parameter: it does not know which one
    /// the value was passed as.
    let checkedBytes (bytes : ImmutableArray<byte>) : ImmutableArray<byte> =
        if bytes.IsDefault then
            raise (
                ArgumentException
                    "UnixByteString: value carries no bytes at all, so it can only have come from `Unchecked.defaultof` or C# `default`; construct one with UnixByteString.ofBytes or UnixByteString.ofString instead."
            )

        bytes

    /// Lexicographic on the unsigned bytes, with a proper prefix sorting first.
    /// Total across differing lengths, which `ImmutableArray`'s own
    /// `IStructuralComparable` is not: that one throws on two arrays of
    /// unequal length, and a directory is a map keyed on exactly these.
    let compareBytes (left : ImmutableArray<byte>) (right : ImmutableArray<byte>) : int =
        let left = checkedBytes left
        let right = checkedBytes right
        let shared = min left.Length right.Length

        let mutable i = 0
        let mutable result = 0

        while result = 0 && i < shared do
            result <- compare left.[i] right.[i]
            i <- i + 1

        if result <> 0 then
            result
        else
            compare left.Length right.Length

    let equalBytes (left : ImmutableArray<byte>) (right : ImmutableArray<byte>) : bool =
        let left = checkedBytes left
        let right = checkedBytes right

        if left.Length <> right.Length then
            false
        else

        let mutable i = 0
        let mutable equal = true

        while equal && i < left.Length do
            equal <- left.[i] = right.[i]
            i <- i + 1

        equal

    /// FNV-1a over the bytes. Computed on demand rather than stored: F# `Map`
    /// is a balanced tree and uses comparison, so nothing in the hot path hashes a
    /// name, and a stored hash would be one more field a forged value could make
    /// inconsistent with the bytes beside it.
    let hashBytes (bytes : ImmutableArray<byte>) : int =
        let bytes = checkedBytes bytes
        let mutable hash = 2166136261u

        for i in 0 .. bytes.Length - 1 do
            hash <- (hash ^^^ uint32 bytes.[i]) * 16777619u

        int hash

    /// Decode as strict UTF-8, or `None` if the bytes are not strict UTF-8.
    let tryDecode (bytes : ImmutableArray<byte>) : string option =
        let bytes = checkedBytes bytes
        // Every UTF-8 sequence yields at most as many UTF-16 code units as it has
        // bytes: one-, two- and three-byte sequences give one, and the four-byte
        // sequences give a surrogate pair. So the source length always suffices.
        let destination = Array.zeroCreate<char> bytes.Length
        let mutable bytesRead = 0
        let mutable charsWritten = 0

        let status =
            Utf8.ToUtf16 (bytes.AsSpan (), destination.AsSpan (), &bytesRead, &charsWritten, false, true)

        match status with
        | OperationStatus.Done -> Some (String (destination, 0, charsWritten))
        | OperationStatus.InvalidData
        | OperationStatus.NeedMoreData -> None
        | OperationStatus.DestinationTooSmall ->
            // Answering `None` here would say "not UTF-8" about bytes that are.
            failwith
                $"UnixByteString.tryToString: decoding %d{bytes.Length} bytes overflowed a %d{destination.Length}-code-unit buffer, which cannot happen since UTF-8 never expands into UTF-16. This is a bug in UnixByteString."
        | status -> failwith $"UnixByteString.tryToString: unrecognised decoder status %O{status}."

    /// Total, injective rendering: strict UTF-8 runs verbatim, any other byte
    /// becomes `\xNN`, and a literal backslash doubles.
    let escape (bytes : ImmutableArray<byte>) : string =
        let bytes = checkedBytes bytes
        let builder = StringBuilder bytes.Length
        // As in `tryDecode`: never more code units than there are bytes.
        let destination = Array.zeroCreate<char> bytes.Length
        let mutable i = 0

        while i < bytes.Length do
            let mutable bytesRead = 0
            let mutable charsWritten = 0

            // Decoding the remainder consumes the longest strictly-valid prefix
            // and reports where it stopped, so the scan advances a whole
            // sequence at a time rather than a byte at a time.
            let status =
                Utf8.ToUtf16 (bytes.AsSpan().Slice i, destination.AsSpan (), &bytesRead, &charsWritten, false, true)

            for j in 0 .. charsWritten - 1 do
                let c = destination.[j]

                if c = '\\' then
                    builder.Append "\\\\" |> ignore<StringBuilder>
                else
                    builder.Append c |> ignore<StringBuilder>

            i <- i + bytesRead

            match status with
            | OperationStatus.Done -> ()
            | OperationStatus.InvalidData
            | OperationStatus.NeedMoreData ->
                // `i` is now the first byte the decoder refused. Escape that one
                // byte and resume: a later byte may well start a valid sequence.
                builder.Append('\\').Append('x').Append (bytes.[i].ToString "X2")
                |> ignore<StringBuilder>

                i <- i + 1
            | OperationStatus.DestinationTooSmall ->
                failwith
                    $"UnixByteString.toEscaped: decoding %d{bytes.Length - i} bytes overflowed a %d{destination.Length}-code-unit buffer, which cannot happen since UTF-8 never expands. This is a bug in UnixByteString."
            | status -> failwith $"UnixByteString.toEscaped: unrecognised decoder status %O{status}."

        builder.ToString ()

/// <summary>
/// A NUL-free sequence of bytes: what a Unix kernel means by "a string".
/// </summary>
///
/// <remarks>
/// No encoding is implied. A Unix filesystem just directly stores the bytes
/// a caller handed it, so a name need not be text at all. That is why
/// <c>tryToString</c> is a partial function.
///
/// Construct via <c>UnixByteString.ofBytes</c> or <c>UnixByteString.ofString</c>.
/// </remarks>
[<Struct>]
[<CustomEquality>]
[<CustomComparison>]
type UnixByteString =
    private
        {
            Bytes : ImmutableArray<byte>
        }

    /// <summary>
    /// The escaped rendering, for error messages.
    /// </summary>
    /// <remarks>
    /// See <c>UnixByteString.toEscaped</c>.
    ///
    /// Not round-trippable through any parser here: it exists only so that
    /// diagnostics can reproduce a byte string that has no .NET string.
    /// </remarks>
    override this.ToString () : string =
        UnixByteStringInternal.escape this.Bytes

    override this.Equals (other : obj) : bool =
        match other with
        | :? UnixByteString as other -> UnixByteStringInternal.equalBytes this.Bytes other.Bytes
        | _ -> false

    override this.GetHashCode () : int =
        UnixByteStringInternal.hashBytes this.Bytes

    interface IEquatable<UnixByteString> with
        member this.Equals (other : UnixByteString) : bool =
            UnixByteStringInternal.equalBytes this.Bytes other.Bytes

    interface IComparable<UnixByteString> with
        member this.CompareTo (other : UnixByteString) : int =
            UnixByteStringInternal.compareBytes this.Bytes other.Bytes

    interface IComparable with
        member this.CompareTo (other : obj) : int =
            match other with
            | :? UnixByteString as other -> UnixByteStringInternal.compareBytes this.Bytes other.Bytes
            // `IComparable`'s contract: every instance sorts after null.
            | null -> 1
            | _ ->
                raise (
                    ArgumentException (
                        $"cannot compare a UnixByteString with %s{other.GetType().FullName}",
                        nameof other
                    )
                )

[<RequireQualifiedAccess>]
module UnixByteString =
    /// <summary>
    /// Human-readable rendering of a rejection reason.
    /// </summary>
    let describe (defect : UnixByteStringDefect) : string =
        match defect with
        | UnixByteStringDefect.ContainsNul index ->
            $"contains a NUL at byte index %d{index}, which cannot survive a C string boundary"

    /// Take these bytes as a Unix byte string, or explain why they are not one.
    ///
    /// Throws if `bytes` is a *default* `ImmutableArray` rather than
    /// an empty one: that is a forged value rather than data, and no byte string a
    /// caller could supply produces it.
    let ofBytes (bytes : ImmutableArray<byte>) : Result<UnixByteString, UnixByteStringDefect> =
        if bytes.IsDefault then
            raise (
                ArgumentException (
                    "a default ImmutableArray is not an empty byte string; it has no underlying array at all",
                    nameof bytes
                )
            )

        let index = bytes.IndexOf 0uy

        if index >= 0 then
            Error (UnixByteStringDefect.ContainsNul index)
        else
            Ok
                {
                    Bytes = bytes
                }

    /// Encode this .NET string as UTF-8 and take the result as a Unix byte string,
    /// or explain why the string has no such encoding.
    ///
    /// This is the constructor for host-supplied configuration, where a path is
    /// written as an F# literal. A path a process supplies arrives as bytes and goes
    /// through `ofBytes` instead.
    ///
    /// An unpaired surrogate is refused here rather than encoded: it has no UTF-8
    /// encoding, so a strict encoder would throw and a lenient one would silently
    /// substitute U+FFFD and name a different file.
    let ofString (candidate : string) : Result<UnixByteString, UnixPathTextDefect> =
        if isNull candidate then
            nullArg (nameof candidate)

        match UnixPathText.firstDefect candidate with
        | Some defect -> Error defect
        | None ->
            Ok
                {
                    Bytes = UnixPathText.utf8.GetBytes candidate |> ImmutableArray.CreateRange
                }

    /// The bytes, as a Unix kernel would hand them back.
    /// Has no NUL terminator; callers that need a C string append it themselves.
    let toBytes (s : UnixByteString) : ImmutableArray<byte> =
        UnixByteStringInternal.checkedBytes s.Bytes

    /// <summary>
    /// How many bytes are in this string.
    /// </summary>
    /// <remarks>
    /// This count doesn't include a NUL terminator (which you can't store in a <c>UnixByteString</c> anyway).
    /// </remarks>
    let length (s : UnixByteString) : int =
        (UnixByteStringInternal.checkedBytes s.Bytes).Length

    /// <summary>
    /// The empty byte string.
    /// </summary>
    let empty : UnixByteString =
        {
            Bytes = ImmutableArray<byte>.Empty
        }

    /// <summary>
    /// The <c>count</c> bytes starting at <c>start</c>.
    /// </summary>
    /// <remarks>
    /// Throws if that range is not within <c>s</c>.
    /// </remarks>
    let slice (start : int) (count : int) (s : UnixByteString) : UnixByteString =
        let bytes = UnixByteStringInternal.checkedBytes s.Bytes

        if start < 0 || count < 0 || start > bytes.Length - count then
            raise (
                ArgumentOutOfRangeException (
                    nameof start,
                    $"UnixByteString.slice: %d{count} bytes from offset %d{start} is not within a %d{bytes.Length}-byte string"
                )
            )

        // A slice of a NUL-free string is NUL-free, so no check is owed.
        {
            Bytes = bytes.Slice (start, count)
        }

    /// <summary>
    /// <c>left</c> followed by <c>right</c>.
    /// </summary>
    let append (left : UnixByteString) (right : UnixByteString) : UnixByteString =
        let left = UnixByteStringInternal.checkedBytes left.Bytes
        let right = UnixByteStringInternal.checkedBytes right.Bytes
        // Two NUL-free strings concatenate to a NUL-free one, so no check is owed.
        {
            Bytes = left.AddRange right
        }

    /// <summary>
    /// Interpret the bytes as a string and represent that string in .NET, if that's possible.
    /// </summary>
    ///
    /// <returns>
    /// <c>None</c> exactly when the bytes are not strictly-valid UTF-8.
    /// </returns>
    ///
    /// <remarks>
    /// Our Darwin flavour currently happens to admit exactly the names for which this
    /// is <c>Some</c>, but that is a chosen approximation of APFS's rule rather than
    /// APFS's rule: real APFS also refuses Unicode noncharacters and over-long
    /// combining sequences, which this accepts.
    /// Do not read a <c>Some</c> here as "a real Darwin would bind this".
    /// </remarks>
    let tryToString (s : UnixByteString) : string option =
        UnixByteStringInternal.tryDecode s.Bytes

    /// <summary>
    /// A rendering for human-readable diagnostics: total, and injective, so two distinct byte
    /// strings never print alike.
    /// </summary>
    ///
    /// <remarks>
    /// Strictly-valid UTF-8 runs verbatim; every other byte becomes <c>\xNN</c>;
    /// a literal backslash doubles. Use this rather than <c>tryToString</c> in
    /// error messages, because <c>tryToString</c> doesn't render anything for
    /// non-UTF-8 bytes.
    /// </remarks>
    let toEscaped (s : UnixByteString) : string = UnixByteStringInternal.escape s.Bytes

    /// `assertValid`, naming `operation` as the function and `parameter` as its
    /// parameter that the value was passed as.
    let internal assertValidFor (operation : string) (parameter : string) (s : UnixByteString) : UnixByteString =
        // The only value this can reject is `Unchecked.defaultof` / C# `default`,
        // whose payload is a default ImmutableArray. Every other value came from a
        // constructor, all of which refuse a NUL, and the representation is
        // private, so there is nothing else to re-check.
        if s.Bytes.IsDefault then
            raise (
                Refusal.exceptionOf
                    operation
                    (RefusalKind.Contradictory parameter)
                    "this UnixByteString carries no bytes at all, so it came from `Unchecked.defaultof` or C# `default`; construct one with UnixByteString.ofBytes instead."
            )

        s

    /// <summary>
    /// Re-check the invariant of a value that may not have come from a constructor.
    /// </summary>
    /// <remarks>
    /// The constructors already ensure the invariant holds, so there is no need to
    /// call this if you know where the value came from. Takes constant time.
    /// </remarks>
    /// <exception cref="ArgumentException">Throws if the invariant doesn't hold.</exception>
    let assertValid (context : string) (s : UnixByteString) : UnixByteString = assertValidFor context "s" s
