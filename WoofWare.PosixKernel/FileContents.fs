namespace WoofWare.PosixKernel

open System
open System.Collections.Immutable
open System.Runtime.InteropServices

/// The bytes a regular file holds.
///
/// Two values are equal when they hold the same bytes and the same holes: a
/// range that reads as zero because nothing was written there is distinct from
/// one a write filled with zeroes.
[<CustomEquality>]
[<CustomComparison>]
[<StructuredFormatDisplay("{Display}")>]
type FileContents =
    private
        {
            Length : int64
            // Page `i` holds bytes `[i * pageSize, (i + 1) * pageSize)`, cut
            // short at `Length`, so that every page's length is a function of
            // its index and `Length` alone. A page absent here is a hole, which
            // reads as zeroes.
            //
            // A page is a view of memory nothing will change: an array a write
            // made for it alone, or a slice of the array a file was made from,
            // which `ImmutableArray` promises nothing changes.
            Pages : Map<int64, ReadOnlyMemory<byte>>
        }

    member private this.Display : string =
        let shown = 32

        let prefix =
            let count = int (min this.Length (int64 shown))
            let bytes = Array.zeroCreate<byte> count

            for KeyValue (index, page) in this.Pages do
                // Only page 0 reaches into the first `shown` bytes, a page
                // being longer than `shown`.
                if index = 0L then
                    page.Span.Slice(0, min page.Length count).CopyTo (bytes.AsSpan ())

            bytes |> Array.map (fun b -> b.ToString "x2") |> String.concat " "

        let ellipsis = if this.Length > int64 shown then " ..." else ""
        $"FileContents (%d{this.Length} bytes, %d{this.Pages.Count} pages held: %s{prefix}%s{ellipsis})"

    override this.ToString () : string = this.Display

    override this.Equals (other : obj) : bool =
        match other with
        | :? FileContents as other ->
            Object.ReferenceEquals (this, other)
            || this.Length = other.Length
               && this.Pages.Count = other.Pages.Count
               && Seq.forall2
                   (fun (KeyValue (i, p : ReadOnlyMemory<byte>)) (KeyValue (j, q : ReadOnlyMemory<byte>)) ->
                       i = j && p.Span.SequenceEqual q.Span
                   )
                   this.Pages
                   other.Pages
        | _ -> false

    // Of the length and the number of pages alone, so that hashing a file
    // costs nothing in proportion to its length; equal values agree on both.
    override this.GetHashCode () : int =
        hash this.Length * 31 + this.Pages.Count

    interface IComparable with
        member this.CompareTo (other : obj) : int =
            match other with
            | :? FileContents as other ->
                match compare this.Length other.Length with
                | 0 ->
                    Seq.compareWith
                        (fun (KeyValue (i, p : ReadOnlyMemory<byte>)) (KeyValue (j, q : ReadOnlyMemory<byte>)) ->
                            match compare i j with
                            | 0 -> p.Span.SequenceCompareTo q.Span
                            | c -> c
                        )
                        this.Pages
                        other.Pages
                | c -> c
            | _ -> invalidArg "other" $"FileContents: cannot compare with %O{other}"

/// Making and reading `FileContents`.
[<RequireQualifiedAccess>]
module FileContents =

    // The granularity at which a write copies, and at which holes are kept.
    // This representation's alone, not any filesystem's block size; a block
    // size that is a multiple of it can be read off the pages held.
    let internal pageSize : int = 4096

    let private pageSize64 : int64 = int64 pageSize

    /// A file holding no bytes.
    let empty : FileContents =
        {
            Length = 0L
            Pages = Map.empty
        }

    /// How many bytes the file holds.
    let length (contents : FileContents) : int64 = contents.Length

    // How long page `index` is in a file `length` bytes long.
    let private pageLength (length : int64) (index : int64) : int =
        min pageSize64 (length - index * pageSize64) |> int

    /// A file holding exactly `bytes`, with no holes.
    ///
    /// Shares `bytes` rather than copying it, so that a file of two gigabytes
    /// costs nothing more to make; the array is held until every page of it
    /// has been written over or truncated away.
    let ofImmutableArray (bytes : ImmutableArray<byte>) : FileContents =
        // `ImmutableArray` is a struct wrapping an array, so `default` carries a
        // null one. Rejected rather than treated as empty: a caller who wrote
        // `default` meant something, and an empty file would hide the mistake.
        if bytes.IsDefault then
            invalidArg
                (nameof bytes)
                "FileContents.ofImmutableArray: bytes is the default ImmutableArray, whose underlying array is null. That is not an empty file; pass ImmutableArray<byte>.Empty."

        let length = int64 bytes.Length
        let pageCount = (length + pageSize64 - 1L) / pageSize64

        let memory = bytes.AsMemory ()

        let pages =
            (Map.empty, seq { 0L .. pageCount - 1L })
            ||> Seq.fold (fun pages index ->
                Map.add index (memory.Slice (int (index * pageSize64), pageLength length index)) pages
            )

        {
            Length = length
            Pages = pages
        }

    /// The bytes from `offset`, up to `count` of them, stopping at the end of
    /// the file: empty when `offset` is at or past the end.
    let read (offset : int64) (count : int) (contents : FileContents) : ImmutableArray<byte> =
        if offset < 0L then
            invalidArg (nameof offset) $"FileContents.read: offset %d{offset} is negative."

        if count < 0 then
            invalidArg (nameof count) $"FileContents.read: count %d{count} is negative."

        if offset >= contents.Length || count = 0 then
            ImmutableArray.Empty
        else

        // In `(0, count]`, so the conversion is exact.
        let transfer = min (int64 count) (contents.Length - offset) |> int
        let result = Array.zeroCreate<byte> transfer
        let last = offset + int64 transfer

        for index in offset / pageSize64 .. (last - 1L) / pageSize64 do
            match Map.tryFind index contents.Pages with
            // A hole, which the zero-initialised result already reads as.
            | None -> ()
            | Some page ->
                let pageStart = index * pageSize64
                let from = max offset pageStart
                let until = min last (pageStart + int64 page.Length)

                page.Span.Slice(int (from - pageStart), int (until - from)).CopyTo (result.AsSpan (int (from - offset)))

        // Wrapped rather than copied: nothing else holds `result`.
        ImmutableCollectionsMarshal.AsImmutableArray result

    /// Every byte the file holds.
    ///
    /// Throws `ArgumentException` for a file longer than one array can be.
    let toImmutableArray (contents : FileContents) : ImmutableArray<byte> =
        if contents.Length > int64 Array.MaxLength then
            invalidArg
                (nameof contents)
                $"FileContents.toImmutableArray: the file is %d{contents.Length} bytes long, more than the %d{Array.MaxLength} one array can hold."

        read 0L (int contents.Length) contents

    // `page`, the old contents of page `index`, at the length that index has in
    // a file `length` bytes long: cut short, or copied and padded with zeroes.
    let private resized (length : int64) (index : int64) (page : ReadOnlyMemory<byte>) : ReadOnlyMemory<byte> =
        let wanted = pageLength length index

        if wanted <= page.Length then
            page.Slice (0, wanted)
        else
            let bytes = Array.zeroCreate<byte> wanted
            page.Span.CopyTo (bytes.AsSpan ())
            ReadOnlyMemory<byte> bytes

    // The page the file's last byte is on, if it has one, and if a write has
    // filled it. Its length is the only one that a change of `Length` changes
    // without the change touching it.
    let private finalPage (contents : FileContents) : (int64 * ReadOnlyMemory<byte>) option =
        if contents.Length = 0L then
            None
        else
            let index = (contents.Length - 1L) / pageSize64
            Map.tryFind index contents.Pages |> Option.map (fun page -> index, page)

    // The pages of `contents` at the lengths they have in a file `length` bytes
    // long, which must be no shorter. Only the final page can change.
    let private extendedPages (length : int64) (contents : FileContents) : Map<int64, ReadOnlyMemory<byte>> =
        match finalPage contents with
        | None -> contents.Pages
        | Some (index, page) -> Map.add index (resized length index page) contents.Pages

    /// The file after `bytes` are written at `offset`.
    ///
    /// The file grows to reach the end of the write, if it did not already;
    /// what lies between its old end and `offset` is a hole. A write of no
    /// bytes changes nothing, however far past the end it is aimed.
    let internal write (offset : int64) (bytes : ImmutableArray<byte>) (contents : FileContents) : FileContents =
        if bytes.IsDefault then
            invalidArg
                (nameof bytes)
                "FileContents.write: bytes is the default ImmutableArray, whose underlying array is null. That is not an empty write; pass ImmutableArray<byte>.Empty."

        if offset < 0L then
            invalidArg (nameof offset) $"FileContents.write: offset %d{offset} is negative."

        if offset > Int64.MaxValue - int64 bytes.Length then
            invalidArg
                (nameof offset)
                $"FileContents.write: %d{bytes.Length} bytes at offset %d{offset} end past Int64.MaxValue."

        if bytes.IsEmpty then
            contents
        else

        let last = offset + int64 bytes.Length
        let length = max contents.Length last

        let pages =
            (extendedPages length contents, seq { offset / pageSize64 .. (last - 1L) / pageSize64 })
            ||> Seq.fold (fun pages index ->
                let pageStart = index * pageSize64

                // Zero-initialised, which is what a hole and the page's growth
                // past the old end read as. A write never shortens a page. A
                // page of its own, never a slice of `bytes`, so that the file
                // holds nothing of the caller's buffer but what it keeps.
                let updated = Array.zeroCreate<byte> (pageLength length index)

                match Map.tryFind index pages with
                | Some page -> page.Span.CopyTo (updated.AsSpan ())
                | None -> ()

                let from = max offset pageStart
                let until = min last (pageStart + int64 updated.Length)

                bytes.AsSpan(int (from - offset), int (until - from)).CopyTo (updated.AsSpan (int (from - pageStart)))

                Map.add index (ReadOnlyMemory<byte> updated) pages
            )

        {
            Length = length
            Pages = pages
        }

    /// The file after truncation to `length` bytes: shortening discards the
    /// bytes past `length`, and lengthening leaves a hole.
    let internal truncate (length : int64) (contents : FileContents) : FileContents =
        if length < 0L then
            invalidArg (nameof length) $"FileContents.truncate: length %d{length} is negative."

        if length = contents.Length then
            contents
        elif length > contents.Length then
            {
                Length = length
                Pages = extendedPages length contents
            }
        else

        // The first page wholly past the new end.
        let firstGone = (length + pageSize64 - 1L) / pageSize64

        // Removed from the top down, each removal copying a path of the map,
        // until as many have gone as could be kept: no more than `firstGone`
        // pages can be. From there a map built of the pages kept is cheaper,
        // so the cost is in whichever of the two is smaller.
        let rec drop (pages : Map<int64, ReadOnlyMemory<byte>>) (removed : int64) : Map<int64, ReadOnlyMemory<byte>> =
            if pages.IsEmpty then
                pages
            else
                let index, _ = Map.maxKeyValue pages

                if index < firstGone then
                    pages
                elif removed >= firstGone then
                    Map.filter (fun index _ -> index < firstGone) contents.Pages
                else
                    drop (Map.remove index pages) (removed + 1L)

        let shortened =
            {
                Length = length
                Pages = drop contents.Pages 0L
            }

        match finalPage shortened with
        | None -> shortened
        | Some (index, page) ->
            { shortened with
                Pages = Map.add index (resized length index page) shortened.Pages
            }

    // Which pages hold data rather than a hole, in ascending order.
    let internal heldPages (contents : FileContents) : int64 list =
        contents.Pages |> Map.keys |> List.ofSeq

    // What is wrong with the representation, if anything is: every page index
    // must be inside the file, and every page exactly the length its index has.
    let internal invariantViolation (contents : FileContents) : string option =
        if contents.Length < 0L then
            Some $"the length %d{contents.Length} is negative"
        else
            contents.Pages
            |> Seq.tryPick (fun (KeyValue (index, page)) ->
                if index < 0L || index * pageSize64 >= contents.Length then
                    Some $"page %d{index} is outside a file %d{contents.Length} bytes long"
                elif page.Length <> pageLength contents.Length index then
                    Some
                        $"page %d{index} is %d{page.Length} bytes, where a file %d{contents.Length} bytes long has %d{pageLength contents.Length index}"
                else
                    None
            )
