namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// Bytes in first-in, first-out order, kept as the chunks they arrived in, so
/// that neither appending nor taking copies what stays behind.
///
/// Two queues are equal when they hold the same bytes in the same order,
/// however those bytes are chunked.
[<CustomEquality ; NoComparison>]
type internal ByteQueue =
    private
        {
            /// The oldest chunk; empty exactly when the queue is.
            Head : ImmutableArray<byte>
            /// How many of `Head`'s bytes have been taken already. Always less
            /// than `Head`'s length unless the queue is empty.
            HeadTaken : int
            /// The later chunks, oldest first, none of them empty.
            Rest : ImmutableQueue<ImmutableArray<byte>>
            Length : int
        }

    /// Every chunk held, oldest first, each with the index of its first held
    /// byte; none of them is wholly taken.
    member private this.Chunks : (ImmutableArray<byte> * int) list =
        if this.Length = 0 then
            []
        else
            (this.Head, this.HeadTaken) :: [ for chunk in this.Rest -> chunk, 0 ]

    override this.Equals (other : obj) : bool =
        match other with
        | :? ByteQueue as other ->
            // Most comparisons are of a queue with itself, reached through two
            // states that share it.
            if obj.ReferenceEquals (this, other) then
                true
            elif this.Length <> other.Length then
                false
            else
                // Walk both queues' chunks at once, comparing the longest run
                // the two current chunks both still hold.
                let mutable mine = this.Chunks
                let mutable theirs = other.Chunks
                let mutable same = true

                while same && not mine.IsEmpty do
                    let mineChunk, mineStart = mine.Head
                    let theirChunk, theirStart = theirs.Head
                    let run = min (mineChunk.Length - mineStart) (theirChunk.Length - theirStart)

                    same <-
                        System.MemoryExtensions.SequenceEqual (
                            mineChunk.AsSpan (mineStart, run),
                            theirChunk.AsSpan (theirStart, run)
                        )

                    mine <-
                        if mineStart + run = mineChunk.Length then
                            mine.Tail
                        else
                            (mineChunk, mineStart + run) :: mine.Tail

                    theirs <-
                        if theirStart + run = theirChunk.Length then
                            theirs.Tail
                        else
                            (theirChunk, theirStart + run) :: theirs.Tail

                same
        | _ -> false

    override this.GetHashCode () : int = this.Length

[<RequireQualifiedAccess>]
module internal ByteQueue =
    let empty : ByteQueue =
        {
            Head = ImmutableArray.Empty
            HeadTaken = 0
            Rest = ImmutableQueue.Empty
            Length = 0
        }

    let length (queue : ByteQueue) : int = queue.Length

    let append (chunk : ImmutableArray<byte>) (queue : ByteQueue) : ByteQueue =
        if chunk.IsEmpty then
            queue
        elif queue.Length = 0 then
            {
                Head = chunk
                HeadTaken = 0
                Rest = ImmutableQueue.Empty
                Length = chunk.Length
            }
        else
            { queue with
                Rest = queue.Rest.Enqueue chunk
                Length = queue.Length + chunk.Length
            }

    /// The oldest `count` bytes, which must not be more than the queue holds,
    /// and the queue without them. Copies the bytes returned and nothing else.
    let take (count : int) (queue : ByteQueue) : ImmutableArray<byte> * ByteQueue =
        if count < 0 || count > queue.Length then
            failwith
                $"ByteQueue.take: %d{count} bytes asked of a queue holding %d{queue.Length} (this is a bug in this library)."

        let taken = ImmutableArray.CreateBuilder<byte> count
        let mutable head = queue.Head
        let mutable headTaken = queue.HeadTaken
        let mutable rest = queue.Rest
        let mutable remaining = count

        while remaining > 0 do
            let unread = head.Length - headTaken

            if unread <= remaining then
                taken.AddRange (head.AsSpan (headTaken, unread))
                remaining <- remaining - unread
                headTaken <- 0

                if rest.IsEmpty then
                    head <- ImmutableArray.Empty
                else
                    let mutable next = ImmutableArray.Empty
                    rest <- rest.Dequeue &next
                    head <- next
            else
                taken.AddRange (head.AsSpan (headTaken, remaining))
                headTaken <- headTaken + remaining
                remaining <- 0

        taken.MoveToImmutable (),
        {
            Head = head
            HeadTaken = headTaken
            Rest = rest
            Length = queue.Length - count
        }

    /// The oldest `count` bytes, which must not be more than the queue holds,
    /// leaving the queue as it was. Copies the bytes returned and nothing else.
    let peek (count : int) (queue : ByteQueue) : ImmutableArray<byte> =
        if count < 0 || count > queue.Length then
            failwith
                $"ByteQueue.peek: %d{count} bytes asked of a queue holding %d{queue.Length} (this is a bug in this library)."

        fst (take count queue)
