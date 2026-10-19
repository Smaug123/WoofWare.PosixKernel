namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open WoofWare.PosixKernel

/// Whole writes and sends for tests, through the library's public protocol and
/// held to the internal steps it is made of; and the internal steps
/// themselves, made by the process's leader, for a test whose write must raise
/// no signal: the answer and the system, or the refusal. A write that raised
/// one fails the test.
[<RequireQualifiedAccess>]
module internal WriteOutcomes =

    /// The answer and system of `outcome`, failing if the write raised a signal.
    let returned<'Answer, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (outcome : Result<WriteStep<'Answer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>)
        : Result<'Answer * UnixSystem<'Thread, 'Handler>, WriteRefusal>
        =
        outcome
        |> Result.map (fun outcome ->
            match outcome with
            | WriteStep.Returns (answer, system) -> answer, system
            | WriteStep.ReturnsRaising _
            | WriteStep.ProcessEnded _
            | WriteStep.WouldBlock _
            | WriteStep.Interrupted _ ->
                failwith $"expected a write that returns and raises no signal, got %A{outcome}"
        )

    /// The step after the copy of a `write` through `fd` that its admission
    /// said to transfer: `UnixReadWrite.tryApplyWrite` of `bytes` into `into`,
    /// marked as a `write` is, in the view of the only process. Fails if the
    /// write delivered bytes out of the machine, which only one into a pipe a
    /// client drains does.
    let applyWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (into : WriteInto)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        Lone.UnixReadWrite.tryApplyWriteThrough fd into bytes system
        |> Result.map (fun (step, delivery) ->
            match delivery with
            | None -> step
            | Some delivery -> failwith $"expected a write that delivers nothing, got %A{delivery}"
        )

    /// The step after the copy of a blocking `write` by `thread` through `fd`
    /// that its admission said to transfer part of and sleep:
    /// `UnixReadWrite.applyWriteThenSleep`, marked as a `write` is, in the view
    /// of the only process.
    let applyWriteThenSleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (total : int)
        (into : WriteIntoThenSleep)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>
        =
        Lone.UnixReadWrite.applyWriteThenSleepThrough thread fd total into bytes system

    /// A whole `write(2)` by `caller`, made a step at a time through the
    /// library's internal steps, in the view of the caller's process:
    /// `UnixReadWrite.tryAdmitWrite`, and if it says to transfer,
    /// `tryApplyWrite` or `applyWriteThenSleep` of the first that many of
    /// `bytes` with the decision it made, marked as a `write` is. An
    /// admission's answer is reported as the write's. Beside the step, the
    /// delivery `tryApplyWrite` made, if it was the one called. The oracle
    /// `admitThenWrite` holds the public protocol to.
    let private stepsThenWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread> * Delivery option, WriteRefusal>
        =
        let thread = Caller.thread caller

        let stepped =
            match
                UnixReadWrite.tryAdmitWrite
                    thread
                    fd
                    buffer
                    (uint64 bytes.Length)
                    (Proc.view (Caller.processId caller) system)
            with
            | Error refusal -> Error refusal
            | Ok (WriteStep.Returns (WriteAdmission.Answered answer, after)) ->
                Ok (WriteStep.Returns (answer, after), None)
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.Answered answer, signal, after)) ->
                Ok (WriteStep.ReturnsRaising (answer, signal, after), None)
            | Ok (WriteStep.ProcessEnded (ended, after)) -> Ok (WriteStep.ProcessEnded (ended, after), None)
            | Ok (WriteStep.WouldBlock (condition, after)) -> Ok (WriteStep.WouldBlock (condition, after), None)
            | Ok (WriteStep.Interrupted after) -> Ok (WriteStep.Interrupted after, None)
            | Ok (WriteStep.Returns (WriteAdmission.Transfer (count, into), admitted)) ->
                if count > bytes.Length then
                    failwith $"admitWrite asked for %d{count} of %d{bytes.Length} bytes"

                UnixReadWrite.tryApplyWrite into (ImmutableArray.Create (bytes, 0, count)) admitted
                |> Result.map (fun (step, delivery) -> UnixReadWrite.markedThrough fd admitted step, delivery)
            | Ok (WriteStep.Returns (WriteAdmission.TransferThenSleep (count, total, into), admitted)) ->
                if total <> bytes.Length || count > bytes.Length then
                    failwith $"admitWrite asked for %d{count} of %d{total} bytes, given %d{bytes.Length}"

                let step =
                    UnixReadWrite.applyWriteThenSleep
                        thread
                        total
                        into
                        (ImmutableArray.Create (bytes, 0, count))
                        admitted
                    |> UnixReadWrite.markedThrough fd admitted

                Ok (step, None)
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.Transfer (count, _), signal, _))
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.TransferThenSleep (count, _, _), signal, _)) ->
                failwith $"admitWrite raised %A{signal} and still asked for %d{count} bytes"

        stepped
        |> Result.map (fun (step, delivery) -> WriteStep.map Proc.unfocus step, delivery)

    /// A whole `send(2)` by `caller` with the raw flag word `flags`, made a step
    /// at a time as `stepsThenWrite` makes a `write(2)`: the oracle
    /// `admitThenSend` holds the public protocol to.
    let private stepsThenSend<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
        =
        let thread = Caller.thread caller

        let stepped =
            match
                UnixReadWrite.tryAdmitSend
                    thread
                    fd
                    buffer
                    (uint64 bytes.Length)
                    flags
                    (Proc.view (Caller.processId caller) system)
            with
            | Error refusal -> Error refusal
            | Ok (WriteStep.Returns (WriteAdmission.Answered answer, after)) -> Ok (WriteStep.Returns (answer, after))
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.Answered answer, signal, after)) ->
                Ok (WriteStep.ReturnsRaising (answer, signal, after))
            | Ok (WriteStep.ProcessEnded (ended, after)) -> Ok (WriteStep.ProcessEnded (ended, after))
            | Ok (WriteStep.WouldBlock (condition, after)) -> Ok (WriteStep.WouldBlock (condition, after))
            | Ok (WriteStep.Interrupted after) -> Ok (WriteStep.Interrupted after)
            | Ok (WriteStep.Returns (WriteAdmission.Transfer (count, into), admitted)) ->
                if count > bytes.Length then
                    failwith $"admitSend asked for %d{count} of %d{bytes.Length} bytes"

                UnixReadWrite.tryApplySend into (ImmutableArray.Create (bytes, 0, count)) admitted
            | Ok (WriteStep.Returns (WriteAdmission.TransferThenSleep (count, total, into), admitted)) ->
                if total <> bytes.Length || count > bytes.Length then
                    failwith $"admitSend asked for %d{count} of %d{total} bytes, given %d{bytes.Length}"

                Ok (
                    UnixReadWrite.applyWriteThenSleep
                        thread
                        total
                        into
                        (ImmutableArray.Create (bytes, 0, count))
                        admitted
                )
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.Transfer (count, _), signal, _))
            | Ok (WriteStep.ReturnsRaising (WriteAdmission.TransferThenSleep (count, _, _), signal, _)) ->
                failwith $"admitSend raised %A{signal} and still asked for %d{count} bytes"

        stepped |> Result.map (WriteStep.map Proc.unfocus)

    /// A paused write's or send's answer, in the shape of the internal steps
    /// the tests match on.
    let private stepOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>)
        : WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>
        =
        match fate with
        | ProcessFate.ProcessEnded (ended, system) -> WriteStep.ProcessEnded (ended, system)
        | ProcessFate.Continues (WriteOutcome.Returns answer, system) -> WriteStep.Returns (answer, system)
        | ProcessFate.Continues (WriteOutcome.ReturnsRaising (answer, signal), system) ->
            WriteStep.ReturnsRaising (answer, signal, system)
        | ProcessFate.Continues (WriteOutcome.WouldBlock condition, system) -> WriteStep.WouldBlock (condition, system)
        | ProcessFate.Continues (WriteOutcome.Interrupted, system) -> WriteStep.Interrupted system

    /// The bytes of `bytes` a paused call's `range` names, failing unless the
    /// range lies in the buffer the call was made with, from its start.
    let private copied (call : string) (range : CopyRange) (bytes : ImmutableArray<byte>) : ImmutableArray<byte> =
        if range.FirstByte <> 0 || range.ByteCount < 0 || range.ByteCount > bytes.Length then
            failwith $"%s{call} asked for %A{range} of a buffer of %d{bytes.Length} bytes"

        ImmutableArray.Create (bytes, range.FirstByte, range.ByteCount)

    /// `actual`, having failed unless it is what the oracle `expected` says.
    let private agreeing<'Answer, 'Refusal when 'Answer : equality and 'Refusal : equality>
        (call : string)
        (expected : Result<'Answer, 'Refusal>)
        (actual : Result<'Answer, 'Refusal>)
        : Result<'Answer, 'Refusal>
        =
        if actual <> expected then
            failwith $"%s{call} through the paused call answered %A{actual}, and made a step at a time, %A{expected}"

        actual

    /// A whole `write(2)` by `caller` of `bytes` from `buffer`, through the
    /// library's public protocol (`UnixReadWrite.write`, and if it stops at the
    /// copy, `writeWithBytes` of the bytes `PausedWrite.copyRange` names),
    /// held to `stepsThenWrite`, which makes the same write a step at a time;
    /// and beside its step, the delivery `writeWithBytes` answered, if it was
    /// called.
    let admitThenWriteDeliveringAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread> * Delivery option, WriteRefusal>
        =
        let actual =
            UnixReadWrite.tryWrite caller fd buffer (uint64 bytes.Length) system
            |> Result.map (CallProgress.mapAnswered (fun fate -> fate, None))
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.tryWriteWithBytes (copied "write" (PausedWrite.copyRange paused) bytes) paused
            )
            |> Result.map (fun (fate, delivery) -> stepOf fate, delivery)

        agreeing "write" (stepsThenWrite caller fd buffer bytes system) actual

    /// `admitThenWriteDeliveringAs`, without the delivery.
    let admitThenWriteAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        admitThenWriteDeliveringAs caller fd buffer bytes system |> Result.map fst

    /// `admitThenWriteAs` the thread `thread` of the only process on the
    /// machine.
    let admitThenWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        admitThenWriteAs (Callers.thread thread system) fd buffer bytes system

    /// A whole `send(2)` by `caller` with the raw flag word `flags`, through the
    /// library's public protocol, as `admitThenWriteAs` makes a `write(2)`, held
    /// to `stepsThenSend`.
    let admitThenSendAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
        =
        let actual =
            UnixReadWrite.trySend caller fd buffer (uint64 bytes.Length) flags system
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.trySendWithBytes (copied "send" (PausedSend.copyRange paused) bytes) paused
            )
            |> Result.map stepOf

        agreeing "send" (stepsThenSend caller fd buffer bytes flags system) actual

    /// `admitThenSendAs` the thread `thread` of the only process on the
    /// machine.
    let admitThenSend<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (buffer : UserBuffer)
        (bytes : ImmutableArray<byte>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
        =
        admitThenSendAs (Callers.thread thread system) fd buffer bytes flags system

    /// The woken `write` or `send` of `thread`, finished a step at a time:
    /// `UnixReadWrite.tryAdmitFinishWrite`, and if it says to transfer,
    /// `tryApplyResumedWrite` of `bytesAt offset count` with the decision it
    /// made. The oracle `finishWrite` holds the public protocol to.
    let private stepsThenFinishWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (bytesAt : int -> int -> ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        let thread = Caller.thread caller

        let stepped =
            match UnixReadWrite.tryAdmitFinishWrite thread (Proc.view (Caller.processId caller) system) with
            | Error refusal -> Error refusal
            | Ok (WriteStep.Returns (WriteResumption.Transfer (offset, count, into), admitted)) ->
                UnixReadWrite.tryApplyResumedWrite thread into (bytesAt offset count) admitted
            | Ok (WriteStep.Returns (WriteResumption.Answered answer, after)) -> Ok (WriteStep.Returns (answer, after))
            | Ok (WriteStep.ReturnsRaising (WriteResumption.Answered answer, signal, after)) ->
                Ok (WriteStep.ReturnsRaising (answer, signal, after))
            | Ok (WriteStep.ReturnsRaising (WriteResumption.Transfer _ as resumption, signal, _)) ->
                failwith $"admitFinishWrite raised %A{signal} and still asked for %A{resumption}"
            | Ok (WriteStep.ProcessEnded (ended, after)) -> Ok (WriteStep.ProcessEnded (ended, after))
            | Ok (WriteStep.WouldBlock (condition, after)) -> Ok (WriteStep.WouldBlock (condition, after))
            | Ok (WriteStep.Interrupted after) -> Ok (WriteStep.Interrupted after)

        stepped |> Result.map (WriteStep.map Proc.unfocus)

    /// The woken `write` or `send` of `caller`, finished through the library's
    /// public protocol (`UnixReadWrite.finishWrite`, and if it stops at the
    /// copy, `writeWithBytes` of `bytesAt offset count` for the range
    /// `PausedWrite.copyRange` names), held to `stepsThenFinishWrite`.
    /// `bytesAt` must answer exactly `count` bytes. Fails if the write
    /// delivered bytes out of the machine, which a woken write never does.
    let finishWriteAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (bytesAt : int -> int -> ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        let actual =
            UnixReadWrite.tryFinishWrite caller system
            |> CallProgress.resumeWith (fun paused ->
                let range = PausedWrite.copyRange paused

                if range.FirstByte < 0 || range.ByteCount <= 0 then
                    failwith $"finishWrite asked for %A{range}"

                UnixReadWrite.tryWriteWithBytes (bytesAt range.FirstByte range.ByteCount) paused
                |> Result.map (fun (fate, delivery) ->
                    match delivery with
                    | None -> fate
                    | Some delivery -> failwith $"a woken write delivered %A{delivery}"
                )
            )
            |> Result.map stepOf

        agreeing "finishWrite" (stepsThenFinishWrite caller bytesAt system) actual

    /// `finishWriteAs` the thread `thread` of the only process on the machine.
    let finishWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (bytesAt : int -> int -> ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        finishWriteAs (Callers.thread thread system) bytesAt system

    /// A whole `write(2)` by `caller` of `bytes`, `admitThenWriteAs` from a
    /// mapped buffer: every answer the call gives, or the bytes the call takes
    /// and what it does with them.
    let writeBytesAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        admitThenWriteAs caller fd UserBuffer.Mapped bytes system

    /// `writeBytesAs` the thread `thread` of the only process on the machine.
    let writeBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
        =
        writeBytesAs (Callers.thread thread system) fd bytes system

    /// A whole `send(2)` by `thread` of `bytes` with the raw flag word `flags`,
    /// `admitThenSend` from a mapped buffer.
    let sendBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
        =
        admitThenSend thread fd UserBuffer.Mapped bytes flags system

    /// `UnixReadWrite.tryAdmitWrite` by the leader, through `returned`.
    let admitWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (buffer : UserBuffer)
        (count : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteAdmission * UnixSystem<'Thread, 'Handler>, WriteRefusal>
        =
        Lone.UnixReadWrite.tryAdmitWrite (Lone.leader system) fd buffer count system
        |> returned

    /// A whole `write(2)` of `bytes` by the leader, `admitThenWriteDeliveringAs`
    /// from a mapped buffer, through `returned`, and beside it the delivery
    /// the write made.
    let writeDelivering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<(WriteAnswer * UnixSystem<'Thread, 'Handler>) * Delivery option, WriteRefusal>
        =
        match
            admitThenWriteDeliveringAs (Callers.thread (Lone.leader system) system) fd UserBuffer.Mapped bytes system
        with
        | Error refusal -> Error refusal
        | Ok (step, delivery) -> returned (Ok step) |> Result.map (fun returned -> returned, delivery)

    /// A whole `write(2)` of `bytes` by the leader, `admitThenWrite` from a
    /// mapped buffer, through `returned`.
    let write<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteAnswer * UnixSystem<'Thread, 'Handler>, WriteRefusal>
        =
        admitThenWrite (Lone.leader system) fd UserBuffer.Mapped bytes system
        |> returned

    /// A whole `pwrite(2)` by the thread `thread` of the only process on the
    /// machine, of `bytes` from a mapped buffer at `offset`, through the
    /// library's public protocol (`UnixReadWrite.pwrite`, and if it stops at
    /// the copy, `pwriteWithBytes` of the bytes `PausedPWrite.copyRange`
    /// names), held to the same call made a step at a time (`tryAdmitPWrite`,
    /// then `tryApplyPWrite` with the decision it made).
    let admitThenPwrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (offset : int64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteAnswer * UnixSystem<'Thread, 'Handler>, PWriteRefusal>
        =
        let steps =
            match Lone.UnixReadWrite.tryAdmitPWrite fd UserBuffer.Mapped (uint64 bytes.Length) offset system with
            | Error refusal -> Error refusal
            | Ok (PWriteAdmission.Answered answer) -> Ok (answer, system)
            | Ok (PWriteAdmission.Faults _ as faults) -> failwith $"a mapped buffer faulted: %A{faults}"
            | Ok (PWriteAdmission.Transfer (count, into)) ->
                if count > bytes.Length then
                    failwith $"admitPWrite asked for %d{count} of %d{bytes.Length} bytes"

                Lone.UnixReadWrite.tryApplyPWrite fd offset into (ImmutableArray.Create (bytes, 0, count)) system

        let actual =
            UnixReadWrite.tryPwrite
                (Callers.thread thread system)
                fd
                UserBuffer.Mapped
                (uint64 bytes.Length)
                offset
                system
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.tryPwriteWithBytes (copied "pwrite" (PausedPWrite.copyRange paused) bytes) paused
            )

        agreeing "pwrite" steps actual

/// `UnixReadWrite.tryAdmitWrite` for a write whose admission must change nothing:
/// every target but a Darwin pipe, whose timestamps a write moves whatever it
/// answers but `EPIPE`.
[<RequireQualifiedAccess>]
module internal WriteAdmissions =

    /// The admission, having checked that the system came back as it arrived.
    let unchanged<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (buffer : UserBuffer)
        (count : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<WriteAdmission, WriteRefusal>
        =
        WriteOutcomes.admitWrite fd buffer count system
        |> Result.map (fun (admission, after) ->
            if after <> system then
                failwith
                    $"admitWrite on fd %d{fd} changed the system for an admission of %A{admission}, which only a write reaching a Darwin pipe may do"

            admission
        )
