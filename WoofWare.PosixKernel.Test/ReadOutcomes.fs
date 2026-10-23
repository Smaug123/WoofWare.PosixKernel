namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `UnixReadWrite.read` for a test about what a read answers rather than about
/// whether it sleeps.
[<RequireQualifiedAccess>]
module internal ReadOutcomes =

    /// `UnixReadWrite.read` by the leader of the process `pid`, failing the
    /// test if the call sleeps.
    let readIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (fd : int)
        (buffer : UserBuffer)
        (count : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ReadAnswer * UnixSystem<'Thread, 'Handler>, ReadRefusal>
        =
        UnixReadWrite.tryRead (Caller.make pid (Proc.leader pid system)) fd buffer count system
        |> Result.map (fun (outcome, after) ->
            match outcome with
            | ReadOutcome.Answered answer -> answer, after
            | ReadOutcome.WouldBlock _
            | ReadOutcome.Interrupted -> failwith $"expected a read that returns, got %A{outcome}"
        )

    /// `readIn` the only process on the machine.
    let read<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (buffer : UserBuffer)
        (count : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ReadAnswer * UnixSystem<'Thread, 'Handler>, ReadRefusal>
        =
        readIn (Lone.pid system) fd buffer count system
