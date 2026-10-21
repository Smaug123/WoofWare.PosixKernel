namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `UnixNamespace.openPath` and `UnixNamespace.openat` for a test about what
/// an open answers rather than about whether it sleeps.
[<RequireQualifiedAccess>]
module internal OpenOutcomes =

    /// An open's result as the answer it returned, failing the test if the
    /// call slept. Nothing in this version makes a FIFO, the one object whose
    /// open sleeps, so no open the library answers can sleep.
    let answered<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (result : Result<OpenOutcome * UnixSystem<'Thread, 'Handler>, OpenRefusal>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        result
        |> Result.map (fun (outcome, after) ->
            match outcome with
            | OpenOutcome.Answered answer -> answer, after
            | OpenOutcome.WouldBlock _ -> failwith $"expected an open that returns, got %A{outcome}"
        )

    /// `UnixNamespace.openPath` by the leader of the process `pid`, failing the
    /// test if the call sleeps.
    let openPathIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        UnixNamespace.tryOpenPath (Caller.make pid (Proc.leader pid system)) path flags mode system
        |> answered

    /// `openPathIn` the only process on the machine.
    let openPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        openPathIn (Lone.pid system) path flags mode system

    /// `UnixNamespace.openat` by the process's leader, failing the test if the
    /// call sleeps.
    let openat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        UnixNamespace.tryOpenat (Callers.leader system) dirfd path flags mode system
        |> answered
