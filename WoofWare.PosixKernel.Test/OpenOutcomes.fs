namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `UnixNamespace.openPath` and `UnixNamespace.openat` for a test about what
/// an open answers rather than about whether it sleeps.
[<RequireQualifiedAccess>]
module internal OpenOutcomes =

    /// An open's result as the answer it returned, failing the test if the
    /// call slept or restarted. Nothing in this version makes a FIFO, the one
    /// object whose open sleeps, so no open the library answers can do either.
    let answered<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (result : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, OpenRefusal>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        result
        |> Result.map (fun (outcome, after) ->
            match outcome with
            | SyscallOutcome.Answered answer -> answer, after
            | SyscallOutcome.WouldBlock _
            | SyscallOutcome.Restarts -> failwith $"expected an open that returns, got %A{outcome}"
        )

    /// `UnixNamespace.openPath` by the process's leader, failing the test if
    /// the call sleeps.
    let openPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (flags : int)
        (path : PathArgumentBytes)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        UnixNamespace.tryOpenPath system.Leader flags path mode system |> answered

    /// `UnixNamespace.openat` by the process's leader, failing the test if the
    /// call sleeps.
    let openat<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (dirfd : int)
        (path : PathArgumentBytes)
        (flags : int)
        (mode : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
        =
        UnixNamespace.tryOpenat system.Leader dirfd path flags mode system |> answered
