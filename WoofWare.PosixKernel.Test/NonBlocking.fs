namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `O_NONBLOCK` set through `UnixDescriptor.setNonBlocking`, for a test that
/// needs a descriptor non-blocking and is not about the call that makes it so.
[<RequireQualifiedAccess>]
module internal NonBlocking =

    /// `system` once the leader of its only process has set `O_NONBLOCK` on
    /// `fd`, failing the test unless the call answers that it did.
    let set<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        match UnixDescriptor.setNonBlocking (Callers.leader system) fd true system with
        | SetNonBlockingAnswer.Set, system -> system
        | SetNonBlockingAnswer.Failed error, _ -> failwith $"setting O_NONBLOCK on fd %d{fd} answered %O{error}"
