namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The `Caller` a test of a machine holding one process makes a call as.
///
/// Each function fails loudly unless the machine holds exactly one process, as
/// `Lone`'s do. A test of a machine holding several names the process, through
/// `Caller.make`.
[<RequireQualifiedAccess>]
module internal Callers =

    /// The leader of the only process on the machine: the thread it started
    /// with.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Caller<'Thread>
        =
        Caller.make (Lone.pid system) (Lone.leader system)

    /// The thread `name` of the only process on the machine, whether or not it
    /// is one of the process's threads.
    let thread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (name : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : Caller<'Thread>
        =
        Caller.make (Lone.pid system) name

    /// The thread `name` of the process a boot gives `UnixSystem.defaultProcessId`:
    /// for a test that names, in a defect it expects, a thread of a system
    /// booted so.
    let ofDefault<'Thread> (name : 'Thread) : Caller<'Thread> =
        Caller.make UnixSystem.defaultProcessId name
