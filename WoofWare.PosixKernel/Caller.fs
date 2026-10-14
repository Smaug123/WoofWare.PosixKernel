namespace WoofWare.PosixKernel

/// Who makes a call: one of a process's threads, named by the process's ID and
/// the client's name for the thread.
///
/// A thread's name is its process's own, so two processes may each have a
/// thread the client calls `0`, and their callers differ by process.
///
/// Generic in what names a thread, for the same reason `UnixSystem` is.
[<Struct>]
type Caller<'Thread> =
    private
    | Caller of processId : ProcessId * thread : 'Thread

    override this.ToString () : string =
        match this with
        | Caller (pid, thread) -> $"thread %O{thread} of process %O{pid}"

[<RequireQualifiedAccess>]
module Caller =
    /// The thread `thread` of the process `pid`.
    let make<'Thread> (pid : ProcessId) (thread : 'Thread) : Caller<'Thread> = Caller (pid, thread)

    /// The ID of the process the call is made in.
    let processId<'Thread> (caller : Caller<'Thread>) : ProcessId =
        match caller with
        | Caller (pid, _) -> pid

    /// The client's name for the thread making the call.
    let thread<'Thread> (caller : Caller<'Thread>) : 'Thread =
        match caller with
        | Caller (_, thread) -> thread
