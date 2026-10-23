namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Threads in states no call leaves them in: for a test of what such a state
/// does, or of what `UnixSystem.checkInvariants` reports of it. Every test
/// forges a thread's state through here, and reads one through `Proc` or
/// `Lone`, so that a change to how a process holds its threads changes these
/// modules alone (`scripts/check-test-boundaries.py`).
///
/// Each function writes threads alone: it mints no park ordinal, and takes or
/// lets go of no hold on an open file description. Each that takes a caller
/// fails loudly unless the system holds the caller's process and that process
/// has the caller's thread.
[<RequireQualifiedAccess>]
module internal ForgedThread =

    let private write<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (f : 'Thread -> ThreadTable<'Thread> -> ThreadTable<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.mapThreadTable (Caller.processId caller) (f (Caller.thread caller)) system

    /// `system` with the thread `caller` names as `state`, whatever its park
    /// or debt: for a state no other function here forges, such as a thread on
    /// a processor the machine does not have, or a park whose ordinal no
    /// park minted.
    let withState<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (state : UnixThreadState)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.thread caller system |> ignore<UnixThreadState>

        write
            caller
            (fun thread table -> UnixThreadTable.byName table |> Map.add thread state |> UnixThreadTable.ofMap)
            system

    /// `system` with the thread `caller` names in `park`. Refuses, as the
    /// kernel's own record of a park does, a park of one syscall over a park of
    /// another, and a park whose state moves other than as a wake and a re-park
    /// move it.
    let parked<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (park : ThreadPark)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        write caller (fun thread -> UnixThreadTable.withPark thread park) system

    /// `system` with the thread `caller` names, asleep in a call, woken for
    /// `fired`, as though `UnixWait.wake` had woken it. Refuses a thread that
    /// is not asleep in a call, and an empty `fired`.
    let woken<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fired : Set<WakePrimitive>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        write caller (fun thread -> UnixThreadTable.markWoken thread fired) system

    /// `system` with the thread `caller` names owing `owed` before it makes
    /// another call. Refuses a parked thread, and one that owes a return
    /// already.
    let owing<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (owed : OwedReturn)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        write caller (fun thread -> UnixThreadTable.owe thread owed) system

    /// `system` with the thread `caller` names owing nothing, as though it had
    /// returned to user mode and taken nothing there.
    let settled<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        write caller UnixThreadTable.settle system

    /// `system` without the thread `caller` names, which has gone from its
    /// process with nothing else changed: its thread ID still live, and every
    /// record naming it still held. Refuses a parked thread.
    let gone<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.thread caller system |> ignore<UnixThreadState>
        write caller UnixThreadTable.remove system

    /// `system` with every thread of the process `pid` as `source` holds
    /// them: for a test that asks whether two systems differ in anything but
    /// that process's threads.
    let threadsAsIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (source : UnixSystem<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.mapThreadTable pid (fun _ -> Proc.threadTable pid source) system
