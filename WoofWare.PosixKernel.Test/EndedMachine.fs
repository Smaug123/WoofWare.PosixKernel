namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open WoofWare.PosixKernel

/// What the end of a process leaves of the system it ran in.
[<RequireQualifiedAccess>]
module EndedMachine =

    /// Assert that `after`, the system a call by `caller` answered as it ended
    /// `caller`'s process, is what `exit_group` by `caller` leaves of `before`,
    /// the system the call was made in: so the call changed nothing outside
    /// the process before it ended it, and the process ended as an exit ends
    /// it, its descriptors closed and the process gone. A `caller` that owes
    /// a return to user mode in `before`, as one returning to end the process
    /// does, exits as if it had made that return and taken nothing.
    let assertAsExit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (before : UnixSystem<'Thread, 'Handler>)
        (after : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        UnixSystem.processIds after
        |> Set.contains (Caller.processId caller)
        |> shouldEqual false

        let before =
            before
            |> Proc.mapThreads (Caller.processId caller) (UnixThreadTable.settle (Caller.thread caller))

        let _, exited = UnixThreadLifecycle.exitGroup caller 0 before
        after |> shouldEqual exited

    /// Assert that `after` is the system a process that ran alone left as it
    /// ended: no process is on the machine, no thread ID or process ID is
    /// live, no process stands in a directory, no open file description is
    /// left, and every invariant holds.
    let assertNoneLeft<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (after : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        UnixSystem.processIds after |> shouldEqual Set.empty
        ThreadIdAllocator.live after.Machine.ThreadIds |> shouldEqual Set.empty
        ProcessIdTable.live after.Machine.ProcessIds |> shouldEqual Set.empty
        after.Machine.CurrentDirectories |> shouldEqual Map.empty
        OpenFileTable.descriptions after.Machine.OpenFiles |> shouldEqual Map.empty
        UnixSystem.checkInvariants after |> shouldEqual []
