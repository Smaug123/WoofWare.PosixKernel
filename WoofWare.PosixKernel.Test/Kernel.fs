namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A test's reach into the kernel-wide internals of a system, which belong to
/// no one process: its machine, and which thread each of its processors runs
/// with how long it has been up. Every test reads and writes those through
/// here, rather than through the `UnixSystem` record's fields, so that a
/// change to what a `UnixSystem` holds changes this module, `Proc` and `Lone`
/// alone (`scripts/check-test-boundaries.py`).
///
/// A test that needs only what a client can see asks the public query instead
/// (`UnixSystem.platform`, `fileSystem`, `openFiles`, `nanosecondsSinceBoot`,
/// `advanceClock`, ...).
[<RequireQualifiedAccess>]
module internal Kernel =

    /// The machine `system` runs on.
    let machine<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixMachineState
        =
        system.Machine

    /// `system` with its machine rewritten by `f`.
    let mapMachine<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : UnixMachineState -> UnixMachineState)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Machine = f system.Machine
        }

    /// `system` with `machine` as its machine.
    let withMachine<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (machine : UnixMachineState)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Machine = machine
        }

    /// How long `system`'s machine has been up, and which thread each of its
    /// processors runs.
    let scheduling<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSchedulingState
        =
        system.Scheduling

    /// `system` with its scheduling rewritten by `f`.
    let mapScheduling<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : UnixSchedulingState -> UnixSchedulingState)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Scheduling = f system.Scheduling
        }

    /// The numbering `system`'s signals are read under: its platform's,
    /// whichever process asks.
    let signalNumbering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : SignalNumbering
        =
        SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)
