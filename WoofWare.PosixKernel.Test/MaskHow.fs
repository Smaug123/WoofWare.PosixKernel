namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The `how` that `sigprocmask(2)`, `pthread_sigmask(3)` and `rt_sigprocmask`
/// take, by this test project's own reading of
/// `docs/plans/2026-08-23-posix-kernel-extraction/sigprocmask-ops.c`,
/// independently of the library's decoder. Its outputs' header lines give
/// Linux's `SIG_BLOCK`, `SIG_UNBLOCK` and `SIG_SETMASK` as 0, 1 and 2, and
/// Darwin's as 1, 2 and 3, and its "how" rows found each to make the change it
/// names.
[<RequireQualifiedAccess>]
module internal MaskHow =

    /// The number `numbering`'s `<signal.h>` gives `change`.
    let number (numbering : SignalNumbering) (change : SignalMaskChange) : int =
        match numbering, change with
        | SignalNumbering.Linux, SignalMaskChange.Block -> 0
        | SignalNumbering.Linux, SignalMaskChange.Unblock -> 1
        | SignalNumbering.Linux, SignalMaskChange.SetMask -> 2
        | SignalNumbering.Darwin, SignalMaskChange.Block -> 1
        | SignalNumbering.Darwin, SignalMaskChange.Unblock -> 2
        | SignalNumbering.Darwin, SignalMaskChange.SetMask -> 3

    /// `SIG_BLOCK` in `numbering`.
    let block (numbering : SignalNumbering) : int = number numbering SignalMaskChange.Block

    /// `SIG_UNBLOCK` in `numbering`.
    let unblock (numbering : SignalNumbering) : int =
        number numbering SignalMaskChange.Unblock

    /// `SIG_SETMASK` in `numbering`.
    let setMask (numbering : SignalNumbering) : int =
        number numbering SignalMaskChange.SetMask
