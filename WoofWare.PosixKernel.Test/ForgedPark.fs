namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Parks no syscall could make, for tests that `UnixSystem.checkInvariants`
/// reports them.
[<RequireQualifiedAccess>]
module ForgedPark =

    /// `system` with the unparked thread `thread` parked in `parked`, at the next
    /// park ordinal, holding those of the descriptions it names that the open
    /// file table holds. `Parking.park` refuses a park on a description the
    /// table does not hold, which is exactly the park a test of
    /// `ParkedOnAbsentDescription` needs.
    let onAbsent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (parked : ParkedSyscall)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        if (Lone.parkOf thread system).IsSome then
            failwith $"ForgedPark.onAbsent: thread %O{thread} is parked already"

        let (ParkOrdinal.ParkOrdinal ordinal) = (Kernel.machine system).NextParkOrdinal

        let openFiles =
            ParkedSyscall.descriptions parked
            |> List.filter (fun id -> (OpenFileTable.tryFind id (UnixSystem.openFiles system)).IsSome)
            |> List.fold (fun openFiles id -> OpenFileTable.hold id openFiles) (UnixSystem.openFiles system)

        Kernel.mapMachine
            (fun machine ->
                { machine with
                    OpenFiles = openFiles
                    NextParkOrdinal = ParkOrdinal.ParkOrdinal (ordinal + 1L)
                }
            )
            system
        |> ForgedThread.parked
            (Callers.thread thread system)
            {
                Syscall = parked
                Ordinal = (Kernel.machine system).NextParkOrdinal
                State = ParkState.Asleep
            }

    /// `system` with the thread `caller` names, which is asleep in a call,
    /// woken as though `UnixWait.wake` had woken it for the first primitive of
    /// its call's wake condition: for a test of a woken thread that it does not
    /// reach by waking it, such as one whose wake something has since taken
    /// away, or a forged park.
    let wokenCaller<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        match Proc.parkOf caller system with
        | None -> failwith $"ForgedPark.wokenCaller: %O{caller} is not parked"
        | Some park ->
            let first =
                WakeCondition.ofPark park.Syscall |> WakeCondition.primitives |> List.head

            system |> ForgedThread.woken caller (Set.singleton first)

    /// `wokenCaller` of the thread `thread` of the only process.
    let woken<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        wokenCaller (Callers.thread thread system) system
