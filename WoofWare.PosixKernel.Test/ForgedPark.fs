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
        if (UnixThreadTable.parkOf thread (Lone.threads system)).IsSome then
            failwith $"ForgedPark.onAbsent: thread %O{thread} is parked already"

        let (ParkOrdinal.ParkOrdinal ordinal) = system.Machine.NextParkOrdinal

        let openFiles =
            ParkedSyscall.descriptions parked
            |> List.filter (fun id -> (OpenFileTable.tryFind id system.Machine.OpenFiles).IsSome)
            |> List.fold (fun openFiles id -> OpenFileTable.hold id openFiles) system.Machine.OpenFiles

        { system with
            Machine =
                { system.Machine with
                    OpenFiles = openFiles
                    NextParkOrdinal = ParkOrdinal.ParkOrdinal (ordinal + 1L)
                }
        }
        |> Lone.mapThreads (
            UnixThreadTable.withPark
                thread
                {
                    Syscall = parked
                    Ordinal = system.Machine.NextParkOrdinal
                    State = ParkState.Asleep
                }
        )

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
        let pid = Caller.processId caller
        let thread = Caller.thread caller

        match UnixThreadTable.parkOf thread (Proc.threads pid system) with
        | None -> failwith $"ForgedPark.wokenCaller: %O{caller} is not parked"
        | Some park ->
            let first =
                WakeCondition.ofPark park.Syscall |> WakeCondition.primitives |> List.head

            system
            |> Proc.mapThreads pid (UnixThreadTable.markWoken thread (Set.singleton first))

    /// `wokenCaller` of the thread `thread` of the only process.
    let woken<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        wokenCaller (Callers.thread thread system) system
