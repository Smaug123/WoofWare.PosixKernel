namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The sweep of sleeping threads as the library made it before a park recorded
/// whether its thread had been woken (commit cc8cf4a's `UnixWait.wakes` and
/// `UnixWait.deadlines`), kept as the reference the library's sweep is held to.
///
/// The client named the threads it held asleep, and a parked thread it left out
/// counted as woken and not yet finished, holding each exclusive queue its call
/// waits on.
[<RequireQualifiedAccess>]
module internal ReferenceWake =

    /// The threads of `asleep` that `system` wakes, in the order they parked,
    /// each with the primitives of its wake condition which hold.
    let wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (asleep : Set<Caller<'Thread>>)
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list
        =
        let machine = system.Machine

        let satisfied =
            asleep
            |> Set.toList
            |> List.choose (fun caller ->
                let pid = Caller.processId caller
                let thread = Caller.thread caller

                let slot =
                    match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
                    | Some slot -> slot
                    | None -> failwith $"ReferenceWake.wakes: the system holds no process %O{pid}"

                match UnixThreadTable.parkOf thread slot.Threads with
                | None -> failwith $"ReferenceWake.wakes: thread %O{thread} of process %O{pid} records no park"
                | Some park ->
                    let fired =
                        ProcessView.ofSlot pid slot system
                        |> WakeCondition.satisfied thread (WakeCondition.ofPark park.Syscall)

                    if Set.isEmpty fired then
                        None
                    else
                        Some (park.Ordinal, caller, fired)
            )
            |> List.sortBy (fun (ordinal, _, _) -> ordinal)

        let finishing : Set<ExclusiveWaitQueue> =
            system.Processes
            |> Seq.collect (fun (KeyValue (key, slot)) ->
                let pid = ProcessId.parseOrFail "ReferenceWake.wakes" key

                slot.Threads
                |> Map.toSeq
                |> Seq.filter (fun (thread, _) -> not (Set.contains (Caller.make pid thread) asleep))
            )
            |> Seq.collect (fun (_, state) ->
                match state.Parked with
                | Some park -> Parking.exclusiveQueuesOfPark machine park.Syscall
                | None -> []
            )
            |> Set.ofSeq

        let chosen : Map<ExclusiveWaitQueue, Caller<'Thread>> =
            satisfied
            |> List.collect (fun (ordinal, thread, fired) ->
                fired
                |> Set.toList
                |> List.choose (fun primitive ->
                    Parking.exclusiveQueueOf machine primitive
                    |> Option.map (fun queue -> queue, (ordinal, thread))
                )
            )
            |> List.groupBy fst
            |> List.choose (fun (queue, waiters) ->
                if Set.contains queue finishing then
                    None
                else
                    let waiters = waiters |> List.map snd

                    let _, woken =
                        match queue with
                        | ExclusiveWaitQueue.Epoll _ -> List.maxBy fst waiters
                        | ExclusiveWaitQueue.Listener _
                        | ExclusiveWaitQueue.PipeReaders _
                        | ExclusiveWaitQueue.PipeWriters _ -> List.minBy fst waiters

                    Some (queue, woken)
            )
            |> Map.ofList

        satisfied
        |> List.filter (fun (_, thread, fired) ->
            fired
            |> Set.exists (fun primitive ->
                match Parking.exclusiveQueueOf machine primitive with
                | Some queue -> Map.tryFind queue chosen = Some thread
                | None -> true
            )
        )
        |> List.map (fun (_, caller, fired) -> caller, fired)

    /// Every deadline the parks of `asleep` are waiting for, in nanoseconds
    /// since boot, with a repeat for each park that waits for it.
    let deadlines<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (asleep : Set<Caller<'Thread>>)
        (system : UnixSystem<'Thread, 'Handler>)
        : int64 list
        =
        asleep
        |> Set.toList
        |> List.collect (fun caller ->
            let pid = Caller.processId caller
            let thread = Caller.thread caller

            let slot =
                match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
                | Some slot -> slot
                | None -> failwith $"ReferenceWake.deadlines: the system holds no process %O{pid}"

            match UnixThreadTable.parkOf thread slot.Threads with
            | None -> failwith $"ReferenceWake.deadlines: thread %O{thread} of process %O{pid} records no park"
            | Some park -> WakeCondition.deadlines (WakeCondition.ofPark park.Syscall)
        )
