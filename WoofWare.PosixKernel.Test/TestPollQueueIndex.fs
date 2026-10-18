namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `PollQueueTable` keeps a record of the sleeping Darwin polls' kqueues that
/// registered through each descriptor of each process, which
/// `PollQueueTable.registeringThrough` and
/// `PollQueueTable.dropRegistrationsThrough` read. Over random walks of the
/// table's own changes, each answers what a scan of every queue answers.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPollQueueIndex =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    /// A seed for a walk's own `System.Random`, from the whole range, and with
    /// no shrinker: a smaller seed is another walk, not a simpler one.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private owners : ProcessId list =
        [
            ProcessId.parseOrFail "TestPollQueueIndex" 1
            ProcessId.parseOrFail "TestPollQueueIndex" 2
        ]

    /// The descriptor numbers a walk registers through.
    let private fds : int list = [ 0 ; 1 ; 2 ]

    let private filters : KqueueFilter list = [ KqueueFilter.Read ; KqueueFilter.Write ]

    let private registration : PollRegistration =
        {
            Entry = 0
            OutOfBand = false
            RegisteredAt = 0
            Socket = None
        }

    /// A queue of `owner`'s, registering a random few filters, some active.
    let private freshQueue (rng : System.Random) (owner : ProcessId) : PollQueue =
        let keys =
            [
                for fd in fds do
                    for filter in filters do
                        if rng.Next 3 = 0 then
                            fd, filter
            ]

        {
            Owner = owner
            Registrations = keys |> List.map (fun key -> key, registration) |> Map.ofList
            Active = keys |> List.filter (fun _ -> rng.Next 2 = 0)
        }

    /// One of the table's own changes, at random, to `table`, whose next
    /// queue would get the identity `next`.
    let private step (rng : System.Random) (next : int64) (table : PollQueueTable) : PollQueueTable =
        let pick (items : 'a list) : 'a = items.[rng.Next items.Length]
        let queues = PollQueueTable.all table |> Map.toList

        match queues, rng.Next 6 with
        | [], _
        | _, 0 -> PollQueueTable.add (PollQueueId next) (freshQueue rng (pick owners)) table
        | queues, 1 ->
            // A park's end.
            PollQueueTable.remove (fst (pick queues)) table
        | queues, 2 ->
            // A scan, which removes what reported and empties the active
            // list; or, however unsoundly, a queue made afresh, or the same
            // registrations of another owner, in its place.
            let id, queue = pick queues

            let rewritten =
                match rng.Next 6 with
                | 0 -> freshQueue rng (pick owners)
                | 1 ->
                    { queue with
                        Owner = pick owners
                    }
                | _ ->
                    let remaining = queue.Registrations |> Map.filter (fun _ _ -> rng.Next 2 = 0)

                    {
                        Owner = queue.Owner
                        Registrations = remaining
                        Active = []
                    }

            PollQueueTable.set id rewritten table
        | _, 3 ->
            // An event, which activates registrations and registers nothing.
            table
            |> PollQueueTable.map (fun queue ->
                { queue with
                    Active =
                        queue.Registrations
                        |> Map.toList
                        |> List.map fst
                        |> List.filter (fun key -> not (List.contains key queue.Active) && rng.Next 2 = 0)
                        |> List.append queue.Active
                }
            )
        | _, 4 ->
            // However unsoundly: a change to every queue that drops what it
            // registers.
            table
            |> PollQueueTable.map (fun queue ->
                if rng.Next 2 = 0 then
                    queue
                else
                    let remaining = queue.Registrations |> Map.filter (fun _ _ -> rng.Next 2 = 0)

                    {
                        Owner = queue.Owner
                        Registrations = remaining
                        Active = queue.Active |> List.filter (fun key -> Map.containsKey key remaining)
                    }
            )
        | _, _ ->
            // A close.
            PollQueueTable.dropRegistrationsThrough (pick owners) (pick fds) table

    /// What `PollQueueTable.dropRegistrationsThrough` must make of `table`, by
    /// a scan of every queue.
    let private droppedByScan (owner : ProcessId) (fd : int) (table : PollQueueTable) : Map<PollQueueId, PollQueue> =
        PollQueueTable.all table
        |> Map.map (fun _ queue ->
            if queue.Owner = owner then
                { queue with
                    Registrations = queue.Registrations |> Map.filter (fun (registered, _) _ -> registered <> fd)
                    Active = queue.Active |> List.filter (fun (active, _) -> active <> fd)
                }
            else
                queue
        )

    let private agree (table : PollQueueTable) : unit =
        for owner in owners do
            for fd in 9 :: fds do
                let scanned =
                    PollQueueTable.all table
                    |> Map.toList
                    |> List.filter (fun (_, queue) ->
                        queue.Owner = owner
                        && queue.Registrations |> Map.exists (fun (registered, _) _ -> registered = fd)
                    )
                    |> List.map fst

                PollQueueTable.registeringThrough owner fd table
                |> List.sort
                |> shouldEqual scanned

                PollQueueTable.all (PollQueueTable.dropRegistrationsThrough owner fd table)
                |> shouldEqual (droppedByScan owner fd table)

        PollQueueTable.indexFresh table |> shouldEqual true

    [<Test>]
    let ``the index of registrations by descriptor answers what a scan of the queues answers`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (PollQueueTable.empty, [ 1L .. int64 (rng.Next (1, 40)) ])
            ||> List.fold (fun table next ->
                let next = step rng next table
                agree next
                next
            )
            |> ignore<PollQueueTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)
