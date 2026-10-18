namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `OpenFileTable` keeps a count of the descriptions naming each end of each
/// pipe and a record of the `flock`s held on each object, which
/// `OpenFileTable.describesPipeEnd` and `OpenFileTable.flockConflicts` read.
/// Over random walks of the table's own changes, each answers what a scan of
/// every description answers.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestOpenFileIndex =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    /// A seed for a walk's own `System.Random`, from the whole range, and with
    /// no shrinker: a smaller seed is another walk, not a simpler one.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private pipes : PipeId list = [ PipeId 0L ; PipeId 1L ; PipeId 2L ]

    /// What a walk opens: the ends of a few pipes, a few sockets, and a few
    /// files, so that several descriptions share each object.
    let private targets : OpenFileTarget list =
        [
            for pipe in pipes do
                OpenFileTarget.Pipe (pipe, PipeEnd.Read)
                OpenFileTarget.Pipe (pipe, PipeEnd.Write)
            OpenFileTarget.Socket (SocketId 0L)
            OpenFileTarget.Socket (SocketId 1L)
            OpenFileTarget.File (InodeNumber 10L, 0L)
            OpenFileTarget.File (InodeNumber 11L, 0L)
        ]

    let private locks : FlockMode option list =
        [ None ; Some FlockMode.Shared ; Some FlockMode.Exclusive ]

    let private description (target : OpenFileTarget) : OpenFileDescription =
        {
            Target = target
            AccessMode = FileAccessMode.ReadWrite
            NonBlocking = false
            Flock = None
            Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
        }

    let private live (table : OpenFileTable) : OpenFileDescriptionId list =
        OpenFileTable.toSeq table |> Seq.map fst |> List.ofSeq

    /// One of the table's own changes, at random, to `table`.
    let private step (rng : System.Random) (table : OpenFileTable) : OpenFileTable =
        let pick (items : 'a list) : 'a = items.[rng.Next items.Length]

        match live table, rng.Next 7 with
        | [], _
        | _, 0 ->
            let target = pick targets

            let through =
                if OpenFileTable.namesInode target then
                    Some ReachedThrough.Unnamed
                else
                    None

            OpenFileTable.create (description target) through table |> snd
        | ids, 1 -> OpenFileTable.retain (pick ids) table
        | ids, 2 ->
            // The last close of a descriptor, or a call's last hold let go
            // of: whichever the description has, and then its destruction if
            // nothing references it any more.
            let id = pick ids

            let released =
                if OpenFileTable.descriptorCount id table = Some 0 then
                    OpenFileTable.releaseHold id table
                else
                    OpenFileTable.release id table

            OpenFileTable.destroyIfUnreferenced id released |> fst
        | ids, 3 -> OpenFileTable.hold (pick ids) table
        | ids, 4 ->
            let mode = pick locks

            OpenFileTable.mapDescription
                "TestOpenFileIndex"
                (pick ids)
                (fun description ->
                    { description with
                        Flock = mode
                    }
                )
                table
        | ids, 5 ->
            // However unsoundly: an index must follow a description that
            // names something else, though no syscall makes one.
            let target = pick targets

            OpenFileTable.mapDescription
                "TestOpenFileIndex"
                (pick ids)
                (fun description ->
                    { description with
                        Target = target
                    }
                )
                table
        | _, _ ->
            // A change that rewrites every description it reaches and leaves
            // the rest as they were.
            OpenFileTable.signalEpollInstances (Set.ofList (live table)) None table

    let private conflictsByScan
        (object : OpenFileObject)
        (requester : OpenFileDescriptionId)
        (mode : FlockMode)
        (table : OpenFileTable)
        : bool
        =
        OpenFileTable.toSeq table
        |> Seq.exists (fun (other, description) ->
            other <> requester
            && OpenFileDescription.object other description = object
            && (
                match mode, description.Flock with
                | _, None -> false
                | FlockMode.Shared, Some FlockMode.Shared -> false
                | FlockMode.Shared, Some FlockMode.Exclusive
                | FlockMode.Exclusive, Some _ -> true
            )
        )

    /// Every question the indexes answer about `table`, answered by them and
    /// by a scan, which must agree.
    let private agree (table : OpenFileTable) : unit =
        for pipe in pipes do
            for pipeEnd in [ PipeEnd.Read ; PipeEnd.Write ] do
                let scanned =
                    OpenFileTable.toSeq table
                    |> Seq.exists (fun (_, description) -> description.Target = OpenFileTarget.Pipe (pipe, pipeEnd))

                OpenFileTable.describesPipeEnd pipe pipeEnd table |> shouldEqual scanned

        // A requester need not be live: one that has gone, or never was, asks
        // too.
        let requesters = OpenFileDescriptionId 1000L :: live table

        let objects =
            OpenFileTable.toSeq table
            |> Seq.map (fun (id, description) -> OpenFileDescription.object id description)
            |> Seq.append [ OpenFileObject.Pipe (PipeId 9L) ]
            |> Seq.distinct
            |> List.ofSeq

        for object in objects do
            for requester in requesters do
                for mode in [ FlockMode.Shared ; FlockMode.Exclusive ] do
                    OpenFileTable.flockConflicts object requester mode table
                    |> shouldEqual (conflictsByScan object requester mode table)

        OpenFileTable.checkInvariants [] table
        |> List.contains FileDescriptorRegistryDefect.StaleIndex
        |> shouldEqual false

    [<Test>]
    let ``the pipe-end and flock indexes answer what a scan of the descriptions answers`` () : unit =
        let property (seed : int) : unit =
            let rng = System.Random seed

            (OpenFileTable.empty, [ 1 .. rng.Next (1, 40) ])
            ||> List.fold (fun table _ ->
                let next = step rng table
                agree next
                next
            )
            |> ignore<OpenFileTable>

        Check.One (propertyConfig, Prop.forAll walkSeed property)
