namespace WoofWare.PosixKernel.Test

open System
open System.Diagnostics
open System.Reflection
open FsUnitTyped
open NUnit.Framework

/// NUnit runs a fixture with no `Parallelizable` attribute on its own, after
/// every parallel fixture has finished, so a fixture that says nothing costs CI
/// its whole duration with three cores idle. Every fixture therefore says which
/// it is: `[<Parallelizable(ParallelScope.All)>]`, or `[<NonParallelizable>]`
/// with a comment saying what it would disturb.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFixtureParallelism =

    let private fixtures : Lazy<Type[]> =
        lazy
            Assembly.GetExecutingAssembly().GetTypes ()
            |> Array.filter (fun t -> t.IsDefined (typeof<TestFixtureAttribute>, false))

    let private isParallel (fixture : Type) : bool =
        match fixture.GetCustomAttribute<ParallelizableAttribute> false with
        | null -> false
        | attribute -> attribute.Scope <> ParallelScope.None

    [<Test>]
    let ``every fixture says whether it runs in parallel`` () : unit =
        fixtures.Value.Length |> shouldBeGreaterThan 200

        fixtures.Value
        |> Array.filter (fun t -> not (t.IsDefined (typeof<ParallelizableAttribute>, false)))
        |> Array.map (fun t -> t.FullName)
        |> Array.sort
        |> shouldEqual [||]

    let private startsProcesses (fixture : Type) : bool =
        IlCalls.methodsWithin fixture
        |> List.exists (fun method ->
            IlCalls.callees method
            |> List.exists (fun callee ->
                match callee with
                | Ok callee -> callee.DeclaringType = typeof<Process> && callee.Name = "Start"
                | Error _ -> false
            )
        )

    /// A child process inherits every descriptor the test host holds without
    /// close-on-exec, which includes every raw socket a host test opens
    /// through libc: a child started beside it would hold the socket's
    /// endpoint after the test closed it, and the test's next bind of that
    /// endpoint would find it taken.
    [<Test>]
    let ``no fixture that starts a process runs in parallel`` () : unit =
        let starting = fixtures.Value |> Array.filter startsProcesses

        // Not vacuous: the README's code blocks run under `dotnet fsi`.
        starting |> Array.map (fun t -> t.Name) |> shouldContain "TestReadme"

        starting
        |> Array.filter isParallel
        |> Array.map (fun t -> t.FullName)
        |> Array.sort
        |> shouldEqual [||]
