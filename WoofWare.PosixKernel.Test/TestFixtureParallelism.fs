namespace WoofWare.PosixKernel.Test

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

    [<Test>]
    let ``every fixture says whether it runs in parallel`` () : unit =
        let fixtures =
            Assembly.GetExecutingAssembly().GetTypes ()
            |> Array.filter (fun t -> t.IsDefined (typeof<TestFixtureAttribute>, false))

        fixtures.Length |> shouldBeGreaterThan 200

        fixtures
        |> Array.filter (fun t -> not (t.IsDefined (typeof<ParallelizableAttribute>, false)))
        |> Array.map (fun t -> t.FullName)
        |> Array.sort
        |> shouldEqual [||]
