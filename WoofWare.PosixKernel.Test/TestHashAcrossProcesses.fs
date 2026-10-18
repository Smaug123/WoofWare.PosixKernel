namespace WoofWare.PosixKernel.Test

open System
open System.Diagnostics
open System.IO
open System.Reflection
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A platform, and a system holding it, hash alike in every process: .NET
/// seeds `HashCode.Combine` and `String.GetHashCode` afresh in each, so a hash
/// built on either differs between two processes hashing the same value.
[<TestFixture>]
[<NonParallelizable>]
// Starts a child process, which inherits the raw sockets a host test beside
// it holds and keeps their endpoints after the test closes them; see
// TestFixtureParallelism.
module TestHashAcrossProcesses =

    /// `HashedValues.hashes`, as a fresh `dotnet fsi` process computes them.
    let private hashesInAnotherProcess () : (string * int) list =
        let source =
            let name = "WoofWare.PosixKernel.Test.HashedValues.fs"

            use stream = Assembly.GetExecutingAssembly().GetManifestResourceStream name

            if isNull stream then
                failwith $"expected the test assembly to embed %s{name}"

            use reader = new StreamReader (stream)
            reader.ReadToEnd ()

        let directory = Directory.CreateTempSubdirectory "hashed-values"

        try
            File.WriteAllText (Path.Combine (directory.FullName, "HashedValues.fs"), source)
            let script = Path.Combine (directory.FullName, "print.fsx")
            let library = typeof<UnixError>.Assembly.Location

            File.WriteAllText (
                script,
                $"#r @\"%s{library}\"\n"
                + "#load \"HashedValues.fs\"\n"
                + "for name, h in WoofWare.PosixKernel.Test.HashedValues.hashes () do printfn \"%s\\t%d\" name h\n"
            )

            let info = ProcessStartInfo "dotnet"
            info.ArgumentList.Add "fsi"
            info.ArgumentList.Add script
            info.WorkingDirectory <- directory.FullName
            info.RedirectStandardOutput <- true
            info.RedirectStandardError <- true
            info.UseShellExecute <- false
            info.Environment.["DOTNET_NOLOGO"] <- "1"
            info.Environment.["DOTNET_CLI_TELEMETRY_OPTOUT"] <- "1"

            use proc = Process.Start info
            let stdout = proc.StandardOutput.ReadToEndAsync ()
            let stderr = proc.StandardError.ReadToEndAsync ()

            if not (proc.WaitForExit (TimeSpan.FromMinutes 5.0)) then
                proc.Kill true
                failwith "dotnet fsi did not hash the values in five minutes"

            if proc.ExitCode <> 0 then
                failwith
                    $"dotnet fsi exited %d{proc.ExitCode} hashing the values:\n%s{stdout.Result}\n%s{stderr.Result}"

            stdout.Result.TrimEnd().Split '\n'
            |> Array.map (fun (line : string) ->
                match line.TrimEnd('\r').Split '\t' with
                | [| name ; h |] -> name, int h
                | _ -> failwith $"expected a name and a hash, separated by a tab: %s{line}"
            )
            |> List.ofArray
        finally
            directory.Delete true

    [<Test>]
    let ``another process hashes the platforms and their systems alike`` () : unit =
        hashesInAnotherProcess () |> shouldEqual (HashedValues.hashes ())
