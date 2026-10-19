namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Runtime.InteropServices
open FsCheck
open FsCheck.FSharp
open WoofWare.PosixKernel

/// A comparison of the model with the kernel running the suite, on generated
/// inputs, split so that a kernel's answers can be recorded on one machine and
/// the model held to them on every other.
///
/// The host's half runs only on the kernel it measures; the model's half is
/// pure, and judges the model against an answer however it was obtained: live
/// from this host, or read back from a corpus another host recorded.
type HostComparison<'input, 'answer when 'input : equality and 'answer : equality> =
    {
        /// Names the corpus: `hostCorpus/<Name>.<flavour>.txt`.
        Name : string
        /// The inputs to put to a kernel of this platform's flavour.
        Inputs : SimulatedUnixPlatform -> Gen<'input>
        /// How many inputs a live run checks, and a recording records.
        Count : int
        /// An input as one field of a corpus line: no tab, carriage return or
        /// line feed, and not beginning `#`.
        WriteInput : 'input -> string
        /// The inverse of `WriteInput`.
        ParseInput : string -> 'input
        /// An answer as one field of a corpus line: no tab, carriage return or
        /// line feed.
        WriteAnswer : 'answer -> string
        /// The inverse of `WriteAnswer`.
        ParseAnswer : string -> 'answer
        /// What this host's kernel answers to an input, measured. Runs only on
        /// a host of the platform's flavour.
        Host : SimulatedUnixPlatform -> 'input -> 'answer
        /// How the model, as the platform, disagrees with what a kernel of its
        /// flavour answered to an input, or `None` where it agrees.
        Disagreement : SimulatedUnixPlatform -> 'input -> 'answer -> string option
    }

/// Running a `HostComparison`: live against this host, recording this host's
/// answers to a corpus, and replaying a recorded corpus on any host.
///
/// CI runs on Linux only, so a comparison checks Darwin's column only on a
/// developer's Mac unless that Mac's answers are recorded. To record them, set
/// `POSIXKERNEL_RECORD_HOST_CORPUS` to the test project's `hostCorpus`
/// directory and run the live test on the host, for instance
/// `POSIXKERNEL_RECORD_HOST_CORPUS=$PWD/WoofWare.PosixKernel.Test/hostCorpus nix develop -c dotnet test WoofWare.PosixKernel.Test/WoofWare.PosixKernel.Test.fsproj --filter "FullyQualifiedName~TestSockOptAgainstHost"`.
/// It rewrites `<Name>.<flavour>.txt` there, which the replay test reads as an
/// embedded resource once the project is rebuilt.
[<RequireQualifiedAccess>]
module HostCorpus =

    /// The directory a live run records into, if one was asked for.
    let private recordingDirectory () : string option =
        match Environment.GetEnvironmentVariable "POSIXKERNEL_RECORD_HOST_CORPUS" with
        | null
        | "" -> None
        | directory -> Some directory

    let private fileName (name : string) (flavour : SimulatedUnixFlavour) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> $"%s{name}.linux.txt"
        | SimulatedUnixFlavour.Darwin -> $"%s{name}.darwin.txt"

    /// Why `written` cannot be the input field of a corpus line, if it cannot.
    let private notAnInputField (written : string) : string option =
        if written.IndexOfAny [| '\t' ; '\r' ; '\n' |] >= 0 then
            Some "it holds a tab or a line break"
        elif written.StartsWith ("#", StringComparison.Ordinal) then
            Some "it begins as a comment does"
        else
            None

    /// One corpus line for an input and its answer, checking that each reads
    /// back as itself.
    let private line (comparison : HostComparison<'input, 'answer>) (input : 'input) (answer : 'answer) : string =
        let writtenInput = comparison.WriteInput input
        let writtenAnswer = comparison.WriteAnswer answer

        match notAnInputField writtenInput with
        | Some why -> failwith $"%s{comparison.Name}: %A{input} was written as %s{writtenInput}, and %s{why}"
        | None -> ()

        if writtenAnswer.IndexOfAny [| '\t' ; '\r' ; '\n' |] >= 0 then
            failwith
                $"%s{comparison.Name}: %A{answer} was written as %s{writtenAnswer}, which holds a tab or a line break"

        if comparison.ParseInput writtenInput <> input then
            failwith $"%s{comparison.Name}: %A{input} reads back from %s{writtenInput} as something else"

        if comparison.ParseAnswer writtenAnswer <> answer then
            failwith $"%s{comparison.Name}: %A{answer} reads back from %s{writtenAnswer} as something else"

        $"%s{writtenInput}\t%s{writtenAnswer}"

    let private failOn (name : string) (checkedCount : int) (disagreements : string list) : unit =
        match disagreements with
        | [] -> ()
        | _ ->
            let shown = disagreements |> List.truncate 5 |> String.concat "\n"

            failwith
                $"%s{name}: the model disagreed on %d{disagreements.Length} of %d{checkedCount} inputs, first on:\n%s{shown}"

    /// Put `comparison`'s inputs to this host's kernel and to the model as
    /// `platform`, which must be of this host's flavour. When
    /// `POSIXKERNEL_RECORD_HOST_CORPUS` names a directory, this also writes
    /// every input and the host's answer to it there, before comparing.
    let live (comparison : HostComparison<'input, 'answer>) (platform : SimulatedUnixPlatform) : unit =
        let flavour = SimulatedUnixPlatform.flavour platform

        if HostPlatform.flavour () <> Some flavour then
            failwith $"%s{comparison.Name}: a live run as %O{platform} on a host of another flavour"

        match recordingDirectory () with
        | None ->
            let property (input : 'input) : unit =
                match comparison.Disagreement platform input (comparison.Host platform input) with
                | None -> ()
                | Some disagreement -> failwith $"%s{comparison.Name}: %s{disagreement}"

            Check.One (
                Config.QuickThrowOnFailure.WithMaxTest comparison.Count,
                Prop.forAll (Arb.fromGen (comparison.Inputs platform)) property
            )
        | Some directory ->
            let inputs =
                Gen.sample comparison.Count (comparison.Inputs platform) |> List.ofArray

            let answers = inputs |> List.map (comparison.Host platform)

            let date = DateTime.UtcNow.ToString "yyyy-MM-dd"

            let header =
                [
                    $"# %s{comparison.Name}: what a kernel answered, one input<TAB>answer row per input."
                    $"# Recorded by HostCorpus.live on %s{RuntimeInformation.OSDescription} %O{RuntimeInformation.OSArchitecture},"
                    $"# as %O{platform}, on %s{date}."
                ]

            let rows = List.map2 (line comparison) inputs answers
            Directory.CreateDirectory directory |> ignore<DirectoryInfo>
            File.WriteAllLines (Path.Combine (directory, fileName comparison.Name flavour), header @ rows)

            List.map2 (comparison.Disagreement platform) inputs answers
            |> List.choose id
            |> failOn comparison.Name inputs.Length

    /// Every input in a flavour's corpus, and the answer recorded for it.
    let private rows
        (comparison : HostComparison<'input, 'answer>)
        (flavour : SimulatedUnixFlavour)
        : ('input * 'answer) list
        =
        let resource =
            $"WoofWare.PosixKernel.Test.hostCorpus.%s{fileName comparison.Name flavour}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"embedded resource %s{resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.map (fun line -> line.TrimEnd '\r')
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))
        |> List.map (fun line ->
            match line.Split '\t' with
            | [| input ; answer |] -> comparison.ParseInput input, comparison.ParseAnswer answer
            | _ -> failwith $"%s{resource}: not input<TAB>answer: %s{line}"
        )

    /// Hold the model, as `platform`, to every answer its flavour's corpus
    /// recorded. Runs on any host.
    let replay (comparison : HostComparison<'input, 'answer>) (platform : SimulatedUnixPlatform) : unit =
        let recorded = rows comparison (SimulatedUnixPlatform.flavour platform)

        // A recording writes exactly `Count` rows; fewer means a truncated file.
        if recorded.Length <> comparison.Count then
            failwith
                $"%s{comparison.Name}: the %O{platform} corpus has %d{recorded.Length} rows, not the %d{comparison.Count} a recording writes"

        recorded
        |> List.choose (fun (input, answer) -> comparison.Disagreement platform input answer)
        |> failOn comparison.Name recorded.Length

    /// Every input `comparison` generates for `platform` is one corpus field,
    /// and reads back as itself, so that a recording replays the inputs it
    /// was made from.
    let inputsRoundTrip (comparison : HostComparison<'input, 'answer>) (platform : SimulatedUnixPlatform) : unit =
        let property (input : 'input) : unit =
            let written = comparison.WriteInput input

            match notAnInputField written with
            | Some why -> failwith $"%s{comparison.Name}: %A{input} was written as %s{written}, and %s{why}"
            | None -> ()

            if comparison.ParseInput written <> input then
                failwith $"%s{comparison.Name}: %A{input} reads back from %s{written} as something else"

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 500,
            Prop.forAll (Arb.fromGen (comparison.Inputs platform)) property
        )
