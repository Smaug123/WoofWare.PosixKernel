namespace WoofWare.PosixKernel.Test

open System
open System.Runtime.InteropServices
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `Signal.isUnblockableUnder`'s column for the flavour this test process runs
/// on, measured against the machine itself: for every signo the kernel has,
/// add it to the calling thread's mask with `pthread_sigmask(3)`, read the
/// mask back, and compare membership with the model. `TestSignal` restates
/// both columns as literals; this is what keeps the restatement honest, the
/// way `TestSignalAgainstHost` does for the signo table.
///
/// Safe to run in the test host, unlike a `sigaction` sweep (see
/// `TestSignalAgainstHost`'s header for why that one is probe-pinned
/// instead): a mask is per-thread, so nothing outside this test's own thread
/// is touched; the original mask is restored after every signo; and the
/// signals whose membership we assert *absent* never enter the mask at all —
/// that is the fact under test.
///
/// The single-signal set is built by setting the signo's bit directly rather
/// than through `sigaddset(3)`, so that libc's `sigaddset`-level screening
/// cannot hide what the mask call itself does with the bit. The bit layout —
/// bit `signo - 1`, little-endian — is glibc's `unsigned long` array and
/// Darwin's `uint32_t` alike, on every architecture .NET supports.
[<TestFixture>]
[<NonParallelizable>]
// Blocks every signal in turn on its worker thread, Linux's SIGRTMIN among
// them, which the runtime sends a thread to suspend it for a collection: a
// collection that a test beside it starts would have to wait for the mask.
module TestSignalMaskAgainstHost =

    [<DllImport("libc", SetLastError = true)>]
    extern int private pthread_sigmask(int how, byte[] set, byte[] oldSet)

    /// A comfortable margin over both platforms' `sigset_t`: glibc's is 128
    /// bytes and Darwin's is 4, and the callee reads only its own size.
    [<Literal>]
    let private sigsetBytes : int = 256

    let private setBit (buffer : byte[]) (signo : int) : unit =
        buffer.[(signo - 1) / 8] <- buffer.[(signo - 1) / 8] ||| (1uy <<< ((signo - 1) % 8))

    let private getBit (buffer : byte[]) (signo : int) : bool =
        (buffer.[(signo - 1) / 8] >>> ((signo - 1) % 8)) &&& 1uy = 1uy

    /// Whether this host, whose signals `numbering` numbers, lets the calling
    /// thread block `signo`: block it, read the mask back, restore the
    /// original mask.
    let private hostCanBlock (numbering : SignalNumbering) (signo : int) : bool =
        let sigBlock = MaskHow.block numbering
        let one : byte[] = Array.zeroCreate sigsetBytes
        setBit one signo
        let original : byte[] = Array.zeroCreate sigsetBytes

        let rc = pthread_sigmask (sigBlock, one, original)

        if rc <> 0 then
            failwith $"pthread_sigmask(SIG_BLOCK, {{%d{signo}}}) failed with %d{rc}, which the model has no row for"

        try
            let current : byte[] = Array.zeroCreate sigsetBytes
            let rc = pthread_sigmask (sigBlock, null, current)

            if rc <> 0 then
                failwith $"pthread_sigmask read-back for signo %d{signo} failed with %d{rc}"

            getBit current signo
        finally
            pthread_sigmask (MaskHow.setMask numbering, original, null) |> ignore<int>

    [<Test>]
    let ``isUnblockableUnder agrees with this host's pthread_sigmask about every signo`` () : unit =
        HostPlatform.onUnixHost (fun flavour ->
            let numbering = HostPlatform.signalNumberingOf flavour

            let disagreements =
                [ 1 .. Signal.highestSignoUnder numbering ]
                |> List.choose (fun signo ->
                    let signal =
                        match Signal.ofRawSignoUnder numbering signo with
                        | ValueSome signal -> signal
                        | ValueNone ->
                            failwith
                                $"%O{numbering}: signo %d{signo} is within the model's range but ofRawSignoUnder refused it"

                    let modelled = not (Signal.isUnblockableUnder numbering signal)
                    let measured = hostCanBlock numbering signo

                    if modelled = measured then
                        None
                    else
                        Some
                            $"signo %d{signo} (%O{signal}): model says blockable=%b{modelled}, host says %b{measured}"
                )

            if not (List.isEmpty disagreements) then
                let report = String.concat "; " disagreements

                failwith $"%O{numbering}: isUnblockableUnder disagrees with this host's pthread_sigmask: %s{report}"
        )

    let private wordOfBuffer (buffer : byte[]) : uint64 = BitConverter.ToUInt64 (buffer, 0)

    let private bufferOfWord (word : uint64) : byte[] =
        let buffer : byte[] = Array.zeroCreate sigsetBytes
        BitConverter.GetBytes(word).CopyTo (buffer, 0)
        buffer

    /// One `pthread_sigmask` call: its raw `how`, and the set's word, if it
    /// passes one.
    type private MaskCall =
        {
            How : int
            Set : uint64 option
        }

    /// What the kernel answered to one call: its return code, the old mask it
    /// wrote, and the thread's mask after it.
    type private MaskAnswer =
        {
            Code : int
            Old : uint64
            After : uint64
        }

    let private writeCall (call : MaskCall) : string =
        match call.Set with
        | None -> $"%d{call.How}:-"
        | Some word -> $"%d{call.How}:%x{word}"

    let private parseCall (text : string) : MaskCall =
        match text.Split ':' with
        | [| how ; "-" |] ->
            {
                How = int how
                Set = None
            }
        | [| how ; word |] ->
            {
                How = int how
                Set = Some (Convert.ToUInt64 (word, 16))
            }
        | _ -> failwith $"not a pthread_sigmask call: %s{text}"

    let private writeAnswer (answer : MaskAnswer) : string =
        $"%d{answer.Code}:%x{answer.Old}:%x{answer.After}"

    let private parseAnswer (text : string) : MaskAnswer =
        match text.Split ':' with
        | [| code ; old ; after |] ->
            {
                Code = int code
                Old = Convert.ToUInt64 (old, 16)
                After = Convert.ToUInt64 (after, 16)
            }
        | _ -> failwith $"not a pthread_sigmask answer: %s{text}"

    let private spaced (write : 'a -> string) (items : 'a list) : string =
        items |> List.map write |> String.concat " "

    let private unspaced (parse : string -> 'a) (text : string) : 'a list =
        text.Split ' ' |> Array.toList |> List.map parse

    /// Sequences of ten calls on a thread whose mask starts empty, each made on
    /// the host and on the model, compared answer by answer and mask by mask.
    /// A Mac's answers are recorded in `hostCorpus/pthreadSigmask.darwin.txt`,
    /// which every host replays, so CI, which runs on Linux, holds the Darwin
    /// column too.
    /// The sets name only signals the test host can leave blocked for a moment,
    /// SIGKILL's and SIGSTOP's bits, and the bits one flavour treats specially:
    /// Linux's 32 and 33, which glibc screens, and Darwin's bit 31, which names
    /// no signal and is kept. `how` is one of the three the flavour numbers, or
    /// 100, which neither does.
    let private callSequences : HostComparison<MaskCall list, MaskAnswer list> =
        {
            Name = "pthreadSigmask"
            Inputs =
                fun platform ->
                    let numbering = SimulatedUnixPlatform.signalNumbering platform

                    let bitOf (signal : Signal) : int =
                        Signal.toRawSignoUnder numbering signal - 1

                    let bits =
                        [
                            Signal.SIGHUP
                            Signal.SIGINT
                            Signal.SIGUSR2
                            Signal.SIGTERM
                            Signal.SIGALRM
                            Signal.SIGKILL
                            Signal.SIGSTOP
                        ]
                        |> List.map bitOf
                        |> List.append (
                            match SimulatedUnixPlatform.flavour platform with
                            | SimulatedUnixFlavour.Linux -> [ 31 ; 32 ]
                            | SimulatedUnixFlavour.Darwin -> [ 31 ]
                        )

                    let setGen : Gen<uint64> =
                        bits
                        |> List.map (fun bit -> Gen.elements [ 0UL ; 1UL <<< bit ])
                        |> Gen.sequenceToList
                        |> Gen.map (List.fold (|||) 0UL)

                    let callGen : Gen<MaskCall> =
                        Gen.map2
                            (fun how set ->
                                {
                                    How = how
                                    Set = set
                                }
                            )
                            (Gen.elements
                                [
                                    MaskHow.block numbering
                                    MaskHow.unblock numbering
                                    MaskHow.setMask numbering
                                    100
                                ])
                            (Gen.frequency [ 1, Gen.constant None ; 5, Gen.map Some setGen ])

                    Gen.listOfLength 10 callGen
            Count = 200
            WriteInput = spaced writeCall
            ParseInput = unspaced parseCall
            WriteAnswer = spaced writeAnswer
            ParseAnswer = unspaced parseAnswer
            Host =
                fun platform calls ->
                    let numbering = SimulatedUnixPlatform.signalNumbering platform
                    let original : byte[] = Array.zeroCreate sigsetBytes

                    if pthread_sigmask (MaskHow.block numbering, null, original) <> 0 then
                        failwith "could not read this thread's mask"

                    try
                        if pthread_sigmask (MaskHow.setMask numbering, bufferOfWord 0UL, null) <> 0 then
                            failwith "could not clear this thread's mask"

                        calls
                        |> List.map (fun call ->
                            let old : byte[] = Array.zeroCreate sigsetBytes

                            let code =
                                pthread_sigmask (call.How, (call.Set |> Option.map bufferOfWord |> Option.toObj), old)

                            let now : byte[] = Array.zeroCreate sigsetBytes
                            pthread_sigmask (MaskHow.block numbering, null, now) |> ignore<int>

                            {
                                Code = code
                                Old = wordOfBuffer old
                                After = wordOfBuffer now
                            }
                        )
                    finally
                        pthread_sigmask (MaskHow.setMask numbering, original, null) |> ignore<int>
            Disagreement =
                fun platform calls answers ->
                    let numbering = SimulatedUnixPlatform.signalNumbering platform

                    let system : UnixSystem<int, unit> =
                        UnixSystem.initial platform
                        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

                    let rec go (system : UnixSystem<int, unit>) (pairs : (MaskCall * MaskAnswer) list) : string option =
                        match pairs with
                        | [] -> None
                        | (call, answer) :: rest ->

                        let modelSet =
                            call.Set
                            |> Option.map (fun word ->
                                match SignalMask.ofWord numbering word with
                                | Ok mask -> mask
                                | Error refusal -> failwith (SignalMaskRefusal.describe refusal)
                            )

                        let disagreement, system =
                            match UnixSignal.pthreadSigmask (Callers.thread 0 system) call.How modelSet system with
                            | SignalMaskAnswer.Completed modelOld, after ->
                                let modelOld = SignalMask.toWord modelOld

                                if answer.Code <> 0 || answer.Old <> modelOld then
                                    Some
                                        $"%s{writeCall call}: the model answered 0 with old mask %x{modelOld}, the kernel %d{answer.Code} with %x{answer.Old}",
                                    after
                                else
                                    None, after
                            | SignalMaskAnswer.Failed errno, after ->
                                after |> shouldEqual system

                                let expected =
                                    UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) errno

                                if answer.Code <> expected then
                                    Some
                                        $"%s{writeCall call}: the model answered %d{expected}, the kernel %d{answer.Code}",
                                    system
                                else
                                    None, system

                        let modelAfter =
                            SignalState.maskOf 0 (UnixSystem.signals (Lone.pid system) system)
                            |> SignalMask.toWord

                        match disagreement with
                        | Some _ -> disagreement
                        | None when modelAfter <> answer.After ->
                            Some
                                $"%s{writeCall call}: the model's mask is then %x{modelAfter}, the kernel's %x{answer.After}"
                        | None -> go system rest

                    if answers.Length <> calls.Length then
                        Some $"%d{calls.Length} calls, but %d{answers.Length} answers"
                    else
                        go system (List.zip calls answers)
                    |> Option.map (fun disagreement -> $"in [%s{spaced writeCall calls}], %s{disagreement}")
        }

    [<Test>]
    let ``UnixSignal.pthreadSigmask answers as this host's pthread_sigmask, call for call`` () : unit =
        HostPlatform.onUnixHost (fun flavour -> HostCorpus.live callSequences (HostPlatform.platformOf flavour))

    [<Test>]
    let ``UnixSignal.pthreadSigmask answers as Darwin's pthread_sigmask did, call for call`` () : unit =
        HostCorpus.replay callSequences SimulatedUnixPlatform.macOsArm64

    [<Test>]
    let ``every pthread_sigmask sequence reads back as itself`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            HostCorpus.inputsRoundTrip callSequences platform
