namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The machine's host name: what `UnixBootImage.withHostName` admits, and
/// what `gethostname(3)` makes of it at every capacity, held to every row of
/// `docs/probes/gethostname` and to a transcription of each flavour's C
/// library.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestGetHostName =

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    let private nameOf (bytes : byte[]) : UnixByteString =
        match UnixByteString.ofBytes (ImmutableArray.Create<byte> bytes) with
        | Ok name -> name
        | Error defect -> failwith $"test bug: %s{UnixByteString.describe defect}"

    /// `length` bytes of 'h', the name the probe sets.
    let private hs (length : int) : UnixByteString = nameOf (Array.create length (byte 'h'))

    let private imageOn (platform : SimulatedUnixPlatform) : UnixBootImage<int, string> = UnixSystem.initial platform

    let private boot (image : UnixBootImage<int, string>) : UnixSystem<int, string> =
        Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0) image

    let private bootNamed (platform : SimulatedUnixPlatform) (name : UnixByteString) : UnixSystem<int, string> =
        imageOn platform
        |> UnixBootImage.tryWithHostName name
        |> Configured.expectOk HostNameRefusal.describe
        |> boot

    let private ask
        (system : UnixSystem<int, string>)
        (destination : UserBuffer)
        (capacity : uint64)
        : Result<GetHostNameAnswer, GetHostNameRefusal>
        =
        UnixHostName.tryGetHostName (Callers.thread 0 system) destination capacity system

    /// The longest name each flavour holds: Linux's `__NEW_UTS_LEN` (measured,
    /// `sethostname` of 64 bytes succeeds and of 65 is EINVAL), and Darwin's
    /// `MAXHOSTNAMELEN` less its terminator (`sysconf(_SC_HOST_NAME_MAX)` is
    /// 255 there).
    let private maximum (platform : SimulatedUnixPlatform) : int =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> 64
        | SimulatedUnixFlavour.Darwin -> 255

    // ------------------------------------------------------------ the setter

    [<Test>]
    let ``a machine nobody names is localhost`` () : unit =
        for platform in platforms do
            let system = boot (imageOn platform)

            (Kernel.machine system).HostName
            |> UnixByteString.toBytes
            |> Seq.toArray
            |> shouldEqual "localhost"B

            UnixSystem.defaultHostName |> shouldEqual (nameOf "localhost"B)

    [<Test>]
    let ``withHostName admits exactly the names the flavour can hold, and the machine reports what it admitted``
        ()
        : unit
        =
        let property (platform : SimulatedUnixPlatform, length : int) : unit =
            let name = hs length
            let flavour = SimulatedUnixPlatform.flavour platform

            let admissible =
                length <= maximum platform
                && (length > 0 || flavour = SimulatedUnixFlavour.Linux)

            match UnixBootImage.tryWithHostName name (imageOn platform), admissible with
            | Ok image, true -> (Kernel.machine (boot image)).HostName |> shouldEqual name
            | Error refusal, false ->
                if length = 0 then
                    refusal |> shouldEqual HostNameRefusal.EmptyOnDarwin
                else
                    refusal |> shouldEqual (HostNameRefusal.TooLong (length, maximum platform))
            | Ok _, false -> failwith $"a name of %d{length} bytes was admitted on %O{platform}"
            | Error refusal, true -> failwith $"a name of %d{length} bytes was refused on %O{platform}: %A{refusal}"

        let lengths =
            Gen.oneof
                [
                    Gen.choose (0, 300)
                    Gen.elements [ 0 ; 1 ; 63 ; 64 ; 65 ; 254 ; 255 ; 256 ]
                ]

        Check.One (config, Prop.forAll (Arb.fromGen (Gen.zip (Gen.elements platforms) lengths)) property)

    [<Test>]
    let ``withHostName's boundaries are at each flavour's maximum`` () : unit =
        for platform in platforms do
            let max = maximum platform

            UnixBootImage.tryWithHostName (hs max) (imageOn platform)
            |> Result.map ignore
            |> shouldEqual (Ok ())

            UnixBootImage.tryWithHostName (hs (max + 1)) (imageOn platform)
            |> Result.map ignore
            |> shouldEqual (Error (HostNameRefusal.TooLong (max + 1, max)))

    [<Test>]
    let ``withHostName raises an empty Darwin name as unmodelled and an overlong name as an argument error`` () : unit =
        let darwin = imageOn SimulatedUnixPlatform.macOsArm64
        let linux = imageOn SimulatedUnixPlatform.linuxX64

        Assert.Throws<UnmodelledException> (fun () -> UnixBootImage.withHostName (hs 0) darwin |> ignore)
        |> ignore

        let e =
            Assert.Throws<ArgumentException> (fun () -> UnixBootImage.withHostName (hs 65) linux |> ignore)

        e.ParamName |> shouldEqual "name"
        e.Message |> shouldContainText "UnixBootImage.withHostName"

    // ------------------------------------------------- the recorded probe

    /// One row of a recording: the capacity, the destination's kind, and what
    /// was measured.
    type private Row =
        {
            Line : string
            Capacity : uint64
            Destination : string
            Outcome : Outcome
        }

    and [<RequireQualifiedAccess>] private Outcome =
        /// The call returned. `Placed` is `None` for an unwritable destination,
        /// which the probe cannot read back.
        | Returned of ret : int * errno : string * placed : Placed option
        /// The child making the call died of this signal.
        | Signalled of signal : string
        /// The call returned, but stored before the start of the buffer.
        | StoredBefore

    /// What a mapped destination held afterwards: how many leading bytes
    /// changed, where the first NUL among them was, and whether the bytes
    /// before it were a prefix of the name.
    and private Placed =
        {
            Changed : int
            Nul : int option
            Prefix : bool
        }

    /// A recording's sections: the length of the name each measured (with
    /// `None` for a name `sethostname` refused, and that refusal's errno), and
    /// its rows.
    type private Section =
        {
            Length : int
            SetErrno : string option
            Rows : Row list
        }

    let private resource (flavour : SimulatedUnixFlavour) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.gethostname.linux.txt"
        | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.gethostname.darwin.txt"

    let private parseRow (line : string) : Row =
        let m = Regex.Match (line, @"^cap=(\d+) dest=(\S+): (.*)$")

        if not m.Success then
            failwith $"unrecognised row: %s{line}"

        let rest = m.Groups.[3].Value

        let outcome =
            let signalled = Regex.Match (rest, @"^signal=(\S+)$")

            if signalled.Success then
                Outcome.Signalled signalled.Groups.[1].Value
            else

            let returned =
                Regex.Match (
                    rest,
                    @"^ret=(-?\d+) errno=(\S+)(?: changed=(\d+) nul=(\d+|none) prefix=([yn]))?(?: before=(\d+))?$"
                )

            if not returned.Success then
                failwith $"unrecognised outcome: %s{line}"

            if returned.Groups.[6].Success then
                Outcome.StoredBefore
            else

            let placed =
                if returned.Groups.[3].Success then
                    Some
                        {
                            Changed = int returned.Groups.[3].Value
                            Nul =
                                match returned.Groups.[4].Value with
                                | "none" -> None
                                | index -> Some (int index)
                            Prefix = returned.Groups.[5].Value = "y"
                        }
                else
                    None

            Outcome.Returned (int returned.Groups.[1].Value, returned.Groups.[2].Value, placed)

        {
            Line = line
            Capacity = uint64 m.Groups.[1].Value
            Destination = m.Groups.[2].Value
            Outcome = outcome
        }

    let private sections (flavour : SimulatedUnixFlavour) : Section list =
        let name = resource flavour

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)
        let lines = reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)

        // A recording with no `## sethostname` line measured the machine's own
        // name, whose length its `# name length` line gives.
        let mutable result : Section list = []
        let mutable current : Section option = None

        let flush () =
            match current with
            | Some section ->
                result <-
                    { section with
                        Rows = List.rev section.Rows
                    }
                    :: result
            | None -> ()

        for line in lines do
            let set = Regex.Match (line, @"^## sethostname len=(\d+): ret=(-?\d+) errno=(\S+)$")
            let measured = Regex.Match (line, @"^# name length (\d+);")

            if set.Success then
                flush ()

                current <-
                    Some
                        {
                            Length = int set.Groups.[1].Value
                            SetErrno =
                                if set.Groups.[2].Value = "0" then
                                    None
                                else
                                    Some set.Groups.[3].Value
                            Rows = []
                        }
            elif measured.Success then
                match current with
                | Some section -> section.Length |> shouldEqual (int measured.Groups.[1].Value)
                | None ->
                    current <-
                        Some
                            {
                                Length = int measured.Groups.[1].Value
                                SetErrno = None
                                Rows = []
                            }
            elif line.StartsWith ("cap=", StringComparison.Ordinal) then
                match current with
                | Some section ->
                    current <-
                        Some
                            { section with
                                Rows = parseRow line :: section.Rows
                            }
                | None -> failwith $"%s{name}: a row before any section: %s{line}"
            elif line.StartsWith ("#", StringComparison.Ordinal) then
                ()
            else
                failwith $"%s{name}: unrecognised line: %s{line}"

        flush ()
        List.rev result

    let private destinationOf (kind : string) : UserBuffer =
        match kind with
        | "mapped" -> UserBuffer.Mapped
        | "null" -> UserBuffer.Unmapped 0UL
        // A page the probe mapped `PROT_NONE` or `PROT_READ`: storage this
        // caller cannot write, at an address other than zero.
        | "prot_none"
        | "read_only" -> UserBuffer.Unmapped 0x1000_0000UL
        | other -> failwith $"unrecognised destination %s{other}"

    let private errnoName (answer : GetHostNameAnswer) : int * string =
        match answer with
        | GetHostNameAnswer.Returned _ -> 0, "0"
        | GetHostNameAnswer.Failed (_, error) -> -1, error.ToString ()

    let private placedOf (answer : GetHostNameAnswer) : ImmutableArray<byte> =
        match answer with
        | GetHostNameAnswer.Returned placed -> placed
        | GetHostNameAnswer.Failed (placed, _) -> placed

    /// What the probe would have printed of a mapped buffer holding `placed`.
    let private summarise (name : UnixByteString) (placed : ImmutableArray<byte>) : Placed =
        let nul =
            match placed.IndexOf 0uy with
            | -1 -> None
            | index -> Some index

        let compared = defaultArg nul placed.Length
        let nameBytes = UnixByteString.toBytes name

        {
            Changed = placed.Length
            Nul = nul
            Prefix =
                compared <= nameBytes.Length
                && Seq.forall (fun i -> placed.[i] = nameBytes.[i]) (seq { 0 .. compared - 1 })
        }

    /// Every way the model disagrees with the row, as text.
    let private disagreement
        (name : UnixByteString)
        (row : Row)
        (answer : Result<GetHostNameAnswer, GetHostNameRefusal>)
        : string option
        =
        match row.Outcome, answer with
        | Outcome.Returned (ret, errno, placed), Ok answer ->
            let modelRet, modelErrno = errnoName answer
            let modelPlaced = placedOf answer

            if (modelRet, modelErrno) <> (ret, errno) then
                Some $"model returned %d{modelRet} errno %s{modelErrno}"
            else

            match placed with
            | Some placed ->
                let modelSummary = summarise name modelPlaced

                if modelSummary <> placed then
                    Some $"model placed %A{modelSummary}"
                else
                    None
            | None ->
                // No unwritable destination takes a byte.
                if modelPlaced.IsEmpty then
                    None
                else
                    Some $"model placed %d{modelPlaced.Length} bytes in an unwritable destination"
        | Outcome.Returned _, Error refusal -> Some $"model refused: %s{GetHostNameRefusal.describe refusal}"
        | Outcome.Signalled _, Error GetHostNameRefusal.FatalToTheProcess -> None
        | Outcome.Signalled _, Error GetHostNameRefusal.StoresBeforeTheBuffer when row.Capacity = 0UL -> None
        | Outcome.StoredBefore, Error GetHostNameRefusal.StoresBeforeTheBuffer -> None
        | (Outcome.Signalled _ | Outcome.StoredBefore), other -> Some $"model answered %A{other}"

    [<TestCase "Linux">]
    [<TestCase "Darwin">]
    let ``the model reproduces every row of the recording`` (flavourName : string) : unit =
        let flavour, platform =
            match flavourName with
            | "Linux" -> SimulatedUnixFlavour.Linux, SimulatedUnixPlatform.linuxArm64
            | "Darwin" -> SimulatedUnixFlavour.Darwin, SimulatedUnixPlatform.macOsArm64
            | other -> failwith $"test bug: no flavour %s{other}"

        let sections = sections flavour
        sections |> shouldNotEqual []

        let failures =
            [
                for section in sections do
                    let name = hs section.Length

                    match section.SetErrno with
                    | Some errno ->
                        // `sethostname` refused it, so no machine of the flavour
                        // holds it.
                        errno |> shouldEqual "EINVAL"

                        match UnixBootImage.tryWithHostName name (imageOn platform) with
                        | Error (HostNameRefusal.TooLong _) -> ()
                        | other ->
                            yield $"name of %d{section.Length} bytes: setter answered %A{Result.map ignore other}"
                    | None ->
                        section.Rows |> shouldNotEqual []
                        let system = bootNamed platform name

                        for row in section.Rows do
                            match disagreement name row (ask system (destinationOf row.Destination) row.Capacity) with
                            | Some why -> yield $"name of %d{section.Length} bytes: %s{row.Line}: %s{why}"
                            | None -> ()
            ]

        failures |> shouldEqual []

    // ------------------------------------------------- against each C library

    /// What `gethostname` leaves in a buffer of `capacity` bytes, transcribed
    /// from each C library onto an array standing for the buffer: glibc's
    /// `sysdeps/posix/gethostname.c` copies the name and its terminator,
    /// truncated to the buffer, and fails if it truncated; Darwin's Libc
    /// `strncpy`s a copy of `kern.hostname` and terminates the buffer below
    /// `MAXHOSTNAMELEN + 1`, and from there lets `sysctl` copy the name and
    /// terminator out. `None` for a capacity of zero on Darwin, which stores at
    /// index -1.
    let private transcription
        (flavour : SimulatedUnixFlavour)
        (name : byte[])
        (capacity : int)
        : (int * byte[]) option
        =
        let buffer = Array.create (capacity + 1024) 0xAAuy
        let terminated = Array.append name [| 0uy |]

        let ret =
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                let copied = min capacity terminated.Length
                Array.blit terminated 0 buffer 0 copied
                if terminated.Length > capacity then Some -1 else Some 0
            | SimulatedUnixFlavour.Darwin ->
                if capacity = 0 then
                    None
                elif capacity < 257 then
                    // strncpy: the source up to its NUL, then NULs to `capacity`.
                    for i in 0 .. capacity - 1 do
                        buffer.[i] <- if i < name.Length then name.[i] else 0uy

                    buffer.[capacity - 1] <- 0uy
                    Some 0
                else
                    Array.blit terminated 0 buffer 0 terminated.Length
                    Some 0

        ret
        |> Option.map (fun ret ->
            let changed =
                match Array.tryFindIndexBack (fun b -> b <> 0xAAuy) buffer with
                | Some last -> last + 1
                | None -> 0

            ret, Array.sub buffer 0 changed
        )

    [<Test>]
    let ``the model places what each C library's code places, at every capacity`` () : unit =
        let property (platform : SimulatedUnixPlatform, length : int, capacity : int) : unit =
            let flavour = SimulatedUnixPlatform.flavour platform

            let length =
                if flavour = SimulatedUnixFlavour.Darwin then
                    max 1 length
                else
                    length

            let length = min length (maximum platform)
            // Any byte but NUL and the sentinel, so the transcription's
            // reading-back is exact.
            let name = Array.init length (fun i -> byte (1 + (i * 7) % 0xA9))
            let system = bootNamed platform (nameOf name)

            match transcription flavour name capacity, ask system UserBuffer.Mapped (uint64 capacity) with
            | None, Error GetHostNameRefusal.StoresBeforeTheBuffer -> ()
            | Some (ret, placed), Ok answer ->
                fst (errnoName answer) |> shouldEqual ret
                Seq.toArray (placedOf answer) |> shouldEqual placed

                match answer with
                | GetHostNameAnswer.Failed (_, error) -> error |> shouldEqual UnixError.ENAMETOOLONG
                | GetHostNameAnswer.Returned _ -> ()
            | expected, actual ->
                failwith
                    $"%O{platform}, name of %d{length}, capacity %d{capacity}: expected %A{expected}, got %A{actual}"

        let capacities =
            Gen.oneof
                [
                    Gen.choose (0, 300)
                    Gen.elements [ 0 ; 1 ; 2 ; 64 ; 65 ; 255 ; 256 ; 257 ; 258 ; 4096 ]
                ]

        Check.One (
            config,
            Prop.forAll (Arb.fromGen (Gen.zip3 (Gen.elements platforms) (Gen.choose (0, 300)) capacities)) property
        )

    /// A destination whose bytes the client cannot produce is refused at the
    /// point bytes would be placed in it, and only there: a Linux capacity of
    /// zero places nothing, so it is answered whatever the destination.
    [<Test>]
    let ``an opaque or addressless destination is refused only where bytes would be placed`` () : unit =
        for platform in platforms do
            let system = boot (imageOn platform)

            for destination in [ UserBuffer.Opaque ; UserBuffer.Addressless ] do
                for capacity in [ 0UL ; 1UL ; 5UL ; 256UL ; 257UL ; 4096UL ] do
                    let case = $"%O{platform}, %A{destination}, capacity %d{capacity}"

                    match SimulatedUnixPlatform.flavour platform, capacity, ask system destination capacity with
                    | SimulatedUnixFlavour.Linux, 0UL, Ok (GetHostNameAnswer.Failed (placed, UnixError.ENAMETOOLONG)) when
                        placed.IsEmpty
                        ->
                        ()
                    | SimulatedUnixFlavour.Darwin, 0UL, Error GetHostNameRefusal.StoresBeforeTheBuffer -> ()
                    | _, capacity, Error (GetHostNameRefusal.Buffer _) when capacity > 0UL -> ()
                    | _, _, other -> failwith $"%s{case}: %A{other}"

    [<Test>]
    let ``UnixSystem.step answers a GetHostName label with what getHostName answers`` () : unit =
        let flatten (answer : GetHostNameAnswer) : int * byte[] =
            fst (errnoName answer), Seq.toArray (placedOf answer)

        for platform in platforms do
            let system = boot (imageOn platform)
            let caller = Callers.thread 0 system

            for capacity in [ 1UL ; 9UL ; 10UL ; 300UL ] do
                match UnixSystem.step caller (Syscall.GetHostName (UserBuffer.Mapped, capacity)) system with
                | SteppedCall.GetHostName answer ->
                    flatten answer
                    |> shouldEqual (flatten (UnixHostName.getHostName caller UserBuffer.Mapped capacity system))
                | other -> failwith $"%O{platform}: step answered %A{other}"
