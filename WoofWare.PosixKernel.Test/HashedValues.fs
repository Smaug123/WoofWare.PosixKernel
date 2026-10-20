namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The values whose hashes `TestHashAcrossProcesses` compares between the test
/// host and a child process. The child runs this very file, embedded in the
/// test assembly, under `dotnet fsi`, so the two hash the same values.
[<RequireQualifiedAccess>]
module HashedValues =

    let private created : SimulatedUnixPlatform =
        SimulatedUnixPlatform.createOrFail
            "HashedValues"
            (SimulatedUnixKernel.Linux (
                {
                    Major = 6u
                    Minor = 18u
                    Patch = 5u
                },
                LinuxKernelBuild.SmallBuffer832
            ))
            SimulatedUnixArchitecture.Arm64
            SimulatedPageSize.FourKiB
            "6.18.5-custom"

    let private booted (platform : SimulatedUnixPlatform) : UnixSystem<int, unit> =
        let launch =
            ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

        UnixSystem.initial platform |> UnixBootImage.boot launch

    /// Each platform's hash, and the hash of a system booted on it, named.
    let hashes () : (string * int) list =
        [
            "linuxX64", SimulatedUnixPlatform.linuxX64
            "linuxArm64", SimulatedUnixPlatform.linuxArm64
            "macOsArm64", SimulatedUnixPlatform.macOsArm64
            "created", created
        ]
        |> List.collect (fun (name, platform) ->
            [
                $"%s{name} platform", hash platform
                $"%s{name} system", hash (booted platform)
            ]
        )
