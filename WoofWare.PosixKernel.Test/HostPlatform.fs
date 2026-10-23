namespace WoofWare.PosixKernel.Test

open System
open System.Runtime.InteropServices
open System.Text
open System.Text.RegularExpressions
open NUnit.Framework
open WoofWare.PosixKernel

/// Reading a Linux kernel's version out of the release string `uname -r`
/// prints.
[<RequireQualifiedAccess>]
module LinuxRelease =

    /// The version a release such as `6.17.0-1022-azure` or `6.18.5` begins with,
    /// or `None` for one that does not begin `major.minor`. A missing patch
    /// level is 0, as the kernel's own Makefile prints a `SUBLEVEL` of 0.
    let version (release : string) : LinuxKernelVersion option =
        let m = Regex.Match (release, @"^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?")

        if not m.Success then
            None
        else
            let part (i : int) : uint32 =
                if m.Groups.[i].Success then
                    UInt32.Parse m.Groups.[i].Value
                else
                    0u

            Some
                {
                    Major = part 1
                    Minor = part 2
                    Patch = part 3
                }

/// Reading a Darwin kernel's version out of the release string `uname -r`
/// prints.
[<RequireQualifiedAccess>]
module DarwinRelease =

    /// The version a release such as `27.0.0` is, or `None` for one that is not
    /// exactly `major.minor.revision`: Darwin's `uname -r` is its
    /// `config/MasterVersion` and nothing else.
    let version (release : string) : DarwinKernelVersion option =
        let m = Regex.Match (release, @"^([0-9]+)\.([0-9]+)\.([0-9]+)$")

        if not m.Success then
            None
        else
            Some
                {
                    VersionMajor = UInt32.Parse m.Groups.[1].Value
                    VersionMinor = UInt32.Parse m.Groups.[2].Value
                    VersionRevision = UInt32.Parse m.Groups.[3].Value
                }

/// The kernel *this test process* is running on, in the vocabulary the emulated
/// kernel uses for the kernel it impersonates.
///
/// Tests reach for this in two quite different situations, and it is worth keeping
/// them apart. Some measure the host's own libc, or .NET's `System.Native`
/// library, to check a modelled fact against the thing being modelled, and must
/// skip where there is nothing to measure. Others decide whether a comparison
/// against this host is *meaningful* for a model that describes one particular
/// kernel.
[<RequireQualifiedAccess>]
module HostPlatform =

    /// `None` on a host whose flavour the library does not model at all —
    /// Windows, or any Unix that is neither Linux nor Darwin.
    let flavour () : SimulatedUnixFlavour option =
        if RuntimeInformation.IsOSPlatform OSPlatform.OSX then
            Some SimulatedUnixFlavour.Darwin
        elif RuntimeInformation.IsOSPlatform OSPlatform.Linux then
            Some SimulatedUnixFlavour.Linux
        else
            None

    /// The preset for a flavour. Only the flavour is consumed from it, so the
    /// architecture each preset is named for need not match this host.
    let platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform =
        match flavour with
        | SimulatedUnixFlavour.Darwin -> SimulatedUnixPlatform.macOsArm64
        | SimulatedUnixFlavour.Linux -> SimulatedUnixPlatform.linuxX64

    /// The signal numbering of a flavour, as the library gives it for the
    /// flavour's preset.
    let signalNumberingOf (flavour : SimulatedUnixFlavour) : SignalNumbering =
        SimulatedUnixPlatform.signalNumbering (platformOf flavour)

    /// Run `action` against this host's flavour, or skip the test where the
    /// library models no such host. For tests that *measure* the host; a test
    /// that merely wants to know whether a comparison is valid should branch on
    /// `flavour ()` rather than skipping, so that it still asserts something
    /// everywhere.
    let onUnixHost (action : SimulatedUnixFlavour -> unit) : unit =
        match flavour () with
        | None -> Assert.Ignore $"no Unix host to measure (%s{RuntimeInformation.OSDescription})"
        | Some flavour -> action flavour

    /// This host process's architecture, or `None` for one the library does not
    /// model.
    let architecture () : SimulatedUnixArchitecture option =
        match RuntimeInformation.ProcessArchitecture with
        | Architecture.X64 -> Some SimulatedUnixArchitecture.X64
        | Architecture.Arm64 -> Some SimulatedUnixArchitecture.Arm64
        | _ -> None

    /// The preset built for this flavour and architecture, or `None` where the
    /// library has none.
    let presetFor
        (flavour : SimulatedUnixFlavour)
        (architecture : SimulatedUnixArchitecture)
        : SimulatedUnixPlatform option
        =
        match flavour, architecture with
        | SimulatedUnixFlavour.Linux, SimulatedUnixArchitecture.X64 -> Some SimulatedUnixPlatform.linuxX64
        | SimulatedUnixFlavour.Linux, SimulatedUnixArchitecture.Arm64 -> Some SimulatedUnixPlatform.linuxArm64
        | SimulatedUnixFlavour.Darwin, SimulatedUnixArchitecture.Arm64 -> Some SimulatedUnixPlatform.macOsArm64
        | SimulatedUnixFlavour.Darwin, SimulatedUnixArchitecture.X64 -> None

    /// Run `action` against the preset for this host's flavour and architecture,
    /// for tests that measure a fact the architecture decides. Skips where the
    /// library models no such host; whether the host's *page size* is the
    /// preset's is `TestArchitectureAgainstHost`'s question, not a reason to skip.
    let onUnixHostPreset (action : SimulatedUnixPlatform -> unit) : unit =
        onUnixHost (fun flavour ->
            match architecture () with
            | None -> Assert.Ignore $"no architecture the library models (%O{RuntimeInformation.ProcessArchitecture})"
            | Some architecture ->

            match presetFor flavour architecture with
            | None -> Assert.Ignore $"the library has no %O{flavour} %O{architecture} platform to compare against"
            | Some platform -> action platform
        )

    /// This host's `uname -r`. The release is the third field of `struct
    /// utsname`, whose fields are 65 bytes on Linux (six of them) and 256 on
    /// Darwin (five).
    let private release (flavour : SimulatedUnixFlavour) : string =
        let fieldLength, fieldCount =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 65, 6
            | SimulatedUnixFlavour.Darwin -> 256, 5

        let buffer = Array.zeroCreate<byte> (fieldCount * fieldLength)

        if HostCalls.uname buffer <> 0 then
            failwith $"uname failed with errno %d{Marshal.GetLastPInvokeError ()}"

        let field = ReadOnlySpan<byte> (buffer, 2 * fieldLength, fieldLength)
        let length = field.IndexOf 0uy

        if length < 0 then
            failwith "uname's release field is not NUL-terminated"

        Encoding.ASCII.GetString (field.Slice (0, length))

    /// How this Linux host's kernel was built, read as
    /// `docs/plans/2026-10-18-udp-data-path/udp-truesize.c` reads it: what an
    /// empty datagram over loopback charges its receiver, through
    /// `SO_MEMINFO`.
    let private linuxBuild () : LinuxKernelBuild =
        let check (what : string) (result : int) : unit =
            if result < 0 then
                failwith $"%s{what} failed with errno %d{Marshal.GetLastPInvokeError ()}"

        // AF_INET is 2, and SOCK_DGRAM 2, on Linux.
        let receiver = HostCalls.socket (2, 2, 0)
        let sender = HostCalls.socket (2, 2, 0)

        try
            check "socket" receiver
            check "socket" sender
            // sockaddr_in for 127.0.0.1, port 0: family 2, then the port and
            // the address in network order.
            let loopback =
                [|
                    2uy
                    0uy
                    0uy
                    0uy
                    127uy
                    0uy
                    0uy
                    1uy
                    0uy
                    0uy
                    0uy
                    0uy
                    0uy
                    0uy
                    0uy
                    0uy
                |]

            check "bind" (HostCalls.bind (receiver, loopback, 16u))
            let name = Array.zeroCreate<byte> 16
            let mutable length = 16u
            check "getsockname" (HostCalls.getSockName (receiver, name, &length))
            check "connect" (HostCalls.connect (sender, name, 16u))
            check "write" (int (HostCalls.write (sender, [||], 0un)))

            // SOL_SOCKET is 1 and SO_MEMINFO 55; the first of its words is
            // the receive buffer's charge. Loopback delivers before the write
            // returns, but a softirq can run it later under load.
            let charge () : uint32 =
                let memory = Array.zeroCreate<byte> 36
                let mutable length = 36u
                check "SO_MEMINFO" (HostCalls.getSockOptBytes (receiver, 1, 55, memory, &length))
                BitConverter.ToUInt32 (memory, 0)

            let deadline = DateTime.UtcNow.AddSeconds 5.0

            let rec settled () : uint32 =
                match charge () with
                | 0u when DateTime.UtcNow < deadline ->
                    Threading.Thread.Sleep 1
                    settled ()
                | charged -> charged

            match settled () with
            | 832u -> LinuxKernelBuild.SmallBuffer832
            | 960u -> LinuxKernelBuild.SmallBuffer960
            | charged ->
                failwith
                    $"this host charges %d{charged} for an empty datagram, which no measured Linux build does (LinuxKernelBuild)"
        finally
            HostCalls.close receiver |> ignore<int>
            HostCalls.close sender |> ignore<int>

    /// `preset`, which must be of this host's flavour, running this host's own
    /// kernel version and reporting its own release, and on Linux built as this
    /// host's kernel was: the model of the kernel this host is running, as far
    /// as `preset`'s architecture and page size allow.
    let runningHostKernel (preset : SimulatedUnixPlatform) : SimulatedUnixPlatform =
        let flavour = SimulatedUnixPlatform.flavour preset
        let release = release flavour

        let kernel =
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                match LinuxRelease.version release with
                | None -> failwith $"this host's release %s{release} does not begin with a Linux version"
                | Some version -> SimulatedUnixKernel.Linux (version, linuxBuild ())
            | SimulatedUnixFlavour.Darwin ->
                match DarwinRelease.version release with
                | None -> failwith $"this host's release %s{release} is not a Darwin version"
                | Some version -> SimulatedUnixKernel.Darwin version

        SimulatedUnixPlatform.createOrFail
            "HostPlatform.runningHostKernel"
            kernel
            (SimulatedUnixPlatform.architecture preset)
            (SimulatedUnixPlatform.pageSize preset)
            release

    /// Run `action` against a model of the kernel this host is running: the
    /// preset for its flavour and architecture, but running this host's own
    /// kernel version and reporting its own release. For tests of a fact that
    /// changed between kernel versions, which must hold on whichever kernel the
    /// suite runs on. Skips where `onUnixHostPreset` does.
    let onUnixHostKernel (action : SimulatedUnixPlatform -> unit) : unit =
        onUnixHostPreset (runningHostKernel >> action)
