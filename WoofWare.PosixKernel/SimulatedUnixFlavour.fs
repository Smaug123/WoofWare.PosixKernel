namespace WoofWare.PosixKernel

/// <summary>
/// Which Unix we are simulating: Linux or Darwin.
/// </summary>
/// <remarks>
/// The client does not configure a flavour directly. It chooses a <c>SimulatedUnixPlatform</c>
/// (for example <c>SimulatedUnixPlatform.linuxX64</c>), whose flavour <c>SimulatedUnixPlatform.flavour</c> reads.
/// <para />
/// The flavour decides most of the ways the two Unixes differ, such as errno numbering, permission bit handling
/// on symlinks, and whether <c>stat</c> reports creation times. Some behaviour follows the platform's kernel version
/// or build instead, so the platform, not the flavour, says what the kernel does
/// (see "Flavours and divergence from host platforms" in the README).
/// </remarks>
[<RequireQualifiedAccess>]
type SimulatedUnixFlavour =
    /// <summary>Linux.</summary>
    | Linux
    /// <summary>Darwin, i.e. macOS.</summary>
    /// <remarks><c>uname -r</c> reports the Darwin kernel release rather than the macOS product version.</remarks>
    | Darwin
