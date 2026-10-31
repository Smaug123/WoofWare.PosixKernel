namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Booting a machine whose first process a test describes, for a test that
/// means every value it passes to be admitted: a refusal fails the test, named
/// by the refusal's own `describe`.
[<RequireQualifiedAccess>]
module internal Launched =

    /// A process launched with `streams`, its leader `leader`
    /// on `cpu`.
    let launch<'Thread when 'Thread : comparison>
        (streams : Map<int, LaunchDescriptor>)
        (leader : 'Thread)
        (cpu : CpuId)
        : ProcessLaunch<'Thread>
        =
        ProcessLaunch.tryCreate streams leader cpu
        |> Configured.expectOk LaunchTableRefusal.describe

    /// `image` booted with a first process launched with `streams`, its leader
    /// `leader` on `cpu`, as `configure` configures the launch.
    let bootWith<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (configure : ProcessLaunch<'Thread> -> ProcessLaunch<'Thread>)
        (streams : Map<int, LaunchDescriptor>)
        (leader : 'Thread)
        (cpu : CpuId)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let launch = launch streams leader cpu |> configure

        UnixBootImage.tryBoot launch image |> Configured.expectOk BootRefusal.describe

    /// `bootWith` with the launch as `ProcessLaunch.create` makes it.
    let boot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (streams : Map<int, LaunchDescriptor>)
        (leader : 'Thread)
        (cpu : CpuId)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        bootWith id streams leader cpu image

    /// `ProcessLaunch.withCredentials`, which the test means to admit them.
    let credentials<'Thread when 'Thread : comparison>
        (credentials : Credentials)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        ProcessLaunch.withCredentials credentials launch

    /// `ProcessLaunch.withUmask`, which the test means to admit it.
    let umask<'Thread when 'Thread : comparison>
        (umask : PermissionBits)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        ProcessLaunch.withUmask umask launch

    /// `UnixBootImage.withProcessId`, which the test means to admit it.
    let processId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        UnixBootImage.tryWithProcessId pid image
        |> Configured.expectOk ProcessIdRefusal.describe

    /// `UnixBootImage.withLeaderThreadId`, which the test means to admit it.
    let leaderThreadId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (id : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        UnixBootImage.tryWithLeaderThreadId id image
        |> Configured.expectOk LeaderThreadIdRefusal.describe

    /// `UnixBootImage.withFileSystem`, which the test means to admit the seed.
    let fileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (createdAt : UnixTimestamp)
        (defaultOwner : InodeOwner)
        (seed : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        UnixBootImage.tryWithFileSystem createdAt defaultOwner seed image
        |> Configured.expectOk (sprintf "%A")
