namespace WoofWare.PosixKernel

/// Why the directory a host named cannot be the one a simulated process starts
/// in (`ProcessLaunch.withCurrentDirectory`). Launching the process returns one
/// instead of deciding what to say about it: the remedy is always "fix the
/// knob you set this from", and only the caller knows what that knob is called.
///
/// Every case is a host mistake rather than a process's, which is why none of
/// them is a `UnixError`: there is no errno for "you launched a process in a
/// directory the filesystem does not contain", and answering ENOENT would blame
/// a process's path when there is no process yet.
///
/// Four cases, and deliberately not six. The walk could also answer an inode
/// the filesystem does not contain, or a directory no path from the root
/// reaches — but not for a filesystem whose invariants hold, walked from its
/// root, so those are bugs in this library and crash rather than being handed
/// to a caller who could do nothing about them.
[<RequireQualifiedAccess>]
type internal CurrentDirectoryFault =
    /// The path does not resolve in the seeded filesystem at all. Carries what
    /// the walk answered.
    | DoesNotResolve of UnixError
    /// The walk refused the path as too long. Distinguished from
    /// `DoesNotResolve` because the directory may well be present: it is a
    /// *length* that is unusable, and the remedy is to shorten something rather
    /// than to go looking for a missing directory.
    ///
    /// Which length is deliberately not said, because the walk does not say:
    /// `ENAMETOOLONG` is one errno covering a component past this flavour's
    /// `NAME_MAX` and — on a flavour that re-checks, which is Darwin — a
    /// symbolic link whose expansion would carry the whole path past
    /// `PATH_MAX`. A real kernel conflates them too. Splitting the case would
    /// need the path walk to report which limit it hit, which every other
    /// caller of the walk would pay for.
    ///
    /// Carries the flavour so that a fault which outlives the call still says
    /// whose limits were in force -- 255 CJK characters name a directory a
    /// Darwin process can start in and a Linux one cannot, and only Darwin
    /// re-checks a splice at all.
    | TooLong of SimulatedUnixFlavour
    /// The path resolves, to something that is not a directory.
    | NotADirectory
    /// This kernel will not resolve the path.
    | Path of PathRefusal

[<RequireQualifiedAccess>]
module internal CurrentDirectoryFault =
    /// Which exception a public entry point raises this fault as.
    let kind (fault : CurrentDirectoryFault) : RefusalKind =
        match fault with
        | CurrentDirectoryFault.DoesNotResolve _ -> RefusalKind.Contradictory "launch"
        | CurrentDirectoryFault.TooLong _ -> RefusalKind.Contradictory "launch"
        | CurrentDirectoryFault.NotADirectory -> RefusalKind.Contradictory "launch"
        | CurrentDirectoryFault.Path inner -> PathRefusal.kind inner

/// Why `ProcessLaunch.create` refuses a launch table.
[<RequireQualifiedAccess>]
type internal LaunchTableRefusal =
    /// The table names a negative descriptor, which no process has.
    /// Contradictory.
    | NegativeDescriptor of fd : int

[<RequireQualifiedAccess>]
module internal LaunchTableRefusal =
    /// What this library knows about why it refused the table, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : LaunchTableRefusal) : string =
        match refusal with
        | LaunchTableRefusal.NegativeDescriptor fd ->
            $"the launch table names descriptor %d{fd}, which is negative; no process has a descriptor below 0."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : LaunchTableRefusal) : RefusalKind =
        match refusal with
        | LaunchTableRefusal.NegativeDescriptor _ -> RefusalKind.OutOfRange "streams"

/// Why launching a process refuses its requested credentials.
[<RequireQualifiedAccess>]
type internal CredentialsRefusal =
    /// More supplementary groups than the `limit` a process can hold on
    /// `flavour` (`SimulatedUnixPlatform.supplementaryGroupsHeld`):
    /// `setgroups(2)` answers EINVAL above `NGROUPS_MAX`, and Darwin's list of
    /// that many holds the effective group too. Contradictory.
    | TooManySupplementaryGroups of count : int * limit : int * flavour : SimulatedUnixFlavour
    /// On Darwin, real, effective and saved IDs that are not all the same.
    /// Which of them a Darwin kernel consults has not been measured, since that
    /// needs a process that can change its user ID, which is root, and none has
    /// been available on Darwin. Unmeasured.
    | IdsDifferOnDarwin of credentials : Credentials

[<RequireQualifiedAccess>]
module internal CredentialsRefusal =
    /// What this library knows about why it refused the credentials, for a
    /// client composing a diagnostic that names its own knob.
    let describe (refusal : CredentialsRefusal) : string =
        match refusal with
        | CredentialsRefusal.TooManySupplementaryGroups (count, limit, flavour) ->
            $"%d{count} supplementary groups is more than the %d{limit} a process can hold on %O{flavour} (setgroups(2) answers EINVAL above NGROUPS_MAX, and on Darwin its list holds the effective group too)."
        | CredentialsRefusal.IdsDifferOnDarwin credentials ->
            $"the credentials %O{credentials} have real, effective and saved IDs that differ, which this library does not model on Darwin: which of them a Darwin kernel consults has not been measured. Give all three the same user ID and the same group ID."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : CredentialsRefusal) : RefusalKind =
        match refusal with
        | CredentialsRefusal.TooManySupplementaryGroups _ -> RefusalKind.Contradictory "launch"
        | CredentialsRefusal.IdsDifferOnDarwin _ -> RefusalKind.Unmodelled

/// Why launching a process refuses its requested mask.
[<RequireQualifiedAccess>]
type internal UmaskRefusal =
    /// The mask holds a bit `flavour`'s `umask(2)` never stores: it keeps only
    /// `stored` (`SimulatedUnixPlatform.umaskStoredBits`). No parent could
    /// have left such a mask. Contradictory.
    | BitsNotStored of umask : PermissionBits * stored : PermissionBits * flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal UmaskRefusal =
    /// What this library knows about why it refused the mask, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : UmaskRefusal) : string =
        match refusal with
        | UmaskRefusal.BitsNotStored (umask, stored, flavour) ->
            $"the mask 0o%04o{PermissionBits.toInt umask} holds a bit %O{flavour}'s umask(2) never stores (it keeps only 0o%04o{PermissionBits.toInt stored}), so no process there could have it."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : UmaskRefusal) : RefusalKind =
        match refusal with
        | UmaskRefusal.BitsNotStored _ -> RefusalKind.Contradictory "launch"

/// Why launching a process refuses its requested signal limit.
[<RequireQualifiedAccess>]
type internal PendingSignalLimitRefusal =
    /// The launch is for `flavour`, which has no `RLIMIT_SIGPENDING`: Darwin
    /// defines no such resource limit and queues no real-time signal.
    | NoSuchLimit of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal PendingSignalLimitRefusal =
    /// What this library knows about why it refused the limit, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : PendingSignalLimitRefusal) : string =
        match refusal with
        | PendingSignalLimitRefusal.NoSuchLimit flavour ->
            $"%O{flavour} has no RLIMIT_SIGPENDING: it defines no such resource limit and queues no real-time signal."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : PendingSignalLimitRefusal) : RefusalKind =
        match refusal with
        | PendingSignalLimitRefusal.NoSuchLimit _ -> RefusalKind.NotOnPlatform

/// Why a process cannot be launched onto a machine as its `ProcessLaunch`
/// describes it.
[<RequireQualifiedAccess>]
type internal LaunchRefusal =
    /// The process cannot start in `directory` on this machine's filesystem.
    | CurrentDirectory of directory : AbsoluteUnixPath * fault : CurrentDirectoryFault
    /// The launch puts its leader on the logical processor `cpu`, and the
    /// machine has `processorCount`, numbered from 0, which do not include it.
    /// Contradictory: no kernel runs a thread on a processor it does not have.
    | LeaderCpuBeyondMachine of cpu : CpuId * processorCount : int
    /// The process specified a pending signal limit which is incompatible with this platform.
    | PendingSignalLimit of PendingSignalLimitRefusal
    /// The process specified a umask which is incompatible with this platform.
    | Umask of UmaskRefusal
    /// The requested credentials cannot be admitted on the machine's platform.
    | Credentials of CredentialsRefusal
    /// The descriptor reaches the bound this kernel models for the process's
    /// `RLIMIT_NOFILE` (`SimulatedUnixPlatform.descriptorBound`).
    | DescriptorAtOrAboveBound of fd : int * bound : int

[<RequireQualifiedAccess>]
module internal LaunchRefusal =
    /// What this library knows about why it refused the launch, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : LaunchRefusal) : string =
        match refusal with
        | LaunchRefusal.CurrentDirectory (directory, fault) ->
            let described = AbsoluteUnixPath.toEscaped directory

            match fault with
            | CurrentDirectoryFault.DoesNotResolve error ->
                $"the process cannot start in \"%s{described}\", which does not resolve in the machine's filesystem (%O{error}). A process cannot be started in a directory that does not exist; make the filesystem contain it."
            | CurrentDirectoryFault.TooLong flavour ->
                $"%O{flavour} refuses \"%s{described}\" as too long: a component is past NAME_MAX, or, on Darwin, a symbolic link it goes through expands past PATH_MAX. Shorten the component, or that link's target."
            | CurrentDirectoryFault.NotADirectory ->
                $"the process cannot start in \"%s{described}\", which resolves to something that is not a directory. Start it in a directory the filesystem holds."
            | CurrentDirectoryFault.Path refusal ->
                $"the kernel will not resolve \"%s{described}\": %s{PathRefusal.describe refusal}"
        | LaunchRefusal.LeaderCpuBeyondMachine (cpu, processorCount) ->
            $"the launch puts its leader on %O{cpu}, but the machine has %d{processorCount} logical processors, numbered from 0."
        | LaunchRefusal.PendingSignalLimit refusal -> PendingSignalLimitRefusal.describe refusal
        | LaunchRefusal.Umask refusal -> UmaskRefusal.describe refusal
        | LaunchRefusal.Credentials refusal -> CredentialsRefusal.describe refusal
        | LaunchRefusal.DescriptorAtOrAboveBound (fd, bound) ->
            $"the launch table names descriptor %d{fd}, at or above the bound %d{bound} this kernel assumes the process's RLIMIT_NOFILE reaches; it hands out no descriptor there."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : LaunchRefusal) : RefusalKind =
        match refusal with
        | LaunchRefusal.CurrentDirectory (_, inner) -> CurrentDirectoryFault.kind inner
        | LaunchRefusal.LeaderCpuBeyondMachine _ -> RefusalKind.Contradictory "launch"
        | LaunchRefusal.PendingSignalLimit inner -> PendingSignalLimitRefusal.kind inner
        | LaunchRefusal.Umask inner -> UmaskRefusal.kind inner
        | LaunchRefusal.Credentials inner -> CredentialsRefusal.kind inner
        | LaunchRefusal.DescriptorAtOrAboveBound _ -> RefusalKind.Unmodelled

/// What a process starts with unless its launch says otherwise: the values of
/// `UnixSystem`'s defaults of the same names, whose docstrings say why each is
/// what it is.
[<RequireQualifiedAccess>]
module internal LaunchDefaults =
    /// `UnixSystem.defaultCurrentDirectory`.
    let currentDirectory : AbsoluteUnixPath = AbsoluteUnixPath.root

    /// `UnixSystem.defaultProcessPath`.
    let processPath : AbsoluteUnixPath option = None

    /// `UnixSystem.defaultUserId`.
    let userId (flavour : SimulatedUnixFlavour) : UserId =
        match flavour with
        | SimulatedUnixFlavour.Linux -> UserId.parseOrFail "UnixSystem.defaultUserId" 1000u
        | SimulatedUnixFlavour.Darwin -> UserId.parseOrFail "UnixSystem.defaultUserId" 501u

    /// `UnixSystem.defaultGroupId`.
    let groupId (flavour : SimulatedUnixFlavour) : GroupId =
        match flavour with
        | SimulatedUnixFlavour.Linux -> GroupId.parseOrFail "UnixSystem.defaultGroupId" 1000u
        | SimulatedUnixFlavour.Darwin -> GroupId.parseOrFail "UnixSystem.defaultGroupId" 20u

    /// `UnixSystem.defaultCredentials`.
    let credentials (flavour : SimulatedUnixFlavour) : Credentials =
        Credentials.ofIds (userId flavour) (groupId flavour) []

    /// `UnixSystem.defaultUmask`.
    let umask : PermissionBits =
        PermissionBits.parseOrFail "UnixSystem.defaultUmask" 0o022

    /// `UnixSystem.defaultCoreDumps`.
    let coreDumps : CoreDumps = CoreDumps.Suppressed

    /// `UnixSystem.defaultPendingSignalLimit`.
    let pendingSignalLimit : uint64 = 4505UL

    /// The `RLIMIT_SIGPENDING` a process of `flavour` starts with: Linux's
    /// default, and none under Darwin, which has no such limit.
    let pendingSignalLimitOf (flavour : SimulatedUnixFlavour) : uint64 voption =
        match flavour with
        | SimulatedUnixFlavour.Linux -> ValueSome pendingSignalLimit
        | SimulatedUnixFlavour.Darwin -> ValueNone

[<Struct>]
type internal PendingSignalLimitSpec =
    /// <summary>
    /// The user has specified that the value of <c>RLIMIT_SIGPENDING</c> is this.
    /// </summary>
    /// <remarks>
    /// We don't currently model <c>setrlimit(2)</c>, so the user is forced to specify
    /// this value directly from the host.
    /// When we model that properly, this should go away, because that syscall will be
    /// the blessed way to specify rlimit values, and it can perform validation
    /// internally.
    /// </remarks>
    | Requested of uint64

/// How a process starts: everything about a process that is fixed before its
/// first instruction, as its launcher sets it up before `exec`. Both the first
/// process on a machine (`UnixBootImage.boot`) and every later one
/// (`UnixSystem.launch`) are launched from one.
///
/// The process's ID is not here: the kernel chooses it, from the machine's
/// counters, when the process is launched.
///
/// Opaque: made by `create`, and configured by the setters in `ProcessLaunch`.
/// `UnixBootImage.boot` and `UnixSystem.launch` choose defaults and check the
/// requested settings against the machine's platform when launching it.
type ProcessLaunch<'Thread when 'Thread : comparison> =
    internal
        {
            /// The descriptors the launcher set up, each a pipe end of its own
            /// whose other end is the client's.
            Streams : Map<int, LaunchDescriptor>
            /// The process's first thread, its thread-group leader.
            Leader : 'Thread
            /// The logical processor the leader starts on.
            LeaderCpu : CpuId
            /// Leave as None for "take the default for the launching platform".
            /// If supplied, we have not yet checked they're valid for the launching platform.
            NonValidatedCredentials : Credentials option
            NonValidatedUmask : PermissionBits voption
            Environment : UnixByteString list
            ProcessPath : AbsoluteUnixPath option
            CoreDumps : CoreDumps
            /// <summary><c>ValueNone</c> if the user hasn't specified a limit.</summary>
            PendingSignalLimit : PendingSignalLimitSpec voption
            /// The directory the process starts in, resolved against the
            /// machine's filesystem when the process is launched.
            CurrentDirectory : AbsoluteUnixPath
        }

[<RequireQualifiedAccess>]
module ProcessLaunch =

    /// `create`, with a refusal answered as the `Error` rather than raised.
    let internal tryCreate<'Thread when 'Thread : comparison>
        (streams : Map<int, LaunchDescriptor>)
        (leader : 'Thread)
        (leaderCpu : CpuId)
        : Result<ProcessLaunch<'Thread>, LaunchTableRefusal>
        =
        let offending =
            streams
            |> Map.toSeq
            |> Seq.tryPick (fun (fd, _) ->
                if fd < 0 then
                    Some (LaunchTableRefusal.NegativeDescriptor fd)
                else
                    None
            )

        match offending with
        | Some refusal -> Error refusal
        | None ->
            Ok
                {
                    Streams = streams
                    Leader = leader
                    LeaderCpu = leaderCpu
                    NonValidatedCredentials = None
                    NonValidatedUmask = ValueNone
                    Environment = []
                    ProcessPath = LaunchDefaults.processPath
                    CoreDumps = LaunchDefaults.coreDumps
                    PendingSignalLimit = ValueNone
                    CurrentDirectory = LaunchDefaults.currentDirectory
                }

    /// <summary>
    /// A launch with the descriptors `streams` open, and one thread, `leader`,
    /// on the logical processor `leaderCpu`; otherwise as a default process of
    /// the launching machine's flavour starts: in the root, with
    /// `UnixSystem.defaultCredentials`, `UnixSystem.defaultUmask`, no
    /// environment, no executable path (`UnixSystem.defaultProcessPath`) and
    /// `UnixSystem.defaultCoreDumps`.
    ///
    /// Each entry of `streams` is a descriptor the launcher set up before the
    /// process started, at that number: a pipe end of its own, whose other end
    /// is the client's, as the entry says (see `LaunchDescriptor`). The pipes
    /// are made, in descriptor order, when the process is launched.
    ///
    /// The leader starts blocking no signal. A real process starts with the
    /// mask its parent's thread had when it called `execve(2)`, which keeps the
    /// mask; a client launching a process that inherits one sets it with
    /// `UnixSignal.pthreadSigmask` and `SIG_SETMASK` before the leader runs its
    /// first instruction, as inherited ignores are installed with
    /// `UnixSignal.sigaction`.
    ///
    /// Refuses a table naming a negative descriptor. `UnixBootImage.boot` and
    /// `UnixSystem.launch` refuse descriptors at or above the launching
    /// machine's bound (`SimulatedUnixPlatform.descriptorBound`).
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The table names a negative descriptor, which no process has. Contradictory.</exception>
    let create<'Thread when 'Thread : comparison>
        (streams : Map<int, LaunchDescriptor>)
        (leader : 'Thread)
        (leaderCpu : CpuId)
        : ProcessLaunch<'Thread>
        =
        tryCreate streams leader leaderCpu
        |> Refusal.orRaise "ProcessLaunch.create" LaunchTableRefusal.kind LaunchTableRefusal.describe

    /// The process's first thread.
    let leader<'Thread when 'Thread : comparison> (launch : ProcessLaunch<'Thread>) : 'Thread = launch.Leader

    /// Validates the NonValidatedCredentials in a ProcessLaunch.
    let private validateCredentialsForPlatform
        (platform : SimulatedUnixPlatform)
        (credentials : Credentials)
        : Result<Credentials, CredentialsRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour platform
        let count = List.length credentials.SupplementaryGroups
        let limit = SimulatedUnixPlatform.supplementaryGroupsHeld platform

        let idsAgree =
            credentials.RealUser = credentials.EffectiveUser
            && credentials.SavedUser = credentials.EffectiveUser
            && credentials.RealGroup = credentials.EffectiveGroup
            && credentials.SavedGroup = credentials.EffectiveGroup

        if count > limit then
            Error (CredentialsRefusal.TooManySupplementaryGroups (count, limit, flavour))
        else

        match flavour with
        | SimulatedUnixFlavour.Darwin when not idsAgree -> Error (CredentialsRefusal.IdsDifferOnDarwin credentials)
        | SimulatedUnixFlavour.Darwin
        | SimulatedUnixFlavour.Linux -> Ok credentials

    /// Set who the process starts as. The launching machine checks the
    /// supplementary-group count and whether it supports these credentials
    /// when `UnixBootImage.boot` or `UnixSystem.launch` launches the process.
    let withCredentials<'Thread when 'Thread : comparison>
        (credentials : Credentials)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            NonValidatedCredentials = Some credentials
        }

    /// Validates that the given umask is valid on this platform.
    let private validateUmask
        (platform : SimulatedUnixPlatform)
        (umask : PermissionBits)
        : Result<PermissionBits, UmaskRefusal>
        =
        let stored = SimulatedUnixPlatform.umaskStoredBits platform

        if PermissionBits.toInt umask &&& ~~~(PermissionBits.toInt stored) <> 0 then
            Error (UmaskRefusal.BitsNotStored (umask, stored, SimulatedUnixPlatform.flavour platform))
        else
            Ok umask

    /// <summary>
    /// Set the file-mode creation mask the process starts with: the one its
    /// parent left it, which it can read and replace with `umask`.
    /// `UnixBootImage.boot` and `UnixSystem.launch` refuse bits the launching
    /// platform's `umask` never stores.
    /// </summary>
    let withUmask<'Thread when 'Thread : comparison>
        (umask : PermissionBits)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            NonValidatedUmask = ValueSome (PermissionBits.assertValidFor "ProcessLaunch.withUmask" "umask" umask)
        }

    /// Set the environment the process was started with, replacing whatever
    /// it held. The entries are kept in the order given, duplicates and all,
    /// and none is parsed: an entry need not be `NAME=VALUE`. See
    /// `UnixSystem.environment`.
    ///
    /// `context` prefixes the `ArgumentException` a forged entry, such as
    /// `Unchecked.defaultof`, earns, and is the client's to choose: the host that has to fix one knows it by whatever
    /// name the client's own configuration gives it.
    let withEnvironment<'Thread when 'Thread : comparison>
        (context : string)
        (environment : UnixByteString list)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            Environment = environment |> List.map (UnixByteString.assertValidFor context "environment")
        }

    /// Set the path to the executable that started the process, or `None` to
    /// report that it has none. `None` is preserved rather than defaulted; see
    /// `UnixSystem.processPath`.
    ///
    /// `context` prefixes the `ArgumentException` a forged path earns; see
    /// `withEnvironment`.
    let withProcessPath<'Thread when 'Thread : comparison>
        (context : string)
        (path : AbsoluteUnixPath option)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            ProcessPath = path |> Option.map (AbsoluteUnixPath.assertValid context)
        }

    /// Set whether the process writes a core dump when a signal whose default
    /// action dumps core kills it. Fixed for the life of the process: this
    /// library models no `setrlimit(2)`.
    let withCoreDumps<'Thread when 'Thread : comparison>
        (coreDumps : CoreDumps)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            CoreDumps = coreDumps
        }

    let private validatePendingSignalLimit
        (platform : SimulatedUnixPlatform)
        (spec : PendingSignalLimitSpec)
        : Result<uint64, PendingSignalLimitRefusal>
        =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Darwin -> Error (PendingSignalLimitRefusal.NoSuchLimit SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->
            let (PendingSignalLimitSpec.Requested limit) = spec
            Ok limit

    /// Set the process's `RLIMIT_SIGPENDING`: how many signals may be queued for
    /// its real user, in all that user's processes on the machine, before a
    /// signal sent to it gets no queue entry. This is meaningful on Linux only,
    /// and fixed for the life of the process: this library models no `setrlimit(2)`.
    /// The default is `UnixSystem.defaultPendingSignalLimit`.
    ///
    /// Past the limit, a real-time signal sent by `kill` is lost, or, if no
    /// instance of it is pending in its set, pending without the information
    /// it was sent with; one sent by `pthread_kill` fails with `EAGAIN`; and a
    /// standard signal is pending as before. Every limit is admitted, the
    /// largest (`RLIM_INFINITY`) included.
    ///
    /// `UnixBootImage.boot` and `UnixSystem.launch` throw
    /// `PlatformNotSupportedException` for an explicit limit on Darwin.
    let withPendingSignalLimit<'Thread when 'Thread : comparison>
        (limit : uint64)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            PendingSignalLimit = ValueSome (PendingSignalLimitSpec.Requested limit)
        }

    /// Set the directory the process starts in.
    ///
    /// Resolved when the process is launched, against the filesystem of the
    /// machine it is launched onto, which is what refuses a directory that is
    /// not there. The walk is privileged and symlink-following, deliberately:
    /// this is a host saying where its process was launched, not a process
    /// looking anything up, and a process is launched into a directory its
    /// parent had already reached. It is also the only moment the name is
    /// resolved, because after it the process holds the *directory* rather than
    /// the name, so the path `getcwd` reports is the physical one with every
    /// symlink resolved away.
    ///
    /// A forged `directory`, such as `Unchecked.defaultof`, throws
    /// `ArgumentException`.
    let withCurrentDirectory<'Thread when 'Thread : comparison>
        (directory : AbsoluteUnixPath)
        (launch : ProcessLaunch<'Thread>)
        : ProcessLaunch<'Thread>
        =
        { launch with
            CurrentDirectory =
                AbsoluteUnixPath.assertValidFor "ProcessLaunch.withCurrentDirectory" "directory" directory
        }

    /// The directory `directory` names in `machine`'s filesystem, walked as
    /// `withCurrentDirectory` says.
    let internal resolveCurrentDirectory
        (directory : AbsoluteUnixPath)
        (machine : UnixMachineState)
        : Result<InodeNumber, CurrentDirectoryFault>
        =
        let platform = machine.UnixPlatform
        let filesystem = machine.FileSystem
        let limits = SimulatedUnixPlatform.pathLimits platform

        match
            PathWalk.resolveExisting
                limits
                // Root, so that no directory's search bit refuses the walk:
                // it is privilege that exempts a caller, whoever owns what.
                (Credentials.ofIds UserId.root (GroupId.parseOrFail "ProcessLaunch.resolveCurrentDirectory" 0u) [])
                // The host names where the process starts; no process follows
                // a link to get there, so no sysctl screens one.
                SymlinkProtection.Off
                (VirtualFileSystem.root filesystem)
                SymlinkPolicy.Follow
                (UnixPath.ofAbsolute directory)
                filesystem
        with
        | Ok inode ->
            match VirtualFileSystem.tryGetContent inode filesystem with
            | Some (InodeContent.Directory _) ->
                // The walk started at the root, so a directory it reached has a
                // path back by construction. Checked anyway: the alternative to
                // crashing here is a process whose `getcwd` reports ENOENT from
                // its first instruction.
                match VirtualFileSystem.pathOfDirectory inode filesystem with
                | Some _ -> Ok inode
                | None ->
                    failwith
                        $"ProcessLaunch.resolveCurrentDirectory: \"%s{AbsoluteUnixPath.toEscaped directory}\" resolved to inode %O{inode}, but no path from the root reaches it (this is a bug in this library)."
            | Some (InodeContent.RegularFile _)
            | Some (InodeContent.Socket _)
            | Some (InodeContent.Fifo _)
            | Some (InodeContent.CharacterDevice _) -> Error CurrentDirectoryFault.NotADirectory
            | Some (InodeContent.Symlink _) ->
                // `SymlinkPolicy.Follow` never finishes on one; `chdir` says
                // the same of the same walk.
                failwith
                    $"ProcessLaunch.resolveCurrentDirectory: the walk resolved \"%s{AbsoluteUnixPath.toEscaped directory}\" to inode %O{inode}, which is a symbolic link -- but it ran under SymlinkPolicy.Follow, which never finishes on one (this is a bug in this library)."
            | None ->
                failwith
                    $"ProcessLaunch.resolveCurrentDirectory: resolving \"%s{AbsoluteUnixPath.toEscaped directory}\" gave inode %O{inode}, which the filesystem does not contain (this is a bug in this library; run VirtualFileSystem.checkInvariants)."
        | Error (PathFailure.Errno UnixError.ENAMETOOLONG) ->
            Error (CurrentDirectoryFault.TooLong (SimulatedUnixPlatform.flavour platform))
        | Error (PathFailure.Errno error) -> Error (CurrentDirectoryFault.DoesNotResolve error)
        | Error (PathFailure.Refused refusal) -> Error (CurrentDirectoryFault.Path refusal)

    /// `launch` started on `machine` as the process `pid`, whose leader has
    /// the thread ID `leaderThreadId`, which the machine's allocator already
    /// records as live: the machine after it, with the launch table's pipes,
    /// the process on its process table and a hold on its current directory,
    /// and the process and its threads.
    let internal launchOnto<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (pid : ProcessId)
        (leaderThreadId : OsThreadId)
        (machine : UnixMachineState)
        : Result<UnixMachineState * UnixProcessState<'Thread, 'Handler> * ThreadTable<'Thread>, LaunchRefusal>
        =
        let platform = machine.UnixPlatform

        let bound = SimulatedUnixPlatform.descriptorBound platform

        match launch.Streams |> Map.toSeq |> Seq.tryFind (fun (fd, _) -> fd >= bound) with
        | Some (fd, _) -> Error (LaunchRefusal.DescriptorAtOrAboveBound (fd, bound))
        | None ->

        let flavour = SimulatedUnixPlatform.flavour platform

        let credentials =
            match launch.NonValidatedCredentials with
            | None -> Ok (LaunchDefaults.credentials flavour)
            | Some credentials -> validateCredentialsForPlatform platform credentials

        match credentials with
        | Error refusal -> Error (LaunchRefusal.Credentials refusal)
        | Ok credentials ->

        let signalLimit =
            match launch.PendingSignalLimit with
            | ValueNone -> LaunchDefaults.pendingSignalLimitOf flavour |> Ok
            | ValueSome s -> validatePendingSignalLimit platform s |> Result.map ValueSome

        match signalLimit with
        | Error e -> Error (LaunchRefusal.PendingSignalLimit e)
        | Ok signalLimit ->

        let umask =
            match launch.NonValidatedUmask with
            | ValueNone -> LaunchDefaults.umask |> Ok
            | ValueSome umask -> validateUmask platform umask

        match umask with
        | Error e -> Error (LaunchRefusal.Umask e)
        | Ok umask ->

        if not (UnixMachineState.hasProcessor launch.LeaderCpu machine) then
            Error (LaunchRefusal.LeaderCpuBeyondMachine (launch.LeaderCpu, machine.ProcessorCount))
        else

        match resolveCurrentDirectory launch.CurrentDirectory machine with
        | Error fault -> Error (LaunchRefusal.CurrentDirectory (launch.CurrentDirectory, fault))
        | Ok directory ->

        if not (Set.contains leaderThreadId (ThreadIdAllocator.live machine.ThreadIds)) then
            failwith
                $"ProcessLaunch.launchOnto: the leader's thread ID %O{leaderThreadId} is not live in the machine's allocator (this is a bug in this library)."

        // One pipe per launch descriptor, numbered in descriptor order from the
        // next pipe the machine makes.
        let (PipeId first) = machine.NextPipeId

        let launched =
            launch.Streams
            |> Map.toList
            |> List.mapi (fun index (fd, descriptor) ->
                let pipeId = PipeId (first + int64 index)
                let pipe, pipeEnd = PipeState.launch platform pid fd descriptor
                fd, pipeId, pipeEnd, pipe
            )

        let registry =
            FileDescriptorRegistry.ofLaunchedPipes
                (SimulatedUnixPlatform.flavour platform)
                (launched
                 |> List.map (fun (fd, pipeId, pipeEnd, _) -> fd, (pipeId, pipeEnd))
                 |> Map.ofList)
                machine.OpenFiles

        let machine =
            { machine with
                OpenFiles = FileDescriptorRegistry.openFiles registry
                Pipes =
                    (machine.Pipes, launched)
                    ||> List.fold (fun pipes (_, pipeId, _, pipe) -> Map.add pipeId pipe pipes)
                NextPipeId = PipeId (first + int64 (List.length launched))
                ProcessIds = ProcessIdTable.add pid machine.ProcessIds
            }
            |> UnixMachineState.holdCurrentDirectory directory

        let proc : UnixProcessState<'Thread, 'Handler> =
            {
                FileDescriptors = FileDescriptorRegistry.descriptorTable registry
                Environment = launch.Environment
                CurrentDirectoryInode = directory
                ProcessPath = launch.ProcessPath
                Credentials = credentials
                Umask = umask
                ProcessId = pid
                Signals = SignalState.initial (SimulatedUnixPlatform.signalNumbering platform) Set.empty
                CoreDumps = launch.CoreDumps
                PendingSignalLimit = signalLimit
            }

        Ok (machine, proc, UnixThreadTable.add launch.Leader launch.LeaderCpu leaderThreadId UnixThreadTable.empty)
