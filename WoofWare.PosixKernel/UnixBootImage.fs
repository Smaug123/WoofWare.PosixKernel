namespace WoofWare.PosixKernel

/// Why `UnixBootImage.withUserAddressLimit` refuses a limit.
[<RequireQualifiedAccess>]
type internal UserAddressLimitRefusal =
    /// The machine's flavour screens no buffer before performing an
    /// operation (Darwin), so it has no `TASK_SIZE_MAX` for a limit to set.
    /// Contradictory: no machine of the flavour has the setting.
    | NoUpFrontScreen of flavour : SimulatedUnixFlavour
    /// No machine of `architecture` has been observed with `limit` as its
    /// `TASK_SIZE_MAX` (see `ObservedUserAddressLimit`). `observedOn` is the
    /// architecture whose machines have been, if any. Unmeasured: a machine
    /// may have such a limit, but this library has not seen one.
    | NotObservedOn of
        limit : uint64 *
        architecture : SimulatedUnixArchitecture *
        observedOn : SimulatedUnixArchitecture option

[<RequireQualifiedAccess>]
module internal UserAddressLimitRefusal =
    /// What this library knows about why it refused the limit, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : UserAddressLimitRefusal) : string =
        match refusal with
        | UserAddressLimitRefusal.NoUpFrontScreen flavour ->
            $"a %O{flavour} kernel screens no buffer before performing an operation, so it has no user address limit to set."
        | UserAddressLimitRefusal.NotObservedOn (limit, architecture, Some observedOn) ->
            $"0x%x{limit} is the TASK_SIZE_MAX of an %O{observedOn} machine, but this platform is %O{architecture}."
        | UserAddressLimitRefusal.NotObservedOn (limit, architecture, None) ->
            $"no %O{architecture} machine has been observed with a TASK_SIZE_MAX of 0x%x{limit}; ObservedUserAddressLimit lists those that have."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : UserAddressLimitRefusal) : RefusalKind =
        match refusal with
        | UserAddressLimitRefusal.NoUpFrontScreen _ -> RefusalKind.Contradictory "limit"
        | UserAddressLimitRefusal.NotObservedOn _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withProcessorCount` refuses a count.
[<RequireQualifiedAccess>]
type internal ProcessorCountRefusal =
    /// The count is below 1. Contradictory: a machine running the process
    /// has at least the processor it runs on, and programs divide by the
    /// count.
    | NotPositive of count : int

[<RequireQualifiedAccess>]
module internal ProcessorCountRefusal =
    /// What this library knows about why it refused the count, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : ProcessorCountRefusal) : string =
        match refusal with
        | ProcessorCountRefusal.NotPositive count ->
            $"%d{count} logical processors is not a machine: a process runs on at least one, and programs divide by the count."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ProcessorCountRefusal) : RefusalKind =
        match refusal with
        | ProcessorCountRefusal.NotPositive _ -> RefusalKind.OutOfRange "count"

/// Why `UnixBootImage.withEphemeralPortRange` refuses a range.
[<RequireQualifiedAccess>]
type internal EphemeralPortRangeRefusal =
    /// The range starts at port 0, which is how a process *asks* for an
    /// ephemeral port, so it cannot also be one handed out. Contradictory.
    | LowIsZero of high : uint16
    /// The low end is above the high end, so the range holds no port and no
    /// bind of port 0 could be answered. Contradictory.
    | Empty of low : uint16 * high : uint16
    /// On Darwin, an end is below 1024. Darwin keeps
    /// `net.inet.ip.portrange.first` and `last` within 1024 to 65535,
    /// whatever is written, so no Darwin machine has such a range.
    /// Contradictory.
    | BelowDarwinFloor of low : uint16 * high : uint16
    /// On Darwin, the low end is above the high end. Darwin takes such a
    /// pair and searches the ports between them downwards, which this kernel
    /// does not model. Unmodelled.
    | Descending of low : uint16 * high : uint16

[<RequireQualifiedAccess>]
module internal EphemeralPortRangeRefusal =
    /// What this library knows about why it refused the range, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : EphemeralPortRangeRefusal) : string =
        match refusal with
        | EphemeralPortRangeRefusal.LowIsZero high ->
            $"the range 0-%d{high} starts at port 0, which is how a process asks for an ephemeral port, so it cannot also be one that gets handed out. Start the range at 1 or above."
        | EphemeralPortRangeRefusal.Empty (low, high) ->
            $"the range %d{low}-%d{high} is empty, so no bind of port 0 could ever be answered."
        | EphemeralPortRangeRefusal.BelowDarwinFloor (low, high) ->
            $"the range %d{low}-%d{high} has an end below 1024, where no Darwin machine's range can: Darwin keeps net.inet.ip.portrange.first and last within 1024 to 65535 whatever is written to them. Keep both ends at 1024 or above."
        | EphemeralPortRangeRefusal.Descending (low, high) ->
            $"the range %d{low}-%d{high} runs downwards. Darwin takes such a pair and searches the ports between them from the high end down, which this kernel does not model; give the low end first."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : EphemeralPortRangeRefusal) : RefusalKind =
        match refusal with
        | EphemeralPortRangeRefusal.LowIsZero _ -> RefusalKind.OutOfRange "low"
        | EphemeralPortRangeRefusal.Empty _ -> RefusalKind.Contradictory "high"
        | EphemeralPortRangeRefusal.BelowDarwinFloor _ -> RefusalKind.OutOfRange "low"
        | EphemeralPortRangeRefusal.Descending _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withUnprivilegedPortStart` refuses a value.
[<RequireQualifiedAccess>]
type internal UnprivilegedPortStartRefusal =
    /// The machine is of `flavour` (Darwin), which has no such setting: its
    /// privileged ports end at 1024, which nothing configures. Contradictory.
    | NoSuchSetting of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal UnprivilegedPortStartRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : UnprivilegedPortStartRefusal) : string =
        match refusal with
        | UnprivilegedPortStartRefusal.NoSuchSetting flavour ->
            $"the machine is %O{flavour}'s, which has no ip_unprivileged_port_start: its privileged ports end at 1024, and no sysctl moves that (measured: net.inet.ip.portrange.reservedlow and reservedhigh do not exist)."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : UnprivilegedPortStartRefusal) : RefusalKind =
        match refusal with
        | UnprivilegedPortStartRefusal.NoSuchSetting _ -> RefusalKind.Contradictory "start"

/// Why `UnixBootImage.boot` refuses to boot an image with a launch.
[<RequireQualifiedAccess>]
type internal BootRefusal =
    /// The launch cannot start on the machine.
    | Launch of LaunchRefusal
    /// Under Linux, the ephemeral range starts at `low`, below the
    /// unprivileged port start `start`. Linux refuses either sysctl a value
    /// that would leave them so, so no Linux machine has them. Contradictory.
    | EphemeralPortsBelowUnprivilegedPortStart of low : uint16 * start : uint16

[<RequireQualifiedAccess>]
module internal BootRefusal =
    /// What this library knows about why it refused to boot, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : BootRefusal) : string =
        match refusal with
        | BootRefusal.Launch refusal -> LaunchRefusal.describe refusal
        | BootRefusal.EphemeralPortsBelowUnprivilegedPortStart (low, start) ->
            $"the ephemeral range starts at port %d{low}, below the unprivileged port start, %d{start}. Linux's ip_local_port_range takes a low end only at or above ip_unprivileged_port_start, and ip_unprivileged_port_start a value only at or below the range's low end (measured), so no Linux machine has these two settings. Lower the unprivileged port start to %d{low}, or start the range at %d{start} or above."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : BootRefusal) : RefusalKind =
        match refusal with
        | BootRefusal.Launch refusal -> LaunchRefusal.kind refusal
        | BootRefusal.EphemeralPortsBelowUnprivilegedPortStart _ -> RefusalKind.Contradictory "image"

/// Why `UnixBootImage.withBootTime` refuses an instant.
[<RequireQualifiedAccess>]
type internal BootTimeRefusal =
    /// The instant is before the Unix epoch. Unmodelled: this library models
    /// no realtime clock reading before it.
    | BeforeEpoch of bootTime : UnixTimestamp
    /// The instant is after `maxSeconds` (`UnixMachineState.maxBootTimeSeconds`)
    /// seconds since the epoch, from which the realtime clock could pass the
    /// largest `time_t` within the longest uptime this library represents.
    /// Unmodelled.
    | PastMaxBootTime of bootTime : UnixTimestamp * maxSeconds : int64
    /// On Darwin, the instant has a nonzero sub-microsecond part. Darwin
    /// keeps the time it booted as a `struct timeval` (`sysctl
    /// kern.boottime`), so no Darwin machine booted at it. Contradictory.
    | FinerThanMicrosecond of bootTime : UnixTimestamp

[<RequireQualifiedAccess>]
module internal BootTimeRefusal =
    /// What this library knows about why it refused the instant, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : BootTimeRefusal) : string =
        match refusal with
        | BootTimeRefusal.BeforeEpoch bootTime ->
            $"%O{bootTime} is before the Unix epoch, and this kernel does not model a realtime clock reading before it."
        | BootTimeRefusal.PastMaxBootTime (bootTime, maxSeconds) ->
            $"%O{bootTime} is after %d{maxSeconds} seconds since the Unix epoch, from which the realtime clock could pass the largest time_t within the longest uptime this kernel represents."
        | BootTimeRefusal.FinerThanMicrosecond bootTime ->
            $"%O{bootTime} is finer than a microsecond, and Darwin keeps its boot instant as a struct timeval (sysctl kern.boottime), so no Darwin machine booted at it."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : BootTimeRefusal) : RefusalKind =
        match refusal with
        | BootTimeRefusal.BeforeEpoch _ -> RefusalKind.Unmodelled
        | BootTimeRefusal.PastMaxBootTime _ -> RefusalKind.Unmodelled
        | BootTimeRefusal.FinerThanMicrosecond _ -> RefusalKind.Contradictory "bootTime"

/// Why `UnixBootImage.withMount` refuses a mount.
[<RequireQualifiedAccess>]
type internal MountRefusal =
    /// A kernel of `flavour` cannot report `fileSystemType`
    /// (`EmulatedFileSystemType.isReportableUnder`), so a process asking
    /// `fstatfs(2)` would learn a fact no such system could tell it: APFS on
    /// Linux is contradictory, since no mainline Linux filesystem reports its
    /// type; tmpfs on Darwin is unmeasured, since a Darwin machine can mount
    /// one but none has been measured.
    | NotReportableUnder of fileSystemType : EmulatedFileSystemType * flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal MountRefusal =
    /// What this library knows about why it refused the mount, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : MountRefusal) : string =
        match refusal with
        | MountRefusal.NotReportableUnder (fileSystemType, flavour) ->
            $"a %O{flavour} kernel cannot report %O{fileSystemType}, so a process asking fstatfs would learn a fact no such system could tell it."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : MountRefusal) : RefusalKind =
        match refusal with
        | MountRefusal.NotReportableUnder (_, SimulatedUnixFlavour.Linux) -> RefusalKind.Contradictory "mount"
        | MountRefusal.NotReportableUnder (_, SimulatedUnixFlavour.Darwin) -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withProtectedFiles` refuses a setting.
[<RequireQualifiedAccess>]
type internal ProtectedFilesRefusal =
    /// `protection` sets an `fs.protected_*` sysctl, and a kernel of
    /// `flavour` (Darwin) has none: measured on Darwin 27.0, it applies none
    /// of their rules. Contradictory.
    | NoSuchSysctls of protection : ProtectedFiles * flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal ProtectedFilesRefusal =
    /// What this library knows about why it refused the setting, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : ProtectedFilesRefusal) : string =
        match refusal with
        | ProtectedFilesRefusal.NoSuchSysctls (protection, flavour) ->
            $"%A{protection} sets an fs.protected_* sysctl, which a %O{flavour} kernel does not have; it applies none of their rules (measured on Darwin 27.0, protected-sysctls.c). Leave every one of them Off."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ProtectedFilesRefusal) : RefusalKind =
        match refusal with
        | ProtectedFilesRefusal.NoSuchSysctls _ -> RefusalKind.Contradictory "protection"

/// Why `UnixBootImage.withPipeDevice` refuses a device.
[<RequireQualifiedAccess>]
type internal PipeDeviceRefusal =
    /// The machine is Darwin's, whose pipes all report `st_dev` 0 (measured
    /// on 27.0.0), and the device is not 0. Contradictory.
    | DarwinReportsZero of device : int64
    /// The device is negative, which no `dev_t` is. Contradictory.
    | Negative of device : int64

[<RequireQualifiedAccess>]
module internal PipeDeviceRefusal =
    /// What this library knows about why it refused the device, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : PipeDeviceRefusal) : string =
        match refusal with
        | PipeDeviceRefusal.DarwinReportsZero device ->
            $"%d{device} is not a device a Darwin pipe reports; every pipe on Darwin reports st_dev 0 (measured on 27.0.0)."
        | PipeDeviceRefusal.Negative device -> $"%d{device} is negative, which no dev_t is."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : PipeDeviceRefusal) : RefusalKind =
        match refusal with
        | PipeDeviceRefusal.DarwinReportsZero _ -> RefusalKind.Contradictory "device"
        | PipeDeviceRefusal.Negative _ -> RefusalKind.OutOfRange "device"

/// Why `UnixBootImage.withSoMaxConn` refuses a value.
[<RequireQualifiedAccess>]
type internal SoMaxConnRefusal =
    /// The value is below 1. Unmeasured: no kernel was measured with a
    /// non-positive `somaxconn`, so the accept-queue capacity it would imply
    /// is a guess.
    | NotPositive of value : int

[<RequireQualifiedAccess>]
module internal SoMaxConnRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : SoMaxConnRefusal) : string =
        match refusal with
        | SoMaxConnRefusal.NotPositive value ->
            $"%d{value} is not positive, and no kernel was measured with a non-positive somaxconn, so the accept-queue capacity it would imply is a guess."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SoMaxConnRefusal) : RefusalKind =
        match refusal with
        | SoMaxConnRefusal.NotPositive _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withInotifyLimits` refuses a value.
[<RequireQualifiedAccess>]
type internal InotifyLimitsRefusal =
    /// The machine is of `flavour` (Darwin), which has no inotify, so nothing
    /// would read the limits.
    | NotReadOn of flavour : SimulatedUnixFlavour
    /// `MaxUserInstances` is below 1. Unmeasured: Linux accepts 0, under which
    /// every `inotify_init1` would be `EMFILE`, but no machine was measured
    /// with it.
    | MaxUserInstancesNotPositive of value : int
    /// `MaxUserWatches` is below 1. Unmeasured, as for `MaxUserInstances`.
    | MaxUserWatchesNotPositive of value : int
    /// `MaxQueuedEvents` is below 1. Unmeasured: what an instance that may
    /// queue nothing does with its first record is a guess.
    | MaxQueuedEventsNotPositive of value : int
    /// `MaxQueuedEvents` is above `largest` (`InotifyLimits.largestQueuedEvents`):
    /// a full queue's bytes would pass what `ioctl(FIONREAD)`'s `int` holds,
    /// where Linux's count wraps. Unmodelled.
    | MaxQueuedEventsTooLarge of value : int * largest : int

[<RequireQualifiedAccess>]
module internal InotifyLimitsRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : InotifyLimitsRefusal) : string =
        match refusal with
        | InotifyLimitsRefusal.NotReadOn flavour ->
            $"the machine is %O{flavour}-flavoured, which has no inotify, so nothing would read the limits."
        | InotifyLimitsRefusal.MaxUserInstancesNotPositive value ->
            $"max_user_instances %d{value} is not positive. Linux accepts 0, under which every inotify_init1 is EMFILE, but no machine was measured with a limit below 1."
        | InotifyLimitsRefusal.MaxUserWatchesNotPositive value ->
            $"max_user_watches %d{value} is not positive. Linux accepts 0, under which every new watch is ENOSPC, but no machine was measured with a limit below 1."
        | InotifyLimitsRefusal.MaxQueuedEventsNotPositive value ->
            $"max_queued_events %d{value} is not positive, and what an instance that may queue no record does with its first one was not measured."
        | InotifyLimitsRefusal.MaxQueuedEventsTooLarge (value, largest) ->
            $"max_queued_events %d{value} is above %d{largest}: a full queue's bytes would pass what ioctl(FIONREAD) reports in an int, where Linux's count wraps, which this kernel does not model."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : InotifyLimitsRefusal) : RefusalKind =
        match refusal with
        | InotifyLimitsRefusal.NotReadOn _ -> RefusalKind.Contradictory "limits"
        | InotifyLimitsRefusal.MaxUserInstancesNotPositive _ -> RefusalKind.Unmodelled
        | InotifyLimitsRefusal.MaxUserWatchesNotPositive _ -> RefusalKind.Unmodelled
        | InotifyLimitsRefusal.MaxQueuedEventsNotPositive _ -> RefusalKind.Unmodelled
        | InotifyLimitsRefusal.MaxQueuedEventsTooLarge _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withTcpSendSpace` refuses a value.
[<RequireQualifiedAccess>]
type internal TcpSendSpaceRefusal =
    /// A value was configured on a machine of `flavour` (Linux), where this
    /// library models no TCP send buffer, so nothing would read it.
    /// Unmodelled.
    | NotReadOn of flavour : SimulatedUnixFlavour * value : int
    /// The value is above `max` (`UnixMachineState.darwinSocketBufferMax`,
    /// `kern.ipc.maxsockbuf`), and Darwin refuses such a
    /// `net.inet.tcp.sendspace` with ERANGE. Contradictory.
    | AboveSocketBufferMax of value : int * max : int
    /// The value is below `sendPipe` (`UnixMachineState.darwinLoopbackSendPipe`),
    /// the send pipe of Darwin's route to 127.0.0.1. A connection's handshake
    /// grows a send buffer that small to the send pipe of the route it takes,
    /// and this library does not model routes. Unmodelled.
    | BelowLoopbackSendPipe of value : int * sendPipe : int

[<RequireQualifiedAccess>]
module internal TcpSendSpaceRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : TcpSendSpaceRefusal) : string =
        match refusal with
        | TcpSendSpaceRefusal.NotReadOn (flavour, value) ->
            $"%d{value} was configured on a %O{flavour} machine, but this kernel models no %O{flavour} TCP send buffer, so nothing would read it."
        | TcpSendSpaceRefusal.AboveSocketBufferMax (value, max) ->
            $"%d{value} exceeds kern.ipc.maxsockbuf (%d{max}), and Darwin refuses such a net.inet.tcp.sendspace with ERANGE."
        | TcpSendSpaceRefusal.BelowLoopbackSendPipe (value, sendPipe) ->
            $"%d{value} is below %d{sendPipe}, the send pipe of Darwin's route to 127.0.0.1. A connection's handshake grows a send buffer that small to the send pipe of the route it takes, and this kernel does not model routes."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : TcpSendSpaceRefusal) : RefusalKind =
        match refusal with
        | TcpSendSpaceRefusal.NotReadOn _ -> RefusalKind.Unmodelled
        | TcpSendSpaceRefusal.AboveSocketBufferMax _ -> RefusalKind.OutOfRange "value"
        | TcpSendSpaceRefusal.BelowLoopbackSendPipe _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withProcessId` refuses a process ID.
[<RequireQualifiedAccess>]
type internal ProcessIdRefusal =
    /// On Linux, the ID is not below the machine's `pid_max`, so a Linux kernel
    /// could not have handed it out. Contradictory.
    | NotBelowPidMax of pid : ProcessId * pidMax : int32
    /// On Darwin, the ID is not below `PID_MAX` (`ProcessIdTable.darwinPidMax`,
    /// read from xnu's source and not measured), so a Darwin kernel could not
    /// have handed it out. Contradictory.
    | NotBelowDarwinPidMax of pid : ProcessId * pidMax : int32

[<RequireQualifiedAccess>]
module internal ProcessIdRefusal =
    /// What this library knows about why it refused the process ID, for a
    /// client composing a diagnostic that names its own knob.
    let describe (refusal : ProcessIdRefusal) : string =
        match refusal with
        | ProcessIdRefusal.NotBelowPidMax (pid, pidMax) ->
            $"process ID %O{pid} is not below pid_max %d{pidMax}, so a Linux kernel could not have handed it out."
        | ProcessIdRefusal.NotBelowDarwinPidMax (pid, pidMax) ->
            $"process ID %O{pid} is not below Darwin's PID_MAX %d{pidMax}, so a Darwin kernel could not have handed it out."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ProcessIdRefusal) : RefusalKind =
        match refusal with
        | ProcessIdRefusal.NotBelowPidMax _ -> RefusalKind.OutOfRange "pid"
        | ProcessIdRefusal.NotBelowDarwinPidMax _ -> RefusalKind.OutOfRange "pid"

/// Why `UnixBootImage.withLeaderThreadId` refuses a thread ID.
[<RequireQualifiedAccess>]
type internal LeaderThreadIdRefusal =
    /// The machine is Linux's, where the leader's thread ID is the process ID,
    /// so it cannot be set apart from it. Contradictory.
    | IsTheProcessIdOnLinux
    /// The ID is 0, which nothing says a Darwin kernel reports, or the largest
    /// 64-bit ID, which leaves the counter no ID for a second thread.
    /// Unmeasured.
    | OutsideCounter of id : uint64

[<RequireQualifiedAccess>]
module internal LeaderThreadIdRefusal =
    /// What this library knows about why it refused the thread ID, for a
    /// client composing a diagnostic that names its own knob.
    let describe (refusal : LeaderThreadIdRefusal) : string =
        match refusal with
        | LeaderThreadIdRefusal.IsTheProcessIdOnLinux ->
            "on Linux the leader's thread ID is the process ID, so it cannot be set apart from it; set the process ID instead."
        | LeaderThreadIdRefusal.OutsideCounter id ->
            $"%d{id} is not a thread ID this library will start a Darwin counter at; it must be between 1 and %d{System.UInt64.MaxValue - 1UL}."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : LeaderThreadIdRefusal) : RefusalKind =
        match refusal with
        | LeaderThreadIdRefusal.IsTheProcessIdOnLinux -> RefusalKind.Contradictory "id"
        | LeaderThreadIdRefusal.OutsideCounter _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withTcpReceiveSpace` refuses a value.
[<RequireQualifiedAccess>]
type internal TcpReceiveSpaceRefusal =
    /// The value is not positive, and Linux refuses such a
    /// `net.ipv4.tcp_rmem` default. Contradictory.
    | NotPositive of value : int
    /// Darwin would grow a receive buffer of this `net.inet.tcp.recvspace`
    /// again as data arrives, which this library does not model; `reason`
    /// says why.
    /// Unmodelled.
    | GrowsAfterHandshake of value : int * reason : string

[<RequireQualifiedAccess>]
module internal TcpReceiveSpaceRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : TcpReceiveSpaceRefusal) : string =
        match refusal with
        | TcpReceiveSpaceRefusal.NotPositive value ->
            $"%d{value} is not positive, and Linux refuses such a net.ipv4.tcp_rmem default."
        | TcpReceiveSpaceRefusal.GrowsAfterHandshake (_, reason) -> reason

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : TcpReceiveSpaceRefusal) : RefusalKind =
        match refusal with
        | TcpReceiveSpaceRefusal.NotPositive _ -> RefusalKind.OutOfRange "value"
        | TcpReceiveSpaceRefusal.GrowsAfterHandshake _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withUdpReceiveSpace` refuses a value.
[<RequireQualifiedAccess>]
type internal UdpReceiveSpaceRefusal =
    /// The value is below `floor`, the smallest receive buffer measured with
    /// datagrams of every size on this machine's flavour, so what it admits
    /// is a guess. Unmodelled.
    | BelowMeasured of value : int * floor : int
    /// The value is above `ceiling`, past which a rule this library has not
    /// measured decides what fits: Linux's admission takes another branch
    /// above `INT_MAX >> 1`, and Darwin's `kern.ipc.maxsockbuf` (8388608)
    /// caps the mbuf budget of a buffer above an eighth of it. Unmodelled.
    | AboveMeasured of value : int * ceiling : int

[<RequireQualifiedAccess>]
module internal UdpReceiveSpaceRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : UdpReceiveSpaceRefusal) : string =
        match refusal with
        | UdpReceiveSpaceRefusal.BelowMeasured (value, floor) ->
            $"%d{value} is below %d{floor}, the smallest UDP receive buffer measured with datagrams of every size on this flavour, so what it admits is a guess."
        | UdpReceiveSpaceRefusal.AboveMeasured (value, ceiling) ->
            $"%d{value} is above %d{ceiling}, past which a rule this library has not measured decides what a UDP receive buffer admits."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : UdpReceiveSpaceRefusal) : RefusalKind =
        match refusal with
        | UdpReceiveSpaceRefusal.BelowMeasured _
        | UdpReceiveSpaceRefusal.AboveMeasured _ -> RefusalKind.Unmodelled

/// Why `UnixBootImage.withTcpSendSpaceMax` refuses a value.
[<RequireQualifiedAccess>]
type internal TcpSendSpaceMaxRefusal =
    /// A value was configured on a machine of `flavour` (Darwin), where this
    /// library sizes a send buffer from `TcpSendSpace` alone, so nothing would
    /// read it. Unmodelled.
    | NotReadOn of flavour : SimulatedUnixFlavour * value : int
    /// The value is not positive, and Linux refuses such a `net.ipv4.tcp_wmem`
    /// maximum. Contradictory.
    | NotPositive of value : int

[<RequireQualifiedAccess>]
module internal TcpSendSpaceMaxRefusal =
    /// What this library knows about why it refused the value, for a client
    /// composing a diagnostic that names its own knob.
    let describe (refusal : TcpSendSpaceMaxRefusal) : string =
        match refusal with
        | TcpSendSpaceMaxRefusal.NotReadOn (flavour, value) ->
            $"%d{value} was configured on a %O{flavour} machine, but this kernel sizes a %O{flavour} send buffer from TcpSendSpace alone, so nothing would read it."
        | TcpSendSpaceMaxRefusal.NotPositive value ->
            $"%d{value} is not positive, and Linux refuses such a net.ipv4.tcp_wmem maximum."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : TcpSendSpaceMaxRefusal) : RefusalKind =
        match refusal with
        | TcpSendSpaceMaxRefusal.NotReadOn _ -> RefusalKind.Unmodelled
        | TcpSendSpaceMaxRefusal.NotPositive _ -> RefusalKind.OutOfRange "value"

/// The boot-time configuration of a simulated machine, applied to the
/// `UnixBootImage` that `UnixSystem.initial` makes, and `boot`, which ends it
/// by launching the machine's first process.
///
/// Every setter here takes and returns an image, and no syscall takes one, so
/// a setting cannot be applied to a system that has already run: it describes
/// the machine from the moment it booted. What changes while the machine runs
/// is a syscall's effect, or an operation of the outside world on the running
/// system, such as `UnixSystem.advanceClock`. How a process starts is not
/// here but in its `ProcessLaunch`, which `boot` takes, apart from the IDs of
/// the first process, which are where the machine's counters start.
///
/// A setter that refuses a value returns `Result`, as a syscall does: its
/// `Error` is a refusal type of its own whose cases state the facts, and whose
/// `describe` says them. Only the caller knows what it called the value,
/// so naming that is the caller's.
[<RequireQualifiedAccess>]
module UnixBootImage =

    let private withMachine<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (image : UnixBootImage<'Thread, 'Handler>)
        (machine : UnixMachineState)
        : UnixBootImage<'Thread, 'Handler>
        =
        { image with
            Machine = machine
        }

    /// The platform the machine was made for, which every launch onto it must
    /// be described for (`ProcessLaunch.create`).
    let platform<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (image : UnixBootImage<'Thread, 'Handler>)
        : SimulatedUnixPlatform
        =
        image.Machine.UnixPlatform

    /// `boot`, with a refusal answered as the `Error` rather than raised.
    let internal tryBoot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixSystem<'Thread, 'Handler>, BootRefusal>
        =
        // The two settings constrain each other, so they are judged here,
        // where both are final, whichever setter ran first. Measured on Linux
        // (`docs/probes/local-port-range`, `docs/probes/unprivileged-port-start`);
        // Darwin's start is fixed at 1024, and its range is not judged
        // against it.
        let low, _ = image.Machine.EphemeralPortRange
        let start = image.Machine.UnprivilegedPortStart

        match SimulatedUnixPlatform.flavour image.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux when low < start ->
            Error (BootRefusal.EphemeralPortsBelowUnprivilegedPortStart (low, start))
        | SimulatedUnixFlavour.Linux
        | SimulatedUnixFlavour.Darwin ->

        let leaderThreadId =
            match ThreadIdAllocator.live image.Machine.ThreadIds |> Set.toList with
            | [ id ] -> id
            | ids ->
                failwith
                    $"UnixBootImage.boot: the boot image's thread ID allocator records %A{ids} as live, where it holds the first process's leader's alone (this is a bug in this library)."

        ProcessLaunch.launchOnto launch image.ProcessId leaderThreadId image.Machine
        |> Result.mapError BootRefusal.Launch
        |> Result.map (fun (machine, proc, threads) ->
            let slot : ProcessSlot<'Thread, 'Handler> =
                {
                    Process = proc
                    Threads = threads
                    Leader = ProcessLaunch.leader launch
                }

            {
                Machine = machine
                Scheduling = UnixSchedulingState.initial
                Processes = ProcessTable.empty |> ProcessTable.add (ProcessId.toInt32 image.ProcessId) slot
                Sweep = WakeMemo.none
            }
        )

    /// <summary>
    /// The machine this image describes, booted, with `launch` as its first
    /// process, ready for that process's first syscall. After this, nothing in
    /// this module applies to it.
    ///
    /// The process has the ID `withProcessId` set, `UnixSystem.defaultProcessId`
    /// unless it was set, and its leader the thread ID the machine's counter
    /// starts at. Refuses a launch described for another platform, one whose
    /// leader is on a processor the machine does not have, and one whose
    /// directory the machine's filesystem does not let it start in; and, on
    /// Linux, an image whose ephemeral range starts below its unprivileged
    /// port start.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The path does not resolve in the seeded filesystem at all. Carries what the walk answered. The walk refused the path as too long. Distinguished from `DoesNotResolve` because the directory may well be present: it is a *length* that is unusable, and the remedy is to shorten something rather than to go looking for a missing directory.  Which length is deliberately not said, because the walk does not say: `ENAMETOOLONG` is one errno covering a component past this flavour's `NAME_MAX` and — on a flavour that re-checks, which is Darwin — a symbolic link whose expansion would carry the whole path past `PATH_MAX`. A real kernel conflates them too. Splitting the case would need the path walk to report which limit it hit, which every other caller of the walk would pay for.  Carries the flavour so that a fault which outlives the call still says whose limits were in force -- 255 CJK characters name a directory a Darwin process can start in and a Linux one cannot, and only Darwin re-checks a splice at all. The path resolves, to something that is not a directory. The launch puts its leader on the logical processor `cpu`, and the machine has `processorCount`, numbered from 0, which do not include it. Contradictory: no kernel runs a thread on a processor it does not have. Under Linux, the ephemeral range starts at `low`, below the unprivileged port start `start`. Linux refuses either sysctl a value that would leave them so, so no Linux machine has them. Contradictory.</exception>
    /// <exception cref="T:System.InvalidOperationException">The launch was described for the platform `launch`, and the machine is `machine`: the description was checked against the wrong platform's rules.</exception>
    let boot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        tryBoot launch image
        |> Refusal.orRaise "UnixBootImage.boot" BootRefusal.kind BootRefusal.describe

    /// `withProcessId`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithProcessId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, ProcessIdRefusal>
        =
        let pid = ProcessId.assertValidFor "UnixBootImage.withProcessId" "pid" pid
        let machine = image.Machine

        match machine.ThreadIds.Counter with
        | ThreadIdCounter.Linux (_, pidMax) ->
            if ProcessId.toInt32 pid >= pidMax then
                Error (ProcessIdRefusal.NotBelowPidMax (pid, pidMax))
            else
                let _, threadIds =
                    ThreadIdAllocator.startLinux "UnixBootImage.withProcessId" pidMax pid

                Ok
                    { image with
                        Machine =
                            { machine with
                                ThreadIds = threadIds
                            }
                        ProcessId = pid
                    }
        | ThreadIdCounter.Darwin _ ->
            if ProcessId.toInt32 pid >= ProcessIdTable.darwinPidMax then
                Error (ProcessIdRefusal.NotBelowDarwinPidMax (pid, ProcessIdTable.darwinPidMax))
            else
                Ok
                    { image with
                        Machine =
                            { machine with
                                ProcessIds = ProcessIdTable.darwinAfter pid
                            }
                        ProcessId = pid
                    }

    /// <summary>
    /// Set the ID `getpid(2)` reports for the machine's first process. On
    /// Linux this is also its leader's thread ID, and the thread IDs the
    /// machine hands out next follow on from it. On Darwin the process IDs the
    /// machine hands out next follow on from it.
    ///
    /// Refuses, on Linux, a process ID that is not below the machine's
    /// `pid_max`, and on Darwin one that is not below `PID_MAX`
    /// (`ProcessIdTable.darwinPidMax`).
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">On Linux, the ID is not below the machine's `pid_max`, so a Linux kernel could not have handed it out. Contradictory. On Darwin, the ID is not below `PID_MAX` (`ProcessIdTable.darwinPidMax`, read from xnu's source and not measured), so a Darwin kernel could not have handed it out. Contradictory.</exception>
    /// <exception cref="T:System.ArgumentException">`pid` is a forged value, such as `Unchecked.defaultof`, which is no process ID.</exception>
    let withProcessId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithProcessId pid image
        |> Refusal.orRaise "UnixBootImage.withProcessId" ProcessIdRefusal.kind ProcessIdRefusal.describe

    /// `withLeaderThreadId`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithLeaderThreadId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (id : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, LeaderThreadIdRefusal>
        =
        let machine = image.Machine

        match machine.ThreadIds.Counter with
        | ThreadIdCounter.Linux _ -> Error LeaderThreadIdRefusal.IsTheProcessIdOnLinux
        | ThreadIdCounter.Darwin _ ->
            // Neither end has been observed. 0 is not refused because a kernel
            // was seen not to report it, but because nothing says one would,
            // and the largest leaves no ID for a second thread.
            if id = 0UL || id = System.UInt64.MaxValue then
                Error (LeaderThreadIdRefusal.OutsideCounter id)
            else
                let _, threadIds =
                    ThreadIdAllocator.startDarwin "UnixBootImage.withLeaderThreadId" id

                { machine with
                    ThreadIds = threadIds
                }
                |> withMachine image
                |> Ok

    /// <summary>
    /// Set the first process's leader's thread ID on Darwin, where it is
    /// unrelated to the process ID; the IDs the machine's later threads get
    /// follow on from it.
    ///
    /// Refuses a Linux machine, where the leader's thread ID is the process ID
    /// (set that with `withProcessId`), and 0 and the largest 64-bit ID.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The machine is Linux's, where the leader's thread ID is the process ID, so it cannot be set apart from it. Contradictory.</exception>
    let withLeaderThreadId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (id : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithLeaderThreadId id image
        |> Refusal.orRaise "UnixBootImage.withLeaderThreadId" LeaderThreadIdRefusal.kind LeaderThreadIdRefusal.describe

    /// `withFileSystem`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithFileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (createdAt : UnixTimestamp)
        (defaultOwner : InodeOwner)
        (seed : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, FileSystemSeedFault>
        =
        let machine = image.Machine
        let platform = machine.UnixPlatform

        // A new filesystem hands out its own inode numbers, so a handle onto
        // the old graph would afterwards dangle or silently name whatever the
        // new one gave the same number. An image holds none: no process has
        // been launched onto it.

        let limits = SimulatedUnixPlatform.pathLimits platform
        let bindable = SimulatedUnixPlatform.bindableEntryNames platform
        let nameMatching = SimulatedUnixPlatform.entryNameMatching platform
        let flavour = SimulatedUnixPlatform.flavour platform

        // The first offender in `Map` order, which is the order the seed is
        // realised in; a directory's names are each checked, and its
        // subdirectories with them, before the directory itself is checked
        // for two spellings of one name.
        let rec firstImpossibleName (entries : Map<DirectoryEntryName, SeedEntry>) : FileSystemSeedFault option =
            let ofEachName =
                entries
                |> Map.toSeq
                |> Seq.tryPick (fun (name, entry) ->
                    // A forged name or target is refused naming the seed,
                    // rather than reaching the measurement as a null.
                    let name =
                        DirectoryEntryName.assertValidFor "UnixBootImage.withFileSystem" "seed" name

                    if not (PathLimits.nameWithinLimit limits name) then
                        Some (FileSystemSeedFault.SeedNameTooLong (name, flavour))
                    elif not (BindableEntryNames.admits bindable name) then
                        Some (FileSystemSeedFault.SeedNameNotBindable (name, flavour))
                    else
                        match entry with
                        | SeedEntry.Directory (children, _, _) -> firstImpossibleName children
                        | SeedEntry.File _ -> None
                        | SeedEntry.CharacterDevice _ -> Some (FileSystemSeedFault.SeedHoldsDeviceNode name)
                        | SeedEntry.Symlink (target, _) ->
                            let target =
                                SymlinkTarget.assertValidFor "UnixBootImage.withFileSystem" "seed" target

                            // `symlink(2)` copies its target in as it does a
                            // pathname, so a target it could not copy in is
                            // one no process made. Measured by
                            // `docs/probes/symlink-target-length` on tmpfs,
                            // ext4, APFS and HFS+: the limit is the flavour's
                            // whatever the filesystem, as the mount type here
                            // does not change it.
                            match
                                PathArgument.copyIn
                                    limits
                                    (PathArgumentBytes.Bytes (SymlinkTarget.toByteString target))
                            with
                            | PathArgument.Parsed _ -> None
                            | PathArgument.Failed _ ->
                                Some (FileSystemSeedFault.SeedSymlinkTargetTooLong (name, flavour))
                )

            match ofEachName, nameMatching with
            | Some fault, _ -> Some fault
            | None, EntryNameMatching.Bytes -> None
            | None, EntryNameMatching.CanonicalEquivalence ->
                EntryNameMatching.firstPossiblyEquivalentPair (Map.keys entries)
                |> Option.map (fun (first, second) ->
                    FileSystemSeedFault.SeedNamesPossiblyEquivalent (first, second, flavour)
                )

        match firstImpossibleName seed with
        | Some fault -> Error fault
        | None ->

        let rootSeed : RootFileSystemSeed =
            {
                SeedCreatedAt = createdAt
                SeedOwner = defaultOwner
                SeedEntries = seed
            }

        match
            UnixSystem.realiseFileSystem platform machine.DeviceMount machine.BootTime rootSeed image.DeviceContents
        with
        | Error (MountFault.CoveredEntryNotAnEmptyDirectory name) ->
            Error (FileSystemSeedFault.SeedCoversDeviceFileSystem name)
        | Ok filesystem ->
            { image with
                Machine =
                    { machine with
                        CommittedFileSystem = CommittedFileSystem.initial filesystem
                    }
                RootSeed = rootSeed
            }
            |> Ok

    /// <summary>
    /// Realise `seed` as this machine's filesystem, created at `createdAt`.
    ///
    /// Takes the moment explicitly rather than reading the machine's realtime
    /// clock, so that the result does not depend on whether the caller
    /// happened to set the clock before or after the filesystem.
    ///
    /// `defaultOwner` owns the root and every seed entry that states no owner
    /// of its own.
    ///
    /// Every name in the seed is checked against the machine's platform: its
    /// `NAME_MAX`, then its rule for which names it binds, the order a binding
    /// checks them in. A name a kernel could never have created is not one its
    /// filesystem can hold. Likewise every symbolic link's target is checked
    /// against the longest target the platform's `symlink(2)` stores, which is
    /// its `PATH_MAX` less the NUL, whatever `withMount` says the filesystem
    /// is. Also refuses a seed whose `dev` at the root is
    /// anything but an empty directory, since the device filesystem is mounted
    /// there.
    ///
    /// On Darwin, whose filesystem holds at most one canonically equivalent
    /// spelling of a name in a directory, also refuses a seed with a directory
    /// holding two names that might be two such spellings: this library holds
    /// no Unicode tables to tell, and raises `UnmodelledException`. Refuses a
    /// seed holding a device node the same way: this kernel holds device nodes
    /// only in the device filesystem (`withDeviceFileSystem`).
    ///
    /// The device filesystem holds what `withDeviceFileSystem` last set,
    /// whichever of the two was called first.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The seed holds a directory entry whose name is past this flavour's `NAME_MAX`, so it describes a filesystem no kernel of that flavour could have mounted: `stat` of the name would answer ENAMETOOLONG while `readdir` listed it. The seed holds a directory entry whose name this flavour's filesystem will not bind (see `SimulatedUnixPlatform.bindableEntryNames`): on Darwin, a name that is not valid UTF-8. No kernel of that flavour could have created it, and a process there could not create it either. The seed holds a symbolic link whose target is longer than this flavour's `symlink(2)` stores (1023 bytes on Darwin, 4095 on Linux), so no process of that flavour could have created it. The seed binds `dev` at its root to something other than an empty directory. The kernel mounts its device filesystem there at boot, and a mount over a populated directory would hide what it holds. The seed holds a forged name or symbolic-link target, such as `Unchecked.defaultof`.</exception>
    let withFileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (createdAt : UnixTimestamp)
        (defaultOwner : InodeOwner)
        (seed : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithFileSystem createdAt defaultOwner seed image
        |> Refusal.orRaise "UnixBootImage.withFileSystem" FileSystemSeedFault.kind FileSystemSeedFault.describe

    /// `withDeviceFileSystem`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithDeviceFileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (contents : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, DeviceFileSystemFault>
        =
        let machine = image.Machine
        let platform = machine.UnixPlatform
        let flavour = SimulatedUnixPlatform.flavour platform
        let limits = SimulatedUnixPlatform.pathLimits platform

        let root =
            {
                User = UserId.root
                Group = GroupId.parseOrFail "UnixBootImage.withDeviceFileSystem" 0u
            }

        // What the device filesystem refuses of one entry, apart from its
        // children. Linux binds any name and matches names byte for byte, so
        // the length is all there is to check of a name there.
        let entryFault (name : DirectoryEntryName) (entry : SeedEntry) : DeviceFileSystemFault option =
            match machine.DeviceMount with
            | DeviceFileSystemMount.Devtmpfs _ ->
                if not (PathLimits.nameWithinLimit limits name) then
                    Some (DeviceFileSystemFault.NameTooLong (name, 255))
                else
                    match entry with
                    | SeedEntry.Directory _
                    | SeedEntry.CharacterDevice _ -> None
                    | SeedEntry.File _
                    | SeedEntry.Symlink _ -> Some (DeviceFileSystemFault.NotMadeByDeviceFileSystem name)
            | DeviceFileSystemMount.Devfs _ ->
                // devfs keeps a name in a 32-byte buffer with its NUL, and
                // `pathconf(_PC_NAME_MAX)` of `/dev` reports 31 (measured on
                // Darwin 27.0, `darwin-devfs.c`, PATHCONF row).
                if UnixByteString.length (DirectoryEntryName.toByteString name) > 31 then
                    Some (DeviceFileSystemFault.NameTooLong (name, 31))
                else
                    match entry with
                    | SeedEntry.Directory (_, permissions, owner) ->
                        let owner = owner |> Option.defaultValue root

                        if permissions <> PermissionBits 0o555 || owner <> root then
                            Some (DeviceFileSystemFault.DirectoryNotAsDevfsMakesIt (name, permissions, owner))
                        else
                            None
                    | SeedEntry.CharacterDevice (number, _, _) ->
                        if DeviceNumber.isEncodableUnder flavour number then
                            None
                        else
                            Some (DeviceFileSystemFault.NumberNotEncodable (name, number))
                    | SeedEntry.File _
                    | SeedEntry.Symlink _ -> Some (DeviceFileSystemFault.NotMadeByDeviceFileSystem name)

        // The first offender in `Map` order, a directory's children before
        // the names after it, and a directory's own pair of possibly
        // equivalent names after all of them, as `withFileSystem` finds one.
        let rec firstFault (entries : Map<DirectoryEntryName, SeedEntry>) : DeviceFileSystemFault option =
            let ofEachName =
                entries
                |> Map.toSeq
                |> Seq.tryPick (fun (name, entry) ->
                    let name =
                        DirectoryEntryName.assertValidFor "UnixBootImage.withDeviceFileSystem" "contents" name

                    match entryFault name entry with
                    | Some fault -> Some fault
                    | None ->
                        match entry with
                        | SeedEntry.Directory (children, _, _) -> firstFault children
                        | SeedEntry.CharacterDevice _
                        | SeedEntry.File _
                        | SeedEntry.Symlink _ -> None
                )

            match ofEachName, SimulatedUnixPlatform.entryNameMatching platform with
            | Some fault, _ -> Some fault
            | None, EntryNameMatching.Bytes -> None
            | None, EntryNameMatching.CanonicalEquivalence ->
                EntryNameMatching.firstPossiblyEquivalentPair (Map.keys entries)
                |> Option.map DeviceFileSystemFault.NamesPossiblyEquivalent

        match firstFault contents with
        | Some fault -> Error fault
        | None ->

        match UnixSystem.realiseFileSystem platform machine.DeviceMount machine.BootTime image.RootSeed contents with
        | Error fault ->
            failwith
                $"UnixBootImage.withDeviceFileSystem: mounting the device filesystem failed with %A{fault}, over a root seed it was mounted over before (this is a bug in this library)."
        | Ok filesystem ->
            { image with
                Machine =
                    { machine with
                        CommittedFileSystem = CommittedFileSystem.initial filesystem
                    }
                DeviceContents = contents
            }
            |> Ok

    /// <summary>
    /// Set what the machine's device filesystem, mounted at `/dev`, holds:
    /// `contents`, realised as `withFileSystem` realises a seed, owned by root
    /// unless an entry says otherwise. On Linux it is a devtmpfs, whose every
    /// inode is made at the epoch, as devtmpfs makes its own nodes before the
    /// realtime clock is set; on Darwin a devfs, whose inodes are made at the
    /// whole second `withBootTime` set and born at the epoch.
    ///
    /// Each name is what `readdir(3)` lists and `stat(2)` reports, whether or
    /// not this kernel has a driver for the number a node holds; opening a
    /// node whose number has none raises `UnmodelledException`
    /// (`CharacterDevice.all` lists the drivers, all of them Linux's). A name
    /// it does not hold is ENOENT. `UnixSystem.defaultDevtmpfsContents` and
    /// `UnixSystem.defaultDevfsContents` are what it holds unless this is
    /// called.
    ///
    /// Raises `UnmodelledException` for contents holding a regular file or a
    /// symbolic link: a device filesystem makes only device nodes and the
    /// directories holding them, at boot, and anything else in it was made by
    /// a process afterwards, at a time and with an access-time history this
    /// configuration does not describe. Likewise, on Darwin, for a directory
    /// whose mode is not 0555 or whose owner is not root, which is how devfs
    /// makes every directory, and for a directory holding two names that might
    /// be canonically equivalent spellings of one, which this kernel cannot
    /// tell apart.
    ///
    /// The root filesystem is what `withFileSystem` last set, whichever of the
    /// two was called first.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The contents hold an entry whose name is longer than the device filesystem holds: Linux's `NAME_MAX` for a devtmpfs, 31 bytes for Darwin's devfs. On Darwin, a node holds a number its 32-bit `dev_t` cannot encode: a major past 255 or a minor past 0xFFFFFF. The contents hold a forged name, such as `Unchecked.defaultof`.</exception>
    let withDeviceFileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (contents : Map<DirectoryEntryName, SeedEntry>)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithDeviceFileSystem contents image
        |> Refusal.orRaise
            "UnixBootImage.withDeviceFileSystem"
            DeviceFileSystemFault.kind
            DeviceFileSystemFault.describe

    /// `withUserAddressLimit`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithUserAddressLimit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (limit : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, UserAddressLimitRefusal>
        =
        let machine = image.Machine

        let platform = machine.UnixPlatform

        if not (SimulatedUnixPlatform.screensUserBufferUpFront platform) then
            Error (UserAddressLimitRefusal.NoUpFrontScreen (SimulatedUnixPlatform.flavour platform))
        else

        let architecture = SimulatedUnixPlatform.architecture platform

        match ObservedUserAddressLimit.architectureOf limit with
        | Some observed when observed = architecture ->
            { machine with
                UserBufferCheck = UserBufferCheck.BeforeOperation limit
            }
            |> withMachine image
            |> Ok
        | observedOn -> Error (UserAddressLimitRefusal.NotObservedOn (limit, architecture, observedOn))

    /// <summary>
    /// Set the greatest range end a user buffer may reach: the machine's
    /// `TASK_SIZE_MAX`.
    ///
    /// Refuses a limit on a platform that screens no buffer up front, which
    /// has no such limit to set, and a limit no machine of the platform's
    /// architecture has been observed to have (see `ObservedUserAddressLimit`).
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The machine's flavour screens no buffer before performing an operation (Darwin), so it has no `TASK_SIZE_MAX` for a limit to set. Contradictory: no machine of the flavour has the setting.</exception>
    let withUserAddressLimit<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (limit : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithUserAddressLimit limit image
        |> Refusal.orRaise
            "UnixBootImage.withUserAddressLimit"
            UserAddressLimitRefusal.kind
            UserAddressLimitRefusal.describe

    /// Seed the machine's entropy pool, which every random-bytes syscall draws
    /// from, with `seed` in place of `UnixSystem.defaultEntropySeed`. Every
    /// byte the pool hands out follows from the seed, so a run that must replay
    /// bit for bit depends on it.
    let withEntropySeed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (seed : uint64)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        { image.Machine with
            EntropyPool = EntropyPool.ofSeed seed
        }
        |> withMachine image

    /// `withProcessorCount`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithProcessorCount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (count : int)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, ProcessorCountRefusal>
        =
        let machine = image.Machine

        if count < 1 then
            Error (ProcessorCountRefusal.NotPositive count)
        else

        { machine with
            ProcessorCount = count
        }
        |> withMachine image
        |> Ok

    /// <summary>
    /// Set the logical-processor count the simulated process reports.
    ///
    /// Refuses a count below 1 at the boundary, rather than letting it reach a
    /// program that will divide by it.
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The count is below 1. Contradictory: a machine running the process has at least the processor it runs on, and programs divide by the count.</exception>
    let withProcessorCount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (count : int)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithProcessorCount count image
        |> Refusal.orRaise "UnixBootImage.withProcessorCount" ProcessorCountRefusal.kind ProcessorCountRefusal.describe

    /// `withEphemeralPortRange`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithEphemeralPortRange<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        ((low, high) : uint16 * uint16)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, EphemeralPortRangeRefusal>
        =
        let machine = image.Machine
        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        // Measured on Linux (`docs/probes/local-port-range`): the sysctl takes
        // ip_unprivileged_port_start <= low <= high, the first of which `boot`
        // judges, once the unprivileged port start is final too. Measured on
        // Darwin 27.0 as root (`docs/probes/darwin-root/port-range.c`): any
        // value below 1024 written to first or last reads back 1024, and any
        // above 65535 reads back 65535; a first above last is kept, and binds
        // of port 0 then take the ports between them downwards.
        if low = 0us then
            Error (EphemeralPortRangeRefusal.LowIsZero high)
        elif flavour = SimulatedUnixFlavour.Darwin && (low < 1024us || high < 1024us) then
            Error (EphemeralPortRangeRefusal.BelowDarwinFloor (low, high))
        elif low > high then
            match flavour with
            | SimulatedUnixFlavour.Darwin -> Error (EphemeralPortRangeRefusal.Descending (low, high))
            | SimulatedUnixFlavour.Linux -> Error (EphemeralPortRangeRefusal.Empty (low, high))
        else

        { machine with
            EphemeralPortRange = low, high
            NextEphemeralPort = low
        }
        |> withMachine image
        |> Ok

    /// <summary>
    /// Sets the ephemeral range, inclusive at both ends, and rewinds the
    /// cursor into it: a cursor left outside the range would hand out its first
    /// port from wherever the previous range had reached.
    ///
    /// Refuses a range that starts at port 0, and an empty one. On Linux,
    /// `boot` refuses a range that starts below the unprivileged port start
    /// (`withUnprivilegedPortStart`), as Linux's sysctl does. On Darwin it
    /// refuses a range with an end below 1024, which Darwin's sysctls never
    /// hold, and one whose low end is above its high end, which Darwin
    /// searches downwards and this kernel does not model.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">On Linux, the low end is above the high end, so the range holds no port and no bind of port 0 could be answered. Contradictory.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The range starts at port 0, which is how a process *asks* for an ephemeral port, so it cannot also be one handed out; or, on Darwin, has an end below 1024, where no Darwin machine's range does. Contradictory.</exception>
    let withEphemeralPortRange<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        ((low, high) : uint16 * uint16)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithEphemeralPortRange (low, high) image
        |> Refusal.orRaise
            "UnixBootImage.withEphemeralPortRange"
            EphemeralPortRangeRefusal.kind
            EphemeralPortRangeRefusal.describe

    /// `withUnprivilegedPortStart`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithUnprivilegedPortStart<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (start : uint16)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, UnprivilegedPortStartRefusal>
        =
        let machine = image.Machine

        match SimulatedUnixPlatform.flavour machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (UnprivilegedPortStartRefusal.NoSuchSetting SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->
            { machine with
                UnprivilegedPortStart = start
            }
            |> withMachine image
            |> Ok

    /// <summary>
    /// Sets Linux's <c>net.ipv4.ip_unprivileged_port_start</c>: the lowest port
    /// a process without privilege may bind. A port below it is
    /// <c>EACCES</c> to an unprivileged <c>bind(2)</c>, at every address. 0
    /// and 1 leave no port privileged.
    ///
    /// Linux takes a value only at or below the ephemeral range's low end, and
    /// a range only starting at or above it, so <c>boot</c> refuses an image
    /// whose range starts below the value, whichever of the two setters ran
    /// first. Darwin has no such setting, and refuses any value.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The machine is of `flavour` (Darwin), which has no such setting: its privileged ports end at 1024, which nothing configures. Contradictory.</exception>
    let withUnprivilegedPortStart<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (start : uint16)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithUnprivilegedPortStart start image
        |> Refusal.orRaise
            "UnixBootImage.withUnprivilegedPortStart"
            UnprivilegedPortStartRefusal.kind
            UnprivilegedPortStartRefusal.describe

    /// `withBootTime`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithBootTime<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (bootTime : UnixTimestamp)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, BootTimeRefusal>
        =
        let machine = image.Machine

        let seconds = UnixTimestamp.seconds bootTime

        let finerThanDarwinKeeps =
            match SimulatedUnixPlatform.flavour machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux -> false
            | SimulatedUnixFlavour.Darwin -> UnixTimestamp.nanoseconds bootTime % 1000 <> 0

        if seconds < 0L then
            Error (BootTimeRefusal.BeforeEpoch bootTime)
        elif seconds > UnixMachineState.maxBootTimeSeconds then
            Error (BootTimeRefusal.PastMaxBootTime (bootTime, UnixMachineState.maxBootTimeSeconds))
        elif finerThanDarwinKeeps then
            Error (BootTimeRefusal.FinerThanMicrosecond bootTime)
        else

        // A devfs's times are the boot's, so the filesystem is realised afresh
        // from what the other setters last set.
        match
            UnixSystem.realiseFileSystem
                machine.UnixPlatform
                machine.DeviceMount
                bootTime
                image.RootSeed
                image.DeviceContents
        with
        | Error fault ->
            failwith
                $"UnixBootImage.withBootTime: mounting the device filesystem failed with %A{fault}, over a root seed it was mounted over before (this is a bug in this library)."
        | Ok filesystem ->

        { machine with
            BootTime = bootTime
            CommittedFileSystem = CommittedFileSystem.initial filesystem
        }
        |> withMachine image
        |> Ok

    /// <summary>
    /// Set what the realtime clock read when this machine booted. On Darwin,
    /// the device filesystem's times are this instant's whole second, whichever
    /// of this and the filesystem setters was called first.
    ///
    /// Refuses an instant before the Unix epoch, since this library models no
    /// realtime clock reading before it, and one after `UnixMachineState.maxBootTimeSeconds`, from
    /// which the realtime clock could leave `time_t`. On Darwin, also refuses an
    /// instant with a nonzero sub-microsecond part: Darwin keeps the time it
    /// booted as a `struct timeval`, so it has no finer boot instant.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">On Darwin, the instant has a nonzero sub-microsecond part. Darwin keeps the time it booted as a `struct timeval` (`sysctl kern.boottime`), so no Darwin machine booted at it. Contradictory.</exception>
    let withBootTime<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (bootTime : UnixTimestamp)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithBootTime bootTime image
        |> Refusal.orRaise "UnixBootImage.withBootTime" BootTimeRefusal.kind BootTimeRefusal.describe

    /// Set the IPv4 addresses this machine holds (`addresses`) and
    /// the prefixes of its local routes (`routes`). Together they decide which
    /// addresses `bind(2)` takes, and which destinations `connect(2)` treats as
    /// this machine's own. The wildcard always binds. Beyond that the flavours
    /// read the lists differently: Linux binds any address inside a route's
    /// prefix, so `127.9.9.9` binds under `127.0.0.0/8`, while Darwin binds
    /// only the addresses themselves. Likewise a TCP connect: Linux answers it
    /// at any address inside a route's prefix, while Darwin answers it only at
    /// the addresses themselves and drops the SYN to any other address on a
    /// route, a wait `connect(2)` refuses to model. A datagram connect needs
    /// only the route, on both.
    ///
    /// Admits any lists, stored as given. An empty list is a machine with
    /// nothing in it: with no addresses, only the wildcard binds. Entries may
    /// repeat or overlap, as on a real machine: every Linux's local table holds
    /// both `127.0.0.0/8` and `127.0.0.1/32`, and an address assigned to two
    /// interfaces holds two routes to one prefix.
    let withLocalIpv4Addresses<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (addresses : Ipv4Address list)
        (routes : Ipv4Prefix list)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        let machine = image.Machine

        { machine with
            LocalIpv4Addresses = addresses
            LocalRoutes = routes
        }
        |> withMachine image

    /// `withMount`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithMount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (mount : EmulatedMount option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, MountRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        let resolved =
            match mount with
            | None -> Ok (EmulatedMount.defaultFor flavour)
            | Some requested ->
                let fsType = EmulatedMount.fileSystemType requested

                if EmulatedFileSystemType.isReportableUnder flavour fsType then
                    Ok requested
                else
                    Error (MountRefusal.NotReportableUnder (fsType, flavour))

        resolved
        |> Result.map (fun resolved ->
            { machine with
                Mount = resolved
            }
            |> withMachine image
        )

    /// <summary>
    /// Set the mount the machine's filesystem claims to be. `None` takes the
    /// flavour's own default.
    ///
    /// Refuses a mount of a type this machine's flavour could not report,
    /// because `fstatfs(2)` answers a *file* from the mount and every other
    /// descriptor from the flavour, so the pair must describe one machine.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">A kernel of `flavour` cannot report `fileSystemType` (`EmulatedFileSystemType.isReportableUnder`), so a process asking `fstatfs(2)` would learn a fact no such system could tell it: APFS on Linux is contradictory, since no mainline Linux filesystem reports its type; tmpfs on Darwin is unmeasured, since a Darwin machine can mount one but none has been measured.</exception>
    let withMount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (mount : EmulatedMount option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithMount mount image
        |> Refusal.orRaise "UnixBootImage.withMount" MountRefusal.kind MountRefusal.describe

    /// `withProtectedFiles`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithProtectedFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (protection : ProtectedFiles)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, ProtectedFilesRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        if not (UnixMachineState.isProtectedFilesOf flavour protection) then
            Error (ProtectedFilesRefusal.NoSuchSysctls (protection, flavour))
        else

        { machine with
            ProtectedFiles = protection
        }
        |> withMachine image
        |> Ok

    /// <summary>
    /// Set the `fs.protected_*` sysctls.
    ///
    /// Refuses anything but `ProtectedFiles.off` on Darwin, which has no such
    /// settings.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">`protection` sets an `fs.protected_*` sysctl, and a kernel of `flavour` (Darwin) has none: measured on Darwin 27.0, it applies none of their rules. Contradictory.</exception>
    let withProtectedFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (protection : ProtectedFiles)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithProtectedFiles protection image
        |> Refusal.orRaise "UnixBootImage.withProtectedFiles" ProtectedFilesRefusal.kind ProtectedFilesRefusal.describe

    /// `withPipeDevice`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithPipeDevice<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (device : int64 option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, PipeDeviceRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        let resolved =
            match device, flavour with
            | None, _ -> Ok (UnixMachineState.defaultPipeDevice flavour)
            | Some device, SimulatedUnixFlavour.Darwin when device <> 0L ->
                Error (PipeDeviceRefusal.DarwinReportsZero device)
            | Some device, _ when device < 0L -> Error (PipeDeviceRefusal.Negative device)
            | Some device, _ -> Ok device

        resolved
        |> Result.map (fun resolved ->
            { machine with
                PipeDevice = resolved
            }
            |> withMachine image
        )

    /// <summary>
    /// Set the `st_dev` every pipe reports. `None` takes the flavour's default
    /// (`UnixMachineState.defaultPipeDevice`).
    ///
    /// Refuses anything but 0 on Darwin, whose pipes all report 0, and a
    /// negative device on Linux, which no `dev_t` is.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The machine is Darwin's, whose pipes all report `st_dev` 0 (measured on 27.0.0), and the device is not 0. Contradictory.</exception>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The device is negative, which no `dev_t` is. Contradictory.</exception>
    let withPipeDevice<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (device : int64 option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithPipeDevice device image
        |> Refusal.orRaise "UnixBootImage.withPipeDevice" PipeDeviceRefusal.kind PipeDeviceRefusal.describe

    /// `withSoMaxConn`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithSoMaxConn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, SoMaxConnRefusal>
        =
        let machine = image.Machine

        let resolved =
            match value with
            | None -> Ok (UnixMachineState.defaultSoMaxConn (SimulatedUnixPlatform.flavour machine.UnixPlatform))
            | Some value when value < 1 -> Error (SoMaxConnRefusal.NotPositive value)
            | Some value -> Ok value

        resolved
        |> Result.map (fun resolved ->
            { machine with
                SoMaxConn = resolved
            }
            |> withMachine image
        )

    /// Set the `somaxconn` sysctl.
    ///
    /// `None` takes the measured default of this machine's flavour. The clamp
    /// this feeds (`connectSocket`'s capacity rule) was measured with the
    /// sysctl set to 3 on Linux and at the default 128 on Darwin, so a
    /// configured value is on measured ground.
    ///
    /// Refuses a value below 1: no machine was measured with a non-positive
    /// somaxconn.
    let withSoMaxConn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithSoMaxConn value image
        |> Refusal.orRaise "UnixBootImage.withSoMaxConn" SoMaxConnRefusal.kind SoMaxConnRefusal.describe

    /// `withInotifyLimits`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithInotifyLimits<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (limits : InotifyLimits)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, InotifyLimitsRefusal>
        =
        match SimulatedUnixPlatform.flavour image.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (InotifyLimitsRefusal.NotReadOn SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        if limits.MaxUserInstances < 1 then
            Error (InotifyLimitsRefusal.MaxUserInstancesNotPositive limits.MaxUserInstances)
        elif limits.MaxUserWatches < 1 then
            Error (InotifyLimitsRefusal.MaxUserWatchesNotPositive limits.MaxUserWatches)
        elif limits.MaxQueuedEvents < 1 then
            Error (InotifyLimitsRefusal.MaxQueuedEventsNotPositive limits.MaxQueuedEvents)
        elif limits.MaxQueuedEvents > InotifyLimits.largestQueuedEvents then
            Error (
                InotifyLimitsRefusal.MaxQueuedEventsTooLarge (limits.MaxQueuedEvents, InotifyLimits.largestQueuedEvents)
            )
        else
            { image.Machine with
                InotifyLimits = limits
            }
            |> withMachine image
            |> Ok

    /// <summary>
    /// Set Linux's `fs.inotify` sysctls (`InotifyLimits`); the defaults are
    /// `UnixSystem.defaultInotifyLimits`. Each limit must be positive, the
    /// queue's at most `InotifyLimits.largestQueuedEvents`, and the machine
    /// Linux-flavoured: Darwin has no inotify to read them.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The machine is of `flavour` (Darwin), which has no inotify, so nothing would read the limits.</exception>
    let withInotifyLimits<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (limits : InotifyLimits)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithInotifyLimits limits image
        |> Refusal.orRaise "UnixBootImage.withInotifyLimits" InotifyLimitsRefusal.kind InotifyLimitsRefusal.describe

    /// Set the sysctl that gives a new IPv6 socket its `IPV6_V6ONLY`: Linux's
    /// `net.ipv6.bindv6only`, Darwin's `net.inet6.ip6.v6only`. Off by default
    /// on both.
    let withIpv6OnlyByDefault<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : bool)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        { image.Machine with
            Ipv6OnlyByDefault = value
        }
        |> withMachine image

    /// `withTcpSendSpace`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithTcpSendSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, TcpSendSpaceRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        let resolved =
            match value, flavour with
            | None, _ -> Ok (UnixMachineState.defaultTcpSendSpace flavour)
            | Some value, SimulatedUnixFlavour.Linux -> Error (TcpSendSpaceRefusal.NotReadOn (flavour, value))
            | Some value, SimulatedUnixFlavour.Darwin ->
                if value > UnixMachineState.darwinSocketBufferMax then
                    Error (TcpSendSpaceRefusal.AboveSocketBufferMax (value, UnixMachineState.darwinSocketBufferMax))
                elif value < UnixMachineState.darwinLoopbackSendPipe then
                    Error (TcpSendSpaceRefusal.BelowLoopbackSendPipe (value, UnixMachineState.darwinLoopbackSendPipe))
                else
                    Ok value

        resolved
        |> Result.map (fun resolved ->
            { machine with
                TcpSendSpace = resolved
            }
            |> withMachine image
        )

    /// <summary>
    /// Set the TCP send buffer sysctl (`TcpSendSpace`). `None` takes the
    /// measured default of this machine's flavour.
    ///
    /// Under Darwin a value must lie between `UnixMachineState.darwinLoopbackSendPipe` and
    /// `UnixMachineState.darwinSocketBufferMax`, inclusive, and this refuses one
    /// outside them: Darwin itself refuses a sendspace above the maximum, and
    /// below the send pipe the size a connection's buffer grows to depends on
    /// which route it took, which this kernel does not model. Under Linux
    /// nothing reads the value, so this refuses any configured one rather than
    /// silently ignoring it.
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The value is above `max` (`UnixMachineState.darwinSocketBufferMax`, `kern.ipc.maxsockbuf`), and Darwin refuses such a `net.inet.tcp.sendspace` with ERANGE. Contradictory.</exception>
    let withTcpSendSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithTcpSendSpace value image
        |> Refusal.orRaise "UnixBootImage.withTcpSendSpace" TcpSendSpaceRefusal.kind TcpSendSpaceRefusal.describe

    /// `withTcpReceiveSpace`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithTcpReceiveSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, TcpReceiveSpaceRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        let resolved =
            match value, flavour with
            | None, _ -> Ok (UnixMachineState.defaultTcpReceiveSpace flavour)
            | Some value, SimulatedUnixFlavour.Linux ->
                if value <= 0 then
                    Error (TcpReceiveSpaceRefusal.NotPositive value)
                else
                    Ok value
            | Some value, SimulatedUnixFlavour.Darwin ->
                match TcpBufferSizing.darwinReceiveSpaceRefusal value with
                | Some reason -> Error (TcpReceiveSpaceRefusal.GrowsAfterHandshake (value, reason))
                | None -> Ok value

        resolved
        |> Result.map (fun resolved ->
            { machine with
                TcpReceiveSpace = resolved
            }
            |> withMachine image
        )

    /// <summary>
    /// Set the TCP receive buffer sysctl (`TcpReceiveSpace`). `None` takes the
    /// measured default of this machine's flavour.
    ///
    /// Under Linux a value must be positive. Under Darwin it must be one whose
    /// buffer a connection's handshake sizes once and for all, since this
    /// library does not model a receive buffer that grows as data arrives.
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The value is not positive, and Linux refuses such a `net.ipv4.tcp_rmem` default. Contradictory.</exception>
    let withTcpReceiveSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithTcpReceiveSpace value image
        |> Refusal.orRaise
            "UnixBootImage.withTcpReceiveSpace"
            TcpReceiveSpaceRefusal.kind
            TcpReceiveSpaceRefusal.describe

    /// `withUdpReceiveSpace`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithUdpReceiveSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, UdpReceiveSpaceRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        // Measured with datagrams of every size at the defaults, and on Linux
        // at 1048576 too (`udp-capacity.c` and `udp-truesize.c` in
        // docs/plans/2026-10-18-udp-data-path); the rules scale with the
        // buffer between those and the ceilings.
        let floor = UnixMachineState.defaultUdpReceiveSpace flavour

        let ceiling =
            match flavour with
            | SimulatedUnixFlavour.Linux -> System.Int32.MaxValue >>> 1
            | SimulatedUnixFlavour.Darwin -> 8388608 / 8

        let resolved =
            match value with
            | None -> Ok floor
            | Some value when value < floor -> Error (UdpReceiveSpaceRefusal.BelowMeasured (value, floor))
            | Some value when value > ceiling -> Error (UdpReceiveSpaceRefusal.AboveMeasured (value, ceiling))
            | Some value -> Ok value

        resolved
        |> Result.map (fun resolved ->
            { machine with
                UdpReceiveSpace = resolved
            }
            |> withMachine image
        )

    /// Set the receive buffer a new UDP socket starts with (`UdpReceiveSpace`):
    /// Linux's `net.core.rmem_default` sysctl, Darwin's
    /// `net.inet.udp.recvspace`. `None` takes the measured default of this
    /// machine's flavour, 212992 on Linux and 786896 on Darwin.
    ///
    /// Refuses a value below that default, the smallest buffer measured with
    /// datagrams of every size, and one above `INT_MAX >> 1` on Linux or
    /// 1048576 on Darwin, past which a rule this library has not measured
    /// decides what fits.
    let withUdpReceiveSpace<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithUdpReceiveSpace value image
        |> Refusal.orRaise
            "UnixBootImage.withUdpReceiveSpace"
            UdpReceiveSpaceRefusal.kind
            UdpReceiveSpaceRefusal.describe

    /// `withTcpSendSpaceMax`, with a refusal answered as the `Error` rather than raised.
    let internal tryWithTcpSendSpaceMax<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : Result<UnixBootImage<'Thread, 'Handler>, TcpSendSpaceMaxRefusal>
        =
        let machine = image.Machine

        let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

        let resolved =
            match value, flavour with
            | None, _ -> Ok (UnixMachineState.defaultTcpSendSpaceMax flavour)
            | Some value, SimulatedUnixFlavour.Darwin -> Error (TcpSendSpaceMaxRefusal.NotReadOn (flavour, value))
            | Some value, SimulatedUnixFlavour.Linux ->
                if value <= 0 then
                    Error (TcpSendSpaceMaxRefusal.NotPositive value)
                else
                    Ok value

        resolved
        |> Result.map (fun resolved ->
            { machine with
                TcpSendSpaceMax = resolved
            }
            |> withMachine image
        )

    /// <summary>
    /// Set the ceiling a TCP send buffer autotunes to (`TcpSendSpaceMax`).
    /// `None` takes the measured default of this machine's flavour.
    ///
    /// Under Linux a value must be positive. Under Darwin nothing reads the
    /// value, since this kernel sizes a Darwin send buffer from
    /// `TcpSendSpace` alone, so configuring one is refused rather than
    /// silently ignored.
    /// </summary>
    /// <exception cref="T:System.ArgumentOutOfRangeException">The value is not positive, and Linux refuses such a `net.ipv4.tcp_wmem` maximum. Contradictory.</exception>
    let withTcpSendSpaceMax<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (value : int option)
        (image : UnixBootImage<'Thread, 'Handler>)
        : UnixBootImage<'Thread, 'Handler>
        =
        tryWithTcpSendSpaceMax value image
        |> Refusal.orRaise
            "UnixBootImage.withTcpSendSpaceMax"
            TcpSendSpaceMaxRefusal.kind
            TcpSendSpaceMaxRefusal.describe
