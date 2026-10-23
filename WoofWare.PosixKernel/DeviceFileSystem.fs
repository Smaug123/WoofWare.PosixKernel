namespace WoofWare.PosixKernel

/// The configuration of a Linux devtmpfs that `stat(2)` and `statfs(2)` can
/// see.
type internal DevtmpfsMount =
    {
        /// The `st_dev` every inode on the devtmpfs reports: the anonymous
        /// device the kernel gave it when it mounted it, which depends on what
        /// was mounted before it.
        DeviceId : int64
        /// The `f_fsid` the mount reports, which a real devtmpfs draws at
        /// random when it is mounted.
        FileSystemId : FileSystemId
        /// `f_flags`: the `ST_*` bits of the mount's options, in Linux's
        /// numbering, `ST_VALID` included.
        Flags : int64
    }

[<RequireQualifiedAccess>]
module internal DevtmpfsMount =
    /// A devtmpfs as one measured Linux machine mounted it.
    let defaults : DevtmpfsMount =
        {
            // Measured 2026-10-02 on `/dev` in a Linux 6.18.5 aarch64 VM under
            // Apple's `container` (`devices.c`, STAT and STATFS rows): `st_dev`
            // 0,6; `f_fsid` 544366de:ad9235de; `f_flags` 0x1022, which is
            // ST_VALID, ST_NOSUID and ST_RELATIME, from the mount's
            // `rw,nosuid,relatime`.
            DeviceId = 6L
            FileSystemId =
                {
                    First = int32 0x544366deu
                    Second = int32 0xad9235deu
                }
            Flags = 0x1022L
        }

    /// What a devtmpfs holds when a client expresses no preference: the nodes
    /// Linux's memory-device driver makes on every kernel, which are `null`,
    /// `zero`, `full`, `random` and `urandom`, each 0666 and owned by root.
    let defaultContents : Map<DirectoryEntryName, SeedEntry> =
        // `drivers/char/mem.c` registers these five whatever the kernel was
        // configured with; every other node a devtmpfs holds is there because
        // of a configuration option (kmsg for CONFIG_PRINTK, tty and console
        // for CONFIG_TTY, mem for CONFIG_DEVMEM) or of the machine's hardware.
        // Each node's number, mode and owner are measured on Linux 6.18.5
        // (`docs/probes/devtmpfs-contents`, ENTRY rows).
        [ "null", 3u ; "zero", 5u ; "full", 7u ; "random", 8u ; "urandom", 9u ]
        |> List.map (fun (name, minor) ->
            DirectoryEntryName.parseOrFail "DevtmpfsMount.defaultContents" name,
            SeedEntry.CharacterDevice (DeviceNumber (1u, minor), PermissionBits 0o666, None)
        )
        |> Map.ofList

/// The configuration of a Darwin devfs that `stat(2)` and `statfs(2)` can
/// see.
type internal DevfsMount =
    {
        /// The `st_dev` every inode on the devfs reports, Darwin's 32-bit
        /// `dev_t` widened with its sign: a number the kernel draws afresh at
        /// each boot. `statfs` reports it as the first word of `f_fsid`.
        DeviceId : int64
        /// `f_flags`: the `MNT_*` bits of the mount, in Darwin's numbering.
        Flags : uint32
    }

[<RequireQualifiedAccess>]
module internal DevfsMount =
    /// A devfs as one measured Mac mounted it.
    let defaults : DevfsMount =
        {
            // Measured on Darwin 27.0 arm64 (`docs/probes/devfs-darwin`, STAT
            // and STATFS rows): `st_dev` 0x52597f09, which an earlier boot
            // reported as 0xc954548f (`devices.c`); `f_flags` 0x4101000, which
            // is MNT_LOCAL, MNT_DONTBROWSE and MNT_MULTILABEL, on both boots.
            DeviceId = int64 (int32 0x52597f09u)
            Flags = 0x4101000u
        }

    /// What a devfs holds when a client expresses no preference: `null` (3,2)
    /// and `zero` (3,3), from the memory driver's static slot, and `random`
    /// (17,0) and `urandom` (17,1), each 0666 and owned by root.
    let defaultContents : Map<DirectoryEntryName, SeedEntry> =
        // Darwin's nearest to Linux's memory-device driver: `bsd/dev/arm64/conf.c`
        // gives the memory driver slot 3, and `randomdev.c` asks for a slot at
        // boot, which two boots of one Mac answered with 17. Every real devfs
        // also holds what devfs makes itself (`fd`, and the `stdin`, `stdout`
        // and `stderr` links into it), which this kernel does not model, and
        // the nodes of every other driver the kernel registers. Each node's
        // number, mode and owner are measured on Darwin 27.0
        // (`docs/probes/devfs-darwin`, STAT rows).
        [
            "null", (3u, 2u)
            "zero", (3u, 3u)
            "random", (17u, 0u)
            "urandom", (17u, 1u)
        ]
        |> List.map (fun (name, (major, minor)) ->
            DirectoryEntryName.parseOrFail "DevfsMount.defaultContents" name,
            SeedEntry.CharacterDevice (DeviceNumber (major, minor), PermissionBits 0o666, None)
        )
        |> Map.ofList

/// The filesystem a machine has mounted at `/dev`.
[<RequireQualifiedAccess>]
type internal DeviceFileSystemMount =
    /// Linux's devtmpfs, holding what the machine's configuration says.
    | Devtmpfs of DevtmpfsMount
    /// Darwin's devfs, holding what the machine's configuration says.
    | Devfs of DevfsMount

[<RequireQualifiedAccess>]
module internal DeviceFileSystemMount =
    /// The device filesystem a machine of `flavour` mounts at `/dev` when a
    /// client expresses no preference.
    let defaultFor (flavour : SimulatedUnixFlavour) : DeviceFileSystemMount =
        match flavour with
        | SimulatedUnixFlavour.Linux -> DeviceFileSystemMount.Devtmpfs DevtmpfsMount.defaults
        | SimulatedUnixFlavour.Darwin -> DeviceFileSystemMount.Devfs DevfsMount.defaults

    /// What the filesystem's inode graph holds of this mount.
    let internal mounted (mount : DeviceFileSystemMount) : MountedFileSystem =
        match mount with
        | DeviceFileSystemMount.Devtmpfs _ -> MountedFileSystem.Devtmpfs
        | DeviceFileSystemMount.Devfs _ -> MountedFileSystem.Devfs

    /// Whether a machine of `flavour` can have this device filesystem.
    let isMountableUnder (flavour : SimulatedUnixFlavour) (mount : DeviceFileSystemMount) : bool =
        match flavour, mount with
        | SimulatedUnixFlavour.Linux, DeviceFileSystemMount.Devtmpfs _
        | SimulatedUnixFlavour.Darwin, DeviceFileSystemMount.Devfs _ -> true
        | SimulatedUnixFlavour.Linux, DeviceFileSystemMount.Devfs _
        | SimulatedUnixFlavour.Darwin, DeviceFileSystemMount.Devtmpfs _ -> false

/// The filesystem an inode is on, as the rules that differ from one
/// filesystem to another see it.
[<RequireQualifiedAccess>]
type internal InodeFileSystem =
    /// A filesystem of a type a client chooses for the root mount: the root
    /// filesystem itself, or Linux's devtmpfs, which is a tmpfs underneath
    /// (measured: its `f_type`, and its directories' sizes, follow tmpfs's
    /// rules).
    | Typed of EmulatedFileSystemType
    /// Darwin's devfs, which no client chooses for the root.
    | Devfs

/// What `stat(2)` reports of an inode on Darwin's devfs that its own rules
/// decide, rather than its configuration.
[<RequireQualifiedAccess>]
module internal Devfs =
    /// A devfs directory's `st_size`: 8 bytes plus its length for each name it
    /// holds, `.` and `..` not counted.
    let directorySize (directory : InodeNumber) (vfs : VirtualFileSystem) : int64 =
        // Measured on Darwin 27.0 (`docs/probes/devfs-darwin`, DENTS and STAT
        // rows): 5087 bytes for `/dev`'s 367 names, which is the sum exactly,
        // and 14 for `/dev/monotonic`, holding `uncore`.
        match VirtualFileSystem.tryGetDirectory directory vfs with
        | Some content ->
            content.Entries
            |> Map.fold
                (fun size name _ -> size + 8L + int64 (UnixByteString.length (DirectoryEntryName.toByteString name)))
                0L
        | None ->
            failwith
                $"Devfs.directorySize: inode %O{directory} is not a directory this filesystem holds (this is a bug in the caller)."

    /// A devfs directory's `st_nlink`: 2, plus one for each subdirectory.
    let directoryLinkCount (directory : InodeNumber) (vfs : VirtualFileSystem) : int64 =
        // Measured on Darwin 27.0 (`docs/probes/devfs-darwin`, DENTS and STAT
        // rows): 4 for `/dev`, holding `fd` and `monotonic`, and 2 for
        // `/dev/monotonic`, holding a node. No devfs directory is ever
        // removed: every process is refused that.
        2L + int64 (VirtualFileSystem.subdirectoryCount directory vfs)

    /// `st_blksize` and `st_blocks` of an inode on devfs whose `st_size` is
    /// `size`: a directory takes 512-byte blocks, and a node none.
    let allocation (inode : InodeNumber) (content : InodeContent) (size : int64) : int64 * int64 =
        // Measured on Darwin 27.0 (`docs/probes/devfs-darwin`, STAT rows):
        // `/dev` 512 and 10 at 5087 bytes, `/dev/monotonic` 512 and 1 at 14,
        // each node 65536 and 0.
        match content with
        | InodeContent.Directory _ -> 512L, (size + 511L) / 512L
        | InodeContent.CharacterDevice _ -> 65536L, 0L
        | InodeContent.RegularFile _
        | InodeContent.Symlink _
        | InodeContent.Fifo _
        | InodeContent.Socket _ ->
            failwith
                $"Devfs.allocation: inode %O{inode} is on devfs, which holds only nodes and directories here (this is a bug in this library)."

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module CharacterDevice =
    /// Every device this kernel has a driver for: a character device node can
    /// be opened only if it holds the number one of these is registered under.
    let all : CharacterDevice list = [ CharacterDevice.Null ; CharacterDevice.URandom ]

    /// What an `ioctl(2)` the device's Linux driver does not recognise answers:
    /// `FIONREAD` and `TCGETS` (`tcgetattr`) among them, neither device being a
    /// queue or a terminal. The buffer the request names is never looked at.
    ///
    /// Linux only: this kernel registers no Darwin driver, so no description
    /// of a Darwin node exists to ask through. Only for a device in
    /// `CharacterDevice.all`: no other device can be opened to ask through.
    let internal unrecognisedIoctl (device : CharacterDevice) : UnixError =
        // Measured on Linux 6.18.5 (`devices-l2.c`, FIONREAD and TCGETATTR
        // rows, through descriptors opened for reading and for writing): null
        // has no ioctl operation, so the call is ENOTTY, while urandom's
        // `random_ioctl` answers EINVAL for a command it does not know.
        match device with
        | CharacterDevice.Null -> UnixError.ENOTTY
        | CharacterDevice.URandom -> UnixError.EINVAL
        | CharacterDevice.Zero
        | CharacterDevice.Random
        | CharacterDevice.Tty ->
            failwith
                $"CharacterDevice.unrecognisedIoctl: asked about %O{device}, which this kernel has no driver for yet, so no open file description names it (this is a bug in the caller)."

    /// The number a kernel of `flavour` registers the device's driver under,
    /// which its node holds.
    ///
    /// Linux only: this kernel registers no Darwin driver.
    let internal number (flavour : SimulatedUnixFlavour) (device : CharacterDevice) : DeviceNumber =
        match flavour with
        | SimulatedUnixFlavour.Darwin ->
            failwith
                $"CharacterDevice.number: asked for the number of %O{device} on Darwin, where this kernel registers no driver (this is a bug in the caller)."
        | SimulatedUnixFlavour.Linux ->

        // The mem driver's registrations, which are fixed: 1,3 for null, 1,5
        // for zero, 1,8 for random and 1,9 for urandom, measured on Linux
        // 6.18.5 (`devices.c`, STAT rows). The tty driver's `/dev/tty` is 5,0,
        // also fixed, measured there too (`darwin-devfs.c`, STAT rows).
        match device with
        | CharacterDevice.Null -> DeviceNumber (1u, 3u)
        | CharacterDevice.Zero -> DeviceNumber (1u, 5u)
        | CharacterDevice.Random -> DeviceNumber (1u, 8u)
        | CharacterDevice.URandom -> DeviceNumber (1u, 9u)
        | CharacterDevice.Tty -> DeviceNumber (5u, 0u)

    /// The driver that opening a character device node holding `held` reaches
    /// under a kernel of `flavour`, or `None` if this kernel has no driver
    /// registered for that number.
    let internal driverOf (flavour : SimulatedUnixFlavour) (held : DeviceNumber) : CharacterDevice option =
        match flavour with
        // Darwin's drivers keep a position and stamp times where Linux's do
        // not, which this kernel does not model yet: its nodes are listed and
        // reported, and opening one is refused.
        | SimulatedUnixFlavour.Darwin -> None
        | SimulatedUnixFlavour.Linux -> all |> List.tryFind (fun device -> number flavour device = held)

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module internal DeviceNumber =
    /// Whether a kernel of `flavour` can encode `number` in its `dev_t`:
    /// anything on Linux, whose 64-bit `dev_t` holds 32 bits of each, and on
    /// Darwin, whose 32-bit `dev_t` holds 8 bits of major and 24 of minor,
    /// only a pair within those.
    let isEncodableUnder (flavour : SimulatedUnixFlavour) (number : DeviceNumber) : bool =
        match flavour with
        | SimulatedUnixFlavour.Linux -> true
        | SimulatedUnixFlavour.Darwin ->
            let (DeviceNumber (major, minor)) = number
            major <= 0xFFu && minor <= 0xFFFFFFu

    /// `st_rdev` for a node holding `number` under a kernel of `flavour`, in
    /// that flavour's `dev_t` encoding.
    ///
    /// Throws on Darwin for a pair it cannot encode (`isEncodableUnder`).
    let specialFileDevice (flavour : SimulatedUnixFlavour) (number : DeviceNumber) : int64 =
        let (DeviceNumber (major, minor)) = number

        match flavour with
        | SimulatedUnixFlavour.Darwin ->
            if not (isEncodableUnder flavour number) then
                failwith
                    $"DeviceNumber.specialFileDevice: %O{number} does not fit Darwin's dev_t, 8 bits of major and 24 of minor, which the configuration should have refused (this is a bug in the caller)."

            // `makedev`: measured, 3,2 is reported as 0x3000002 and 17,1 as
            // 0x11000001 (`docs/probes/devfs-darwin`, STAT rows). A `dev_t` is
            // signed, so a major from 128 is negative, as `st_dev` is.
            int64 (int32 ((major <<< 24) ||| minor))
        | SimulatedUnixFlavour.Linux ->

        let major = int64 major
        let minor = int64 minor

        // glibc's `makedev`, which is how a 64-bit Linux `stat` encodes the pair:
        // measured, 1,3 is reported as 259 and 1,9 as 265.
        ((major &&& 0xFFFFF000L) <<< 32)
        ||| ((major &&& 0xFFFL) <<< 8)
        ||| ((minor &&& 0xFFFFFF00L) <<< 12)
        ||| (minor &&& 0xFFL)
