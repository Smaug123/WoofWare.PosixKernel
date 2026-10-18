namespace WoofWare.PosixKernel

/// The filesystem an emulated mount claims to be, as `fstatfs(2)` reports it.
///
/// A *choice* rather than a measured fact, because this library's filesystem
/// is an in-memory graph that is not any real filesystem. That is why it is
/// something a client configures rather than a derivation from the flavour the
/// way the errno numbering is: a single Linux reports `0xEF53`,
/// `0x01021994` and `0x9FA0` for three directories in one process, so a flavour
/// does not determine a mount's type. It does *constrain* it, which is what
/// `EmulatedFileSystemType.isReportableUnder` carries.
///
/// This changes what `fstatfs(2)` reports for a file, a directory's `st_size`,
/// and where `lseek(2)` with `SEEK_END` lands on a directory. Path resolution keeps its flavour's limits either way — `pathLimits`
/// carries `NameLengthLimit` as an ext4-versus-APFS fact — so a kernel
/// configured `Nfs` reports NFS while still resolving names as its flavour
/// does.
///
/// Only three cases, because only three have a consumer. Note that a fourth
/// could not be told apart as `Ext4` by `fstatfs(2)` alone: Linux reports
/// `0xEF53` for ext2, ext3 and ext4 alike.
[<RequireQualifiedAccess>]
type EmulatedFileSystemType =
    /// Linux's in-memory filesystem, and so the honest analogue of a
    /// filesystem that only ever exists in memory.
    | Tmpfs
    /// What a macOS file is on. Darwin's answer, since a default macOS mounts
    /// no tmpfs.
    | Apfs
    /// A network filesystem, which both flavours can mount. Code that treats
    /// network mounts specially (for example, by declining to take a `flock`
    /// on one) sees one under this configuration.
    | Nfs

/// The fields of `struct statfs` that name the type of filesystem a
/// descriptor is on, as one flavour's `fstatfs(2)` fills them in.
///
/// The flavours name a filesystem differently, so each case carries its own
/// flavour's fields and nothing else.
[<RequireQualifiedAccess>]
type FileSystemTypeFields =
    /// Linux's `f_type`: the filesystem's magic number, such as `0x01021994`
    /// for tmpfs. The field is a `__fsword_t`, which is a `long` on the 64-bit
    /// Linuxes modelled.
    | Linux of fType : int64
    /// Darwin's `f_type` and `f_fstypename`. The `f_type` is the number the
    /// kernel gave the filesystem when it registered it, not a magic number
    /// taken from the filesystem's format; the `f_fstypename` is its name,
    /// such as `apfs`.
    | Darwin of fType : uint32 * fsTypeName : UnixByteString

[<RequireQualifiedAccess>]
module EmulatedFileSystemType =
    /// The type-naming fields `fstatfs(2)` reports for a file on a mount of
    /// this type, under a kernel of this flavour.
    ///
    /// Throws `ArgumentException` for a `flavour` and `fsType` that do not
    /// describe one machine (see `isReportableUnder`).
    let fieldsFor (flavour : SimulatedUnixFlavour) (fsType : EmulatedFileSystemType) : FileSystemTypeFields =
        let darwinName (name : string) : UnixByteString =
            match UnixByteString.ofString name with
            | Ok name -> name
            | Error defect ->
                failwith
                    $"EmulatedFileSystemType.fieldsFor: the filesystem name %s{name} is not a Unix string (%O{defect}) (this is a bug in this library)"

        match flavour, fsType with
        // Linux's magic numbers, `<linux/magic.h>`. Tmpfs measured on
        // `/dev/shm` (Linux 6.18.5); NFS is `NFS_SUPER_MAGIC`, which no local
        // NFS mount was available to measure.
        | SimulatedUnixFlavour.Linux, EmulatedFileSystemType.Tmpfs -> FileSystemTypeFields.Linux 0x01021994L
        | SimulatedUnixFlavour.Linux, EmulatedFileSystemType.Nfs -> FileSystemTypeFields.Linux 0x6969L
        // Measured 2026-09-23 on macOS 26.6 (Darwin 25.6.0, arm64): `fstatfs`
        // on a file and a directory of every APFS volume mounted (`/`,
        // `/System/Volumes/Data`, `/private/tmp`, a home directory) reported
        // `f_type` 0x1A and `f_fstypename` "apfs", before and after a reboot,
        // and `/nix`'s volume too the second time. Darwin hands out type
        // numbers from 24 upwards in the order filesystems register, unless
        // the filesystem asks for a fixed one (`vfs_fsadd` in XNU's
        // `bsd/vfs/kpi_vfs.c`), and APFS's source is not published, so 0x1A is
        // a measurement of that release rather than a constant of the format.
        | SimulatedUnixFlavour.Darwin, EmulatedFileSystemType.Apfs ->
            FileSystemTypeFields.Darwin (0x1Au, darwinName "apfs")
        // NFS asks for a fixed number: `install_nfs_vfs_fs` in the NFS kext
        // (apple-oss-distributions/NFS, `kext/nfs_vfsops.c`) registers
        // `vfe_fstypenum = VT_NFS`, which is 2, under the name "nfs", and sets
        // no name override. `vfs_get_statfs64` (`bsd/vfs/vfs_syscalls.c`,
        // which `fstatfs64` answers from, and arm64's `fstatfs` is the same
        // libSystem symbol) copies both into `struct statfs`. Both read at
        // xnu `main` and NFS `main` on 2026-09-23. Measured the same day on macOS 26.6 by
        // `getvfsbyname("nfs")`, which reported type number 2 for the loaded
        // kext. No NFS mount was available to call `fstatfs` on.
        | SimulatedUnixFlavour.Darwin, EmulatedFileSystemType.Nfs -> FileSystemTypeFields.Darwin (2u, darwinName "nfs")
        | SimulatedUnixFlavour.Linux, EmulatedFileSystemType.Apfs
        | SimulatedUnixFlavour.Darwin, EmulatedFileSystemType.Tmpfs ->
            raise (
                Refusal.exceptionOf
                    "EmulatedFileSystemType.fieldsFor"
                    (RefusalKind.Contradictory "fsType")
                    $"asked what a %O{flavour} kernel reports for a %O{fsType} mount, which %O{flavour} cannot have. The flavour and the mount type have come apart; they constrain each other (see EmulatedFileSystemType.isReportableUnder) and must be chosen together rather than set one at a time."
            )

    /// A directory's `st_size` on a mount of this type, given how many names it
    /// holds besides `.` and `..`, or `None` where the mount's type does not
    /// determine it.
    ///
    /// NFS is the `None`: an NFS client reports whatever the server's own
    /// filesystem says, and nothing about this machine says what that is.
    let internal directorySize (fsType : EmulatedFileSystemType) (entries : int) : int64 option =
        System.Diagnostics.Debug.Assert (entries >= 0, "directorySize: a directory cannot hold fewer than no names")

        // Measured 2026-09-23 by a history probe run from an empty directory:
        // 300 regular files created one at a time with names of 1 to 255
        // bytes, 150 of them removed at random, then 600 random steps of
        // creat, mkdir, symlink, link, mkfifo, unlink, rmdir, and rename
        // within, into, out of and over the directory, then drained; twelve
        // seeds per filesystem, about 14,500 observations each, `stat` and
        // `fstat` agreeing on every one. Separately, 5000 files created and
        // removed one at a time, and a subdirectory holding 50 files. The
        // size is affine in the number of names alone: no step's name length,
        // entry kind, or history moved it, and neither did the contents of a
        // subdirectory.
        match fsType with
        // Linux 6.18.5 on `/dev/shm`: two 20-byte "entries" for `.` and `..`,
        // and 20 more per name.
        | EmulatedFileSystemType.Tmpfs -> Some (40L + 20L * int64 entries)
        // macOS 26.6 (Darwin 25.6.0) on the APFS volume holding `/tmp`: 32
        // bytes per name, `.` and `..` included.
        | EmulatedFileSystemType.Apfs -> Some (64L + 32L * int64 entries)
        // Not measured: no NFS server or mount was available. The answer
        // comes from the server's GETATTR, so it is the size the *server's*
        // filesystem gives the directory: a small one is 4096 bytes on a local
        // ext4, and would be the rule above on an exported tmpfs.
        | EmulatedFileSystemType.Nfs -> None

    /// A directory's `st_nlink` on a mount of this type, or `None` where the
    /// mount's type does not determine it.
    ///
    /// Not the number of names the directory has: each filesystem counts some
    /// of the directory's own entries instead. tmpfs counts "." and each
    /// subdirectory's "..", so a directory holds 2 plus its subdirectories,
    /// and 0 once it has been removed. APFS counts 2 plus every name the
    /// directory binds, whatever it names; a removed directory is empty, so
    /// it holds 2.
    ///
    /// NFS is the `None`, as for `directorySize`: the server's own filesystem
    /// decides.
    ///
    /// Partial in `directory`, which must be a directory `vfs` contains.
    let internal directoryLinkCount
        (fsType : EmulatedFileSystemType)
        (directory : InodeNumber)
        (vfs : VirtualFileSystem)
        : int64 option
        =
        match VirtualFileSystem.tryGetContent directory vfs with
        | Some (InodeContent.Directory _) -> ()
        | Some _
        | None ->
            failwith
                $"EmulatedFileSystemType.directoryLinkCount: inode %O{directory} is not a directory this filesystem contains (this is a bug in the caller)."

        // Measured 2026-10-02 by `stat-fields.c`, over 4000 steps of a seeded
        // random history (creat, mkdir, symlink, link, mkfifo, unlink, rmdir,
        // and rename within, into, out of and over the directory), each read
        // through `stat` and through a held descriptor, and a fresh mount's
        // root; and by `stat-nlink-limit.c` out to 70000 names.
        match fsType with
        // Linux 6.18.5 on `/dev/shm` and on a freshly mounted tmpfs: 2 plus
        // the subdirectories at every step, a symbolic link to a directory not
        // counting. A directory removed by `rmdir`, displaced by `rename`, or
        // removed while it was the current directory reports 0.
        | EmulatedFileSystemType.Tmpfs ->
            if VirtualFileSystem.isOrphanedDirectory directory vfs then
                Some 0L
            else
                Some (2L + int64 (VirtualFileSystem.subdirectoryCount directory vfs))
        // macOS (Darwin 27.0) on the APFS volume holding `/tmp` and on a fresh
        // APFS disk image: 2 plus the names at every step, a removed or
        // displaced directory included.
        | EmulatedFileSystemType.Apfs -> Some (2L + int64 (VirtualFileSystem.entryCount directory vfs))
        // Not measured: no NFS server or mount was available.
        | EmulatedFileSystemType.Nfs -> None

    /// An inode's `st_blksize` and `st_blocks` on a mount of this type, under
    /// a kernel with pages of `pageSize`, each `None` where nothing in the
    /// machine determines it.
    ///
    /// On tmpfs a regular file has a page for each 4096 bytes a write has
    /// filled, and for the page a write allocated before its buffer faulted;
    /// truncation frees the pages from the new end on, and a hole has none.
    /// APFS allocates as it writes a file back, at a time and by a rule the
    /// model does not follow, so a regular file of any length but 0 has no
    /// stated `st_blocks`.
    let internal allocation
        (fsType : EmulatedFileSystemType)
        (pageSize : SimulatedPageSize)
        (content : InodeContent)
        : int64 option * int64 option
        =
        // Measured 2026-10-02 by `stat-fields.c` (docs/plans/2026-08-23-
        // posix-kernel-extraction/) and 2026-10-18 by `stat-blocks.c`
        // (docs/probes/stat-blocks/), on Linux 6.18.5 aarch64 (`/dev/shm`) and
        // Darwin 27.0 arm64 (the APFS volume holding `/tmp`): every file
        // size from 0 to 70000 in one write, 1 and 16 MiB, holes of a page to
        // 64 MiB made by a write past the end or by `ftruncate`, each read at
        // once, after `fsync`, after 45 seconds and by path once closed;
        // writes whose buffer faulted, and histories after them; symbolic
        // links of 1 to 4095 bytes; directories of up to 20000 names; a
        // FIFO; and Linux's `/dev/null`.

        // Both filesystems allocate a regular file in 4096-byte units, 8 of
        // `st_blocks`'s 512 bytes, which are `FileContents`'s pages.
        if FileContents.pageSize <> 4096 then
            failwith
                $"EmulatedFileSystemType.allocation: FileContents holds pages of %d{FileContents.pageSize} bytes, which are not the 4096-byte units tmpfs and APFS allocate (this is a bug in this library)."

        let pageBlocks = 8L

        let socket () : int64 option * int64 option =
            failwith
                "EmulatedFileSystemType.allocation: asked about a socket file. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."

        match fsType with
        | EmulatedFileSystemType.Tmpfs ->
            // tmpfs counts in pages of memory, which are `FileContents`'s
            // pages only on a kernel with 4 KiB pages: every Linux admitted.
            match pageSize with
            | SimulatedPageSize.FourKiB -> ()
            | SimulatedPageSize.SixteenKiB
            | SimulatedPageSize.SixtyFourKiB ->
                failwith
                    $"EmulatedFileSystemType.allocation: asked about tmpfs under a kernel with %d{SimulatedPageSize.bytes pageSize}-byte pages, which no measured Linux has (this is a bug in this library: SimulatedUnixPlatform.create admits none)."

            match content with
            | InodeContent.RegularFile (contents, _) ->
                Some 4096L, Some (pageBlocks * FileContents.heldPageCount contents)
            // A target shorter than 128 bytes is held in the inode itself; a
            // longer one takes a page.
            | InodeContent.Symlink (target, _) ->
                let length = UnixByteString.length (SymlinkTarget.toByteString target)
                Some 4096L, Some (if length >= 128 then pageBlocks else 0L)
            | InodeContent.Directory _
            | InodeContent.Fifo _
            | InodeContent.CharacterDevice _ -> Some 4096L, Some 0L
            | InodeContent.Socket _ -> socket ()
        | EmulatedFileSystemType.Apfs ->
            match content with
            // Measured, a file of data reported more blocks than its pages
            // as APFS filled a hole with zeroes when it wrote the file back
            // (on `fsync`, or within 45 seconds); as it allocated ahead of
            // one-byte appends, from a size that differed every trial (176129
            // to 286721 bytes) and in one run never came, which `fsync` kept;
            // and once a truncation had removed a file's data, as it kept the
            // zeroes it had allocated. Only a file of no bytes is certain.
            | InodeContent.RegularFile (contents, _) ->
                Some 4096L, (if FileContents.length contents = 0L then Some 0L else None)
            // A link measured 0 at every length `symlink(2)` takes, up to
            // 1023 bytes.
            | InodeContent.Symlink _
            | InodeContent.Directory _
            | InodeContent.Fifo _ -> Some 4096L, Some 0L
            | InodeContent.CharacterDevice _ ->
                failwith
                    "EmulatedFileSystemType.allocation: asked about a character device on APFS. Nothing makes one: mknod of a device is refused, and a seed holds none (this is a bug in this library)."
            | InodeContent.Socket _ -> socket ()
        // Not measured: no NFS server or mount was available. The mount's
        // transfer size and the server's filesystem decide.
        | EmulatedFileSystemType.Nfs -> None, None

    /// What a write whose copy from the caller's buffer faults leaves
    /// allocated in a regular file on a mount of this type.
    let internal faultedWriteAllocation (fsType : EmulatedFileSystemType) : FaultedWriteAllocation =
        // Measured 2026-10-18 by `stat-blocks.c`: a faulting `pwrite(2)` of 1
        // or 10000 bytes, from NULL or a PROT_NONE page, at offsets from 0 to
        // 100000 into an empty, a dense and an `ftruncate`-extended file.
        match fsType with
        // Linux 6.18.5 `/dev/shm`: the page holding the offset, and no other,
        // whatever the count; an empty file faulted at 0 reports 0 bytes and
        // 8 blocks.
        | EmulatedFileSystemType.Tmpfs -> FaultedWriteAllocation.PageAtOffset
        // Darwin 27.0: anything from no page to every page up to the offset,
        // varying with the count, which the model does not follow;
        // `allocation` states no `st_blocks` for a file of data there.
        | EmulatedFileSystemType.Apfs -> FaultedWriteAllocation.Untracked
        // `allocation` states no `st_blocks` on NFS.
        | EmulatedFileSystemType.Nfs -> FaultedWriteAllocation.Untracked

    /// The type a mount reports when a host expresses no preference.
    ///
    /// `Tmpfs` under Linux because this library's filesystem really is in
    /// memory, and `Apfs` under Darwin because a default macOS mounts no tmpfs.
    let defaultFor (flavour : SimulatedUnixFlavour) : EmulatedFileSystemType =
        match flavour with
        | SimulatedUnixFlavour.Linux -> EmulatedFileSystemType.Tmpfs
        | SimulatedUnixFlavour.Darwin -> EmulatedFileSystemType.Apfs

    /// Whether a kernel of this flavour could report this filesystem type at
    /// all.
    ///
    /// The flavour does not *determine* a mount's type, but it does rule
    /// several out, and a kernel that claimed one of those would be handing a
    /// process a fact no real system of the platform it impersonates could
    /// produce. Written as an exhaustive pair match rather than as a
    /// predicate over one axis, so that a new flavour or a new filesystem
    /// stops compiling until someone has looked the combination up.
    let isReportableUnder (flavour : SimulatedUnixFlavour) (fsType : EmulatedFileSystemType) : bool =
        match fsType, flavour with
        // Measured: `/dev/shm` reports it. A default macOS mounts no tmpfs,
        // and no Darwin tmpfs has been measured. Darwin can have one, though:
        // macOS 26.6 registers a "tmpfs" (type number 28 from
        // `getvfsbyname`) and ships `mount_tmpfs`, which refused uid 501 with
        // EPERM on 2026-09-23.
        | EmulatedFileSystemType.Tmpfs, SimulatedUnixFlavour.Linux -> true
        | EmulatedFileSystemType.Tmpfs, SimulatedUnixFlavour.Darwin -> false
        // No mainline Linux filesystem reports `0x1A`; a FUSE-mounted APFS
        // reports fuse's own `0x65735546`.
        | EmulatedFileSystemType.Apfs, SimulatedUnixFlavour.Linux -> false
        | EmulatedFileSystemType.Apfs, SimulatedUnixFlavour.Darwin -> true
        // Both mount NFS.
        | EmulatedFileSystemType.Nfs, SimulatedUnixFlavour.Linux
        | EmulatedFileSystemType.Nfs, SimulatedUnixFlavour.Darwin -> true

/// `f_fsid`: the two words `statfs(2)` reports to identify a mounted
/// filesystem, `val[0]` and `val[1]` on both flavours.
type FileSystemId =
    {
        /// `f_fsid.val[0]`.
        First : int32
        /// `f_fsid.val[1]`.
        Second : int32
    }

/// The configuration of a tmpfs mount that `statfs(2)` can see.
///
/// Its capacity is not configurable: a tmpfs mounted with `size=0,nr_inodes=0`
/// has no limit, and every count `statfs(2)` reports for it is 0. That is the
/// only capacity this library's filesystem has, since it never refuses a write
/// for space.
type TmpfsMount =
    {
        /// The `f_fsid` the mount reports. A real tmpfs draws it at random when
        /// it is mounted, so any value is one a real mount could report.
        FileSystemId : FileSystemId
    }

[<RequireQualifiedAccess>]
module TmpfsMount =
    /// A tmpfs mount whose `f_fsid` is one a real `/dev/shm` reported.
    let defaults : TmpfsMount =
        {
            // Measured 2026-09-26 on `/dev/shm` in a Linux 6.18.5 container:
            // `da683e7a:5631524e`. Any fixed value would do as well; this one
            // is at least a draw a real kernel made.
            FileSystemId =
                {
                    First = int32 0xda683e7au
                    Second = 0x5631524e
                }
        }

/// The configuration of an APFS mount that `statfs(2)` can see.
type ApfsMount =
    {
        /// `f_iosize`, the transfer size the filesystem advises. It varies
        /// between APFS containers: 1 MiB on a Mac's internal disk, 2 MiB on a
        /// disk image.
        IoSize : int32
        /// `f_owner`: the user that mounted the volume. 0 for the volumes a Mac
        /// mounts at boot.
        Owner : uint32
        /// `f_mntfromname`: the device the volume was mounted from, such as
        /// `/dev/disk3s5`.
        MountedFrom : UnixByteString
    }

[<RequireQualifiedAccess>]
module ApfsMount =
    /// An APFS mount as a Mac's internal disk would present it: a 1 MiB
    /// transfer size, mounted by root, from the first volume of the first disk.
    let defaults : ApfsMount =
        {
            IoSize = 1048576
            Owner = 0u
            MountedFrom =
                match UnixByteString.ofString "/dev/disk1s1" with
                | Ok name -> name
                | Error defect ->
                    failwith
                        $"ApfsMount.defaults: the device name is not a Unix string (%O{defect}) (this is a bug in this library)"
        }

/// The filesystem a machine has mounted at its root, with what its type lets
/// a caller of `statfs(2)` configure about it.
[<RequireQualifiedAccess>]
type EmulatedMount =
    /// A tmpfs; see `TmpfsMount`.
    | Tmpfs of TmpfsMount
    /// An APFS volume; see `ApfsMount`.
    | Apfs of ApfsMount
    /// An NFS mount. Nothing about it is configurable, because everything
    /// `statfs(2)` reports about one beyond its type comes from the server, and
    /// this library refuses to state it.
    | Nfs

[<RequireQualifiedAccess>]
module EmulatedMount =
    /// The type of filesystem this mount is.
    let fileSystemType (mount : EmulatedMount) : EmulatedFileSystemType =
        match mount with
        | EmulatedMount.Tmpfs _ -> EmulatedFileSystemType.Tmpfs
        | EmulatedMount.Apfs _ -> EmulatedFileSystemType.Apfs
        | EmulatedMount.Nfs -> EmulatedFileSystemType.Nfs

    /// A mount of this type with its default configuration.
    let defaultOf (fsType : EmulatedFileSystemType) : EmulatedMount =
        match fsType with
        | EmulatedFileSystemType.Tmpfs -> EmulatedMount.Tmpfs TmpfsMount.defaults
        | EmulatedFileSystemType.Apfs -> EmulatedMount.Apfs ApfsMount.defaults
        | EmulatedFileSystemType.Nfs -> EmulatedMount.Nfs

    /// The mount a machine of this flavour has when a client expresses no
    /// preference: `EmulatedFileSystemType.defaultFor`'s type, with its
    /// default configuration.
    let defaultFor (flavour : SimulatedUnixFlavour) : EmulatedMount =
        defaultOf (EmulatedFileSystemType.defaultFor flavour)
