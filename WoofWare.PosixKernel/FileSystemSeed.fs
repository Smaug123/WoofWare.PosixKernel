namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// One entry in the filesystem a host hands to the emulated kernel.
///
/// A tree, so duplicate paths, orphaned children, and declaration order are
/// unrepresentable rather than checked.
///
/// The tree cannot express a hard link, since every inode has exactly one
/// container here. `VirtualFileSystem` can, so a seeded hard link would mean
/// growing a case here; it is not a limit of the model.
///
/// A file's or directory's permission bits are part of the seed, and are
/// required rather than optional: the differential oracle chmods the host tree
/// to the same bits, so the mode is a fact the model and the host kernel share.
///
/// `SeedEntry.file` and `SeedEntry.directory` supply the modes a `umask 022`
/// process would have created, for the many seeds that only care about shape.
///
/// A symlink has no mode field: Linux gives every link 0o777 and never changes
/// it, and a seeded link gets what its flavour gives a link created under
/// `SeedEntry.symlinkCreatorsUmask`. A Darwin link whose own mode was later
/// changed is not seedable.
///
/// Every entry has an optional owner. `None` means the owner the seed is
/// realised with, which whoever realises it states explicitly
/// (`UnixBootImage.withFileSystem`'s `defaultOwner`, and root for the device
/// filesystem's contents, as devtmpfs makes its own nodes); it does not mean
/// "the same owner as the directory holding this entry".
[<RequireQualifiedAccess ; NoComparison>]
type SeedEntry =
    | File of contents : ImmutableArray<byte> * permissions : PermissionBits * owner : InodeOwner option
    | Directory of
        entries : Map<DirectoryEntryName, SeedEntry> *
        permissions : PermissionBits *
        owner : InodeOwner option
    /// Held verbatim, and *not* resolved when the seed is realised: a symlink's
    /// target is a string to the kernel, so it may dangle, may be absolute, and
    /// may point outside anything the seed declares.
    | Symlink of target : SymlinkTarget * owner : InodeOwner option
    /// A character device node holding `number`, which `open(2)` looks the
    /// driver up by. Only the device filesystem's contents may hold one
    /// (`UnixBootImage.withDeviceFileSystem`): `UnixBootImage.withFileSystem`
    /// refuses a seed that does.
    | CharacterDevice of number : DeviceNumber * permissions : PermissionBits * owner : InodeOwner option

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module SeedEntry =
    /// <summary>
    /// What a <c>umask 022</c> process gets from <c>open(2)</c> called with <c>0o666</c>.
    /// </summary>
    let defaultPermsForRegularFile : PermissionBits =
        PermissionBits (0o666 &&& ~~~0o022)

    /// <summary>
    /// What a <c>umask 022</c> process inherits from <c>mkdir(2)</c>'s <c>0o777</c>.
    /// </summary>
    /// <remarks>
    /// <c>022</c> (-rw-r--r--) is the default umask on the emulated Unixes, although apparently Ubuntu
    /// relaxed this to <c>002</c> (-rw-rw-r--) starting at version 11.10.
    ///
    /// See <c>defaultForRegularFile</c> for the files version.
    /// </remarks>
    let defaultPermsForDirectory : PermissionBits = PermissionBits (0o777 &&& ~~~0o022)

    /// <summary>
    /// The default umask when creating a symlink via a FileSystemSeed.
    /// </summary>
    /// <remarks>
    /// This is only relevant on Darwin, which subtracts this from 0o777 to decide perms for a symlink;
    /// Linux always gives a symlink 0o777.
    /// </remarks>
    let symlinkCreatorsUmask : PermissionBits = PermissionBits 0o022

    /// <summary>
    /// Create an entry for a file with the default mode you'd get from a process with <c>umask 022</c>,
    /// as you'd get if you created it with <c>open(O_CREAT)</c>.
    /// </summary>
    /// <remarks>The resulting file belongs to whatever owner the seed is realised with.</remarks>
    let file (contents : ImmutableArray<byte>) : SeedEntry =
        SeedEntry.File (contents, defaultPermsForRegularFile, None)

    /// <summary>
    /// Create an entry for a directory with the default mode you'd get from a process with <c>umask 022</c>,
    /// as you'd get if you created it with <c>mkdir</c>.
    /// </summary>
    /// <remarks>The resulting directory belongs to whatever owner the seed is realised with.</remarks>
    let directory (entries : Map<DirectoryEntryName, SeedEntry>) : SeedEntry =
        SeedEntry.Directory (entries, defaultPermsForDirectory, None)

[<RequireQualifiedAccess>]
module FileSystemSeed =
    /// <summary>
    /// A seed describing nothing but an empty root directory.
    /// </summary>
    let empty : Map<DirectoryEntryName, SeedEntry> = Map.empty
