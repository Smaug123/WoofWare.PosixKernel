namespace WoofWare.PosixKernel

/// <summary>
/// Which names a platform's filesystem is willing to bind (that is, to create or rename
/// onto).
/// </summary>
/// <remarks>
/// This configuration doesn't apply to name lookups, since the filesystem could never have
/// created an entry with an unbindable name in the first place.
/// <para />
/// Note that merely satisfying this configuration doesn't necessarily mean a name is valid.
/// For example, Linux/ext4's <c>AnyBytes</c> configuration still has length limits, and
/// the directory separator "/" still can't be part of a name.
/// </remarks>
[<RequireQualifiedAccess>]
type BindableEntryNames =
    /// <summary>Entry names need not use any particular character encoding.</summary>
    /// <example>Linux/ext4 does this.</example>
    | AnyBytes
    /// <summary>
    /// Only names that are valid UTF-8 can be entry names.
    /// </summary>
    /// <example>
    /// This approximates Darwin/APFS, though APFS also refuses some valid UTF-8 names:
    /// for example, APFS rejects Unicode noncharacters, and combining sequences longer than 32 characters.
    /// <c>StrictUtf8</c> nevertheless admits those, to keep WoofWare.PosixKernel's implementation simple;
    /// the use of <c>StrictUtf8</c> there rather than a precise APFS model is a user-visible bug which
    /// I hope to fix eventually.
    /// </example>
    | StrictUtf8

[<RequireQualifiedAccess>]
module BindableEntryNames =
    /// <summary>
    /// Whether a filesystem following <c>rule</c> will bind <c>name</c>.
    /// </summary>
    /// <remarks>
    /// If the filesystem refuses to bind the name, you must be on Darwin;
    /// in that case, the caller gets EILSEQ.
    /// </remarks>
    let admits (rule : BindableEntryNames) (name : DirectoryEntryName) : bool =
        match rule with
        | BindableEntryNames.AnyBytes -> true
        | BindableEntryNames.StrictUtf8 -> (DirectoryEntryName.tryToString name).IsSome
