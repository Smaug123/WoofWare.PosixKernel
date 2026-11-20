namespace WoofWare.PosixKernel

/// <summary>
/// Which names a platform's filesystem is willing to bind (that is, to create or rename onto).
/// </summary>
/// <remarks>
/// This is a fact of the flavour, not configuration: the kernel already applies the rule which
/// <c>SimulatedUnixPlatform.bindableEntryNames</c> holds, and a client reads it only to learn what
/// the kernel will do.
/// <para />
/// The rule doesn't apply to name lookups, since the filesystem could never have
/// created an entry with an unbindable name in the first place.
/// <para />
/// Note that a call may still fail to bind a name which satisfies this rule, for another reason.
/// For example, under Linux's <c>AnyBytes</c> a name longer than <c>NAME_MAX</c> still gets
/// <c>ENAMETOOLONG</c>.
/// </remarks>
[<RequireQualifiedAccess>]
type BindableEntryNames =
    /// <summary>Entry names need not use any particular character encoding.</summary>
    /// <example>Linux does this.</example>
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
    /// Whether a filesystem whose character encoding follows <c>rule</c> will bind <c>name</c>.
    /// </summary>
    /// <remarks>
    /// Under Linux's <c>AnyBytes</c> this is always true. The kernel checks a name's length separately,
    /// before it binds the name, so <c>admits</c> may accept a name which the call then answers
    /// <c>ENAMETOOLONG</c> for.
    /// <para />
    /// Under Darwin's <c>StrictUtf8</c>, a call that would bind a name which this does not admit answers
    /// <c>EILSEQ</c>. In the creating <c>open</c>, <c>mkdir</c> and <c>rename</c>, as measured, that is the
    /// last check the call makes, so any other error the call has comes first.
    /// </remarks>
    let admits (rule : BindableEntryNames) (name : DirectoryEntryName) : bool =
        match rule with
        | BindableEntryNames.AnyBytes -> true
        | BindableEntryNames.StrictUtf8 -> (DirectoryEntryName.tryToString name).IsSome
