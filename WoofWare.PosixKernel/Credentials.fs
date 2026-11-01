namespace WoofWare.PosixKernel

/// <summary>
/// A user ID, as a guest would pass as a syscall argument.
/// </summary>
/// <remarks>
/// This is our model of <c>uid_t</c>.
/// <para />
/// Every <c>uint32</c> except <c>(uid_t)-1</c>, which is not an ID but the "leave this
/// unchanged" argument of <c>setresuid(2)</c> and <c>chown(2)</c>.
/// </remarks>
[<Struct>]
type UserId =
    private
    | UserId of uid : uint32

    override this.ToString () : string =
        match this with
        | UserId uid -> string<uint32> uid

[<RequireQualifiedAccess>]
module UserId =
    // Measured on Linux 6.18.5 as root (`docs/plans/2026-08-23-posix-kernel-extraction/credentials.c`):
    // `setuid((uid_t)-1)` is EINVAL, while `setuid(0xFFFFFFFE)` succeeds. Darwin
    // answers EPERM to an unprivileged caller before it looks at the value, so its
    // own answer is unmeasured; refusing the sentinel there too costs nothing a
    // process could have held on Linux.
    let private unchanged : uint32 = System.UInt32.MaxValue

    /// <summary>The superuser's uid.</summary>
    let root : UserId = UserId 0u

    /// <summary>
    /// Convert to a raw <c>uid_t</c>.
    /// </summary>
    let toUInt32 (uid : UserId) : uint32 =
        match uid with
        | UserId uid -> uid

    /// <summary>
    /// The user ID <c>candidate</c> names, or <c>None</c> if it is the "do not change" indicator <c>(uid_t)-1</c>.
    /// </summary>
    let parse (candidate : uint32) : UserId option =
        if candidate = unchanged then
            None
        else
            Some (UserId candidate)

    /// <summary>
    /// As <c>parse</c>, but throwing <c>ArgumentException</c> if the candidate is the "do not change" indicator <c>(uid_t)-1</c>.
    /// </summary>
    let parseOrFail (context : string) (candidate : uint32) : UserId =
        match parse candidate with
        | Some uid -> uid
        | None ->
            raise (
                Refusal.exceptionOf
                    context
                    (RefusalKind.Contradictory "candidate")
                    $"%d{candidate} is (uid_t)-1, which is not a user ID a process can hold; setresuid(2) and chown(2) read it as \"leave this ID unchanged\"."
            )

/// <summary>
/// A group ID, as a guest would pass as a syscall argument.
/// </summary>
/// <remarks>
/// This is our model of <c>gid_t</c>.
/// <para />
/// Every <c>uint32</c> except <c>(gid_t)-1</c>, which is not an ID but the "leave this
/// unchanged" argument of <c>setresgid(2)</c> and <c>chown(2)</c>.
/// </remarks>
[<Struct>]
type GroupId =
    private
    | GroupId of gid : uint32

    override this.ToString () : string =
        match this with
        | GroupId gid -> string<uint32> gid

[<RequireQualifiedAccess>]
module GroupId =
    // Measured on Linux 6.18.5 as root: `setgid((gid_t)-1)` is EINVAL, and so is
    // `setgroups` with `(gid_t)-1` among the groups. Darwin's answer is unmeasured,
    // as for `UserId`.
    let private unchanged : uint32 = System.UInt32.MaxValue

    /// <summary>
    /// Convert to a raw <c>gid_t</c>.
    /// </summary>
    let toUInt32 (gid : GroupId) : uint32 =
        match gid with
        | GroupId gid -> gid

    /// <summary>
    /// The group ID <c>candidate</c> names, or <c>None</c> if it is <c>(gid_t)-1</c>.
    /// </summary>
    let parse (candidate : uint32) : GroupId option =
        if candidate = unchanged then
            None
        else
            Some (GroupId candidate)

    /// <summary>
    /// As <c>parse</c>, but throwing <c>ArgumentException</c> if the candidate is
    /// <c>(gid_t)-1</c>.
    /// </summary>
    let parseOrFail (context : string) (candidate : uint32) : GroupId =
        match parse candidate with
        | Some gid -> gid
        | None ->
            raise (
                Refusal.exceptionOf
                    context
                    (RefusalKind.Contradictory "candidate")
                    $"%d{candidate} is (gid_t)-1, which is not a group ID a process can hold; setresgid(2) and chown(2) read it as \"leave this ID unchanged\"."
            )

/// <summary>
/// Who a process is: the IDs a kernel consults when it decides what the
/// process may do.
/// </summary>
/// <remarks>
/// The real IDs are who started the process.
/// The effective IDs are who it is acting as (e.g. if you're running a <c>setuid</c> process).
/// The saved IDs are what it may switch its effective IDs back to with <c>seteuid</c>.
/// (These are all standard POSIX concepts; see <c>setresuid</c>.)
/// <para />
/// Most of the time, all these IDs are the same: they differ only in a process
/// that was started from a set-user-ID or set-group-ID executable, or that has changed its IDs since.
/// </remarks>
type Credentials =
    {
        RealUser : UserId
        EffectiveUser : UserId
        SavedUser : UserId
        RealGroup : GroupId
        EffectiveGroup : GroupId
        SavedGroup : GroupId
        /// <summary>
        /// Additional group memberships, with order and duplicates preserved.
        /// </summary>
        /// <remarks>
        /// The effective group is represented separately by <c>EffectiveGroup</c>.
        /// <para />
        /// The platforms differ on how <c>getgroups(2)</c> (<c>UnixCredentials.getgroups</c>) presents this list.
        /// See <c>GroupListReport</c> for the configuration which controls that presentation.
        /// </remarks>
        SupplementaryGroups : GroupId list
    }

/// <summary>
/// Which groups a flavour's <c>getgroups(2)</c> reports for a process's credentials,
/// and in what order.
/// </summary>
[<RequireQualifiedAccess>]
type GroupListReport =
    /// <summary>
    /// The supplementary groups in ascending numeric order, duplicates kept,
    /// and nothing else: the effective group is not added.
    /// </summary>
    /// <example>
    /// Linux does this: it sorts the list when <c>setgroups(2)</c> installs it.
    /// </example>
    | SortedSupplementaryGroups
    /// <summary>
    /// The effective group, then the supplementary groups exactly as they were supplied,
    /// duplicates kept.
    /// </summary>
    /// <example>
    /// Darwin does this: it keeps one list whose first group is the
    /// effective group. <c>setgroups(2)</c> installs the list it is given as it
    /// is, its first group becoming the effective group. Then <c>getgroups(2)</c>
    /// reports it unchanged (so setting <c>30,10,20</c> means <c>getgroups</c>
    /// reports <c>30,10,20</c> and the effective group becomes <c>30</c>).
    /// </example>
    | EffectiveGroupThenSupplementaryGroups

[<RequireQualifiedAccess>]
module Credentials =
    /// <summary>
    /// The credentials of a process whose real, effective and saved IDs are all
    /// <c>user</c> and <c>group</c>.
    /// </summary>
    /// <remarks>
    /// This represents a process that has not been started
    /// set-user-ID or set-group-ID and has not changed its IDs since being started.
    /// </remarks>
    let ofIds (user : UserId) (group : GroupId) (supplementaryGroups : GroupId list) : Credentials =
        {
            RealUser = user
            EffectiveUser = user
            SavedUser = user
            RealGroup = group
            EffectiveGroup = group
            SavedGroup = group
            SupplementaryGroups = supplementaryGroups
        }

    /// <summary>
    /// Whether a process with these credentials is exempt from the permission
    /// rules a kernel applies to everyone else.
    /// </summary>
    /// <remarks>
    /// Decided by the effective user ID alone: only effective uid 0 has this privilege.
    /// </remarks>
    let privilege (credentials : Credentials) : CallerPrivilege =
        // Measured on Linux 6.18.5 (`credentials.c`): binding port 80 succeeds with
        // real 1000 / effective 0 / saved 1000, and is EACCES with real 0 /
        // effective 1000 / saved 0 and with real 1000 / effective 1000 / saved 0.
        // Opening a root-owned 0600 file follows the same split. Group 0 is not
        // root.
        //
        // Every privilege question goes through here rather than comparing an ID
        // at its own site, because the sites answer *different* questions from
        // the same fact (whether `open` may ignore a mode that forbids the access
        // it was asked for, whether a write keeps a file's set-user-ID bits,
        // whether `bind` may take a port below 1024) and must not drift apart
        // about who root is.
        if credentials.EffectiveUser = UserId.root then
            CallerPrivilege.Privileged
        else
            CallerPrivilege.Unprivileged

    /// <summary>
    /// Whether a process with these credentials is in <c>group</c>: it is the
    /// effective group, or one of the supplementary groups.
    /// </summary>
    /// <remarks>
    /// The real and saved groups play no part.
    /// </remarks>
    let isInGroup (credentials : Credentials) (group : GroupId) : bool =
        group = credentials.EffectiveGroup
        || List.contains group credentials.SupplementaryGroups

    /// <summary>
    /// Returns the same credentials but with the effective user/group set
    /// to the current real ones.
    /// </summary>
    /// <remarks>
    /// This is who <c>access(2)</c> checks a path as, at every step of the
    /// walk and at the inode it reaches.
    ///
    /// Everything else is kept, so privilege and group membership are still
    /// decided as for any credentials (see <c>Credentials.privilege</c>), from
    /// the substituted IDs: a real uid of 0 is privileged here whatever
    /// the effective uid, and the supplementary groups count as they always
    /// do.
    /// </remarks>
    let realIdsAsEffective (credentials : Credentials) : Credentials =
        // Measured on Linux 6.18.5 (`access-rules.c`): over all 4096 modes on
        // a file and a directory and every R_OK/W_OK/X_OK combination, with
        // real 0 / effective 1000, real 1000 / effective 0, real and effective
        // users that are and are not the owner, and real and effective groups
        // that are and are not the inode's, `access(2)` answers exactly as
        // these credentials' standing says and `faccessat(AT_EACCESS)` exactly
        // as the originals' does. A directory only the effective user may
        // search refuses `access(2)` a path through it, and one only the real
        // user may search refuses `AT_EACCESS`.
        { credentials with
            EffectiveUser = credentials.RealUser
            EffectiveGroup = credentials.RealGroup
        }

    /// <summary>
    /// The groups <c>getgroups(2)</c> reports for a process with these credentials,
    /// under <c>report</c>.
    /// </summary>
    let internal reportedGroups (report : GroupListReport) (credentials : Credentials) : GroupId list =
        match report with
        | GroupListReport.SortedSupplementaryGroups ->
            // Measured on Linux 6.18.5 (`getgroups.c`): `setgroups(30,10,20)`
            // reports `10,20,30`; `(7,7,3,7)` reports `3,7,7,7`; an effective
            // group of 4242 that is not in the list is not reported; and IDs
            // above 2^31 sort as unsigned (`0,65536,2147483648,4294967294`).
            credentials.SupplementaryGroups |> List.sortBy GroupId.toUInt32
        | GroupListReport.EffectiveGroupThenSupplementaryGroups ->
            // Measured on Darwin 27.0 as root (`setresid.c`,
            // `docs/probes/darwin-root/credentials.c`): every list setgroups
            // installed was reported as given, its first group the effective
            // group; and at uid 501 (`getgroups.c`) a login process reports
            // its effective group first.
            credentials.EffectiveGroup :: credentials.SupplementaryGroups
