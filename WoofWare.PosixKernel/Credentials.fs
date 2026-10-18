namespace WoofWare.PosixKernel

/// A user ID: a `uid_t` a process can hold.
///
/// Every `uint32` except `(uid_t)-1`, which is not an ID but the "leave this
/// one unchanged" argument of `setresuid(2)` and `chown(2)`.
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

    /// The superuser.
    let root : UserId = UserId 0u

    /// The `uid_t` a kernel would report for this ID.
    let toUInt32 (uid : UserId) : uint32 =
        match uid with
        | UserId uid -> uid

    /// The user ID `candidate` names, or `None` if it is `(uid_t)-1`.
    let parse (candidate : uint32) : UserId option =
        if candidate = unchanged then
            None
        else
            Some (UserId candidate)

    /// As `parse`, but throwing `ArgumentException`, with `context` in the
    /// message, if `candidate` is `(uid_t)-1`.
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

/// A group ID: a `gid_t` a process can hold.
///
/// Every `uint32` except `(gid_t)-1`, which is not an ID but the "leave this
/// one unchanged" argument of `setresgid(2)` and `chown(2)`.
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

    /// The `gid_t` a kernel would report for this ID.
    let toUInt32 (gid : GroupId) : uint32 =
        match gid with
        | GroupId gid -> gid

    /// The group ID `candidate` names, or `None` if it is `(gid_t)-1`.
    let parse (candidate : uint32) : GroupId option =
        if candidate = unchanged then
            None
        else
            Some (GroupId candidate)

    /// As `parse`, but throwing `ArgumentException`, with `context` in the
    /// message, if `candidate` is `(gid_t)-1`.
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

/// Who a process is: the IDs a kernel consults when it decides what the
/// process may do.
///
/// The real IDs are who started the process, the effective IDs are who it is
/// acting as, and the saved IDs are what it may switch its effective IDs back
/// to. They differ only in a process that was started from a set-user-ID or
/// set-group-ID executable, or that has changed its IDs since.
type Credentials =
    {
        RealUser : UserId
        EffectiveUser : UserId
        SavedUser : UserId
        RealGroup : GroupId
        EffectiveGroup : GroupId
        SavedGroup : GroupId
        /// On Linux, the groups `setgroups(2)` was given, in the order it was
        /// given them, duplicates and all. On Darwin, which keeps one list
        /// whose first group is the effective group, the rest of that list:
        /// the groups `setgroups(2)` was given after its first, which became
        /// `EffectiveGroup`.
        ///
        /// Not necessarily what `getgroups(2)` reports
        /// (`UnixDescriptor.getgroups`): Linux reports these sorted, and Darwin
        /// reports the effective group and then these.
        SupplementaryGroups : GroupId list
    }

/// Which groups a flavour's `getgroups(2)` reports for a process's credentials,
/// and in what order.
[<RequireQualifiedAccess>]
type GroupListReport =
    /// The supplementary groups in ascending numeric order, duplicates kept,
    /// and nothing else: the effective group is not added.
    ///
    /// This is Linux, which sorts the list when `setgroups(2)` installs it.
    | SortedSupplementaryGroups
    /// The effective group, then the supplementary groups as they are held,
    /// duplicates kept.
    ///
    /// This is Darwin, which keeps one list whose first group is the
    /// effective group: `setgroups(2)` installs the list it is given as it
    /// is, its first group becoming the effective group, and `getgroups(2)`
    /// reports it unchanged (`30,10,20` as `30,10,20` with effective group 30;
    /// `7,7,3,7` as given).
    | EffectiveGroupThenSupplementaryGroups

[<RequireQualifiedAccess>]
module Credentials =
    /// The credentials of a process whose real, effective and saved IDs are all
    /// `user` and `group`, which is every process that has not been started
    /// set-user-ID or set-group-ID and has not changed its IDs since.
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

    /// Whether a process with these credentials is exempt from the permission
    /// rules a kernel applies to everyone else.
    ///
    /// Decided by the effective user ID alone: effective uid 0, and nothing else.
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

    /// Whether a process with these credentials is in `group`: it is the
    /// effective group, or one of the supplementary groups.
    ///
    /// The real and saved groups play no part.
    let isInGroup (credentials : Credentials) (group : GroupId) : bool =
        group = credentials.EffectiveGroup
        || List.contains group credentials.SupplementaryGroups

    /// These credentials with the real user and group standing in for the
    /// effective ones: who `access(2)` checks a path as, at every step of the
    /// walk and at the inode it reaches.
    ///
    /// Everything else is kept, so privilege and group membership are still
    /// decided as for any credentials (see `Credentials.privilege`), from
    /// the substituted IDs: a real uid of 0 is privileged here whatever
    /// the effective uid, and the supplementary groups count as they always
    /// do.
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

    /// The groups `getgroups(2)` reports for a process with these credentials,
    /// under `report`.
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
