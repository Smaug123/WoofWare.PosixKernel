namespace WoofWare.PosixKernel

/// Each flavour's `<fcntl.h>` number for the `AT_*` flags the `*at`
/// syscalls' flag words carry.
[<RequireQualifiedAccess>]
module internal AtFlagNumbering =

    // Linux's `<linux/fcntl.h>`, measured by `at-dirfd.c` (CONST, FLAGS) and
    // `access-rules.c` on Linux 6.18.5.

    /// Linux's `AT_SYMLINK_NOFOLLOW`.
    [<Literal>]
    let LinuxSymlinkNoFollow : int = 0x100

    /// Linux's `AT_REMOVEDIR`, which `faccessat(2)` reads as `AT_EACCESS`.
    [<Literal>]
    let LinuxRemoveDir : int = 0x200

    /// Linux's `AT_EACCESS`, which other calls read as `AT_REMOVEDIR`.
    [<Literal>]
    let LinuxEAccess : int = 0x200

    /// Linux's `AT_SYMLINK_FOLLOW`.
    [<Literal>]
    let LinuxSymlinkFollow : int = 0x400

    /// Linux's `AT_NO_AUTOMOUNT`.
    [<Literal>]
    let LinuxNoAutomount : int = 0x800

    /// Linux's `AT_EMPTY_PATH`.
    [<Literal>]
    let LinuxEmptyPath : int = 0x1000

    /// Linux's `AT_STATX_FORCE_SYNC`, one of the `AT_STATX_SYNC_TYPE` bits.
    [<Literal>]
    let LinuxStatxForceSync : int = 0x2000

    /// Linux's `AT_STATX_DONT_SYNC`, the other `AT_STATX_SYNC_TYPE` bit.
    [<Literal>]
    let LinuxStatxDontSync : int = 0x4000

    // Darwin's `<sys/fcntl.h>`, measured by the same probes on Darwin 27.0.

    /// Darwin's `AT_EACCESS`.
    [<Literal>]
    let DarwinEAccess : int = 0x10

    /// Darwin's `AT_SYMLINK_NOFOLLOW`.
    [<Literal>]
    let DarwinSymlinkNoFollow : int = 0x20

    /// Darwin's `AT_SYMLINK_FOLLOW`.
    [<Literal>]
    let DarwinSymlinkFollow : int = 0x40

    /// Darwin's `AT_REMOVEDIR`.
    [<Literal>]
    let DarwinRemoveDir : int = 0x80

    /// A bit Darwin's `unlinkat(2)` accepts and the SDK's `<sys/fcntl.h>`
    /// does not name.
    [<Literal>]
    let DarwinUnnamedBit8 : int = 0x100

    /// Darwin's `AT_REALDEV`.
    [<Literal>]
    let DarwinRealDev : int = 0x200

    /// Darwin's `AT_FDONLY`.
    [<Literal>]
    let DarwinFdOnly : int = 0x400

    /// Darwin's `AT_SYMLINK_NOFOLLOW_ANY`.
    [<Literal>]
    let DarwinSymlinkNoFollowAny : int = 0x800

    /// Another bit Darwin's `unlinkat(2)` accepts and the SDK's
    /// `<sys/fcntl.h>` does not name.
    [<Literal>]
    let DarwinUnnamedBit12 : int = 0x1000

    /// Darwin's `AT_RESOLVE_BENEATH`.
    [<Literal>]
    let DarwinResolveBeneath : int = 0x2000

    /// Darwin's `AT_NODELETEBUSY`.
    [<Literal>]
    let DarwinNoDeleteBusy : int = 0x4000

    /// Darwin's `AT_UNIQUE`.
    [<Literal>]
    let DarwinUnique : int = 0x8000

    /// The name each flavour's header gives each bit this kernel accepts as
    /// unmodelled somewhere, for a refusal's message.
    let private unmodelledNames (flavour : SimulatedUnixFlavour) : (int * string) list =
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            [
                LinuxNoAutomount, "AT_NO_AUTOMOUNT"
                LinuxStatxForceSync, "AT_STATX_FORCE_SYNC"
                LinuxStatxDontSync, "AT_STATX_DONT_SYNC"
            ]
        | SimulatedUnixFlavour.Darwin ->
            [
                DarwinUnnamedBit8, "a bit the SDK does not name"
                DarwinRealDev, "AT_REALDEV"
                DarwinFdOnly, "AT_FDONLY"
                DarwinSymlinkNoFollowAny, "AT_SYMLINK_NOFOLLOW_ANY"
                DarwinUnnamedBit12, "a bit the SDK does not name"
                DarwinResolveBeneath, "AT_RESOLVE_BENEATH"
                DarwinNoDeleteBusy, "AT_NODELETEBUSY"
                DarwinUnique, "AT_UNIQUE"
            ]

    /// Each set bit of `bits`, named as `flavour`'s header names it, with its
    /// number.
    let internal describeBits (flavour : SimulatedUnixFlavour) (bits : int) : string list =
        let names = unmodelledNames flavour

        [ 0..30 ]
        |> List.map (fun shift -> 1 <<< shift)
        |> List.filter (fun bit -> bits &&& bit <> 0)
        |> List.map (fun bit ->
            match names |> List.tryFind (fun (named, _) -> named = bit) with
            | Some (_, name) -> $"%s{name} (0x%x{bit})"
            | None -> $"0x%x{bit}"
        )

/// What the flag word of `fstatat(2)`, `fchmodat(2)`, `fchownat(2)`,
/// `utimensat(2)`, `linkat(2)` or `faccessat(2)` says about its path, once
/// screened.
type internal AtFlagArguments =
    {
        /// Whether a symbolic link in the path's final position is followed.
        FinalSymlink : SymlinkPolicy
        /// What the call makes of an empty path: under Linux's
        /// `AT_EMPTY_PATH`, the object `dirfd` names.
        EmptyPath : EmptyPathMeaning
    }

/// A flag word a `*at` syscall refused, because it carries flags the flavour
/// accepts and this library does not model.
type internal UnmodelledAtFlags =
    {
        /// The flavour whose numbering the word is in.
        Flavour : SimulatedUnixFlavour
        /// The whole word.
        Flags : int
        /// The bits of `Flags` the call accepts and this library does not
        /// model.
        Unmodelled : int
    }

[<RequireQualifiedAccess>]
module internal UnmodelledAtFlags =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked.
    let describe (refused : UnmodelledAtFlags) : string =
        let bits =
            match AtFlagNumbering.describeBits refused.Flavour refused.Unmodelled |> List.rev with
            | [] -> "no such flag"
            | [ only ] -> only
            | last :: rest -> String.concat ", " (List.rev rest) + " and " + last

        $"the flag word 0x%x{refused.Flags} carries %s{bits}, which this %O{refused.Flavour} call accepts and this library does not model."

/// What screening a `*at` syscall's flag word came to.
[<RequireQualifiedAccess>]
type internal AtFlagScreen<'Arguments> =
    /// The word is one this kernel accepts, and this is what it says.
    | Screened of 'Arguments
    /// The call fails with this errno before its path is copied in.
    | Failed of error : UnixError
    /// The word carries flags the flavour accepts and this library does not
    /// model.
    | Unmodelled of UnmodelledAtFlags

[<RequireQualifiedAccess>]
module internal AtFlagScreen =
    /// What a screened word says, read by `read`; a failure or a refusal as
    /// it was.
    let map<'A, 'B> (read : 'A -> 'B) (screen : AtFlagScreen<'A>) : AtFlagScreen<'B> =
        match screen with
        | AtFlagScreen.Screened arguments -> AtFlagScreen.Screened (read arguments)
        | AtFlagScreen.Failed error -> AtFlagScreen.Failed error
        | AtFlagScreen.Unmodelled refused -> AtFlagScreen.Unmodelled refused

/// What a `*at` syscall answers for a bit of its flag word it neither
/// models nor accepts as unmodelled.
[<RequireQualifiedAccess>]
type internal OtherAtFlags =
    /// Nothing: the bit is ignored.
    | Ignored
    /// EINVAL, which beats an unmodelled bit beside it.
    | RejectedBeforeUnmodelled
    /// EINVAL, except that a word carrying an unmodelled bit beside it is
    /// refused: which of the two a real kernel answers is unmeasured.
    | RejectedUnlessUnmodelled

/// How one flavour's `*at` syscall screens its flag word, before its path is
/// copied in.
type internal AtFlagScreening =
    {
        /// The bits the call accepts and this library models.
        Modelled : int
        /// The bits the call accepts and this library does not model.
        Unmodelled : int
        /// What the call answers for any other bit.
        Others : OtherAtFlags
    }

/// Which bit of a flag word says whether a symbolic link in the path's final
/// position is followed.
[<RequireQualifiedAccess>]
type internal FinalSymlinkFlag =
    /// The link is followed unless the word carries this bit:
    /// `AT_SYMLINK_NOFOLLOW`.
    | NotFollowedUnder of bit : int
    /// The link is followed only if the word carries this bit:
    /// `AT_SYMLINK_FOLLOW`.
    | FollowedUnder of bit : int

/// How one flavour's `*at` syscall screens its flag word, and what the bits it
/// admits say about its path.
type internal AtFlagRules =
    {
        /// Which bits the call accepts, and what it answers for the rest.
        Screening : AtFlagScreening
        /// The bit that decides whether a final symbolic link is followed.
        FinalSymlink : FinalSymlinkFlag
        /// The bit that makes an empty path name what `dirfd` names (Linux's
        /// `AT_EMPTY_PATH`), where the call reads one.
        EmptyPath : int option
    }

[<RequireQualifiedAccess>]
module internal AtFlags =

    /// The bits of `flags` that `screening` admits, if it admits the word,
    /// which is in `flavour`'s numbering.
    let screenWord (flavour : SimulatedUnixFlavour) (screening : AtFlagScreening) (flags : int) : AtFlagScreen<int> =
        let unmodelled = flags &&& screening.Unmodelled
        let rejected = flags &&& ~~~(screening.Modelled ||| screening.Unmodelled)

        let refused () : AtFlagScreen<int> =
            AtFlagScreen.Unmodelled
                {
                    Flavour = flavour
                    Flags = flags
                    Unmodelled = unmodelled
                }

        let admitted () : AtFlagScreen<int> =
            AtFlagScreen.Screened (flags &&& screening.Modelled)

        match screening.Others with
        | OtherAtFlags.Ignored -> if unmodelled <> 0 then refused () else admitted ()
        | OtherAtFlags.RejectedBeforeUnmodelled ->
            if rejected <> 0 then AtFlagScreen.Failed UnixError.EINVAL
            elif unmodelled <> 0 then refused ()
            else admitted ()
        | OtherAtFlags.RejectedUnlessUnmodelled ->
            if unmodelled <> 0 then refused ()
            elif rejected <> 0 then AtFlagScreen.Failed UnixError.EINVAL
            else admitted ()

    /// What the admitted bits `admitted` say about the path, under `rules`.
    let read (rules : AtFlagRules) (admitted : int) : AtFlagArguments =
        {
            FinalSymlink =
                match rules.FinalSymlink with
                | FinalSymlinkFlag.NotFollowedUnder bit ->
                    if admitted &&& bit <> 0 then
                        SymlinkPolicy.NoFollowFinal
                    else
                        SymlinkPolicy.Follow
                | FinalSymlinkFlag.FollowedUnder bit ->
                    if admitted &&& bit <> 0 then
                        SymlinkPolicy.Follow
                    else
                        SymlinkPolicy.NoFollowFinal
            EmptyPath =
                match rules.EmptyPath with
                | Some bit when admitted &&& bit <> 0 -> EmptyPathMeaning.NamesStartingPoint
                | Some _
                | None -> EmptyPathMeaning.Walked
        }

    /// Screen `flags` by `rules`, in `flavour`'s numbering, and read what the
    /// word says about the path.
    let screen (flavour : SimulatedUnixFlavour) (rules : AtFlagRules) (flags : int) : AtFlagScreen<AtFlagArguments> =
        screenWord flavour rules.Screening flags |> AtFlagScreen.map (read rules)

/// Each `*at` syscall's flag word, on each flavour: which bits it accepts and
/// models, which it accepts and this library does not, and which of EINVAL
/// and a refusal a word carrying both a rejected and an unmodelled bit gets.
/// The calls differ on purpose: each row is measured.
[<RequireQualifiedAccess>]
module internal AtFlagRules =
    // Every screening below runs before the path is copied in and before
    // `dirfd` is looked at.

    /// `fstatat(2)`.
    let fstatat (flavour : SimulatedUnixFlavour) : AtFlagRules =
        // Measured by `at-dirfd.c`: every single bit, with AT_FDCWD and a
        // regular file (FLAGS), and a rejected bit against an unreadable path,
        // a bad dirfd, an empty path and a missing name (FLAGORDER), which it
        // beats on both flavours. Which of EINVAL and an unmodelled flag's own
        // answer wins when a word carries both is unmeasured, so such a word
        // is refused.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.LinuxSymlinkNoFollow ||| AtFlagNumbering.LinuxEmptyPath
                        Unmodelled =
                            AtFlagNumbering.LinuxNoAutomount
                            ||| AtFlagNumbering.LinuxStatxForceSync
                            ||| AtFlagNumbering.LinuxStatxDontSync
                        Others = OtherAtFlags.RejectedUnlessUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.LinuxSymlinkNoFollow
                EmptyPath = Some AtFlagNumbering.LinuxEmptyPath
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.DarwinSymlinkNoFollow
                        Unmodelled =
                            AtFlagNumbering.DarwinRealDev
                            ||| AtFlagNumbering.DarwinFdOnly
                            ||| AtFlagNumbering.DarwinSymlinkNoFollowAny
                            ||| AtFlagNumbering.DarwinResolveBeneath
                            ||| AtFlagNumbering.DarwinUnique
                        Others = OtherAtFlags.RejectedUnlessUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.DarwinSymlinkNoFollow
                EmptyPath = None
            }

    /// `fchmodat(2)` and `fchownat(2)`, which accept the same flags on each
    /// flavour.
    let attributeChange (flavour : SimulatedUnixFlavour) : AtFlagRules =
        // Measured by `at-dirfd.c` (FLAGS, FLAGORDER): every single bit with
        // AT_FDCWD and a regular file, and a rejected bit against an
        // unreadable path, a bad dirfd, an empty path and a missing name,
        // which it beats on both flavours. `chmod-chown-at.c` (FLAGMIX): a
        // rejected bit beside each accepted one is EINVAL too.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.LinuxSymlinkNoFollow ||| AtFlagNumbering.LinuxEmptyPath
                        Unmodelled = 0
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.LinuxSymlinkNoFollow
                EmptyPath = Some AtFlagNumbering.LinuxEmptyPath
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.DarwinSymlinkNoFollow
                        Unmodelled =
                            AtFlagNumbering.DarwinSymlinkNoFollowAny
                            ||| AtFlagNumbering.DarwinResolveBeneath
                            ||| AtFlagNumbering.DarwinUnique
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.DarwinSymlinkNoFollow
                EmptyPath = None
            }

    /// `utimensat(2)`.
    let utimensat (flavour : SimulatedUnixFlavour) : AtFlagRules =
        // Measured by `at-dirfd.c` (FLAGS, FLAGORDER): each single bit with
        // AT_FDCWD and a regular file; Linux's rejected bit beats an
        // unreadable path, a bad dirfd, an empty path and a missing name.
        // `utimensat-rules.c` (DFLAGS): on Darwin every single bit against a
        // final link, a link mid-path, a path through "..", and an absolute
        // path; only 0x20 (the final link not followed), 0x800 (ELOOP for a
        // link anywhere, the final one not followed) and 0x2000 (an absolute
        // path refused) changed anything.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.LinuxSymlinkNoFollow ||| AtFlagNumbering.LinuxEmptyPath
                        Unmodelled = 0
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.LinuxSymlinkNoFollow
                EmptyPath = Some AtFlagNumbering.LinuxEmptyPath
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.DarwinSymlinkNoFollow
                        Unmodelled =
                            AtFlagNumbering.DarwinSymlinkNoFollowAny
                            ||| AtFlagNumbering.DarwinResolveBeneath
                            ||| AtFlagNumbering.DarwinUnique
                        Others = OtherAtFlags.Ignored
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.DarwinSymlinkNoFollow
                EmptyPath = None
            }

    /// `linkat(2)`, whose flag word speaks of its source.
    let linkat (flavour : SimulatedUnixFlavour) : AtFlagRules =
        // Measured by `at-dirfd.c` (FLAGS, FLAGORDER): every single bit, and a
        // bad bit against a NULL source, a bad dirfd and the empty path.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.LinuxSymlinkFollow ||| AtFlagNumbering.LinuxEmptyPath
                        Unmodelled = 0
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.FollowedUnder AtFlagNumbering.LinuxSymlinkFollow
                EmptyPath = Some AtFlagNumbering.LinuxEmptyPath
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.DarwinSymlinkFollow
                        Unmodelled =
                            AtFlagNumbering.DarwinSymlinkNoFollowAny
                            ||| AtFlagNumbering.DarwinResolveBeneath
                            ||| AtFlagNumbering.DarwinUnique
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.FollowedUnder AtFlagNumbering.DarwinSymlinkFollow
                EmptyPath = None
            }

    /// `faccessat(2)`'s flag word, which Linux screens after its mode word and
    /// Darwin alone (see `AccessRules.screen`). Its modelled bits include
    /// `AT_EACCESS`, which says which IDs the path is judged with.
    let faccessat (flavour : SimulatedUnixFlavour) : AtFlagRules =
        // Measured by `access-rules.c`: every single bit of the word, and the
        // order of bad flags, a bad dirfd and the path's copy-in against one
        // another. On Darwin, which of EINVAL and an unmodelled flag's own
        // answer wins when a word carries both is unmeasured, so such a word
        // is refused.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Screening =
                    {
                        Modelled =
                            AtFlagNumbering.LinuxSymlinkNoFollow
                            ||| AtFlagNumbering.LinuxEAccess
                            ||| AtFlagNumbering.LinuxEmptyPath
                        Unmodelled = 0
                        Others = OtherAtFlags.RejectedBeforeUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.LinuxSymlinkNoFollow
                EmptyPath = Some AtFlagNumbering.LinuxEmptyPath
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Screening =
                    {
                        Modelled = AtFlagNumbering.DarwinEAccess ||| AtFlagNumbering.DarwinSymlinkNoFollow
                        Unmodelled =
                            AtFlagNumbering.DarwinSymlinkNoFollowAny
                            ||| AtFlagNumbering.DarwinResolveBeneath
                            ||| AtFlagNumbering.DarwinUnique
                        Others = OtherAtFlags.RejectedUnlessUnmodelled
                    }
                FinalSymlink = FinalSymlinkFlag.NotFollowedUnder AtFlagNumbering.DarwinSymlinkNoFollow
                EmptyPath = None
            }

    /// `unlinkat(2)`'s flag word, whose one modelled bit is `AT_REMOVEDIR`
    /// (see `UnlinkAtRules.screen`).
    let unlinkat (flavour : SimulatedUnixFlavour) : AtFlagScreening =
        // Measured by `at-dirfd.c` (FLAGS, FLAGORDER: every single bit, and a
        // rejected bit against a NULL path, a bad dirfd and the empty path)
        // and by `unlinkat-rules.c` (FLAGS2: AT_REMOVEDIR, and each of
        // Darwin's six, beside a rejected bit, against a file, a directory, a
        // NULL path and a bad dirfd, which is EINVAL in every cell).
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            {
                Modelled = AtFlagNumbering.LinuxRemoveDir
                Unmodelled = 0
                Others = OtherAtFlags.RejectedBeforeUnmodelled
            }
        | SimulatedUnixFlavour.Darwin ->
            {
                Modelled = AtFlagNumbering.DarwinRemoveDir
                Unmodelled =
                    AtFlagNumbering.DarwinUnnamedBit8
                    ||| AtFlagNumbering.DarwinSymlinkNoFollowAny
                    ||| AtFlagNumbering.DarwinUnnamedBit12
                    ||| AtFlagNumbering.DarwinResolveBeneath
                    ||| AtFlagNumbering.DarwinNoDeleteBusy
                    ||| AtFlagNumbering.DarwinUnique
                Others = OtherAtFlags.RejectedBeforeUnmodelled
            }
