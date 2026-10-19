namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// How a caller stands towards an inode it need not own, and every rule that
/// reads that standing: which permission triple applies, the sticky
/// directory, and the set-group-ID bit a write, a truncation or a creating
/// open strips.
///
/// The rows come from
/// `docs/plans/2026-08-23-posix-kernel-extraction/permission-standing.c`, run
/// on Linux 6.18.5 (aarch64, root in the container, ext4 and tmpfs) and on
/// Darwin 27.0 at uid 501; its output is beside it. The sweeps it ran are
/// replayed here as exhaustive properties against the same predictions it
/// compared the kernels with, and its individually measured rows as literals
/// against filesystems built to match the ones it measured.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPermissionStanding =

    let private context : string = "TestPermissionStanding"

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private epoch : UnixTimestamp = UnixTimestamp.ofMillisecondsSinceEpoch 0L

    let private uid (raw : uint32) : UserId = UserId.parseOrFail context raw
    let private gid (raw : uint32) : GroupId = GroupId.parseOrFail context raw

    let private owner (user : uint32) (group : uint32) : InodeOwner =
        {
            User = uid user
            Group = gid group
        }

    let private mode (bits : int) : PermissionBits = PermissionBits.parseOrFail context bits

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private ok (result : Result<'a, 'e>) : 'a =
        match result with
        | Ok value -> value
        | Error error -> failwith $"expected Ok, got %O{error}"

    /// Every one of the eight standings, each of which some caller can be in.
    let private allStandings : Standing list =
        [
            for privilege in [ CallerPrivilege.Unprivileged ; CallerPrivilege.Privileged ] do
                for owns in [ false ; true ] do
                    for inGroup in [ false ; true ] do
                        yield
                            {
                                Privilege = privilege
                                Owns = owns
                                InGroup = inGroup
                            }
        ]

    let private allModes : int list = [ 0..0o7777 ]

    let private allRequests : AccessRequest list =
        [ AccessRequest.Read ; AccessRequest.Write ; AccessRequest.SearchDirectory ]

    // ------------------------------------------------------------- Standing.toward

    [<Test>]
    let ``a caller's standing is read from its effective IDs and supplementary groups alone`` () : unit =
        let ownerGen =
            Gen.map2
                (fun user group ->
                    {
                        User = user
                        Group = group
                    }
                )
                CredentialsGen.userId
                CredentialsGen.groupId

        // Owners drawn half the time from the credentials' own IDs, so that the
        // `true` answers are reached as often as the `false` ones.
        let gen =
            gen {
                let! credentials = CredentialsGen.credentials

                let! owner =
                    Gen.oneof
                        [
                            ownerGen
                            gen {
                                let! user =
                                    Gen.elements
                                        [ credentials.EffectiveUser ; credentials.RealUser ; credentials.SavedUser ]

                                let! group =
                                    Gen.elements (
                                        credentials.EffectiveGroup
                                        :: credentials.RealGroup
                                        :: credentials.SavedGroup
                                        :: credentials.SupplementaryGroups
                                    )

                                return
                                    {
                                        User = user
                                        Group = group
                                    }
                            }
                        ]

                return credentials, owner
            }

        let property (credentials : Credentials, owner : InodeOwner) : unit =
            let expected =
                {
                    Privilege =
                        if UserId.toUInt32 credentials.EffectiveUser = 0u then
                            CallerPrivilege.Privileged
                        else
                            CallerPrivilege.Unprivileged
                    Owns = owner.User = credentials.EffectiveUser
                    InGroup =
                        credentials.EffectiveGroup :: credentials.SupplementaryGroups
                        |> List.exists (fun group -> group = owner.Group)
                }

            Standing.toward credentials owner |> shouldEqual expected

        Check.One (config, Prop.forAll (Arb.fromGen gen) property)

    [<Test>]
    let ``the measured Linux rows about which IDs are read`` () : unit =
        // real 1001, effective 1000: the effective user owns the file.
        let effectiveOwner =
            { Credentials.ofIds (uid 1000u) (gid 1000u) [] with
                RealUser = uid 1001u
                RealGroup = gid 1001u
            }

        let standing = Standing.toward effectiveOwner (owner 1000u 3000u)

        PermissionBits.deniedTo standing AccessRequest.Read (mode 0o400)
        |> shouldEqual false

        // real group 2000, effective group 1000, no supplementary groups.
        let effectiveGroup =
            { Credentials.ofIds (uid 1000u) (gid 1000u) [] with
                RealGroup = gid 2000u
            }

        PermissionBits.deniedTo (Standing.toward effectiveGroup (owner 1001u 2000u)) AccessRequest.Read (mode 0o040)
        |> shouldEqual true

        PermissionBits.deniedTo (Standing.toward effectiveGroup (owner 1001u 1000u)) AccessRequest.Read (mode 0o040)
        |> shouldEqual false

    // ------------------------------------------------------------- which triple applies

    /// The rule `permission-standing.c` compared every kernel answer against:
    /// the first of owner, group and other that the caller is in selects the
    /// only triple consulted, and root is refused none of these three.
    let private referenceDenied (standing : Standing) (request : AccessRequest) (bits : int) : bool =
        match standing.Privilege with
        | CallerPrivilege.Privileged -> false
        | CallerPrivilege.Unprivileged ->

        let triple =
            if standing.Owns then (bits >>> 6) &&& 7
            elif standing.InGroup then (bits >>> 3) &&& 7
            else bits &&& 7

        let wanted =
            match request with
            | AccessRequest.Read -> 4
            | AccessRequest.Write -> 2
            | AccessRequest.SearchDirectory -> 1

        triple &&& wanted = 0

    [<Test>]
    let ``deniedTo consults exactly the triple the standing selects, over every mode`` () : unit =
        for standing in allStandings do
            for request in allRequests do
                for bits in allModes do
                    let actual = PermissionBits.deniedTo standing request (mode bits)

                    if actual <> referenceDenied standing request bits then
                        failwith $"%O{standing} asking %O{request} of 0o%04o{bits}: deniedTo said %b{actual}"

    // ------------------------------------------------------------- the sticky bit

    [<Test>]
    let ``the sticky bit forbids exactly a caller who owns neither the directory nor the entry`` () : unit =
        for directoryBits in allModes do
            for privilege in [ CallerPrivilege.Unprivileged ; CallerPrivilege.Privileged ] do
                for ownsDirectory in [ false ; true ] do
                    for ownsEntry in [ false ; true ] do
                        for inGroup in [ false ; true ] do
                            let towards (owns : bool) : Standing =
                                {
                                    Privilege = privilege
                                    Owns = owns
                                    InGroup = inGroup
                                }

                            let expected =
                                if directoryBits &&& 0o1000 = 0 || ownsDirectory || ownsEntry then
                                    StickyRemoval.Unrestricted
                                else
                                    match privilege with
                                    | CallerPrivilege.Privileged -> StickyRemoval.ForbiddenButPrivileged
                                    | CallerPrivilege.Unprivileged -> StickyRemoval.Forbidden

                            PermissionBits.stickyRemoval
                                (towards ownsDirectory)
                                (towards ownsEntry)
                                (mode directoryBits)
                            |> shouldEqual expected

    [<Test>]
    let ``two standings that disagree about privilege are not one caller's`` () : unit =
        let unprivileged = Owners.owning CallerPrivilege.Unprivileged
        let privileged = Owners.owning CallerPrivilege.Privileged

        (fun () ->
            PermissionBits.stickyRemoval unprivileged privileged (mode 0o1777)
            |> ignore<StickyRemoval>
        )
        |> shouldFail

    // ------------------------------------------------------------- write and truncation strips

    /// `permission-standing.c`'s prediction for Linux, which every write and
    /// truncation it made matched.
    let private linuxStrip (standing : Standing) (bits : int) : int =
        match standing.Privilege with
        | CallerPrivilege.Privileged -> bits
        | CallerPrivilege.Unprivileged ->

        let clearsGroup = bits &&& 0o010 <> 0 || not standing.InGroup
        bits &&& ~~~(0o4000 ||| (if clearsGroup then 0o2000 else 0))

    [<Test>]
    let ``Linux's write and truncation strip S_ISGID from a writer outside the group, over every mode`` () : unit =
        for standing in allStandings do
            for bits in allModes do
                let expected = linuxStrip standing bits

                PermissionBits.afterContentChangingWrite
                    SetGroupIdOnWrite.StripWhenGroupExecutableOrWriterOutsideGroup
                    standing
                    (mode bits)
                |> shouldEqual (mode expected)

                PermissionBits.afterTruncation SetIdBitsOnTruncation.Strip standing (mode bits)
                |> shouldEqual (mode expected)

    [<Test>]
    let ``Darwin's write and truncation strip both set-ID bits and keep them, over every mode and standing`` () : unit =
        for standing in allStandings do
            for bits in allModes do
                let written =
                    match standing.Privilege with
                    | CallerPrivilege.Privileged -> bits
                    | CallerPrivilege.Unprivileged -> bits &&& ~~~0o6000

                PermissionBits.afterContentChangingWrite SetGroupIdOnWrite.StripAlways standing (mode bits)
                |> shouldEqual (mode written)

                PermissionBits.afterTruncation SetIdBitsOnTruncation.Preserve standing (mode bits)
                |> shouldEqual (mode bits)

    [<Test>]
    let ``Darwin's root-files SETID rows, for root and for uid 501, over every mode`` () : unit =
        // `docs/probes/darwin-root/root-files.c`, run as root on Darwin 27.0:
        // a file of each of the 4096 modes, owned by root, uid 501 or uid 502
        // in groups 0, 20, 701 and 7777, opened O_WRONLY (with O_TRUNC for
        // `open(O_TRUNC)`) by root or by uid 501 in groups 20 and 701, and
        // then written one byte or none, or truncated. A cell is `.` when the
        // mode is unchanged, the digit of the special bits dropped otherwise,
        // and `A` where the open was EACCES.
        let rows = DarwinRootFiles.section "SETID"
        rows |> List.length |> shouldEqual 45

        let changed (before : int) (after : PermissionBits) : char =
            let after = PermissionBits.toInt after

            if after = before then
                '.'
            else
                char (int '0' + ((before &&& ~~~after) >>> 9))

        let mismatches =
            [
                for row in rows do
                    let standing = Standing.toward (DarwinRootFiles.credentialsOf row.Caller) row.Owner

                    for bits in allModes do
                        let written () =
                            PermissionBits.afterContentChangingWrite SetGroupIdOnWrite.StripAlways standing (mode bits)
                            |> changed bits

                        let truncated () =
                            PermissionBits.afterTruncation SetIdBitsOnTruncation.Preserve standing (mode bits)
                            |> changed bits

                        let modelled =
                            if PermissionBits.deniedTo standing AccessRequest.Write (mode bits) then
                                'A'
                            else
                                match row.Call with
                                | "write(1)" -> written ()
                                // A write of no bytes changes nothing.
                                | "write(0)" -> '.'
                                | "ftruncate(0)"
                                | "ftruncate(same)"
                                | "open(O_TRUNC)" -> truncated ()
                                | other -> failwith $"unexpected SETID call %s{other}"

                        if modelled <> row.Cells.[bits] then
                            yield
                                $"%s{row.Caller} %O{row.Owner} %s{row.Call} 0o%04o{bits}: measured %c{row.Cells.[bits]}, modelled %c{modelled}"
            ]

        if not (List.isEmpty mismatches) then
            let shown = mismatches |> List.truncate 10 |> String.concat "\n"
            failwith $"%d{List.length mismatches} cells differ, for example:\n%s{shown}"

    [<Test>]
    let ``the measured Linux write rows, by writer`` () : unit =
        // `WRITE-SGID` in `ownership-probe.c`'s Linux output, which wrote one
        // byte and truncated to 0 alike.
        let rows =
            [
                // owns, in group, before, after
                false, true, 0o2666, 0o2666
                false, false, 0o2666, 0o0666
                false, false, 0o2676, 0o0676
                true, false, 0o2666, 0o0666
                true, true, 0o2666, 0o2666
                false, false, 0o4666, 0o0666
            ]

        for owns, inGroup, before, after in rows do
            let standing =
                {
                    Privilege = CallerPrivilege.Unprivileged
                    Owns = owns
                    InGroup = inGroup
                }

            PermissionBits.afterContentChangingWrite
                SetGroupIdOnWrite.StripWhenGroupExecutableOrWriterOutsideGroup
                standing
                (mode before)
            |> shouldEqual (mode after)

            PermissionBits.afterTruncation SetIdBitsOnTruncation.Strip standing (mode before)
            |> shouldEqual (mode after)

        // Root, not in the file's group: nothing moves.
        let root =
            {
                Privilege = CallerPrivilege.Privileged
                Owns = false
                InGroup = false
            }

        PermissionBits.afterContentChangingWrite
            SetGroupIdOnWrite.StripWhenGroupExecutableOrWriterOutsideGroup
            root
            (mode 0o2666)
        |> shouldEqual (mode 0o2666)

    // ------------------------------------------------------------- the creation strip

    let private linuxOpen : CreatingOpenRules =
        SimulatedUnixPlatform.creatingOpenRules SimulatedUnixPlatform.linuxX64

    let private darwinOpen : CreatingOpenRules =
        SimulatedUnixPlatform.creatingOpenRules SimulatedUnixPlatform.macOsArm64

    /// The probe's `umask(2)` arguments.
    let private umasks : int list = [ 0 ; 0o010 ; 0o022 ; 0o7777 ]

    /// The mask `umask(argument)` leaves a process on `platform` with, which is
    /// what a creation reads.
    let private stored (platform : SimulatedUnixPlatform) (argument : int) : PermissionBits =
        mode (
            argument
            &&& PermissionBits.toInt (SimulatedUnixPlatform.umaskStoredBits platform)
        )

    /// `permission-standing.c`'s prediction for a Linux creating open.
    let private linuxCreated (parentSetGroupId : bool) (standing : Standing) (requested : int) (umask : int) : int =
        let stripped =
            if
                requested &&& 0o2010 = 0o2010
                && parentSetGroupId
                && standing.Privilege = CallerPrivilege.Unprivileged
                && not standing.InGroup
            then
                requested &&& ~~~0o2000
            else
                requested

        stripped &&& 0o7777 &&& ~~~(umask &&& 0o777)

    [<Test>]
    let ``Linux's creating open strips S_ISGID in a foreign set-group-ID directory, over every mode and umask``
        ()
        : unit
        =
        for parentBits in [ 0o777 ; 0o2777 ] do
            for standing in allStandings do
                for umask in umasks do
                    for requested in allModes do
                        CreatingOpenRules.createdPermissions
                            linuxOpen
                            standing
                            (mode parentBits)
                            (stored SimulatedUnixPlatform.linuxX64 umask)
                            requested
                        |> shouldEqual (mode (linuxCreated (parentBits &&& 0o2000 <> 0) standing requested umask))

    [<Test>]
    let ``Darwin's creating open can never set S_ISGID, whoever owns the directory`` () : unit =
        for standing in allStandings do
            for umask in umasks do
                for requested in allModes do
                    let created =
                        CreatingOpenRules.createdPermissions
                            darwinOpen
                            standing
                            (mode 0o2777)
                            (stored SimulatedUnixPlatform.macOsArm64 umask)
                            requested

                    created |> shouldEqual (mode (requested &&& 0o777 &&& ~~~(umask &&& 0o777)))

    // ------------------------------------------------------------- bit identity for an owner

    // The rules as they stood when every caller was taken to own every inode,
    // transcribed. A caller that owns an inode and is in its group, which is
    // every caller towards everything in a filesystem it built itself, must
    // get exactly these answers.

    let private ownerOnlyDenied (privilege : CallerPrivilege) (request : AccessRequest) (bits : int) : bool =
        match privilege with
        | CallerPrivilege.Privileged -> false
        | CallerPrivilege.Unprivileged ->
            let bit =
                match request with
                | AccessRequest.Read -> 0o400
                | AccessRequest.Write -> 0o200
                | AccessRequest.SearchDirectory -> 0o100

            bits &&& bit <> bit

    let private ownerOnlyStrip (privilege : CallerPrivilege) (linux : bool) (bits : int) : int =
        match privilege with
        | CallerPrivilege.Privileged -> bits
        | CallerPrivilege.Unprivileged ->
            let cleared =
                if linux then
                    0o4000 ||| (if bits &&& 0o010 <> 0 then 0o2000 else 0)
                else
                    0o6000

            bits &&& ~~~cleared

    [<Test>]
    let ``every rule answers an owner in the inode's group exactly as it answered before standings existed`` () : unit =
        for privilege in [ CallerPrivilege.Unprivileged ; CallerPrivilege.Privileged ] do
            let standing = Owners.owning privilege

            for bits in allModes do
                for request in allRequests do
                    PermissionBits.deniedTo standing request (mode bits)
                    |> shouldEqual (ownerOnlyDenied privilege request bits)

                PermissionBits.afterContentChangingWrite
                    SetGroupIdOnWrite.StripWhenGroupExecutableOrWriterOutsideGroup
                    standing
                    (mode bits)
                |> shouldEqual (mode (ownerOnlyStrip privilege true bits))

                PermissionBits.afterContentChangingWrite SetGroupIdOnWrite.StripAlways standing (mode bits)
                |> shouldEqual (mode (ownerOnlyStrip privilege false bits))

                PermissionBits.afterTruncation SetIdBitsOnTruncation.Strip standing (mode bits)
                |> shouldEqual (mode (ownerOnlyStrip privilege true bits))

                PermissionBits.afterTruncation SetIdBitsOnTruncation.Preserve standing (mode bits)
                |> shouldEqual (mode bits)

                PermissionBits.stickyRemoval standing standing (mode bits)
                |> shouldEqual StickyRemoval.Unrestricted

                for rules in [ linuxOpen ; darwinOpen ] do
                    for umask in umasks do
                        CreatingOpenRules.createdPermissions rules standing (mode 0o2777) (mode umask) bits
                        |> shouldEqual (PermissionBits.fromCreationMode rules.ModeMask (mode umask) bits)

    // ------------------------------------------------------------- hand-built filesystems

    /// The inode `p` names, walked as root.
    let private inodeAt (vfs : VirtualFileSystem) (p : string) : InodeNumber =
        match
            PathWalk.resolveExisting
                (SimulatedUnixPlatform.pathLimits SimulatedUnixPlatform.linuxX64)
                Owners.root
                SymlinkProtection.Off
                (VirtualFileSystem.root vfs)
                SymlinkPolicy.NoFollowFinal
                (UnixPath.parseOrFail context p)
                vfs
        with
        | Ok inode -> inode
        | Error error -> failwith $"%s{p} does not resolve in the hand-built filesystem: %O{error}"

    let private parentAndName (p : string) : string * string =
        let slash = p.LastIndexOf '/'
        (if slash = 0 then "/" else p.Substring (0, slash)), p.Substring (slash + 1)

    let private directory (p : string) (by : InodeOwner) (bits : int) (vfs : VirtualFileSystem) : VirtualFileSystem =
        let parent, child = parentAndName p

        GraphMutators.createDirectory (inodeAt vfs parent) (name child) (mode bits) by epoch vfs
        |> ok
        |> snd

    let private file (p : string) (by : InodeOwner) (bits : int) (vfs : VirtualFileSystem) : VirtualFileSystem =
        let parent, child = parentAndName p

        GraphMutators.createFile
            (inodeAt vfs parent)
            (name child)
            (mode bits)
            by
            epoch
            (ImmutableArray.CreateRange [| 1uy ; 2uy ; 3uy ; 4uy |])
            vfs
        |> ok
        |> snd

    let private hardLink (existing : string) (p : string) (vfs : VirtualFileSystem) : VirtualFileSystem =
        let parent, child = parentAndName p

        GraphMutators.hardLink (inodeAt vfs parent) (name child) (inodeAt vfs existing) epoch vfs
        |> ok

    /// A process on `platform` with `credentials`, in the root of `vfs`.
    let private systemOn
        (platform : SimulatedUnixPlatform)
        (credentials : Credentials)
        (vfs : VirtualFileSystem)
        : UnixSystem<int, string>
        =
        let system : UnixSystem<int, string> =
            UnixSystem.initial platform
            |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

        Kernel.mapMachine
            (fun machine ->
                { machine with
                    CommittedFileSystem = CommittedFileSystem.initial vfs
                }
            )
            system
        |> Lone.mapProc (fun proc ->
            { proc with
                CurrentDirectoryInode = VirtualFileSystem.root vfs
            }
        )
        |> Lone.restand

    let private path (p : string) : UnixPath = UnixPath.parseOrFail context p

    let private argument (p : string) : PathArgumentBytes = PathArg.ofText p

    [<RequireQualifiedAccess>]
    type private Call =
        | Unlink of string
        | RmDir of string
        | Rename of string * string

    /// What a call came to: its errno, `None` for success.
    [<RequireQualifiedAccess>]
    type private Outcome = | Answered of error : UnixError option

    /// Run `call`, reporting what it came to and the system after it. A
    /// refusal fails the test.
    let private run (call : Call) (system : UnixSystem<int, string>) : Outcome * UnixSystem<int, string> =
        let result =
            match call with
            | Call.Unlink p ->
                UnixNamespace.tryUnlink (Callers.leader system) (PathArg.ofPath (path p)) system
                |> Result.mapError RemovalRefusal.describe
            | Call.RmDir p ->
                UnixNamespace.tryRmdir (Callers.leader system) (PathArg.ofPath (path p)) system
                |> Result.mapError RemovalRefusal.describe
            | Call.Rename (source, destination) ->
                Eager.tryRename (argument source) (argument destination) system
                |> Result.mapError RenameRefusal.describe

        match result with
        | Error refusal -> failwith $"%A{call} was refused: %s{refusal}"
        | Ok (SyscallAnswer.Completed _, system) -> Outcome.Answered None, system
        | Ok (SyscallAnswer.Failed error, system) -> Outcome.Answered (Some error), system

    /// Run `rows` one after another on one system, as the probe ran them in one
    /// tree, and check each answer.
    let private replay (rows : (Call * UnixError option) list) (system : UnixSystem<int, string>) : unit =
        rows
        |> List.fold
            (fun system (call, expected) ->
                let actual, system = run call system

                if actual <> Outcome.Answered expected then
                    failwith $"%A{call}: expected %A{expected}, got %A{actual}"

                system
            )
            system
        |> ignore<UnixSystem<int, string>>

    // ------------------------------------------------------------- Linux sticky rows

    /// The tree `permission-standing.c` measured Linux's sticky directories in.
    /// `S` is root's and 01777, `U` is root's and 01755, and `W` is u1000's and
    /// 0755. u1001 owns `S/f` (with a second name `S/fl`), `S/e`, `S/n` (which
    /// holds `x`), `S/T` (01777, holding u1000's `g2`), `U/f` and `U/e`; u1000
    /// owns `S/g`, `S/h` and `W/mine`.
    let private linuxStickyTree : VirtualFileSystem =
        let root = owner 0u 0u
        let u1000 = owner 1000u 1000u
        let u1001 = owner 1001u 1001u

        VirtualFileSystem.empty EntryNameMatching.Bytes epoch root
        |> directory "/S" root 0o1777
        |> file "/S/f" u1001 0o666
        |> hardLink "/S/f" "/S/fl"
        |> directory "/S/e" u1001 0o755
        |> directory "/S/n" u1001 0o777
        |> file "/S/n/x" u1001 0o666
        |> file "/S/g" u1000 0o666
        |> directory "/S/h" u1000 0o777
        |> directory "/S/T" u1001 0o1777
        |> file "/S/T/g2" u1000 0o666
        |> directory "/U" root 0o1755
        |> file "/U/f" u1001 0o666
        |> directory "/U/e" u1001 0o777
        |> directory "/W" u1000 0o755
        |> file "/W/mine" u1000 0o666

    /// The calls in the order the probe made them.
    let private linuxStickyCalls : Call list =
        [
            Call.Unlink "/S/e"
            Call.Unlink "/S/f/"
            Call.RmDir "/S/f"
            Call.RmDir "/S/n"
            Call.Rename ("/S/f", "/S/h")
            Call.Rename ("/S/g", "/S/e")
            Call.Rename ("/S/h", "/S/f")
            Call.Rename ("/S/h", "/S/n")
            Call.Rename ("/S/e", "/S/e/x")
            Call.Rename ("/S/f", "/S/f")
            Call.Rename ("/S/f", "/S/fl")
            Call.Rename ("/S/e", "/W/moved")
            Call.Rename ("/S/g", "/S/f/")
            Call.Rename ("/S/T/g2", "/S/T")
            Call.Rename ("/S/f", "/U/new")
            Call.Unlink "/U/f"
            Call.RmDir "/U/e"
            Call.Rename ("/U/f", "/S/new2")
            Call.Rename ("/S/g", "/U/f")
            Call.Rename ("/W/mine", "/S/f")
            Call.Rename ("/W/mine", "/S/g")
        ]

    [<Test>]
    let ``the measured Linux sticky rows, as u1000`` () : unit =
        let measured =
            [
                Some UnixError.EPERM
                Some UnixError.ENOTDIR
                Some UnixError.EPERM
                Some UnixError.EPERM
                Some UnixError.EPERM
                Some UnixError.EPERM
                Some UnixError.EPERM
                Some UnixError.EPERM
                Some UnixError.EINVAL
                None
                None
                Some UnixError.EPERM
                Some UnixError.ENOTDIR
                Some UnixError.ENOTEMPTY
                Some UnixError.EPERM
                Some UnixError.EACCES
                Some UnixError.EACCES
                Some UnixError.EACCES
                Some UnixError.EACCES
                Some UnixError.EPERM
                None
            ]

        let caller = Credentials.ofIds (uid 1000u) (gid 1000u) [ gid 1000u ; gid 2000u ]

        systemOn SimulatedUnixPlatform.linuxX64 caller linuxStickyTree
        |> replay (List.zip linuxStickyCalls measured)

    [<Test>]
    let ``the measured Linux sticky rows, as root`` () : unit =
        // Root's calls succeed, so later rows see what earlier ones did: the
        // probe made them in one tree, and so does this.
        let measured =
            [
                Some UnixError.EISDIR
                Some UnixError.ENOTDIR
                Some UnixError.ENOTDIR
                Some UnixError.ENOTEMPTY
                Some UnixError.EISDIR
                Some UnixError.EISDIR
                Some UnixError.ENOTDIR
                Some UnixError.ENOTEMPTY
                Some UnixError.EINVAL
                None
                None
                None
                Some UnixError.ENOTDIR
                Some UnixError.ENOTEMPTY
                None
                None
                None
                Some UnixError.ENOENT
                None
                None
                Some UnixError.ENOENT
            ]

        systemOn SimulatedUnixPlatform.linuxX64 Owners.root linuxStickyTree
        |> replay (List.zip linuxStickyCalls measured)

    // ------------------------------------------------------------- Darwin sticky rows

    let private darwinCaller : Credentials =
        Credentials.ofIds (uid 501u) (gid 20u) [ gid 20u ; gid 12u ; gid 61u ; gid 100u ; gid 701u ]

    /// The objects `permission-standing.c` measured Darwin's sticky directories
    /// with, at uid 501. `/tmp` is root's 01777, holding two further names `L1`
    /// and `L2` for root's file `/tmp/root`, the caller's own `myfile` and
    /// `mydir`, and its `base` holding `mine` (0755) and `own-sticky` (01777,
    /// holding `L3`, a third name for root's file). `/Library/Helpers` is
    /// root's 01755 holding root's `tool`; `/mds` is root's 01777 holding
    /// root's non-empty `messages`; `/etc` is root's 0755 holding root's
    /// `hosts`; `/Users` is root's 0755.
    let private darwinStickyTree : VirtualFileSystem =
        let root = owner 0u 0u
        let staff = owner 501u 20u
        let wheel = owner 501u 0u

        VirtualFileSystem.empty EntryNameMatching.Bytes epoch root
        |> directory "/tmp" root 0o1777
        |> file "/tmp/root" root 0o644
        |> hardLink "/tmp/root" "/tmp/L1"
        |> hardLink "/tmp/root" "/tmp/L2"
        |> file "/tmp/myfile" wheel 0o600
        |> directory "/tmp/mydir" wheel 0o755
        |> directory "/tmp/base" wheel 0o700
        |> directory "/tmp/base/mine" staff 0o755
        |> directory "/tmp/base/own-sticky" wheel 0o1777
        |> hardLink "/tmp/root" "/tmp/base/own-sticky/L3"
        |> hardLink "/tmp/root" "/tmp/base/mine/L4"
        |> directory "/Library" root 0o755
        |> directory "/Library/Helpers" root 0o1755
        |> file "/Library/Helpers/tool" root 0o544
        |> directory "/mds" root 0o1777
        |> directory "/mds/messages" root 0o755
        |> directory "/mds/messages/inner" root 0o755
        |> directory "/etc" root 0o755
        |> file "/etc/hosts" root 0o644
        |> directory "/Users" (owner 0u 80u) 0o755

    [<Test>]
    let ``the measured Darwin sticky rows, at uid 501`` () : unit =
        let rows =
            [
                Call.Unlink "/tmp/L1", Some UnixError.EACCES
                Call.RmDir "/tmp/L1", Some UnixError.ENOTDIR
                Call.Rename ("/tmp/L1", "/tmp/L1b"), Some UnixError.EACCES
                Call.Rename ("/tmp/myfile", "/tmp/L1"), Some UnixError.EACCES
                Call.Rename ("/tmp/L1", "/tmp/mydir"), Some UnixError.EISDIR
                Call.Rename ("/tmp/mydir", "/tmp/L1"), Some UnixError.ENOTDIR
                Call.Rename ("/tmp/L1", "/tmp/free/"), Some UnixError.ENOENT
                Call.Rename ("/tmp/L1", "/tmp/L2"), Some UnixError.EACCES
                Call.Rename ("/tmp/L1", "/Users/x"), Some UnixError.EACCES
                Call.Rename ("/tmp/L1", "/tmp/base/mine/moved"), Some UnixError.EACCES
                Call.Unlink "/tmp/base/own-sticky/L3", None
                Call.Unlink "/tmp/myfile", None
                Call.Unlink "/Library/Helpers/tool", Some UnixError.EACCES
                Call.RmDir "/Library/Helpers/tool", Some UnixError.ENOTDIR
                Call.Rename ("/Library/Helpers/tool", "/tmp/base/stolen"), Some UnixError.EACCES
                Call.Unlink "/mds/messages", Some UnixError.EPERM
                Call.RmDir "/mds/messages", Some UnixError.EACCES
                Call.Rename ("/mds/messages", "/mds/messages/x"), Some UnixError.EINVAL
                Call.Unlink "/tmp/base/mine/L4", None
                Call.Unlink "/etc/hosts", Some UnixError.EACCES
            ]

        systemOn SimulatedUnixPlatform.macOsArm64 darwinCaller darwinStickyTree
        |> replay rows

    [<Test>]
    let ``Darwin's sticky bit does not restrain a privileged caller`` () : unit =
        // `root-files.c`'s STICKY rows: root removes, renames and replaces
        // another user's entries in a third user's sticky directory.
        // `own-sticky` is uid 501's, so root owns neither it nor what uid 7
        // keeps there.
        let tree =
            darwinStickyTree
            |> file "/tmp/base/own-sticky/theirs" (owner 7u 7u) 0o644
            |> directory "/tmp/base/own-sticky/theirdir" (owner 7u 7u) 0o755

        let system =
            systemOn SimulatedUnixPlatform.macOsArm64 (Credentials.ofIds UserId.root (gid 0u) []) tree

        for call in
            [
                Call.Unlink "/tmp/base/own-sticky/theirs"
                Call.RmDir "/tmp/base/own-sticky/theirdir"
                // The source's sticky directory...
                Call.Rename ("/tmp/base/own-sticky/theirs", "/tmp/elsewhere")
                // ...and the destination's.
                Call.Rename ("/tmp/root", "/tmp/base/own-sticky/theirs")
            ] do
            (call, run call system |> fst) |> shouldEqual (call, Outcome.Answered None)

    [<Test>]
    let ``Darwin's sticky bit plays no part when a directory displaces a directory`` () : unit =
        // `root-files.c`'s STICKY rows: uid 501 moving its own directory over
        // uid 504's in uid 502's sticky directory succeeds when the displaced
        // directory is 0777, and is EACCES when it is 0755, as in a directory
        // without the sticky bit.
        let tree =
            darwinStickyTree
            |> directory "/tmp/theirs" (owner 7u 7u) 0o777
            |> directory "/tmp/theirsclosed" (owner 7u 7u) 0o755
            |> directory "/tmp/emptydir" (owner 501u 0u) 0o755

        let system = systemOn SimulatedUnixPlatform.macOsArm64 darwinCaller tree

        run (Call.Rename ("/tmp/emptydir", "/tmp/theirs")) system
        |> fst
        |> shouldEqual (Outcome.Answered None)

        run (Call.Rename ("/tmp/emptydir", "/tmp/theirsclosed")) system
        |> fst
        |> shouldEqual (Outcome.Answered (Some UnixError.EACCES))

        // Root, whom no write bit restrains.
        systemOn
            SimulatedUnixPlatform.macOsArm64
            (Credentials.ofIds UserId.root (gid 0u) [])
            (tree |> directory "/tmp/base/own-sticky/d" (owner 7u 7u) 0o755)
        |> run (Call.Rename ("/tmp/emptydir", "/tmp/base/own-sticky/d"))
        |> fst
        |> shouldEqual (Outcome.Answered None)

        // Displacing one the caller owns is answered as before.
        let tree = tree |> directory "/tmp/mine2" (owner 501u 0u) 0o755

        systemOn SimulatedUnixPlatform.macOsArm64 darwinCaller tree
        |> run (Call.Rename ("/tmp/emptydir", "/tmp/mine2"))
        |> fst
        |> shouldEqual (Outcome.Answered None)

    [<Test>]
    let ``Darwin's root-files STICKY rows, for root and for uid 501`` () : unit =
        // `docs/probes/darwin-root/root-files.c`, run as root on Darwin 27.0.
        // Each row starts from a fresh tree under `/st`: S is 502:20 at
        // S=<mode>; S/f and S/f2 are 504:20 files and S/d an empty 504:20
        // directory at d=<mode>; S/n is a 504:20 directory holding a file;
        // S/m501 is 501:20; O is root's at 0777, holding root's O/of and O/od
        // and 501:20's O/f501 and O/d501.
        let tree (smode : int) (dmode : int) : VirtualFileSystem =
            VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
            |> directory "/st" (owner 0u 0u) 0o755
            |> directory "/st/S" (owner 502u 20u) smode
            |> file "/st/S/f" (owner 504u 20u) 0o644
            |> file "/st/S/f2" (owner 504u 20u) 0o644
            |> directory "/st/S/d" (owner 504u 20u) dmode
            |> directory "/st/S/n" (owner 504u 20u) 0o755
            |> file "/st/S/n/c" (owner 504u 20u) 0o644
            |> file "/st/S/m501" (owner 501u 20u) 0o644
            |> directory "/st/O" (owner 0u 0u) 0o777
            |> file "/st/O/of" (owner 0u 0u) 0o644
            |> directory "/st/O/od" (owner 0u 0u) 0o755
            |> file "/st/O/f501" (owner 501u 20u) 0o644
            |> directory "/st/O/d501" (owner 501u 20u) 0o755

        // What a path names afterwards, as the probe printed it.
        let names (system : UnixSystem<int, string>) (p : string) : string =
            match
                PathWalk.resolveExisting
                    (SimulatedUnixPlatform.pathLimits SimulatedUnixPlatform.macOsArm64)
                    Owners.root
                    SymlinkProtection.Off
                    (VirtualFileSystem.root (UnixSystem.fileSystem system))
                    SymlinkPolicy.NoFollowFinal
                    (path ("/st/" + p))
                    (UnixSystem.fileSystem system)
            with
            | Error _ -> "absent"
            | Ok inode ->
                let entry =
                    VirtualFileSystem.get "TestPermissionStanding" inode (UnixSystem.fileSystem system)

                let kind =
                    match entry.Content with
                    | InodeContent.Directory _ -> "dir"
                    | _ -> "file"

                $"%s{kind} %d{UserId.toUInt32 entry.Owner.User}:%d{GroupId.toUInt32 entry.Owner.Group}"

        let octal (field : string) (prefix : string) : int =
            System.Convert.ToInt32 (field.Substring prefix.Length, 8)

        let rows = DarwinRootFiles.spot "STICKY"
        rows |> List.length |> shouldEqual 45

        for row in rows do
            // caller, "S=1777 d=0755", call, "-> errno", "after: ..."
            let modes = row.[1].Split ' '
            let smode = octal modes.[0] "S="
            let dmode = octal modes.[1] "d="

            let system =
                systemOn SimulatedUnixPlatform.macOsArm64 (DarwinRootFiles.credentialsOf row.[0]) (tree smode dmode)

            let call, paths =
                let inner = row.[2].Substring(row.[2].IndexOf '(' + 1).TrimEnd ')'
                let arguments = inner.Split ", "

                match row.[2].Substring (0, row.[2].IndexOf '(') with
                | "unlink" -> Call.Unlink ("/st/" + arguments.[0]), [ arguments.[0] ]
                | "rmdir" -> Call.RmDir ("/st/" + arguments.[0]), [ arguments.[0] ]
                | "rename" ->
                    Call.Rename ("/st/" + arguments.[0], "/st/" + arguments.[1]), [ arguments.[0] ; arguments.[1] ]
                | other -> failwith $"unexpected STICKY call %s{other}"

            let outcome, after = run call system

            let answered =
                match outcome with
                | Outcome.Answered None -> "ok"
                | Outcome.Answered (Some error) -> string<UnixError> error

            let named =
                paths |> List.map (fun p -> $"%s{p}=%s{names after p}") |> String.concat " "

            ($"%s{row.[0]} %s{row.[1]} %s{row.[2]}", $"-> %s{answered}", $"after: %s{named}")
            |> shouldEqual ($"%s{row.[0]} %s{row.[1]} %s{row.[2]}", row.[3], row.[4])

    // ------------------------------------------------------------- access, end to end

    let private readOnly : OpenFlags =
        {
            Access = FileAccessMode.ReadOnly
            Create = false
            Exclusive = false
            Truncate = false
            NoFollow = false
            CloseOnExec = false
            Synchronous = false
            DataSynchronous = false
            Directory = false
        }

    let private creating : OpenFlags =
        { readOnly with
            Access = FileAccessMode.WriteOnly
            Create = true
            Exclusive = true
        }

    /// Whether the call answered a descriptor.
    let private opened (answer : SyscallAnswer, system : UnixSystem<int, string>) : bool * UnixSystem<int, string> =
        match answer with
        | SyscallAnswer.Completed _ -> true, system
        | SyscallAnswer.Failed UnixError.EACCES -> false, system
        | SyscallAnswer.Failed error -> failwith $"expected a descriptor or EACCES, got %O{error}"

    [<Test>]
    let ``Linux open, search, opendir and create select the triple the probe measured, over every mode`` () : unit =
        // One file and one directory (holding `kid`) per mode, each owned so
        // that the caller stands towards it as the row names, exactly as
        // `permission-standing.c` built them. The filesystem is built without
        // consulting any permission, so a directory can be given its mode
        // before its child.
        let caller = Credentials.ofIds (uid 1000u) (gid 1000u) [ gid 1000u ; gid 2000u ]

        let callers =
            [
                // owner of every object, standing
                "owner", caller, owner 1000u 3000u, 0
                "group by effective gid", caller, owner 1001u 1000u, 1
                "group by supplementary gid", caller, owner 1001u 2000u, 1
                "other", caller, owner 1001u 3000u, 2
                "root", Owners.root, owner 1001u 3000u, 3
            ]

        for label, credentials, objectOwner, standing in callers do
            for bits in allModes do
                // A filesystem of its own per row: `close` reaps against the
                // whole graph, so one graph holding every row would make the
                // sweep quadratic.
                let system =
                    VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
                    |> file "/f" objectOwner bits
                    |> directory "/d" objectOwner bits
                    |> file "/d/kid" objectOwner 0o666
                    |> systemOn SimulatedUnixPlatform.linuxX64 credentials

                let predicted (request : int) : bool =
                    match standing with
                    | 3 -> true
                    | _ ->
                        let triple = (bits >>> (6 - 3 * standing)) &&& 7
                        triple &&& request = request

                let read, _ = Answered.openPath (path "/f") readOnly 0 system |> opened

                let write, _ =
                    Answered.openPath
                        (path "/f")
                        { readOnly with
                            Access = FileAccessMode.WriteOnly
                        }
                        0
                        system
                    |> opened

                let searched =
                    match
                        UnixPathResolution.tryStat
                            (Callers.leader system)
                            SymlinkPolicy.NoFollowFinal
                            (PathArg.ofPath (path "/d/kid"))
                            system
                    with
                    | Ok (FileStatusAnswer.Reported _) -> true
                    | Ok (FileStatusAnswer.Failed UnixError.EACCES) -> false
                    | other -> failwith $"stat: %A{other}"

                let listed, _ =
                    Answered.openPath
                        (path "/d")
                        { readOnly with
                            Directory = true
                        }
                        0
                        system
                    |> opened

                let created, _ = Answered.openPath (path "/d/new") creating 0o600 system |> opened

                let expected = predicted 4, predicted 2, predicted 1, predicted 4, predicted 3
                let actual = read, write, searched, listed, created

                if actual <> expected then
                    failwith
                        $"%s{label}, mode 0o%04o{bits}: (read, write, search, opendir, create) was %A{actual}, measured %A{expected}"

    [<Test>]
    let ``the measured Darwin rows for the group and other triples`` () : unit =
        // `OTHERS` in `ownership-probe.c`'s Darwin output, at uid 501 in groups
        // 20, 12, 61, 100 and 701. (`opendir` of the 0774 directory answered
        // EPERM from a sandbox, which is not a permission rule and is not a row.)
        let vfs =
            VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
            |> directory "/staff0774" (owner 0u 20u) 0o774
            |> directory "/wheel0750" (owner 0u 0u) 0o750
            |> directory "/wheel0755" (owner 0u 0u) 0o755
            |> directory "/staff0555" (owner 0u 20u) 0o555
            |> directory "/other0700" (owner 503u 20u) 0o700
            |> file "/master.passwd" (owner 0u 0u) 0o600
            |> file "/hosts" (owner 0u 0u) 0o644

        let system = systemOn SimulatedUnixPlatform.macOsArm64 darwinCaller vfs

        let search (p : string) : UnixError option =
            match
                UnixPathResolution.tryStat
                    (Callers.leader system)
                    SymlinkPolicy.NoFollowFinal
                    (PathArg.ofPath (path (p + "/nx")))
                    system
            with
            | Ok (FileStatusAnswer.Failed error) -> Some error
            | other -> failwith $"stat: %A{other}"

        search "/staff0774" |> shouldEqual (Some UnixError.ENOENT)
        search "/wheel0750" |> shouldEqual (Some UnixError.EACCES)
        search "/wheel0755" |> shouldEqual (Some UnixError.ENOENT)
        search "/staff0555" |> shouldEqual (Some UnixError.ENOENT)
        search "/other0700" |> shouldEqual (Some UnixError.EACCES)

        let listed (p : string) : bool =
            Answered.openPath
                (path p)
                { readOnly with
                    Directory = true
                }
                0
                system
            |> opened
            |> fst

        listed "/wheel0750" |> shouldEqual false
        listed "/wheel0755" |> shouldEqual true
        listed "/staff0555" |> shouldEqual true

        let openFor (access : FileAccessMode) (p : string) : bool =
            Answered.openPath
                (path p)
                { readOnly with
                    Access = access
                }
                0
                system
            |> opened
            |> fst

        openFor FileAccessMode.ReadOnly "/master.passwd" |> shouldEqual false
        openFor FileAccessMode.WriteOnly "/master.passwd" |> shouldEqual false
        openFor FileAccessMode.ReadOnly "/hosts" |> shouldEqual true
        openFor FileAccessMode.WriteOnly "/hosts" |> shouldEqual false

        Answered.mkdir (Callers.leader system) (PathArg.ofPath (path "/wheel0755/x")) 0o755 system
        |> fst
        |> shouldEqual (SyscallAnswer.Failed UnixError.EACCES)

    // ------------------------------------------------------------- strips, end to end

    let private modeOf (p : string) (system : UnixSystem<int, string>) : int =
        match VirtualFileSystem.tryGet (inodeAt (UnixSystem.fileSystem system) p) (UnixSystem.fileSystem system) with
        | Some inode -> PermissionBits.toInt (Inode.permissions inode)
        | None -> failwith $"%s{p} is absent"

    [<Test>]
    let ``write, pwrite, ftruncate and O_TRUNC strip S_ISGID for a Linux writer outside the file's group`` () : unit =
        // A 02666 file of a group u1000 is not in: every content change strips
        // the bit, where a member of the group (the second file) keeps it.
        let caller = Credentials.ofIds (uid 1000u) (gid 1000u) [ gid 1000u ; gid 2000u ]

        let vfs =
            VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
            |> file "/outside" (owner 1001u 3000u) 0o2666
            |> file "/inside" (owner 1001u 2000u) 0o2666

        let system = systemOn SimulatedUnixPlatform.linuxX64 caller vfs

        let changed (change : int -> UnixSystem<int, string> -> UnixSystem<int, string>) (p : string) : int =
            let readWrite =
                { readOnly with
                    Access = FileAccessMode.ReadWrite
                }

            match Answered.openPath (path p) readWrite 0 system with
            | SyscallAnswer.Completed fd, system -> change (int fd) system |> modeOf p
            | other -> failwith $"open %s{p}: %A{other}"

        let one = ImmutableArray.Create 9uy

        let changes : (string * (int -> UnixSystem<int, string> -> UnixSystem<int, string>)) list =
            [
                "write", (fun fd system -> WriteOutcomes.write fd one system |> ok |> snd)
                "pwrite", (fun fd system -> WriteOutcomes.admitThenPwrite 0 fd one 0L system |> ok |> snd)
                "ftruncate",
                (fun fd system -> UnixDescriptor.tryFtruncate (Callers.leader system) fd 0L system |> ok |> snd)
            ]

        for label, change in changes do
            (label, changed change "/outside") |> shouldEqual (label, 0o0666)
            (label, changed change "/inside") |> shouldEqual (label, 0o2666)

        let truncating =
            { readOnly with
                Access = FileAccessMode.WriteOnly
                Truncate = true
            }

        for p, expected in [ "/outside", 0o0666 ; "/inside", 0o2666 ] do
            match Answered.openPath (path p) truncating 0 system with
            | SyscallAnswer.Completed _, system -> modeOf p system |> shouldEqual expected
            | other -> failwith $"open O_TRUNC %s{p}: %A{other}"

    [<Test>]
    let ``write, pwrite, ftruncate and O_TRUNC strip both set-ID bits for a Darwin non-owner, and truncation neither``
        ()
        : unit
        =
        // uid 501 in group 20 writing a 06666 file uid 1001 owns
        // (`root-files.c`'s SETID rows, against uid 502's files).
        let vfs =
            VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
            |> file "/f" (owner 1001u 20u) 0o6666

        let system = systemOn SimulatedUnixPlatform.macOsArm64 darwinCaller vfs

        let readWrite =
            { readOnly with
                Access = FileAccessMode.ReadWrite
            }

        let fd, opened =
            match Answered.openPath (path "/f") readWrite 0 system with
            | SyscallAnswer.Completed fd, opened -> int fd, opened
            | other -> failwith $"open: %A{other}"

        let one = ImmutableArray.Create 9uy

        let changes : (string * (UnixSystem<int, string> -> UnixSystem<int, string>) * int) list =
            [
                "write", (fun system -> WriteOutcomes.write fd one system |> ok |> snd), 0o0666
                "pwrite", (fun system -> WriteOutcomes.admitThenPwrite 0 fd one 0L system |> ok |> snd), 0o0666
                "ftruncate",
                (fun system -> UnixDescriptor.tryFtruncate (Callers.leader system) fd 0L system |> ok |> snd),
                0o6666
            ]

        for label, change, expected in changes do
            (label, change opened |> modeOf "/f") |> shouldEqual (label, expected)

        let truncating =
            { readOnly with
                Access = FileAccessMode.WriteOnly
                Truncate = true
            }

        match Answered.openPath (path "/f") truncating 0 system with
        | SyscallAnswer.Completed _, truncated -> modeOf "/f" truncated |> shouldEqual 0o6666
        | other -> failwith $"open(O_TRUNC): %A{other}"

    [<Test>]
    let ``unlink and rmdir through the syscall step answer Darwin's root in a sticky directory`` () : unit =
        let root = Credentials.ofIds UserId.root (gid 0u) []

        let tree =
            darwinStickyTree
            |> file "/tmp/base/own-sticky/theirs" (owner 7u 7u) 0o644
            |> directory "/tmp/base/own-sticky/theirdir" (owner 7u 7u) 0o755

        let system = systemOn SimulatedUnixPlatform.macOsArm64 root tree

        // Darwin's AT_FDCWD, with no flags for unlink and AT_REMOVEDIR for
        // rmdir.
        for p, flags in [ "/tmp/base/own-sticky/theirs", 0 ; "/tmp/base/own-sticky/theirdir", 0x80 ] do
            match
                UnixSystem.tryStep
                    (Callers.thread 0 system)
                    (Syscall.UnlinkAt (-2, PathArg.ofPath (path p), flags))
                    system
            with
            | Ok (SteppedCall.UnlinkAt (SyscallAnswer.Completed 0L, after)) ->
                VirtualFileSystem.tryGetContent (inodeAt tree p) (UnixSystem.fileSystem after)
                |> Option.isSome
                |> shouldEqual false
            | other -> failwith $"unlinkat(%s{p}, 0x%x{flags}) answered %A{Result.map Stepped.view other}"

    [<Test>]
    let ``Linux open(O_CREAT) strips S_ISGID in a set-group-ID directory the creator is not in, end to end`` () : unit =
        // The probe's parents, each created in by u1000 (groups 1000 and
        // 2000) and by root, over every mode and four umasks.
        let caller = Credentials.ofIds (uid 1000u) (gid 1000u) [ gid 1000u ; gid 2000u ]

        let parents =
            [
                // label, parent group, parent mode, credentials, standing towards the parent
                "set-group-ID, outside its group", 3000u, 0o2777, caller
                "set-group-ID, supplementary group", 2000u, 0o2777, caller
                "set-group-ID, effective group", 1000u, 0o2777, caller
                "plain, outside its group", 3000u, 0o777, caller
                "set-group-ID, root outside its group", 3000u, 0o2777, Owners.root
            ]

        for label, parentGroup, parentBits, credentials in parents do
            let vfs =
                VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
                |> directory "/p" (owner 0u parentGroup) parentBits

            let standing = Standing.toward credentials (owner 0u parentGroup)

            for umask in umasks do
                // Set as the probe set it, by `umask(2)`, which is what keeps
                // only 0o777 of 0o7777 on Linux.
                let _, system =
                    systemOn SimulatedUnixPlatform.linuxX64 credentials vfs
                    |> fun system -> UnixSystem.umask (Callers.leader system) umask system

                // From the same system each time, which leaves `/p` holding one
                // entry at most.
                for requested in allModes do
                    match Answered.openPath (path "/p/c") creating requested system with
                    | SyscallAnswer.Completed _, next ->
                        let expected = linuxCreated (parentBits &&& 0o2000 <> 0) standing requested umask
                        let actual = modeOf "/p/c" next

                        if actual <> expected then
                            failwith
                                $"%s{label}, umask 0o%04o{umask}, mode 0o%04o{requested}: created 0o%04o{actual}, measured 0o%04o{expected}"
                    | other -> failwith $"%s{label}: creating /p/c answered %A{other}"

    // ------------------------------------------------------------- every other permission check, end to end

    /// A directory `/d` with mode `bits`, holding a file `f`, an empty
    /// directory `e`, a directory `m` with mode `movedBits` and a file `kid`,
    /// all of uid 1001 and group 2000, beside a directory `/o` the caller owns
    /// holding its file `x`. The caller is u1000 in groups 1000 and 2000, so it
    /// is in the group of everything under `/d` and owns none of it.
    let private groupTree (bits : int) (movedBits : int) : UnixSystem<int, string> =
        let theirs = owner 1001u 2000u

        VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
        |> directory "/d" theirs bits
        |> file "/d/f" theirs 0o666
        |> file "/d/kid" theirs 0o666
        |> directory "/d/e" theirs 0o777
        |> directory "/d/m" theirs movedBits
        |> directory "/o" (owner 1000u 1000u) 0o777
        |> file "/o/x" (owner 1000u 1000u) 0o666
        |> systemOn SimulatedUnixPlatform.linuxX64 (Credentials.ofIds (uid 1000u) (gid 1000u) [ gid 1000u ; gid 2000u ])

    [<Test>]
    let ``every syscall that checks a directory's bits reads the group triple for a member of its group`` () : unit =
        // 0o070 grants the group everything and the owner nothing; 0o707 the
        // other way round. A check that read the owner's triple would answer
        // each mode the other's way.
        let succeeds (answer : SyscallAnswer, _ : UnixSystem<int, string>) : bool =
            match answer with
            | SyscallAnswer.Completed _ -> true
            | SyscallAnswer.Failed UnixError.EACCES -> false
            | SyscallAnswer.Failed error -> failwith $"expected success or EACCES, got %O{error}"

        let renamed (source : string) (destination : string) (system : UnixSystem<int, string>) : bool =
            Eager.tryRename (argument source) (argument destination) system
            |> ok
            |> succeeds

        let calls : (string * (UnixSystem<int, string> -> bool)) list =
            [
                "search (stat /d/kid)",
                fun system ->
                    match
                        UnixPathResolution.tryStat
                            (Callers.leader system)
                            SymlinkPolicy.NoFollowFinal
                            (PathArg.ofPath (path "/d/kid"))
                            system
                    with
                    | Ok (FileStatusAnswer.Reported _) -> true
                    | Ok (FileStatusAnswer.Failed UnixError.EACCES) -> false
                    | other -> failwith $"stat: %A{other}"
                "chdir /d",
                fun system ->
                    Answered.chdir (Callers.leader system) (PathArg.ofPath (path "/d")) system
                    |> succeeds
                "opendir /d",
                fun system ->
                    Answered.openPath
                        (path "/d")
                        { readOnly with
                            Directory = true
                        }
                        0
                        system
                    |> succeeds
                "open(O_CREAT) /d/new",
                fun system -> Answered.openPath (path "/d/new") creating 0o600 system |> succeeds
                "mkdir /d/new",
                fun system ->
                    Answered.mkdir (Callers.leader system) (PathArg.ofPath (path "/d/new")) 0o755 system
                    |> succeeds
                "unlink /d/f", fun system -> Answered.unlink (Callers.leader system) (path "/d/f") system |> succeeds
                "rmdir /d/e", fun system -> Answered.rmdir (Callers.leader system) (path "/d/e") system |> succeeds
                "rename /d/f out of /d", renamed "/d/f" "/o/f"
                "rename into /d", renamed "/o/x" "/d/x"
            ]

        for label, call in calls do
            (label, call (groupTree 0o070 0o070)) |> shouldEqual (label, true)
            (label, call (groupTree 0o707 0o070)) |> shouldEqual (label, false)

        // Moving `m` to another parent rewrites its own "..", so its own write
        // bit is checked; `/d` grants the group everything throughout.
        let moved (movedBits : int) : bool =
            groupTree 0o070 movedBits |> renamed "/d/m" "/o/m"

        moved 0o070 |> shouldEqual true
        moved 0o707 |> shouldEqual false

    // ------------------------------------------------------------- no Linux refusal

    /// Every call whose answer depends on who owns what, made once each
    /// against `system`, and the refusals it met. Each call starts from
    /// `system` rather than from the one before it, so that none of them is
    /// hidden behind an earlier one having removed its file.
    let private refusalsMet (system : UnixSystem<int, string>) : string list =
        let one = ImmutableArray.Create 9uy

        let readWrite =
            { readOnly with
                Access = FileAccessMode.ReadWrite
            }

        let truncating =
            { readOnly with
                Access = FileAccessMode.WriteOnly
                Truncate = true
            }

        let refused (result : Result<'a, 'e>) : string option =
            match result with
            | Ok _ -> None
            | Error refusal -> Some $"%A{refusal}"

        let throughDescriptor (p : string) : string option list =
            match OpenFlagWords.openPath (PathArg.ofPath (path p)) readWrite 0 system with
            | Ok (SyscallAnswer.Completed fd, opened) ->
                let fd = int fd

                [
                    WriteOutcomes.write fd one opened |> refused
                    WriteOutcomes.admitThenPwrite 0 fd one 0L opened |> refused
                    UnixDescriptor.tryFtruncate (Callers.leader opened) fd 0L opened |> refused
                    UnixDescriptor.tryFtruncate (Callers.leader opened) fd 4L opened |> refused
                ]
            | Ok (SyscallAnswer.Failed _, _) -> []
            | Error refusal -> [ Some $"%A{refusal}" ]

        [
            for p in [ "/d/f" ; "/d/g" ] do
                yield OpenFlagWords.openPath (PathArg.ofPath (path p)) truncating 0 system |> refused
                yield! throughDescriptor p
            for p in [ "/d/f" ; "/d/e" ] do
                yield
                    UnixNamespace.tryUnlink (Callers.leader system) (PathArg.ofPath (path p)) system
                    |> refused

                yield
                    UnixNamespace.tryRmdir (Callers.leader system) (PathArg.ofPath (path p)) system
                    |> refused
            for source, destination in
                [
                    "/d/f", "/d/g"
                    "/d/f", "/w/f2"
                    "/d/e", "/w/e2"
                    "/d/e", "/d/h"
                    "/d/h", "/d/e"
                    "/w/k", "/d/e"
                    "/w/k", "/d/f"
                ] do
                yield Eager.tryRename (argument source) (argument destination) system |> refused
        ]
        |> List.choose id

    [<Test>]
    let ``no call meets a refusal on either flavour, whoever owns what`` () : unit =
        // Darwin's sticky and set-ID rules are measured for every caller
        // (`root-files.c`), so no ownership rule refuses. This drives every
        // call that consults one over trees of foreign owners, sticky and
        // set-ID bits, on both flavours, and each must be answered.
        let users = [ 0u ; 1000u ; 1001u ]
        let groups = [ 0u ; 1000u ; 2000u ]

        let ownerGen : Gen<InodeOwner> =
            gen {
                let! user = Gen.elements users
                let! group = Gen.elements groups
                return owner user group
            }

        let modeGen : Gen<int> =
            Gen.oneof
                [
                    Gen.choose (0, 0o7777)
                    Gen.elements [ 0o1777 ; 0o6777 ; 0o2666 ; 0o4755 ; 0o777 ]
                ]

        let treeGen : Gen<VirtualFileSystem> =
            gen {
                let! owners = Gen.listOfLength 7 ownerGen
                let! modes = Gen.listOfLength 7 modeGen

                // Every directory stays searchable by everyone, so that a call
                // is answered by the rule under test rather than refused at the
                // walk; its write and sticky bits are still drawn.
                let searchable (bits : int) : int = bits ||| 0o111

                return
                    VirtualFileSystem.empty EntryNameMatching.Bytes epoch (owner 0u 0u)
                    |> directory "/d" owners.[0] (searchable modes.[0])
                    |> file "/d/f" owners.[1] modes.[1]
                    |> file "/d/g" owners.[2] modes.[2]
                    |> directory "/d/e" owners.[3] (searchable modes.[3])
                    |> directory "/d/h" owners.[4] (searchable modes.[4])
                    |> directory "/w" owners.[5] 0o1777
                    |> directory "/w/k" owners.[6] (searchable modes.[6])
            }

        let callerGen : Gen<Credentials> =
            gen {
                let! user = Gen.elements users
                let! group = Gen.elements groups
                let! supplementary = Gen.subListOf groups
                return Credentials.ofIds (uid user) (gid group) (supplementary |> List.map gid)
            }

        let property (vfs : VirtualFileSystem, caller : Credentials) : unit =
            refusalsMet (systemOn SimulatedUnixPlatform.linuxX64 caller vfs)
            |> shouldEqual []

            refusalsMet (systemOn SimulatedUnixPlatform.macOsArm64 caller vfs)
            |> shouldEqual []

        let gen =
            gen {
                let! vfs = treeGen
                let! caller = callerGen
                return vfs, caller
            }

        Check.One (config.WithMaxTest 500, Prop.forAll (Arb.fromGen gen) property)
