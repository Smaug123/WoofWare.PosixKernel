namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which threads `setresuid(2)`, `setresgid(2)` and `setgroups(2)` reach, and
/// what the C library's way of reaching them does to the calls other threads
/// are asleep in.
///
/// The rows come from `docs/probes/setxid-threads/setxid-threads.c`, run on
/// Linux 6.18.5 (aarch64, glibc 2.41, root in the container, forking a child
/// per row) and on Darwin 27.0 at uid 501, from a set-group-ID copy so that the
/// process holds a group it can change to and back. Both outputs are embedded
/// from beside it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCredentialThreadsMeasured =

    let private context : string = "TestCredentialThreadsMeasured"

    let private uid (raw : uint32) : UserId = UserId.parseOrFail context raw
    let private gid (raw : uint32) : GroupId = GroupId.parseOrFail context raw

    let private lines (flavour : string) : string list =
        let assembly = Assembly.GetExecutingAssembly ()
        let resourceName = $"WoofWare.PosixKernel.Test.setxid-threads.%s{flavour}.txt"

        use stream =
            match assembly.GetManifestResourceStream resourceName with
            | null -> failwith $"embedded resource %s{resourceName} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList

    let private linuxLines : string list = lines "linux"
    let private darwinLines : string list = lines "darwin"

    let private section (name : string) (all : string list) : string list =
        all
        |> List.filter (fun line -> line.StartsWith (name + " ", StringComparison.Ordinal))

    /// The value of `key=` in a line's first part (before any `" | "`).
    let private value (key : string) (line : string) : string =
        let header = line.Split(" | ").[0]

        match
            header.Split ' '
            |> Array.tryFind (fun token -> token.StartsWith (key + "=", StringComparison.Ordinal))
        with
        | Some token -> token.Substring (key.Length + 1)
        | None -> failwith $"no %s{key}= in: %s{line}"

    /// How the row's child ended: the line's last token.
    let private ending (line : string) : string = line.Split (' ') |> Array.last

    let private numbers (separator : char) (text : string) : uint32 list =
        text.Split (separator, StringSplitOptions.RemoveEmptyEntries)
        |> Array.map UInt32.Parse
        |> Array.toList

    /// `"[1,2]"` as `[ 1 ; 2 ]`.
    let private bracketed (text : string) : uint32 list =
        numbers ',' (text.TrimStart('[').TrimEnd (']'))

    // ------------------------------------------------------------- Linux: which threads a call reaches

    /// One thread's IDs: real, effective and saved users, the same of groups,
    /// and the supplementary groups.
    type private Ids =
        {
            Users : uint32 list
            Groups : uint32 list
            Supplementary : uint32 list
        }

    type private Request =
        | SetResUid of int64 * int64 * int64
        | SetResGid of int64 * int64 * int64
        | SetGroups of uint32 list

    type private ScopeRow =
        {
            Line : string
            Case : string
            Raw : bool
            /// 0 for main, 1 for w1.
            Caller : int
            Start : Ids
            Request : Request
            /// "0", or the errno's name.
            Errno : string
            /// What main, w1 and w2 each read of themselves.
            Threads : Ids list
            /// What /proc/self/task/<tid>/status said of main, w1 and w2.
            Proc : Ids list
            /// The filesystem uid and gid /proc reported of main, w1 and w2.
            FileSystemIds : (uint32 * uint32) list
        }

    let private threadPattern : Regex =
        Regex
            @"^(main|w1|w2) getres=uid:(\d+)/(\d+)/(\d+),gid:(\d+)/(\d+)/(\d+),groups:\[([\d,]*)\] proc=uid=(\d+)/(\d+)/(\d+)/(\d+) gid=(\d+)/(\d+)/(\d+)/(\d+) groups=\[([\d,]*)\]( end=\S+)?$"

    let private requestPattern : Regex =
        Regex @"^(setresuid|setresgid)\((-?\d+),(-?\d+),(-?\d+)\)$|^setgroups\((\d+),\[([\d,]*)\]\)$"

    let private parseRequest (text : string) : Request =
        let m = requestPattern.Match text

        if not m.Success then
            failwith $"not a request: %s{text}"
        elif m.Groups.[1].Success then
            let ids =
                (int64 m.Groups.[2].Value, int64 m.Groups.[3].Value, int64 m.Groups.[4].Value)

            match m.Groups.[1].Value with
            | "setresuid" -> Request.SetResUid ids
            | _ -> Request.SetResGid ids
        else
            let groups = numbers ',' m.Groups.[6].Value
            List.length groups |> shouldEqual (int m.Groups.[5].Value)
            Request.SetGroups groups

    let private parseScope (line : string) : ScopeRow =
        let parts = line.Split " | "

        let threads =
            parts.[1..]
            |> Array.toList
            |> List.map (fun part ->
                let m = threadPattern.Match part

                if not m.Success then
                    failwith $"not a thread's report: %s{part}"

                let at (i : int) : uint32 = UInt32.Parse m.Groups.[i].Value

                let own =
                    {
                        Users = [ at 2 ; at 3 ; at 4 ]
                        Groups = [ at 5 ; at 6 ; at 7 ]
                        Supplementary = numbers ',' m.Groups.[8].Value
                    }

                let proc =
                    {
                        Users = [ at 9 ; at 10 ; at 11 ]
                        Groups = [ at 13 ; at 14 ; at 15 ]
                        Supplementary = numbers ',' m.Groups.[17].Value
                    }

                m.Groups.[1].Value, own, proc, (at 12, at 16)
            )

        threads
        |> List.map (fun (name, _, _, _) -> name)
        |> shouldEqual [ "main" ; "w1" ; "w2" ]

        {
            Line = line
            Case = value "case" line
            Raw =
                match value "mode" line with
                | "raw" -> true
                | "libc" -> false
                | other -> failwith $"mode %s{other}"
            Caller =
                match value "caller" line with
                | "main" -> 0
                | "w1" -> 1
                | other -> failwith $"caller %s{other}"
            Start =
                {
                    Users = numbers '/' (value "start-uid" line)
                    Groups = numbers '/' (value "start-gid" line)
                    Supplementary = bracketed (value "start-groups" line)
                }
            Request = parseRequest (value "request" line)
            Errno = value "errno" line
            Threads = threads |> List.map (fun (_, own, _, _) -> own)
            Proc = threads |> List.map (fun (_, _, proc, _) -> proc)
            FileSystemIds = threads |> List.map (fun (_, _, _, fs) -> fs)
        }

    let private scopeRows : ScopeRow list =
        section "scope" linuxLines |> List.map parseScope

    [<Test>]
    let ``the probe ran every scope row, and each thread read of itself what /proc says of it`` () : unit =
        // A truncated or regenerated file would otherwise pass by replaying fewer rows.
        linuxLines
        |> List.head
        |> shouldEqual "# ldd (Debian GLIBC 2.41-12+deb13u4) 2.41"

        scopeRows |> List.length |> shouldEqual (6 * 2 * 2)

        for row in scopeRows do
            ending row.Line |> shouldEqual "end=exit0"
            row.Threads |> shouldEqual row.Proc

            for ids, (fsuid, fsgid) in List.zip row.Threads row.FileSystemIds do
                // The filesystem IDs followed the effective ones on every thread.
                (fsuid, fsgid) |> shouldEqual (ids.Users.[1], ids.Groups.[1])

    [<Test>]
    let ``Linux's system call changes only the thread that makes it, and glibc's wrapper every thread`` () : unit =
        for row in scopeRows do
            let changed = row.Threads.[row.Caller]

            if row.Errno <> "0" then
                // A refused call changes no thread.
                changed |> shouldEqual row.Start

            if row.Raw then
                for thread, ids in List.indexed row.Threads do
                    if thread <> row.Caller then
                        (row.Case, thread, ids) |> shouldEqual (row.Case, thread, row.Start)
            else
                for thread, ids in List.indexed row.Threads do
                    (row.Case, thread, ids) |> shouldEqual (row.Case, thread, changed)

        // Each case's calling thread ends the same under either form.
        for case in scopeRows |> List.map (fun row -> row.Case, row.Caller) |> List.distinct do
            let forms =
                scopeRows
                |> List.filter (fun row -> (row.Case, row.Caller) = case)
                |> List.map (fun row -> row.Errno, row.Threads.[row.Caller])

            List.length forms |> shouldEqual 2
            forms.[0] |> shouldEqual forms.[1]

        // A thread running its own code, in no call, is reached too.
        section "running" linuxLines
        |> List.exactlyOne
        |> value "spinner-getresuid"
        |> shouldEqual "1000/1000/1000"

    let private answerText (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed 0L -> "0"
        | SyscallAnswer.Completed other -> failwith $"a credential call returned %d{other}, not 0"
        | SyscallAnswer.Failed error -> $"%A{error}"

    let private requested (raw : int64) : uint32 option =
        if raw = -1L then None else Some (uint32 raw)

    let private linuxSystem (start : Ids) : UnixSystem<int, string> =
        let credentials =
            {
                RealUser = uid start.Users.[0]
                EffectiveUser = uid start.Users.[1]
                SavedUser = uid start.Users.[2]
                RealGroup = gid start.Groups.[0]
                EffectiveGroup = gid start.Groups.[1]
                SavedGroup = gid start.Groups.[2]
                SupplementaryGroups = start.Supplementary |> List.map gid
            }

        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> Launched.bootWith
            (Launched.credentials credentials
             >> ProcessLaunch.withCoreDumps CoreDumps.Suppressed)
            UnixSystem.pipedStandardStreams
            0
            (CpuId 0)
        |> Threads.spawn 1
        |> Threads.spawn 2

    /// What thread `thread` reads of itself through the library.
    let private readBack (thread : int) (system : UnixSystem<int, string>) : Ids =
        let caller = Callers.thread thread system

        let users =
            match UnixCredentials.getresuid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system with
            | GetIdsAnswer.Copied (r, e, s) -> [ r ; e ; s ] |> List.map UserId.toUInt32
            | other -> failwith $"getresuid answered %A{other}"

        let groups =
            match UnixCredentials.getresgid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system with
            | GetIdsAnswer.Copied (r, e, s) -> [ r ; e ; s ] |> List.map GroupId.toUInt32
            | other -> failwith $"getresgid answered %A{other}"

        let supplementary =
            match UnixCredentials.getgroups caller UserBuffer.Mapped 8 system with
            | GetGroupsAnswer.Copied groups -> groups |> List.map GroupId.toUInt32
            | other -> failwith $"getgroups answered %A{other}"

        {
            Users = users
            Groups = groups
            Supplementary = supplementary
        }

    [<Test>]
    let ``each call answers as glibc's wrapper did, and leaves every thread as the wrapper left it`` () : unit =
        // `UnixCredentials` changes the process, every thread alike, which is
        // what the wrapper rows measured; none of these threads is asleep in a
        // call, nor blocks a signal.
        for row in scopeRows |> List.filter (fun row -> not row.Raw) do
            let before = linuxSystem row.Start
            let caller = Callers.thread row.Caller before

            let answer, after =
                match row.Request with
                | Request.SetResUid (r, e, s) ->
                    UnixCredentials.setresuid
                        caller
                        (requested r |> Option.map uid)
                        (requested e |> Option.map uid)
                        (requested s |> Option.map uid)
                        before
                | Request.SetResGid (r, e, s) ->
                    UnixCredentials.setresgid
                        caller
                        (requested r |> Option.map gid)
                        (requested e |> Option.map gid)
                        (requested s |> Option.map gid)
                        before
                | Request.SetGroups groups ->
                    UnixCredentials.setgroups caller (List.length groups) (GroupListWords.Readable groups) before

            (row.Line, answerText answer) |> shouldEqual (row.Line, row.Errno)

            for thread in 0..2 do
                (row.Line, thread, readBack thread after)
                |> shouldEqual (row.Line, thread, row.Threads.[thread])

    // ------------------------------------------------------------- Linux: glibc's signal 33

    [<Test>]
    let ``glibc catches signal 33 with SA_RESTART once the process has made a thread, and its sigaction refuses it``
        ()
        =
        let handler (signo : int) (``when`` : string) : string =
            section "handler" linuxLines
            |> List.filter (fun line -> line.Contains $"signo=%d{signo} " && line.Contains $"when=%s{``when``} ")
            |> List.exactlyOne

        for signo in [ 32 ; 33 ] do
            value "disposition" (handler signo "before-any-thread") |> shouldEqual "default"

        value "disposition" (handler 32 "after-a-thread") |> shouldEqual "default"
        let installed = handler 33 "after-a-thread"
        value "disposition" installed |> shouldEqual "caught"
        value "sa-restart" installed |> shouldEqual "yes"

        section "handler" linuxLines
        |> List.filter (fun line -> line.StartsWith ("handler libc-sigaction(33,query)", StringComparison.Ordinal))
        |> List.exactlyOne
        |> value "errno"
        |> shouldEqual "EINVAL"

        // `UnixSignal.sigaction` is glibc's sigaction(3), which refuses 33.
        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        match UnixSignal.sigaction (Callers.leader system) 33 None system with
        | SigactionAnswer.Failed error, after ->
            error |> shouldEqual UnixError.EINVAL
            after |> shouldEqual system
        | SigactionAnswer.Completed _, _ -> failwith "sigaction(3) of 33 answered a disposition"

    [<Test>]
    let ``glibc's wrapper never returns while another thread blocks signal 33`` () : unit =
        let blocked (waiter : string) : string =
            section "blocked" linuxLines
            |> List.filter (fun line -> line.Contains $"waiter=%s{waiter} ")
            |> List.exactlyOne

        // The two controls: nothing blocked, and only the caller blocking it.
        for waiter in [ "read-pipe-not-blocking-33" ; "read-pipe-while-the-caller-blocks-33" ] do
            let line = blocked waiter
            value "ret" line |> shouldEqual "0"
            ending line |> shouldEqual "end=exit0"

        // The child's two-second alarm killed it in the call.
        for waiter in [ "read-pipe" ; "spin" ; "raw-rt_sigsuspend-blocking-33" ] do
            let line = blocked waiter
            line.Contains " ret=" |> shouldEqual false
            ending line |> shouldEqual "end=signal14"

    // ------------------------------------------------------------- the interrupt section

    /// One group of an interrupt row's trials: whether the call returned before
    /// the release, its return value, its errno, and how many trials.
    type private Outcome = string * string * string * int

    let private outcomes (line : string) : Outcome list =
        (value "outcomes" line).Split ','
        |> Array.toList
        |> List.map (fun group ->
            match group.Split ':' with
            | [| phase ; ret ; errnoAndCount ; _took |] ->
                match errnoAndCount.Split '*' with
                | [| errno ; count |] -> phase, ret.Substring 4, errno.Substring 6, int count
                | _ -> failwith $"not an outcome: %s{group}"
            | _ -> failwith $"not an outcome: %s{group}"
        )
        |> List.sort

    let private interrupt (all : string list) (call : string) (action : string) : string =
        section "interrupt" all
        |> List.filter (fun line -> value "call" line = call && value "action" line = action)
        |> List.exactlyOne

    let private description : OpenFileDescriptionId = OpenFileDescriptionId 0L

    /// The park each probed call makes, as the library records it.
    let private parkOf (flavour : SimulatedUnixFlavour) (call : string) : ParkedSyscall =
        match call with
        | "poll"
        | "poll-timeout" ->
            let deadline = if call = "poll" then None else Some 400L

            match flavour with
            | SimulatedUnixFlavour.Linux ->
                ParkedSyscall.Poll
                    {
                        Entries = [ ParkedPollEntry.Watched (3, description, 1s) ]
                        Deadline = deadline
                    }
            | SimulatedUnixFlavour.Darwin ->
                ParkedSyscall.KqueuePoll
                    {
                        Entries =
                            [
                                {
                                    Fd = 3
                                    Events = 1s
                                }
                            ]
                        Queue = PollQueueId 0L
                        Deadline = deadline
                    }
        | "epoll_wait" ->
            ParkedSyscall.EpollWait
                {
                    Epoll = description
                    MaxEvents = 1
                    Buffer = UserBuffer.Mapped
                    Deadline = None
                }
        | "kevent" ->
            ParkedSyscall.Kevent
                {
                    Kqueue = description
                    Fd = 3
                    MaxEvents = 1
                    Buffer = UserBuffer.Mapped
                    Deadline = None
                }
        | "sigsuspend"
        | "pause" -> ParkedSyscall.SigSuspend
        | "futex-wait"
        | "futex-wait-timeout" ->
            ParkedSyscall.Futex
                {
                    FutexAddress = 0x1000UL
                    FutexTimeout =
                        if call = "futex-wait" then
                            FutexTimeout.Untimed
                        else
                            FutexTimeout.Until 400L
                    FutexBitset = UnixFutex.FutexBitsetMatchAny
                    TakenByWake = false
                }
        | "read-pipe" ->
            ParkedSyscall.PipeRead
                {
                    Reader = SleepTarget.Waiting (description, 3)
                    Buffer = UserBuffer.Mapped
                    Count = 1
                }
        | "accept" ->
            ParkedSyscall.Accept
                {
                    Listener = SleepTarget.Waiting (description, 3)
                    Destination = UserBuffer.Mapped
                    DeclaredLength = (Some 16u)
                    NewSocketNonBlocking = false
                    NewSocketCloseOnExec = false
                }
        | "nanosleep" ->
            ParkedSyscall.Sleep
                {
                    Deadline = 400L
                    Remainder = SleepRemainder.Unreported
                }
        | other -> failwith $"no park for %s{other}"

    let private linuxCalls : string list =
        [
            "poll"
            "poll-timeout"
            "epoll_wait"
            "sigsuspend"
            "pause"
            "futex-wait"
            "futex-wait-timeout"
            "read-pipe"
            "accept"
            "nanosleep"
        ]

    let private darwinCalls : string list =
        [
            "poll"
            "poll-timeout"
            "kevent"
            "sigsuspend"
            "pause"
            "read-pipe"
            "accept"
            "nanosleep"
        ]

    /// Every trial was taken, and on Linux every waiter was asleep in its call
    /// when the action came.
    let private wellFormed (flavour : SimulatedUnixFlavour) (line : string) : unit =
        line.Contains " failed=" |> shouldEqual false
        outcomes line |> List.sumBy (fun (_, _, _, count) -> count) |> shouldEqual 20

        match flavour with
        | SimulatedUnixFlavour.Linux -> (line, value "asleep-in" line <> "-1") |> shouldEqual (line, true)
        | SimulatedUnixFlavour.Darwin -> ()

    /// A signal caught with SA_RESTART ends each call as `ruleOf` says: one that
    /// fails with EINTR returned EINTR at the signal, in every trial, and one
    /// that restarts ended as the call does unsignalled.
    let private signalRowsFollowRuleOf
        (flavour : SimulatedUnixFlavour)
        (all : string list)
        (calls : string list)
        : unit
        =
        for call in calls do
            let signalled = outcomes (interrupt all call "signal")
            let control = outcomes (interrupt all call "none")

            match SyscallInterruption.ruleOf flavour (parkOf flavour call) with
            | SignalRestartRule.FailsWithEintr ->
                (call, signalled) |> shouldEqual (call, [ "before-release", "-1", "EINTR", 20 ])
            | SignalRestartRule.RestartsUnderSaRestart -> (call, signalled) |> shouldEqual (call, control)

    [<Test>]
    let ``on Linux a caught SA_RESTART signal ends each call as SyscallInterruption.ruleOf says`` () : unit =
        section "interrupt" linuxLines
        |> List.iter (wellFormed SimulatedUnixFlavour.Linux)

        signalRowsFollowRuleOf SimulatedUnixFlavour.Linux linuxLines linuxCalls

    [<Test>]
    let ``on Darwin a caught SA_RESTART signal ends each call as SyscallInterruption.ruleOf says`` () : unit =
        section "interrupt" darwinLines
        |> List.iter (wellFormed SimulatedUnixFlavour.Darwin)

        signalRowsFollowRuleOf SimulatedUnixFlavour.Darwin darwinLines darwinCalls

    [<Test>]
    let ``glibc's wrapper ends another thread's call as a caught SA_RESTART signal does, and the system call does not``
        ()
        =
        section "interrupt" linuxLines |> List.length |> shouldEqual (10 * 5 + 5)

        for call in linuxCalls do
            let signalled = outcomes (interrupt linuxLines call "signal")

            // A failing wrapper signals every other thread too, before its own
            // call fails.
            for action in [ "libc-setresuid" ; "libc-setgroups-einval" ] do
                (call, action, outcomes (interrupt linuxLines call action))
                |> shouldEqual (call, action, signalled)

            (call, outcomes (interrupt linuxLines call "raw-setresuid"))
            |> shouldEqual (call, outcomes (interrupt linuxLines call "none"))

        for call in [ "poll" ; "sigsuspend" ; "futex-wait" ; "read-pipe" ; "nanosleep" ] do
            let line = interrupt linuxLines call "libc-setresuid-eperm"
            value "as" line |> shouldEqual "uid1000"
            value "action-ret" line |> shouldEqual "-1/EPERM"

            (call, outcomes line)
            |> shouldEqual (call, outcomes (interrupt linuxLines call "signal"))

    // ------------------------------------------------------------- Darwin

    let private darwinThreadPattern : Regex =
        Regex @"^(main|w1|w2) uid=(\d+)/(\d+) gid=(\d+)/(\d+) groups=\[([\d,]*)\]( end=\S+)?$"

    /// A `dscope` row's call, its caller, its errno, and what main, w1 and w2
    /// each read of themselves: real and effective users, the same of groups
    /// (Darwin reads back no saved ID), and the groups `getgroups` reported.
    let private darwinScope : (string * string * string * Ids list) list =
        section "dscope" darwinLines
        |> List.map (fun line ->
            let threads =
                line.Split(" | ").[1..]
                |> Array.toList
                |> List.map (fun part ->
                    let m = darwinThreadPattern.Match part

                    if not m.Success then
                        failwith $"not a thread's report: %s{part}"

                    let at (i : int) : uint32 = UInt32.Parse m.Groups.[i].Value

                    {
                        Users = [ at 2 ; at 3 ]
                        Groups = [ at 4 ; at 5 ]
                        Supplementary = numbers ',' m.Groups.[6].Value
                    }
                )

            ending line |> shouldEqual "end=exit0"
            value "call" line, value "caller" line, value "errno" line, threads
        )

    [<Test>]
    let ``Darwin's credential calls change every thread`` () : unit =
        darwinLines.[1] |> shouldEqual "# start uid=501/501 gid=20/12 (real/effective)"
        darwinScope |> List.length |> shouldEqual (11 * 2)

        for call, caller, _, threads in darwinScope do
            for ids in threads do
                (call, caller, ids) |> shouldEqual (call, caller, threads.[0])

        // The set-group-ID copy made these rows real changes.
        for call, caller, errno, threads in darwinScope do
            if
                call.StartsWith ("setegid(rgid)", StringComparison.Ordinal)
                && not (call.Contains ";")
            then
                (call, caller, errno, threads.[0].Groups)
                |> shouldEqual (call, caller, "0", [ 20u ; 20u ])

    [<Test>]
    let ``Darwin's credential calls end no other thread's call`` () : unit =
        section "interrupt" darwinLines
        |> List.length
        |> shouldEqual (List.length darwinCalls * 5)

        for call in darwinCalls do
            let control = outcomes (interrupt darwinLines call "none")

            for action in [ "setegid" ; "seteuid-noop" ; "setgroups-eperm" ] do
                (call, action, outcomes (interrupt darwinLines call action))
                |> shouldEqual (call, action, control)
