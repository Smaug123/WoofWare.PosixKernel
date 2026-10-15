namespace WoofWare.PosixKernel.Test

open System
open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open NUnit.Framework
open WoofWare.PosixKernel

/// `Syscall` is a set of labels for the calls a thread makes, which
/// `UnixSystem.step` interprets by calling each call's own function: one case
/// for every such function, and `SteppedCall` one case for each of those,
/// holding what the function answers.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSyscall =

    let private library : Assembly = typeof<UnixError>.Assembly

    /// Each public function a thread calls as a syscall, by the name a client
    /// writes for it, with the `Syscall` case that names its call.
    let private caseOfFunction : (string * string) list =
        [
            "UnixDescriptor.dup", "Dup"
            "UnixDescriptor.dup2", "Dup2"
            "UnixDescriptor.dup3", "Dup3"
            "UnixDescriptor.fcntl", "Fcntl"
            "UnixDescriptor.lseek", "LSeek"
            "UnixDescriptor.flock", "FLock"
            "UnixDescriptor.ftruncate", "FTruncate"
            "UnixDescriptor.posixFadvise", "PosixFAdvise"
            "UnixDescriptor.close", "Close"
            "UnixDescriptor.bytesAvailable", "BytesAvailable"
            "UnixDescriptor.fileClone", "FileClone"
            "UnixDescriptor.terminalAttributes", "TerminalAttributes"
            "UnixDescriptor.effectiveUserId", "GetEffectiveUserId"
            "UnixDescriptor.effectiveGroupId", "GetEffectiveGroupId"
            "UnixDescriptor.getgroups", "GetGroups"
            "UnixPathResolution.stat", "Stat"
            "UnixPathResolution.fstat", "FStat"
            "UnixPathResolution.fstatat", "FStatAt"
            "UnixPathResolution.chmod", "ChMod"
            "UnixPathResolution.fchmod", "FChMod"
            "UnixPathResolution.fchmodat", "FChModAt"
            "UnixPathResolution.chown", "ChOwn"
            "UnixPathResolution.lchown", "LChOwn"
            "UnixPathResolution.fchown", "FChOwn"
            "UnixPathResolution.fchownat", "FChOwnAt"
            "UnixPathResolution.utimensat", "UTimensAt"
            "UnixPathResolution.statfs", "StatFs"
            "UnixPathResolution.fstatfs", "FStatFs"
            "UnixPathResolution.getcwd", "GetCwd"
            "UnixPathResolution.chdir", "ChDir"
            "UnixPathResolution.access", "Access"
            "UnixPathResolution.faccessat", "FAccessAt"
            "UnixNamespace.openPath", "Open"
            "UnixNamespace.openat", "OpenAt"
            "UnixNamespace.readlink", "ReadLink"
            "UnixNamespace.readlinkat", "ReadLinkAt"
            "UnixNamespace.readDirectoryEntry", "ReadDirectoryEntry"
            "UnixNamespace.mkdir", "MkDir"
            "UnixNamespace.mkdirat", "MkDirAt"
            "UnixNamespace.mknod", "MkNod"
            "UnixNamespace.mknodat", "MkNodAt"
            "UnixNamespace.unlink", "Unlink"
            "UnixNamespace.rmdir", "RmDir"
            "UnixNamespace.unlinkat", "UnlinkAt"
            "UnixNamespace.rename", "Rename"
            "UnixNamespace.renameat", "RenameAt"
            "UnixNamespace.cloneFile", "CloneFile"
            "UnixNamespace.symlink", "Symlink"
            "UnixNamespace.symlinkat", "SymlinkAt"
            "UnixNamespace.link", "Link"
            "UnixNamespace.linkat", "LinkAt"
            "UnixReadWrite.read", "Read"
            "UnixReadWrite.recv", "Recv"
            "UnixReadWrite.pread", "PRead"
            "UnixReadWrite.write", "Write"
            "UnixReadWrite.send", "Send"
            "UnixReadWrite.pwrite", "PWrite"
            "UnixReadWrite.copyFileRange", "CopyFileRange"
            "UnixPipe.pipe2", "Pipe2"
            "UnixSocket.socket", "Socket"
            "UnixSocket.bind", "Bind"
            "UnixConnection.connect", "Connect"
            "UnixSocket.listen", "Listen"
            "UnixConnection.accept", "Accept"
            "UnixConnection.shutdown", "Shutdown"
            "UnixSocket.getsockname", "GetSockName"
            "UnixSocket.getpeername", "GetPeerName"
            "UnixSocket.setsockopt", "SetSockOpt"
            "UnixSocket.getsockopt", "GetSockOpt"
            "UnixPoll.poll", "Poll"
            "UnixPoll.epollCreate1", "EpollCreate1"
            "UnixPoll.epollCtl", "EpollCtl"
            "UnixPoll.epollWait", "EpollWait"
            "UnixKqueue.kqueue", "Kqueue"
            "UnixKqueue.kevent", "Kevent"
            "UnixInotify.inotifyInit1", "InotifyInit1"
            "UnixInotify.inotifyAddWatch", "InotifyAddWatch"
            "UnixInotify.inotifyRmWatch", "InotifyRmWatch"
            "UnixSignal.kill", "Kill"
            "UnixSignal.pthreadKill", "PthreadKill"
            "UnixSignal.sigaction", "SigAction"
            "UnixSignal.sigactionSyscall", "SigActionSyscall"
            "UnixSignal.pthreadSigmask", "PthreadSigMask"
            "UnixSignal.sigprocmask", "SigProcMask"
            "UnixSignal.rtSigprocmask", "RtSigProcMask"
            "UnixSignal.sigpending", "SigPending"
            "UnixSignal.sigsuspend", "SigSuspend"
            "UnixSignal.rtSigsuspend", "RtSigSuspend"
            "UnixSignal.pause", "Pause"
            "UnixSignal.sigreturn", "SigReturn"
            "UnixClock.clockGettime", "ClockGetTime"
            "UnixClock.gettimeofday", "GetTimeOfDay"
            "UnixEntropy.getRandom", "GetRandom"
            "UnixEntropy.getEntropy", "GetEntropy"
            "UnixSystem.processId", "GetProcessId"
            "UnixSystem.umask", "UMask"
            "UnixCredentials.getresuid", "GetResUid"
            "UnixCredentials.getresgid", "GetResGid"
            "UnixCredentials.setresuid", "SetResUid"
            "UnixCredentials.setresgid", "SetResGid"
            "UnixCredentials.setgroups", "SetGroups"
            "UnixThreadLifecycle.spawn", "Spawn"
            "UnixThreadLifecycle.exitThread", "ExitThread"
            "UnixThreadLifecycle.exitGroup", "ExitGroup"
            "UnixScheduling.getcpu", "GetCpu"
        ]

    /// The public functions whose first argument is a `Caller` but which are
    /// no call a thread makes of the kernel, each with why it has no
    /// `Syscall` case.
    let private excluded : (string * string) list =
        let finisher =
            "finishes a call `wake` woke, which the call's own case began; `UnixWait.finish` finishes any of them"

        [
            "UnixWait.finish", finisher
            "UnixDescriptor.flockAcquire", finisher
            "UnixConnection.finishAccept", finisher
            "UnixPoll.finishPoll", finisher
            "UnixPoll.finishEpollWait", finisher
            "UnixKqueue.finishKevent", finisher
            "UnixReadWrite.finishRead", finisher
            "UnixReadWrite.finishWrite", finisher
            "UnixSignal.finishSigsuspend", finisher
            "UnixSignal.onReturnToUser", "the return to user mode, which ends a call rather than making one"
            "UnixScheduling.dispatch", "the client's report of which processor runs a thread, which no thread makes"
            "UnixScheduling.runningOn", "reads the client's own report of where a thread runs"
            "UnixDescriptor.setNonBlocking", "sugar for fcntl(F_GETFL) then fcntl(F_SETFL), which have their case"
            "UnixDescriptor.isNonBlocking", "sugar for fcntl(F_GETFL), which has its case"
            "UnixWait.satisfied", "a question about a parked thread, which no thread asks"
            "UnixSystem.step", "makes the call a case names"
            "Caller.processId", "reads the caller itself, asking the kernel nothing"
            "Caller.thread", "reads the caller itself, asking the kernel nothing"
        ]

    /// The cases of calls this library does not model yet.
    let private reserved : string list =
        [
            "Nanosleep"
            "ClockNanosleep"
            "Select"
            "PSelect"
            "SigWait"
            "SigWaitInfo"
            "SigTimedWait"
            "RecvFrom"
            "RecvMsg"
            "SendTo"
            "SendMsg"
        ]

    /// The cases `step` makes.
    let wired : string list =
        [
            "Dup"
            "Dup2"
            "Dup3"
            "Fcntl"
            "LSeek"
            "FLock"
            "FTruncate"
            "Close"
            "FileClone"
            "GetEffectiveUserId"
            "GetEffectiveGroupId"
            "FChMod"
            "FChModAt"
            "FChOwn"
            "FChOwnAt"
            "UTimensAt"
            "ChDir"
            "FAccessAt"
            "MkDirAt"
            "UnlinkAt"
            "CloneFile"
            "SymlinkAt"
            "LinkAt"
            "CopyFileRange"
            "InotifyInit1"
            "InotifyRmWatch"
            "GetProcessId"
            "UMask"
            "SetResUid"
            "SetResGid"
            "SetGroups"
        ]

    /// The cases `step` does not make yet, by the stage that wires each.
    let private unwired : (string * WiringStage) list =
        [
            for case in
                [
                    "PosixFAdvise"
                    "BytesAvailable"
                    "TerminalAttributes"
                    "GetGroups"
                    "Stat"
                    "FStat"
                    "FStatAt"
                    "ChMod"
                    "ChOwn"
                    "LChOwn"
                    "StatFs"
                    "FStatFs"
                    "GetCwd"
                    "Access"
                    "Open"
                    "OpenAt"
                    "ReadLink"
                    "ReadLinkAt"
                    "ReadDirectoryEntry"
                    "MkDir"
                    "MkNod"
                    "MkNodAt"
                    "Unlink"
                    "RmDir"
                    "Rename"
                    "RenameAt"
                    "Symlink"
                    "Link"
                    "Read"
                    "Recv"
                    "PRead"
                    "Write"
                    "Send"
                    "PWrite"
                    "Pipe2"
                    "Bind"
                    "Connect"
                    "SetSockOpt"
                    "GetSockOpt"
                    "InotifyAddWatch"
                ] do
                yield case, WiringStage.S2
            for case in
                [
                    "Socket"
                    "Listen"
                    "Accept"
                    "Shutdown"
                    "GetSockName"
                    "GetPeerName"
                    "Poll"
                    "EpollCreate1"
                    "EpollCtl"
                    "EpollWait"
                    "Kqueue"
                    "Kevent"
                    "Kill"
                    "PthreadKill"
                    "SigAction"
                    "SigActionSyscall"
                    "PthreadSigMask"
                    "SigProcMask"
                    "RtSigProcMask"
                    "SigPending"
                    "SigSuspend"
                    "RtSigSuspend"
                    "Pause"
                    "SigReturn"
                    "ClockGetTime"
                    "GetTimeOfDay"
                    "GetRandom"
                    "GetEntropy"
                    "GetResUid"
                    "GetResGid"
                    "Spawn"
                    "ExitThread"
                    "ExitGroup"
                    "GetCpu"
                ] do
                yield case, WiringStage.S3
        ]

    let private allCases : BindingFlags = BindingFlags.Public ||| BindingFlags.NonPublic

    let private syscallCases : UnionCaseInfo list =
        FSharpType.GetUnionCases (typeof<Syscall<int, string>>, allCases)
        |> List.ofArray

    let private steppedCases : UnionCaseInfo list =
        FSharpType.GetUnionCases (typeof<SteppedCall<int, string>>, allCases)
        |> List.ofArray

    let private syscallCaseNames : string list =
        syscallCases |> List.map (fun case -> case.Name)

    /// Every public module function whose first argument is a `Caller`, by the
    /// name a client writes for it.
    let private callerFirst : Lazy<Map<string, MethodInfo>> =
        lazy
            library.GetExportedTypes ()
            |> Array.filter (fun (t : Type) -> LibraryNames.kindOf t = Some SourceConstructFlags.Module)
            |> Array.collect (fun (t : Type) ->
                t.GetMethods (BindingFlags.Public ||| BindingFlags.Static ||| BindingFlags.DeclaredOnly)
                |> Array.filter (fun (m : MethodInfo) ->
                    match m.GetParameters () with
                    | [||] -> false
                    | parameters ->
                        let first = parameters.[0].ParameterType

                        first.IsGenericType
                        && first.GetGenericTypeDefinition () = typedefof<Caller<int>>
                )
                |> Array.map (fun (m : MethodInfo) ->
                    $"%s{LibraryNames.dottedName t}.%s{LibraryNames.sourceName m}", m
                )
            )
            |> Array.groupBy fst
            |> Array.map (fun (name, methods) ->
                match methods with
                | [| _, m |] -> name, m
                | several -> failwith $"%s{name} names %d{several.Length} methods"
            )
            |> Map.ofArray

    [<Test>]
    let ``every public function a thread calls as a syscall has a Syscall case, or a reason it has none`` () : unit =
        let functions = callerFirst.Value |> Map.keys |> Set.ofSeq

        // Not vacuous: the functions are found.
        functions |> shouldContain "UnixDescriptor.dup"
        functions |> shouldContain "UnixWait.finish"

        let named = caseOfFunction |> List.map fst

        named |> List.distinct |> shouldEqual named

        Set.intersect (Set.ofList named) (Set.ofList (List.map fst excluded))
        |> shouldEqual Set.empty

        Set.difference functions (Set.ofList named)
        |> shouldEqual (Set.ofList (List.map fst excluded))

        Set.difference (Set.ofList named) functions |> shouldEqual Set.empty

    [<Test>]
    let ``every Syscall case names one function's call, or is reserved`` () : unit =
        let cases = caseOfFunction |> List.map snd

        cases |> List.distinct |> shouldEqual cases
        List.length cases |> shouldEqual 105
        List.length reserved |> shouldEqual 11

        Set.intersect (Set.ofList cases) (Set.ofList reserved) |> shouldEqual Set.empty

        Set.union (Set.ofList cases) (Set.ofList reserved)
        |> shouldEqual (Set.ofList syscallCaseNames)

        List.length syscallCaseNames |> shouldEqual 116

    [<Test>]
    let ``SteppedCall's cases are Syscall's, in the same order`` () : unit =
        steppedCases |> List.map (fun case -> case.Name) |> shouldEqual syscallCaseNames

    /// `t` with the type `'Thread` and `'Handler` stand for in the instances
    /// this fixture reads, `Syscall<int, string>` and
    /// `SteppedCall<int, string>`.
    let private instantiate (m : MethodInfo) : MethodInfo =
        if m.IsGenericMethodDefinition then
            m.GetGenericArguments ()
            |> Array.map (fun (parameter : Type) ->
                match parameter.Name with
                | "Thread" -> typeof<int>
                | "Handler" -> typeof<string>
                | other ->
                    failwith $"%s{m.Name} has a type parameter '%s{other}, which this fixture cannot instantiate"
            )
            |> fun arguments -> m.MakeGenericMethod arguments
        else
            m

    /// What an argument to a case is to the call's own function: a
    /// `CopiedArgument` is the `UserBuffer` the function takes for it.
    let private asFunctionTakesIt (t : Type) : Type =
        if
            t.IsGenericType
            && t.GetGenericTypeDefinition () = typedefof<CopiedArgument<int>>
        then
            typeof<UserBuffer>
        else
            t

    [<Test>]
    let ``each case holds its function's arguments, and a pathname its resumption copies in`` () : unit =
        let faults =
            [
                for name, caseName in caseOfFunction do
                    let m = instantiate (Map.find name callerFirst.Value)
                    let case = syscallCases |> List.find (fun case -> case.Name = caseName)

                    let fields =
                        case.GetFields ()
                        |> Array.map (fun (field : PropertyInfo) -> field.Name, asFunctionTakesIt field.PropertyType)
                        |> List.ofArray

                    // Between the caller and the system the call is made in.
                    let arguments =
                        let parameters = m.GetParameters ()

                        parameters.[parameters.Length - 1].ParameterType
                        |> shouldEqual typeof<UnixSystem<int, string>>

                        parameters.[1 .. parameters.Length - 2]
                        |> Array.map (fun (p : ParameterInfo) -> p.Name, p.ParameterType)
                        |> List.ofArray

                    for argument in arguments do
                        if not (List.contains argument fields) then
                            yield $"%s{caseName} holds nothing for %s{name}'s %A{argument}"

                    for field in fields do
                        if not (List.contains field arguments) && snd field <> typeof<PathArgumentBytes> then
                            yield
                                $"%s{caseName}'s %A{field} is no argument of %s{name}, nor a pathname its resumption takes"
            ]

        faults |> shouldEqual []

    /// What a function answers, as its `SteppedCall` case holds it: a call's
    /// answer where the function answers a `CallProgress`, since `step`
    /// resumes the call, and a tuple's parts as the case's fields.
    let private steppedFields (answer : Type) : Type list =
        let answered =
            if
                answer.IsGenericType
                && answer.GetGenericTypeDefinition () = typedefof<CallProgress<int, int>>
            then
                answer.GetGenericArguments().[1]
            else
                answer

        if FSharpType.IsTuple answered then
            FSharpType.GetTupleElements answered |> List.ofArray
        else
            [ answered ]

    [<Test>]
    let ``each SteppedCall case holds what its function answers`` () : unit =
        let faults =
            [
                for name, caseName in caseOfFunction do
                    let m = instantiate (Map.find name callerFirst.Value)
                    let case = steppedCases |> List.find (fun case -> case.Name = caseName)

                    let fields =
                        case.GetFields ()
                        |> Array.map (fun (field : PropertyInfo) -> field.PropertyType)
                        |> List.ofArray

                    let expected = steppedFields m.ReturnType

                    if fields <> expected then
                        yield $"%s{caseName} holds %A{fields}, but %s{name} answers %A{expected}"
            ]

        faults |> shouldEqual []

    [<Test>]
    let ``each reserved case holds an opaque type of its own, in Syscall and in SteppedCall`` () : unit =
        for caseName in reserved do
            let fieldOf (cases : UnionCaseInfo list) : Type =
                match (cases |> List.find (fun case -> case.Name = caseName)).GetFields () with
                | [| field |] -> field.PropertyType
                | fields -> failwith $"%s{caseName} holds %d{fields.Length} fields"

            let arguments = fieldOf syscallCases
            let stepped = fieldOf steppedCases

            arguments.Name |> shouldEqual $"%s{caseName}Arguments"
            LibraryNames.withoutArity stepped.Name |> shouldEqual $"Stepped%s{caseName}"

            for t in [ arguments ; stepped ] do
                // Opaque: a union whose one case a client cannot build.
                FSharpType.IsUnion (t, BindingFlags.Public) |> shouldEqual false

                FSharpType.GetUnionCases (t, allCases)
                |> Array.map (fun case -> case.GetFields().Length)
                |> shouldEqual [| 0 |]

    /// A value of `case`, each field of which `step` does not read: a reserved
    /// case's opaque value, and otherwise its type's default.
    let private placeholder (case : UnionCaseInfo) : Syscall<int, string> =
        let fields =
            case.GetFields ()
            |> Array.map (fun (field : PropertyInfo) ->
                let t = field.PropertyType

                if
                    FSharpType.IsUnion (t, allCases)
                    && not (FSharpType.IsUnion (t, BindingFlags.Public))
                then
                    FSharpValue.MakeUnion ((FSharpType.GetUnionCases (t, allCases)).[0], [||], allCases)
                elif t.IsValueType then
                    Activator.CreateInstance t
                else
                    null
            )

        FSharpValue.MakeUnion (case, fields, allCases) :?> Syscall<int, string>

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private booted (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial<int, string> platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    [<Test>]
    let ``every case is made, refused as reserved, or refused naming the stage that wires it`` () : unit =
        let unwiredNames = unwired |> List.map fst

        unwiredNames |> List.distinct |> shouldEqual unwiredNames

        List.concat [ wired ; reserved ; unwiredNames ]
        |> List.sort
        |> shouldEqual (List.sort syscallCaseNames)

        for platform in platforms do
            let system = booted platform

            for case in syscallCases do
                if not (List.contains case.Name wired) then
                    let call = placeholder case

                    let expected =
                        match List.tryFind (fun (name, _) -> name = case.Name) unwired with
                        | Some (_, stage) -> SyscallRefusal.Unwired ($"Syscall.%s{case.Name}", stage)
                        | None -> SyscallRefusal.Reserved $"Syscall.%s{case.Name}"

                    match UnixSystem.tryStep (Callers.leader system) call system with
                    | Error refusal -> refusal |> shouldEqual expected
                    | Ok stepped -> failwith $"%s{case.Name} answered %A{Stepped.view stepped}"

                    let thrown =
                        Assert.Throws<UnmodelledException> (fun () ->
                            UnixSystem.step (Callers.leader system) call system |> ignore
                        )

                    thrown.Message |> shouldContainText $"Syscall.%s{case.Name}"
                    thrown.Message |> shouldContainText (SyscallRefusal.describe expected)

    [<Test>]
    let ``a reserved call is refused, whoever makes it, and leaves the system as it was`` () : unit =
        for platform in platforms do
            let system = booted platform
            let pid = Lone.pid system

            for caseName in reserved do
                let call =
                    placeholder (syscallCases |> List.find (fun case -> case.Name = caseName))

                // No system comes back, so nothing the call did can reach the
                // client: the system it passed in is the one it carries on with.
                UnixSystem.tryStep (Callers.leader system) call system
                |> Result.map Stepped.view
                |> shouldEqual (Error (SyscallRefusal.Reserved $"Syscall.%s{caseName}"))

                Assert.Throws<UnmodelledException> (fun () ->
                    UnixSystem.step (Callers.leader system) call system |> ignore
                )
                |> ignore

                UnixSystem.checkInvariants system |> shouldEqual []

                UnixSystem.step (Callers.leader system) Syscall.GetProcessId system
                |> Stepped.shouldBe (SteppedCall.GetProcessId pid)

                // As every call checks its caller first, a reserved one made by
                // a name that is no thread is the client's bug, not unmodelled.
                let thrown =
                    Assert.Throws<InvalidOperationException> (fun () ->
                        UnixSystem.step (Caller.make pid 99) call system |> ignore
                    )

                thrown.Message
                |> shouldContainText "thread 99 is not one of the process's threads"

    /// The method `name` names in the module `owner`, whatever its visibility.
    let private methodOf (owner : string) (name : string) : MethodInfo =
        library.GetTypes ()
        |> Array.filter (fun (t : Type) -> LibraryNames.dottedName t = owner)
        |> Array.collect (fun (t : Type) ->
            t.GetMethods (
                BindingFlags.Public
                ||| BindingFlags.NonPublic
                ||| BindingFlags.Static
                ||| BindingFlags.DeclaredOnly
            )
        )
        |> Array.filter (fun (m : MethodInfo) -> m.Name = name)
        |> function
            | [| m |] -> m
            | several -> failwith $"%s{owner}.%s{name} names %d{several.Length} methods"

    /// The library's methods whose bodies call `callee`, by their declaring
    /// type's name and their own.
    let private callersOf (callee : MethodInfo) : Set<string> =
        let methods =
            library.GetTypes ()
            |> Array.filter (fun (t : Type) -> isNull t.DeclaringType)
            |> Array.collect (fun (t : Type) -> IlCalls.methodsWithin t |> Array.ofList)

        let calls = methods |> Array.map (fun m -> m, IlCalls.callees m)

        // Not vacuous: every call in the library resolved, so none was missed.
        calls
        |> Array.collect (fun (_, callees) ->
            callees
            |> List.choose (fun (callee : Result<MethodBase, string>) ->
                match callee with
                | Ok _ -> None
                | Error fault -> Some fault
            )
            |> Array.ofList
        )
        |> shouldEqual [||]

        calls
        |> Array.filter (fun (_, callees) ->
            callees
            |> List.exists (fun (c : Result<MethodBase, string>) ->
                match c with
                | Ok (:? MethodInfo as m) ->
                    (if m.IsGenericMethod then
                         m.GetGenericMethodDefinition ()
                     else
                         m) = callee
                | Ok _
                | Error _ -> false
            )
        )
        |> Array.map (fun (m, _) -> $"%s{LibraryNames.dottedName m.DeclaringType}.%s{m.Name}")
        |> Set.ofArray

    /// The labels are a description `step` interprets, never the source of
    /// truth: no function makes its call by building a `Syscall` and stepping
    /// it, so `step` is the only caller of `tryStep`, and nothing in the
    /// library calls `step`.
    [<Test>]
    let ``nothing in the library steps a Syscall but step itself`` () : unit =
        let tryStep = methodOf "UnixSystem" "tryStep"
        let step = methodOf "UnixSystem" "step"

        // Controls, so that the walk cannot pass by finding nothing.
        callersOf (methodOf "UnixWait" "tryFinish")
        |> shouldEqual (Set.singleton "UnixWait.finish")

        callersOf tryStep |> shouldEqual (Set.singleton "UnixSystem.step")

        callersOf step |> shouldEqual Set.empty
