namespace WoofWare.PosixKernel.Test

open System
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Every public function of the families that take a `Caller` checks it, through
/// `Entry`, before it does anything else: a caller in another process, a thread
/// the process does not have, a parked thread making a call, and an unparked
/// thread at a finishing function each throw `InvalidOperationException`, naming
/// the function; the caller each requirement admits does not.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCallerChecks =

    /// A public function, made by a caller in a system: what it answers is
    /// thrown away, since only whether it throws matters here.
    type private Call =
        {
            /// The name the function's refusals give it.
            Name : string
            Requirement : CallerRequirement
            Make : Caller<int> -> UnixSystem<int, string> -> unit
        }

    /// One call of each public function of the families that take a caller:
    /// the descriptor and pipe calls on the standard streams, which every
    /// flavour gives as pipes, and the path calls on the root directory, so
    /// that a call's `dirfd` is never looked up.
    let private calls : Call list =
        let root = PathArg.ofText "/"

        let running (name : string) (make : Caller<int> -> UnixSystem<int, string> -> unit) : Call =
            {
                Name = name
                Requirement = CallerRequirement.Running
                Make = make
            }

        [
            running
                "UnixDescriptor.effectiveUserId"
                (fun caller system -> UnixDescriptor.effectiveUserId caller system |> ignore<UserId>)
            running
                "UnixDescriptor.effectiveGroupId"
                (fun caller system -> UnixDescriptor.effectiveGroupId caller system |> ignore<GroupId>)
            running
                "UnixDescriptor.getgroups"
                (fun caller system ->
                    UnixDescriptor.getgroups caller UserBuffer.Mapped 0 system
                    |> ignore<GetGroupsAnswer>
                )
            running "UnixDescriptor.dup" (fun caller system -> UnixDescriptor.dup caller 0 system |> ignore)
            running "UnixDescriptor.dup2" (fun caller system -> UnixDescriptor.dup2 caller 0 5 system |> ignore)
            running "UnixDescriptor.dup3" (fun caller system -> UnixDescriptor.dup3 caller 0 5 0 system |> ignore)
            running
                "UnixDescriptor.fcntl"
                (fun caller system -> UnixDescriptor.fcntl caller 0 FcntlNumbering.GetStatusFlags 0 system |> ignore)
            running
                "UnixDescriptor.setNonBlocking"
                (fun caller system -> UnixDescriptor.setNonBlocking caller 0 true system |> ignore)
            running
                "UnixDescriptor.isNonBlocking"
                (fun caller system -> UnixDescriptor.isNonBlocking caller 0 system |> ignore<bool option>)
            running "UnixDescriptor.lseek" (fun caller system -> UnixDescriptor.lseek caller 0 0L 0 system |> ignore)
            // LOCK_SH, which a pipe end takes at once on Linux.
            running "UnixDescriptor.flock" (fun caller system -> UnixDescriptor.flock caller 0 1 system |> ignore)
            running
                "UnixDescriptor.ftruncate"
                (fun caller system -> UnixDescriptor.ftruncate caller 0 0L system |> ignore)
            running
                "UnixDescriptor.posixFadvise"
                (fun caller system -> UnixDescriptor.posixFadvise caller 0 0L 0L 0 system |> ignore<FileAdviceAnswer>)
            running "UnixDescriptor.close" (fun caller system -> UnixDescriptor.close caller 0 system |> ignore)
            running
                "UnixDescriptor.bytesAvailable"
                (fun caller system ->
                    UnixDescriptor.bytesAvailable caller 0 UserBuffer.Mapped system
                    |> ignore<BytesAvailableAnswer>
                )
            running
                "UnixDescriptor.fileClone"
                (fun caller system -> UnixDescriptor.fileClone caller 0 1 system |> ignore<UnixError>)
            running
                "UnixDescriptor.terminalAttributes"
                (fun caller system ->
                    UnixDescriptor.terminalAttributes caller 0 system
                    |> ignore<TerminalAttributesAnswer>
                )
            running "UnixPipe.pipe2" (fun caller system -> UnixPipe.pipe2 caller 0 UserBuffer.Mapped system |> ignore)
            running
                "UnixPathResolution.stat"
                (fun caller system ->
                    UnixPathResolution.stat caller SymlinkPolicy.Follow root system
                    |> ignore<FileStatusAnswer>
                )
            running
                "UnixPathResolution.fstat"
                (fun caller system -> UnixPathResolution.fstat caller 0 system |> ignore<FileStatusAnswer>)
            running
                "UnixPathResolution.fstatat"
                (fun caller system -> UnixPathResolution.fstatat caller 0 root 0 system |> ignore<FileStatusAnswer>)
            running
                "UnixPathResolution.chmod"
                (fun caller system -> UnixPathResolution.chmod caller root 0o755 system |> ignore)
            running
                "UnixPathResolution.fchmod"
                (fun caller system -> UnixPathResolution.fchmod caller 0 0o600 system |> ignore)
            running
                "UnixPathResolution.fchmodat"
                (fun caller system -> UnixPathResolution.fchmodat caller 0 root 0o755 0 system |> ignore)
            running
                "UnixPathResolution.chown"
                (fun caller system -> UnixPathResolution.chown caller root None None system |> ignore)
            running
                "UnixPathResolution.lchown"
                (fun caller system -> UnixPathResolution.lchown caller root None None system |> ignore)
            running
                "UnixPathResolution.fchown"
                (fun caller system -> UnixPathResolution.fchown caller 0 None None system |> ignore)
            running
                "UnixPathResolution.fchownat"
                (fun caller system -> UnixPathResolution.fchownat caller 0 root None None 0 system |> ignore)
            running
                "UnixPathResolution.utimensat"
                (fun caller system ->
                    UnixPathResolution.utimensat
                        caller
                        0
                        (NullablePathArgument.NotNull root)
                        TimesArgument.Null
                        0
                        system
                    |> ignore
                )
            running
                "UnixPathResolution.statfs"
                (fun caller system ->
                    UnixPathResolution.statfs caller root system
                    |> ignore<FileSystemStatisticsAnswer>
                )
            running
                "UnixPathResolution.fstatfs"
                (fun caller system -> UnixPathResolution.fstatfs caller 0 system |> ignore<FileSystemStatisticsAnswer>)
            running
                "UnixPathResolution.getcwd"
                (fun caller system ->
                    UnixPathResolution.getcwd caller UserBuffer.Mapped 4096UL system
                    |> ignore<GetCwdAnswer>
                )
            running
                "UnixPathResolution.chdir"
                (fun caller system -> UnixPathResolution.chdir caller root system |> ignore)
            // R_OK.
            running
                "UnixPathResolution.access"
                (fun caller system -> UnixPathResolution.access caller 4 system |> ignore)
            running
                "UnixPathResolution.faccessat"
                (fun caller system -> UnixPathResolution.faccessat caller 0 4 0 system |> ignore)
            // Internal: `UnixSystem.step`'s way into `faccessat`.
            running
                "UnixPathResolution.faccessat"
                (fun caller system ->
                    UnixPathResolution.tryFaccessatEager caller 0 root 4 0 system
                    |> ignore<Result<SyscallAnswer, AccessRefusal>>
                )
            running
                "UnixCredentials.getresuid"
                (fun caller system ->
                    UnixCredentials.getresuid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system
                    |> ignore<GetIdsAnswer<UserId>>
                )
            running
                "UnixCredentials.getresgid"
                (fun caller system ->
                    UnixCredentials.getresgid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system
                    |> ignore<GetIdsAnswer<GroupId>>
                )
            running
                "UnixCredentials.setresuid"
                (fun caller system -> UnixCredentials.setresuid caller None None None system |> ignore)
            running
                "UnixCredentials.setresgid"
                (fun caller system -> UnixCredentials.setresgid caller None None None system |> ignore)
            running
                "UnixCredentials.setgroups"
                (fun caller system -> UnixCredentials.setgroups caller 0 (GroupListWords.Readable []) system |> ignore)
            running
                "UnixClock.gettimeofday"
                (fun caller system -> UnixClock.gettimeofday caller system |> ignore<UnixTimestamp>)
            running
                "UnixClock.clockGettime"
                (fun caller system ->
                    UnixClock.clockGettime caller 0 system
                    |> ignore<Result<UnixTimestamp, UnixError>>
                )
            running
                "UnixEntropy.getRandom"
                (fun caller system -> UnixEntropy.getRandom caller UserBuffer.Mapped 8UL 0u system |> ignore)
            running
                "UnixEntropy.getEntropy"
                (fun caller system -> UnixEntropy.getEntropy caller UserBuffer.Mapped 8UL system |> ignore)
            {
                Name = "UnixDescriptor.flockAcquire"
                Requirement = CallerRequirement.Woken
                Make = fun caller system -> UnixDescriptor.flockAcquire caller system |> ignore
            }
        ]

    /// What each requirement refuses, by the thread the caller names: what the
    /// message says.
    [<RequireQualifiedAccess>]
    type private Refused =
        | OtherProcess
        | Absent
        | Parked
        | Unparked

    let private reason (refused : Refused) : string =
        match refused with
        | Refused.OtherProcess -> "but the system holds process"
        | Refused.Absent -> "is not one of the process's threads"
        | Refused.Parked -> "and is making another call"
        | Refused.Unparked -> "is not parked, so there is no call to finish"

    /// A machine of `platform` holding two processes, each with threads 0 to 4,
    /// and the view of the first, in which thread 2 is parked in an `flock` of
    /// a pipe it made (so that `flockAcquire` admits it) and thread 1 in a
    /// `sigsuspend`; and the IDs of the two processes.
    let private world (platform : SimulatedUnixPlatform) : ProcessId * ProcessId * UnixSystem<int, string> =
        let pids, machine = Machines.ofCount platform 2
        let own, other = pids.[0], pids.[1]
        let view = Machines.viewOf own machine

        let view =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin ->
                // Darwin refuses an `flock` of a pipe, so its waiter is parked
                // as the library would park it.
                UnixWait.park
                    2
                    (ParkedSyscall.Flock
                        {
                            ParkedFlock.Requester =
                                FileDescriptorRegistry.tryFindId 0 (Proc.fileDescriptors own view) |> Option.get
                            Mode = FlockMode.Exclusive
                        })
                    view
            | SimulatedUnixFlavour.Linux ->
                // Both ends of a pipe are one object to `flock`, so the write
                // end's lock waits on the read end's.
                let reader, writer, view =
                    match UnixPipe.pipe2 (Caller.make own 0) 0 UserBuffer.Mapped view with
                    | Pipe2Answer.Created (reader, writer), view -> reader, writer, view
                    | other, _ -> failwith $"pipe2: %A{other}"

                let lockExclusive = 2

                match UnixDescriptor.flock (Caller.make own 0) reader lockExclusive view with
                | SyscallOutcome.Answered (SyscallAnswer.Completed 0L), view ->
                    match UnixDescriptor.flock (Caller.make own 2) writer lockExclusive view with
                    | SyscallOutcome.WouldBlock _, view -> view
                    | other -> failwith $"the second flock: expected it to sleep, got %A{other}"
                | other -> failwith $"the first flock: %A{other}"

        own, other, UnixWait.park 1 ParkedSyscall.SigSuspend view

    /// Every public function of the families that take a caller refuses each
    /// caller its requirement refuses, with `InvalidOperationException` naming
    /// it and saying why, before it does anything else, so even where the
    /// flavour would refuse the call itself (`dup3` on Darwin); and does not
    /// refuse the caller its requirement admits.
    [<Test>]
    let ``every function of a family that takes a caller checks it first`` () : unit =
        let mismatches =
            [
                for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
                    let own, other, view = world platform

                    for call in calls do
                        let cases : (Caller<int> * Refused option) list =
                            match call.Requirement with
                            | CallerRequirement.Running ->
                                [
                                    Caller.make own 0, None
                                    Caller.make other 0, Some Refused.OtherProcess
                                    Caller.make own 7, Some Refused.Absent
                                    Caller.make own 1, Some Refused.Parked
                                ]
                            | CallerRequirement.Woken ->
                                [
                                    Caller.make own 2, None
                                    Caller.make other 2, Some Refused.OtherProcess
                                    Caller.make own 7, Some Refused.Absent
                                    Caller.make own 0, Some Refused.Unparked
                                ]
                            | CallerRequirement.Returning
                            | CallerRequirement.Exists -> failwith $"%s{call.Name}: no case for %A{call.Requirement}"

                        for caller, expected in cases do
                            let case = $"%O{platform}, %s{call.Name} by %O{caller}"

                            let thrown =
                                try
                                    call.Make caller view
                                    None
                                with e ->
                                    Some e

                            match expected, thrown with
                            | None, Some (:? InvalidOperationException as e) ->
                                yield $"%s{case}: expected admission, refused: %s{e.Message}"
                            | None, _ -> ()
                            | Some refused, Some (:? InvalidOperationException as e) ->
                                if
                                    not (e.Message.StartsWith $"%s{call.Name}: " && e.Message.Contains (reason refused))
                                then
                                    yield
                                        $"%s{case}: refused, but the message does not name the function and say %s{reason refused}: %s{e.Message}"
                            | Some refused, Some e ->
                                yield
                                    $"%s{case}: expected InvalidOperationException (%A{refused}), threw %s{e.GetType().Name}: %s{e.Message}"
                            | Some refused, None -> yield $"%s{case}: expected refusal (%A{refused}), was admitted"
            ]

        mismatches |> shouldEqual []
