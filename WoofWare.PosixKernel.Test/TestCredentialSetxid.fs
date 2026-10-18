namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixCredentials.setresuid`, `setresgid` and `setgroups` are the C library's
/// functions, which change every thread. Under Linux, glibc's reach the other
/// threads by sending each signal 33, which ends or restarts a call the thread
/// is asleep in as a caught `SA_RESTART` signal does, and with which the
/// wrapper never returns while a thread blocks it
/// (`docs/probes/setxid-threads`, replayed by `TestCredentialThreadsMeasured`).
/// This library does not model that signal, so it refuses those cases.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCredentialSetxid =

    let private context : string = "TestCredentialSetxid"

    let private uid (raw : uint32) : UserId = UserId.parseOrFail context raw
    let private gid (raw : uint32) : GroupId = GroupId.parseOrFail context raw

    /// What a thread other than the caller is doing when the caller changes
    /// the process's credentials.
    type private Other =
        /// Running its own code.
        | Running
        /// Asleep in `pause`.
        | Paused
        /// Asleep in a `poll` of nothing with a timeout.
        | Polling
        /// Owing a return to user mode, for a caught signal deliverable to it.
        | OwesReturn
        /// Running, and blocking signal 33 (Linux only).
        | BlocksSignal33
        /// Running, and blocking `SIGUSR2`.
        | BlocksAnother

    /// Linux's `SIGUSR1` and `SIGUSR2`, and Darwin's.
    let private user1 (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 10
        | SimulatedUnixFlavour.Darwin -> 30

    let private user2 (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 12
        | SimulatedUnixFlavour.Darwin -> 31

    type private Request =
        | SetResUid of uint32 option list
        | SetResGid of uint32 option list
        | SetGroups of uint32 list

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform =
        match flavour with
        | SimulatedUnixFlavour.Linux -> SimulatedUnixPlatform.linuxX64
        | SimulatedUnixFlavour.Darwin -> SimulatedUnixPlatform.macOsArm64

    /// A process with `credentials` whose leader, thread 0, has caught `SIGUSR1`,
    /// and with one more thread for each of `others`, numbered from 1, each
    /// doing what it names.
    let private systemWith
        (flavour : SimulatedUnixFlavour)
        (credentials : Credentials)
        (others : Other list)
        : UnixSystem<int, string>
        =
        let booted =
            UnixSystem.initial<int, string> (platformOf flavour)
            |> Launched.bootWith
                (Launched.credentials credentials
                 >> ProcessLaunch.withCoreDumps CoreDumps.Suppressed)
                UnixSystem.pipedStandardStreams
                0
                (CpuId 0)

        let caught =
            match
                UnixSignal.sigaction
                    (Callers.leader booted)
                    (user1 flavour)
                    (Some (SignalDisposition.Catch (SignalCatch.ofHandler "h")))
                    booted
            with
            | Ok (_, system) -> system
            | Error error -> failwith $"sigaction: %O{error}"

        let numbering =
            match flavour with
            | SimulatedUnixFlavour.Linux -> SignalNumbering.Linux
            | SimulatedUnixFlavour.Darwin -> SignalNumbering.Darwin

        let block (thread : int) (signal : Signal) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let mask = SignalMask.ofSignals numbering (Set.singleton signal)

            match
                UnixSignal.rtSigprocmask (Callers.thread thread system) (MaskHow.block numbering) (Some mask) 8UL system
            with
            | Ok (_, system) -> system
            | Error error -> failwith $"rt_sigprocmask: %O{error}"

        let blockUser2 (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let mask = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR2)

            match
                UnixSignal.pthreadSigmask (Callers.thread thread system) (MaskHow.block numbering) (Some mask) system
            with
            | Ok (_, system) -> system
            | Error error -> failwith $"pthread_sigmask: %O{error}"

        ((caught, 1), others)
        ||> List.fold (fun (system, thread) other ->
            let system = Threads.spawn thread system
            let caller = Callers.thread thread system

            let system =
                match other with
                | Other.Running -> system
                | Other.Paused ->
                    match UnixSignal.pause caller system with
                    | SigsuspendOutcome.WouldBlock _, system -> system
                    | outcome, _ -> failwith $"pause: %A{outcome}"
                | Other.Polling ->
                    match UnixPoll.poll caller [] 1000 system with
                    | PollOutcome.WouldBlock _, system -> system
                    | outcome, _ -> failwith $"poll: %A{outcome}"
                | Other.OwesReturn ->
                    match UnixSignal.pthreadKill (Callers.leader system) thread (user1 flavour) system with
                    | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
                    | other -> failwith $"pthread_kill: %A{other}"
                | Other.BlocksSignal33 -> block thread (Signal.RealTime 1) system
                | Other.BlocksAnother -> blockUser2 thread system

            match other with
            | Other.OwesReturn -> UnixSignal.owesReturn caller system |> shouldEqual true
            | _ -> ()

            system, thread + 1
        )
        |> fst

    /// The call `request` names, made by the leader, with a refusal as the
    /// C library's signal's refusal if it is one, and otherwise described.
    let private make
        (request : Request)
        (system : UnixSystem<int, string>)
        : Result<SyscallAnswer * UnixSystem<int, string>, Choice<SetxidSignalRefusal, string>>
        =
        let caller = Callers.leader system

        let setIdsRefusal (refusal : SetIdsRefusal) : Choice<SetxidSignalRefusal, string> =
            match refusal with
            | SetIdsRefusal.SetxidSignal refusal -> Choice1Of2 refusal
            | other -> Choice2Of2 (SetIdsRefusal.describe other)

        match request with
        | Request.SetResUid ids ->
            UnixCredentials.trySetresuid
                caller
                (Option.map uid ids.[0])
                (Option.map uid ids.[1])
                (Option.map uid ids.[2])
                system
            |> Result.mapError setIdsRefusal
        | Request.SetResGid ids ->
            UnixCredentials.trySetresgid
                caller
                (Option.map gid ids.[0])
                (Option.map gid ids.[1])
                (Option.map gid ids.[2])
                system
            |> Result.mapError setIdsRefusal
        | Request.SetGroups groups ->
            UnixCredentials.trySetgroups caller (List.length groups) (GroupListWords.Readable groups) system
            |> Result.mapError (fun refusal ->
                match refusal with
                | SetGroupsRefusal.SetxidSignal refusal -> Choice1Of2 refusal
                | other -> Choice2Of2 (SetGroupsRefusal.describe other)
            )

    let private small : Gen<uint32> = Gen.elements [ 0u ; 1u ; 1000u ]

    let private credentialsGen : Gen<Credentials> =
        gen {
            let! ids = Gen.listOfLength 6 small
            let! groups = Gen.listOf small

            return
                {
                    RealUser = uid ids.[0]
                    EffectiveUser = uid ids.[1]
                    SavedUser = uid ids.[2]
                    RealGroup = gid ids.[3]
                    EffectiveGroup = gid ids.[4]
                    SavedGroup = gid ids.[5]
                    SupplementaryGroups = groups |> List.map gid
                }
        }

    let private requestGen : Gen<Request> =
        Gen.oneof
            [
                Gen.listOfLength 3 (Gen.optionOf small) |> Gen.map Request.SetResUid
                Gen.listOfLength 3 (Gen.optionOf small) |> Gen.map Request.SetResGid
                Gen.listOf small |> Gen.map Request.SetGroups
            ]

    let private othersGen (choices : Other list) : Gen<Other list> =
        Gen.listOf (Gen.elements choices) |> Gen.resize 3

    /// The threads' parks, what each owes, and its mask: what a credential call
    /// must leave as it found it.
    let private threadsOf (system : UnixSystem<int, string>) =
        Lone.threadMap system
        |> Map.map (fun _ state -> UnixThreadState.park state, state.Owes)

    let private masksOf (system : UnixSystem<int, string>) : Map<int, SignalMask> =
        Lone.threadMap system
        |> Map.map (fun thread _ -> SignalState.maskOf thread (Lone.proc system).Signals)

    [<Test>]
    let ``under Linux a credential call is refused while another thread is asleep, owes a return, or blocks signal 33``
        ()
        =
        // The caller's own mask does not matter: glibc signals only the other
        // threads (measured, the "blocked" rows).
        let leaderBlocking (blocks : bool) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            if blocks then
                let mask =
                    SignalMask.ofSignals SignalNumbering.Linux (Set.singleton (Signal.RealTime 1))

                match
                    UnixSignal.rtSigprocmask
                        (Callers.leader system)
                        (MaskHow.block SignalNumbering.Linux)
                        (Some mask)
                        8UL
                        system
                with
                | Ok (_, system) -> system
                | Error error -> failwith $"rt_sigprocmask: %O{error}"
            else
                system

        let property (credentials : Credentials, others : Other list, request : Request, leaderBlocks : bool) : unit =
            let system =
                systemWith SimulatedUnixFlavour.Linux credentials others
                |> leaderBlocking leaderBlocks

            let alone =
                systemWith SimulatedUnixFlavour.Linux credentials []
                |> leaderBlocking leaderBlocks

            let inKernel =
                others
                |> List.exists (fun other ->
                    match other with
                    | Other.Paused
                    | Other.Polling
                    | Other.OwesReturn -> true
                    | Other.Running
                    | Other.BlocksSignal33
                    | Other.BlocksAnother -> false
                )

            let expected =
                if List.contains Other.BlocksSignal33 others then
                    Some SetxidSignalRefusal.OtherThreadBlocksSignal
                elif inKernel then
                    Some SetxidSignalRefusal.OtherThreadInKernel
                else
                    None

            match make request system, make request alone, expected with
            | Error (Choice1Of2 refusal), Ok _, Some expected -> refusal |> shouldEqual expected
            | Ok (answer, after), Ok (aloneAnswer, aloneAfter), None ->
                // Answered as a process of one thread is: the C library's
                // function changes every thread alike.
                answer |> shouldEqual aloneAnswer
                (Lone.proc after).Credentials |> shouldEqual (Lone.proc aloneAfter).Credentials
                threadsOf after |> shouldEqual (threadsOf system)
                masksOf after |> shouldEqual (masksOf system)
            | ours, alone, _ ->
                failwith
                    $"others %A{others}, request %A{request}: answered %A{Result.map fst ours}, and a lone thread %A{Result.map fst alone}"

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 1000,
            Prop.forAll
                (Arb.fromGen (
                    gen {
                        let! credentials = credentialsGen

                        let! others =
                            othersGen
                                [
                                    Other.Running
                                    Other.Paused
                                    Other.Polling
                                    Other.OwesReturn
                                    Other.BlocksSignal33
                                    Other.BlocksAnother
                                ]

                        let! request = requestGen
                        let! leaderBlocks = Gen.elements [ true ; false ]
                        return credentials, others, request, leaderBlocks
                    }
                ))
                property
        )

    [<Test>]
    let ``under Darwin another thread's state never stands in a credential call's way`` () : unit =
        // Darwin's calls change the process and end no other thread's call
        // (measured); this library answers only its unprivileged setgroups.
        let property (user : uint32, group : uint32, others : Other list, groups : uint32 list) : unit =
            let credentials = Credentials.ofIds (uid (1000u + user)) (gid group) []
            let request = Request.SetGroups groups
            let system = systemWith SimulatedUnixFlavour.Darwin credentials others
            let alone = systemWith SimulatedUnixFlavour.Darwin credentials []

            match make request system, make request alone with
            | Ok (answer, after), Ok (aloneAnswer, _) ->
                answer |> shouldEqual aloneAnswer
                after |> shouldEqual system
            | ours, alone -> failwith $"others %A{others}: answered %A{ours}, and a lone thread %A{alone}"

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 200,
            Prop.forAll
                (Arb.fromGen (
                    gen {
                        let! user = Gen.elements [ 1u ; 2u ]
                        let! group = small

                        let! others =
                            othersGen
                                [
                                    Other.Running
                                    Other.Paused
                                    Other.Polling
                                    Other.OwesReturn
                                    Other.BlocksAnother
                                ]

                        let! groups = Gen.listOf small
                        return user, group, others, groups
                    }
                ))
                property
        )
