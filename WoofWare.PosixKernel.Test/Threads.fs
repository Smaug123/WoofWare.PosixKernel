namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Threads for a test that needs more than a process's leader.
[<RequireQualifiedAccess>]
module Threads =

    /// `child`, created by the process's leader on processor 0, failing the test if
    /// the creation is refused.
    let spawn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (child : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        match UnixThreadLifecycle.trySpawn (Lone.leader system) child (CpuId 0) system with
        | Ok (SpawnAnswer.Spawned _, system) -> system
        | Ok (SpawnAnswer.Failed error, _) -> failwith $"spawning %O{child} failed with %O{error}"
        | Error refusal -> failwith $"spawning %O{child} was refused: %s{SpawnRefusal.describe refusal}"

    /// `system` with a thread `name`: itself if `name` is already a thread, and
    /// otherwise with `name` spawned by the leader.
    let ensure<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (name : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        if Map.containsKey name (Lone.threads system) then
            system
        else
            spawn name system
