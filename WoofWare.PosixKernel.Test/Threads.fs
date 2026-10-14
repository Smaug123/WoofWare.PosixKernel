namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Threads for a test that needs more than a process's leader.
[<RequireQualifiedAccess>]
module Threads =

    /// `child`, created by the leader of the process `pid` on processor 0,
    /// failing the test if the creation is refused.
    let spawnIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (child : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        match UnixThreadLifecycle.trySpawn (Caller.make pid (Proc.leader pid system)) child (CpuId 0) system with
        | Ok (SpawnAnswer.Spawned _, system) -> system
        | Ok (SpawnAnswer.Failed error, _) -> failwith $"spawning %O{child} failed with %O{error}"
        | Error refusal -> failwith $"spawning %O{child} was refused: %s{SpawnRefusal.describe refusal}"

    /// `system` with a thread `name` in the process `pid`: itself if `name` is
    /// already one of its threads, and otherwise with `name` spawned by its
    /// leader.
    let ensureIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (name : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        if Map.containsKey name (Proc.threads pid system) then
            system
        else
            spawnIn pid name system

    /// `spawnIn` the only process on the machine.
    let spawn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (child : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        spawnIn (Lone.pid system) child system

    /// `ensureIn` the only process on the machine.
    let ensure<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (name : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        ensureIn (Lone.pid system) name system
