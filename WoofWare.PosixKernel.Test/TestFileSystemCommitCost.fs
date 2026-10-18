namespace WoofWare.PosixKernel.Test

open System
open NUnit.Framework
open WoofWare.PosixKernel

/// A change of names (`mkdir`, `unlink`, `rmdir`, `rename`) costs time
/// independent of how many processes, open file descriptions and inotify
/// watches the rest of the machine holds: finding the watches on what it
/// changed, the descriptions opened through the names it removed or moved,
/// and whether anything still holds what it unlinked, must not walk every
/// description on the machine. Measured by the bytes a call allocates, which
/// unlike time do not move with the host's load: a call on a machine of four
/// times the processes may allocate a little more, for the deeper maps it
/// looks things up in, and one that visits every description about four
/// times as much.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFileSystemCommitCost =

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    let private launch (platform : SimulatedUnixPlatform) : ProcessLaunch<int> =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private flavourOf (system : UnixSystem<int, unit>) : SimulatedUnixFlavour =
        SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

    /// `caller` opens `path` for reading and writing, creating it, and keeps
    /// the descriptor.
    let private create
        (caller : Caller<int>)
        (path : string)
        (system : UnixSystem<int, unit>)
        : int * UnixSystem<int, unit>
        =
        let flavour = flavourOf system

        // `O_RDWR | O_CREAT`.
        let flags =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 0x2 ||| 0x40
            | SimulatedUnixFlavour.Darwin -> 0x2 ||| 0x200

        match UnixNamespace.openat caller (AtDirectory.atFdCwd flavour) (PathArg.ofText path) flags 0o644 system with
        | SyscallOutcome.Answered (SyscallAnswer.Completed fd), system -> int fd, resume caller system
        | outcome, _ -> failwith $"expected the open of %s{path} to succeed: %A{outcome}"

    let private close (caller : Caller<int>) (fd : int) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixDescriptor.close caller fd system with
        | SyscallAnswer.Completed 0L, system -> resume caller system
        | outcome, _ -> failwith $"expected the close of fd %d{fd} to succeed: %A{outcome}"

    /// `caller` makes the file `path`, and keeps no descriptor of it.
    let private touch (caller : Caller<int>) (path : string) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        let fd, system = create caller path system
        close caller fd system

    /// `caller` makes an inotify instance (Linux), and answers its descriptor.
    let private inotify (caller : Caller<int>) (system : UnixSystem<int, unit>) : int * UnixSystem<int, unit> =
        match UnixInotify.inotifyInit1 caller 0 system with
        | Ok (fd, system) -> fd, resume caller system
        | Error error -> failwith $"expected inotify_init1 to make an instance: %O{error}"

    /// `caller`'s instance `fd` watches `path` for `IN_MODIFY | IN_ATTRIB |
    /// IN_DELETE_SELF`.
    let private watch
        (caller : Caller<int>)
        (fd : int)
        (path : string)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        match Eager.tryInotifyAddWatchAs caller fd (PathArg.ofText path) (0x2u ||| 0x4u ||| 0x400u) system with
        | Ok (SyscallAnswer.Completed _, system) -> resume caller system
        | other -> failwith $"expected inotify_add_watch of %s{path} to succeed: %A{other}"

    /// What each process on the machine holds besides its standard streams;
    /// the process that changes the names holds it too.
    type private Holding =
        /// Nothing.
        | Nothing
        /// A file of its own, open through its own name.
        | OpenFile
        /// An inotify instance watching a file of its own (Linux).
        | Watch

    /// Gives `caller`'s process what `holding` says, `index` telling its
    /// names apart from every other process's.
    let private hold
        (holding : Holding)
        (index : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        match holding with
        | Holding.Nothing -> system
        | Holding.OpenFile -> create caller $"/held%d{index}" system |> snd
        | Holding.Watch ->
            let path = $"/watched%d{index}"
            let system = touch caller path system
            let fd, system = inotify caller system
            watch caller fd path system

    /// A machine of `platform` before boot, which on Linux lets one user hold
    /// an inotify instance in every process of the largest machine here.
    let private image (platform : SimulatedUnixPlatform) : UnixBootImage<int, unit> =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Darwin -> UnixSystem.initial platform
        | SimulatedUnixFlavour.Linux ->
            UnixSystem.initial platform
            |> UnixBootImage.withInotifyLimits
                { UnixSystem.defaultInotifyLimits with
                    MaxUserInstances = 1000
                }

    /// A machine of `count` processes besides the first, each holding what
    /// `holding` says, and the first holding it too; with the first's
    /// caller. The first has made the file "/u", the file "/r" and the
    /// empty directory "/e", and holds no descriptor of any.
    let private machine
        (platform : SimulatedUnixPlatform)
        (holding : Holding)
        (count : int)
        : UnixSystem<int, unit> * Caller<int>
        =
        let booted = image platform |> UnixBootImage.boot (launch platform)
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let system = hold holding 0 leader booted

        let system =
            (system, [ 1..count ])
            ||> List.fold (fun system index ->
                let pid, system = UnixSystem.launch (launch platform) system
                hold holding index (Caller.make pid 0) system
            )

        let system = touch leader "/u" system |> touch leader "/r"

        let system =
            match UnixNamespace.mkdir leader (PathArg.ofText "/e") 0o755 system with
            | SyscallAnswer.Completed 0L, system -> resume leader system
            | answer, _ -> failwith $"expected mkdir of /e to succeed: %A{answer}"

        let _, system = UnixWait.wake system
        system, leader

    /// The fewest bytes one run of `call` allocates, of several, each run
    /// from `system`.
    let private bytes (call : UnixSystem<int, unit> -> unit) (system : UnixSystem<int, unit>) : int64 =
        let once () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()
            call system
            GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    /// The name change `call` names, made by `caller`.
    let private change (caller : Caller<int>) (call : string) (system : UnixSystem<int, unit>) : unit =
        let answer =
            match call with
            | "mkdir" -> UnixNamespace.mkdir caller (PathArg.ofText "/d") 0o755 system |> fst
            | "unlink" -> UnixNamespace.unlink caller (PathArg.ofText "/u") system |> fst
            | "rmdir" -> UnixNamespace.rmdir caller (PathArg.ofText "/e") system |> fst
            | "rename" ->
                match
                    UnixNamespace.tryRename caller (PathArg.ofText "/r") system
                    |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination (PathArg.ofText "/s"))
                with
                | Ok (answer, _) -> answer
                | Error refusal -> failwith $"expected rename to be answered: %s{RenameRefusal.describe refusal}"
            | call -> failwith $"no call %s{call}"

        match answer with
        | SyscallAnswer.Completed 0L -> ()
        | answer -> failwith $"expected %s{call} to succeed: %A{answer}"

    [<TestCase("linux", "nothing", "mkdir")>]
    [<TestCase("linux", "nothing", "unlink")>]
    [<TestCase("linux", "nothing", "rmdir")>]
    [<TestCase("linux", "nothing", "rename")>]
    [<TestCase("linux", "open", "mkdir")>]
    [<TestCase("linux", "open", "unlink")>]
    [<TestCase("linux", "open", "rmdir")>]
    [<TestCase("linux", "open", "rename")>]
    [<TestCase("linux", "watch", "mkdir")>]
    [<TestCase("linux", "watch", "unlink")>]
    [<TestCase("linux", "watch", "rmdir")>]
    [<TestCase("linux", "watch", "rename")>]
    [<TestCase("darwin", "nothing", "mkdir")>]
    [<TestCase("darwin", "nothing", "unlink")>]
    [<TestCase("darwin", "nothing", "rmdir")>]
    [<TestCase("darwin", "nothing", "rename")>]
    [<TestCase("darwin", "open", "mkdir")>]
    [<TestCase("darwin", "open", "unlink")>]
    [<TestCase("darwin", "open", "rmdir")>]
    [<TestCase("darwin", "open", "rename")>]
    let ``a change of names on a machine of four times the processes allocates about as much``
        (flavour : string)
        (held : string)
        (call : string)
        : unit
        =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | "darwin" -> SimulatedUnixPlatform.macOsArm64
            | flavour -> failwith $"no platform for %s{flavour}"

        let holding =
            match held with
            | "nothing" -> Holding.Nothing
            | "open" -> Holding.OpenFile
            | "watch" -> Holding.Watch
            | held -> failwith $"no holding for %s{held}"

        let measure (count : int) : int64 =
            let system, leader = machine platform holding count
            bytes (change leader call) system

        let fewer = measure 100
        let more = measure 400

        // Lookups in maps four times as large give a ratio a little over 1,
        // and visiting every description about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes a %s{call} beside 100 processes, and %d{more} beside 400: %.2f{ratio} times as much"

    /// The fewest bytes, of several, that `inotify_add_watch` of a new file
    /// allocates, into an instance that watches `count` files already.
    let private addWatchBytes (count : int) : int64 =
        let platform = SimulatedUnixPlatform.linuxX64
        let booted = UnixSystem.initial platform |> UnixBootImage.boot (launch platform)
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let fd, system = inotify leader booted

        let system =
            (system, [ 1..count ])
            ||> List.fold (fun system index ->
                let path = $"/w%d{index}"
                touch leader path system |> watch leader fd path
            )

        let system = touch leader "/new" system

        system
        |> bytes (fun system -> watch leader fd "/new" system |> ignore<UnixSystem<int, unit>>)

    [<Test>]
    let ``a watch added to an instance of four times the watches allocates about as much`` () : unit =
        let fewer = addWatchBytes 100
        let more = addWatchBytes 400

        // Lookups in maps four times as large give a ratio a little over 1,
        // and visiting every watch the instance holds about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes a watch added beside 100 others, and %d{more} beside 400: %.2f{ratio} times as much"
