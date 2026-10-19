# WoofWare.PosixKernel

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="logos/dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="logos/light.svg">
  <img alt="Project logo: minimalistic face of a cartoon Shiba Inu, drawn in outline, sitting at the centre of three concentric rings." src="logos/light.svg" width="300">
</picture>

A deterministic, purely functional simulation of a POSIX process.

This library models what a Unix kernel tells a process about the world.
It includes:

* the filesystem, including permissions, with every name a string of bytes exactly as the kernel stores it, never decoded as text
* file descriptors, the open file descriptions they name, and pipes
* sockets and connections, `poll`, Linux's epoll, and Darwin's kqueue
* signals: sending them, their dispositions, each thread's mask, delivery to a handler, and a process ended by one
* the process's threads, and the syscalls they block in
* clock
* entropy

The simulated kernel is a state machine, and each syscall is a pure function from one state to an answer and the next state.
WoofWare.PosixKernel performs no I/O and makes no host reads: all state is simulated.
Two runs from the same starting state see the same world, on any machine, in any order.

## History

This was developed incidentally during the construction of WoofWare.PawPrint,
which (being a deterministic simulation of a .NET runtime) must manufacture the results of e.g. the `open` syscall.
I expect it may be of independent interest, so it is now extracted as a standalone component which knows nothing about the CLR.

It speaks POSIX alone, in each flavour's own numbering wherever a number is involved: an `<errno.h>` error, a signal, an `open(2)` flag word.
Converting those to and from a client's own encoding is the client's business.

### Slop status

100% vibe-coded, by the hand of Claude Opus 4.6 through 5, Claude Fable 5, and GPT-5.5 through 5.6 Sol.

## How a client uses it

A client is whatever runs the process's own code: an emulator trapping `syscall` instructions, a replayer working through an `strace` log, a test harness, or a language runtime intercepting C library calls.
It translates each call the process makes into a call of a function here, and gets back the answer and the kernel's next state.
WoofWare.PosixKernel never calls back into the client.

The rest of this document follows a client through the life of a process: booting a machine, making calls, moving bytes, sleeping and waking, signals, threads, and the end of the process, then several processes on one machine.
After that come the parts of a running process that are the client's rather than the kernel's, and how the simulated platforms relate to real ones.

### The system

The whole kernel is one value, a `UnixSystem<'Thread, 'Handler>`: the machine, and every process on it.

* the machine: the filesystem, the open file descriptions (with the state of each epoll instance, kqueue and inotify instance, and how many descriptors and calls in flight reference each), sockets, connections and pipes, the thread IDs live threads hold, the processes on it and the directories they stand in, the clock, the entropy pool, and the platform being simulated;
* each process: its descriptor table, which says only which open file description each descriptor names, and its credentials, umask, current directory, environment and signal state;
* each process's threads (`UnixThreadState`), and what each is blocked in, if anything. A client looks a thread up in `UnixSystem.threads` of its process by its own name for it, which has no entry for a thread that was never created or has exited, and reads what it finds with `UnixThreadState`'s readers: `UnixThreadState.parkedIn` (the syscall it sleeps in), `UnixThreadState.park` (that syscall, where the park stands in park order, and whether the thread has been woken), `UnixThreadState.cpu` and `UnixThreadState.osThreadId` (what `gettid(2)` answers).

Those records are opaque outside the library.
A query about one process, such as `UnixSystem.threads`, `UnixSystem.signals`, `UnixSystem.credentials` or `UnixSystem.fileDescriptors`, takes the process's ID first, and throws `InvalidOperationException` for a process the system does not hold; one about a thread, such as `UnixWait.satisfied`, `UnixScheduling.runningOn` or `UnixSignal.owesReturn`, takes a `Caller` naming the thread (see "Making a call").
A client reads a system through `UnixSystem`'s queries, such as `UnixSystem.processIds`, `UnixSystem.leader`, `UnixSystem.threads`, `UnixSystem.signals`, `UnixSystem.credentials`, `UnixSystem.fileDescriptors`, `UnixSystem.openFiles` and `UnixSystem.descriptorTarget`, and changes a running one only through the syscalls and the two operations of the outside world described under "When time passes".
`UnixSystem.descriptorTarget` answers what a descriptor's description refers to, an `OpenFileTarget`, of which `OpenFileTarget.Fifo` (a FIFO's inode and an opaque `FifoAttachment`) is reserved: nothing opens a FIFO yet, `UnixSystem.checkInvariants` reports a description naming one as a defect, and the case exists so that a client's matches already handle it when FIFOs arrive.
`OpenFileTarget.CharacterDevice` carries, besides the device and its node, an opaque `CharacterDeviceState`: the description's own state, which holds nothing in this version, because Linux keeps no position for a device and Darwin's devices, which keep one per description, are refused.

`'Thread` is whatever the client calls a thread, and `'Handler` whatever it calls a signal handler.
The library never looks inside either; it only compares them.

### The client's own operations

Besides the syscalls, a client calls these between them (the system argument is left out, as in the tables under "The syscalls"):

| Operation | Function | Answers |
| --- | --- | --- |
| the processes the system holds | `UnixSystem.processIds` | `Set<ProcessId>` |
| a process's threads, by the client's name for each | `UnixSystem.threads (pid : ProcessId)` | `Map<'Thread, UnixThreadState>` |
| which syscall a thread sleeps in | `UnixThreadState.parkedIn (thread : UnixThreadState)` | `ParkedSyscall option` |
| the platform, and its flavour | `UnixSystem.platform` | `SimulatedUnixPlatform` |
| the time since boot | `UnixSystem.nanosecondsSinceBoot` | `int64` |
| time passing | `UnixSystem.advanceClock (nanoseconds : int64)` | `UnixSystem` |
| waking the sleeping threads that can go on | `UnixWait.wake` | `(Caller * Set<WakePrimitive>) list * UnixSystem` |
| whether one sleeping thread could go on | `UnixWait.satisfied (caller : Caller)` | `Set<WakePrimitive> option` |
| finishing a woken thread's call | `UnixWait.finish (caller : Caller)` | `FinishedCall` |
| whether a thread owes a return to user mode | `UnixSignal.owesReturn (caller : Caller)` | `bool` |
| when sleeping calls time out | `UnixWait.deadlines` | `int64 list` |
| another process starting | `UnixSystem.launch (launch : ProcessLaunch)` | `ProcessId * UnixSystem` |
| every way the tables disagree | `UnixSystem.checkInvariants` | `UnixSystemDefect list` |

`SimulatedUnixPlatform.flavour` of a platform is its `SimulatedUnixFlavour`, `SimulatedUnixFlavour.Linux` or `SimulatedUnixFlavour.Darwin`, which decides how a raw number is read.
In prose, as in the tables, a type's `'Thread` and `'Handler` arguments are left out: `PausedWrite` is `PausedWrite<'Thread, 'Handler>`.

## Booting a machine

`UnixSystem.initial` builds the *boot image* of a machine of the given `SimulatedUnixPlatform` that has not done anything yet: a `UnixBootImage`, which no syscall takes.
Configure it with the setters in the `UnixBootImage` module, such as `UnixBootImage.withFileSystem`, `UnixBootImage.withMount`, `UnixBootImage.withBootTime`, `UnixBootImage.withProcessorCount` and `UnixBootImage.withProcessId` (the first process's ID, where the machine's counters start).
Sysctls are configuration too: `UnixBootImage.withInotifyLimits` sets Linux's `fs.inotify` limits (`InotifyLimits`), which default to `UnixSystem.defaultInotifyLimits` (128 instances and 8192 watches per user, 16384 records per instance).
`UnixBootImage.withUnprivilegedPortStart` sets Linux's `net.ipv4.ip_unprivileged_port_start`, the lowest port a process without privilege may bind, which defaults to `UnixSystem.defaultUnprivilegedPortStart` (1024, where Darwin's privileged ports always end); and `UnixBootImage.withEphemeralPortRange` sets the range `bind` of port 0 draws from. Linux's sysctls keep the range at or above the unprivileged port start, so `UnixBootImage.boot` refuses a Linux image whose range starts below it, whichever setter ran first. Darwin's keep both ends within 1024 to 65535, so the setter refuses a Darwin range that starts below 1024; Darwin also takes a low end above the high end and searches downwards, which the setter refuses as unmodelled.
Since no setter takes a booted system, configuration can only describe the machine from the moment it booted.

How a process starts is a `ProcessLaunch`.
`ProcessLaunch.create (platform : SimulatedUnixPlatform) (streams : Map<int, LaunchDescriptor>) (leader : 'Thread) (leaderCpu : CpuId)` takes the descriptors it is launched with, its first thread's name and the processor that thread starts on.
`UnixSystem.pipedStandardStreams` gives descriptors 0, 1 and 2 as pipes: 0 reads a pipe whose far end supplied nothing, and 1 and 2 write to pipes the client drains (see "The far end of a launched pipe").
The setters in the `ProcessLaunch` module set the rest, such as `ProcessLaunch.withCredentials`, `ProcessLaunch.withCurrentDirectory`, `ProcessLaunch.withEnvironment` and `ProcessLaunch.withUmask`.
`UnixBootImage.boot launch` launches the machine's first process, to give the `UnixSystem` its first syscall takes.

A process's leader starts blocking no signal; a client launching one whose parent left signals blocked sets that mask with `UnixSignal.pthreadSigmask` before the leader's first instruction, as it installs inherited ignores with `UnixSignal.sigaction`.

```fsharp
open WoofWare.PosixKernel

let path (text : string) : PathArgumentBytes =
    match UnixByteString.ofString text with
    | Ok bytes -> PathArgumentBytes.Bytes bytes
    | Error defect -> failwith $"not a path: %O{defect}"

// A process on a Linux x86-64 machine, before anything has happened to it:
// a filesystem holding nothing but /dev, and descriptors 0, 1 and 2 as pipes. It has one thread,
// which this client names 0, on logical processor 0, and runs as root.
let system : UnixSystem<int, unit> =
    let launch =
        ProcessLaunch.create SimulatedUnixPlatform.linuxX64 UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> ProcessLaunch.withCredentials (Credentials.ofIds UserId.root (GroupId.parseOrFail "example" 0u) [])

    UnixSystem.initial SimulatedUnixPlatform.linuxX64 |> UnixBootImage.boot launch

// mkdir(2) is mkdirat(2) from AT_FDCWD, in the flavour's own numbering.
let atFdCwd : int = AtDirectory.atFdCwd SimulatedUnixFlavour.Linux

// Thread 0 of the process, its leader, makes each call.
let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds system)) 0

let mkdir (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
    match UnixSystem.step leader (Syscall.MkDirAt (atFdCwd, path "/tmp", 0o755)) system with
    | SteppedCall.MkDirAt (SyscallAnswer.Completed result, system) ->
        printfn "mkdir returned %d" result
        system
    | SteppedCall.MkDirAt (SyscallAnswer.Failed error, system) ->
        let numbering = SimulatedUnixPlatform.rawErrnoNumbering (UnixSystem.platform system)
        printfn "mkdir failed with errno %d" (UnixError.toRawErrnoUnder numbering error)
        system
    | _ -> failwith "step answers a Syscall.MkDirAt as a SteppedCall.MkDirAt"

system |> mkdir |> mkdir |> ignore

// Prints:
// mkdir returned 0
// mkdir failed with errno 17
```

### Giving the machine files

A machine boots with an empty filesystem, apart from the device filesystem the kernel mounts over `/dev` (see "Flavours and divergence from host platforms").
`UnixBootImage.withFileSystem (createdAt : UnixTimestamp) (defaultOwner : InodeOwner) (seed : Map<DirectoryEntryName, SeedEntry>)` replaces it with the tree `seed` describes, created at `createdAt`.
A `SeedEntry` is a file, a directory or a symbolic link, each with an optional owner: an entry that names none belongs to `defaultOwner`, and so does the root.
`SeedEntry.file` and `SeedEntry.directory` give the modes a `umask 022` process would have created; the `SeedEntry.File` and `SeedEntry.Directory` cases take a mode and an owner of their own.
It throws `ArgumentException` for a name the flavour could never have created, for a symbolic link whose target is longer than the flavour's `symlink(2)` stores (1023 bytes on Darwin, 4095 on Linux, whatever the filesystem's type), and for anything at `/dev` but an empty directory.
On Darwin it throws `UnmodelledException` for a directory holding two names that might be spellings of one name (see "Names in the filesystem").

The filesystem's type is what `fstatfs(2)` reports for a file, and it changes a directory's `st_size`, every file's `st_blksize` and `st_blocks`, and where `lseek(2)` with `SEEK_END` lands on a directory.
`FileStatus` states each of those two as `None` where nothing in the machine determines it: both on NFS, where they are the mount's and the server's, and the `st_blocks` of an APFS regular file holding any bytes, which APFS allocates as it writes the file back, by when and how quickly the writes came. A client filling a `struct stat` chooses what to report for `None`.
It is tmpfs on Linux and APFS on Darwin unless `UnixBootImage.withMount` says otherwise: `Some (EmulatedMount.defaultOf EmulatedFileSystemType.Nfs)`, for example, or `EmulatedMount.Tmpfs` and `EmulatedMount.Apfs` with their fields set.
A type the flavour could not report is refused: on Linux, which has no APFS, with `ArgumentException`, and on Darwin, where a tmpfs has not been measured, with `UnmodelledException`.
Path resolution keeps its flavour's limits whichever type is chosen.

Whether a read moves an access time is a mount option, and each type is mounted with one, which `statfs(2)` reports.
The Linux tmpfs is mounted `noatime`, so only `utimensat(2)` moves an access time there.
The Darwin APFS volume has APFS's default options: a `read(2)` or `pread(2)` of at least one byte from a file, even one that answers 0 at end-of-file or `EFAULT`, and a directory read that yields an entry, move the access time to now when it is before the modification time, and nothing else moves it (`readlink(2)` and a path through a symbolic link included).
On NFS no read moves it, which is unmeasured: an NFS file's times are the server's.

```fsharp
open System.Collections.Immutable
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64
let name (text : string) : DirectoryEntryName = DirectoryEntryName.parseOrFail "seed" text

// /etc/hostname holding "sim\n", and a world-writable sticky /tmp. An entry
// that names no owner belongs to the owner withFileSystem is given: root.
let seed : Map<DirectoryEntryName, SeedEntry> =
    Map.ofList
        [
            name "etc", SeedEntry.directory (Map.ofList [ (name "hostname", SeedEntry.file (ImmutableArray.Create<byte> "sim\n"B)) ])
            name "tmp", SeedEntry.Directory (Map.empty, PermissionBits.parseOrFail "seed" 0o1777, None)
        ]

let root : InodeOwner = InodeOwner.ofProcess (Credentials.ofIds UserId.root (GroupId.parseOrFail "seed" 0u) [])

let system : UnixSystem<int, unit> =
    let launch =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial platform
    |> UnixBootImage.withFileSystem UnixTimestamp.epoch root seed
    // fstatfs(2) reports NFS rather than Linux's default, tmpfs.
    |> UnixBootImage.withMount (Some (EmulatedMount.defaultOf EmulatedFileSystemType.Nfs))
    |> UnixBootImage.boot launch

let path (text : string) : PathArgumentBytes =
    match UnixByteString.ofString text with
    | Ok bytes -> PathArgumentBytes.Bytes bytes
    | Error defect -> failwith $"not a path: %O{defect}"

// Thread 0, the process's leader, calls open("/etc/hostname", O_RDONLY), and read(fd, buf, 64).
// O_RDONLY is 0 on every flavour.
let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds system)) 0

match UnixNamespace.openPath leader (path "/etc/hostname") 0 0 system with
| OpenOutcome.Answered (DescriptorAnswer.Returned fd), system ->
    match UnixReadWrite.read leader fd UserBuffer.Mapped 64UL system with
    | ReadOutcome.Answered (ReadAnswer.Completed bytes), _ ->
        printf "%s" (System.Text.Encoding.ASCII.GetString (bytes.AsSpan ()))
    | outcome, _ -> failwith $"unexpected read: %A{outcome}"
| outcome, _ -> failwith $"unexpected open: %A{outcome}"

// Prints:
// sim
```

## Making a call

Each syscall is a function in the module for its family, listed under "The syscalls" below.
It takes its arguments as the kernel does, raw where the kernel validates them (a descriptor, a flag word, a mode, a `whence`, in the flavour's own numbering), and the system last.
It gives back its answer with the system as the call left it, or the answer alone for a call that cannot change anything.

A `Caller` names the thread making a call: `Caller.make (pid : ProcessId) (thread : 'Thread)` is the thread the client calls `thread` in the process whose ID is `pid` (one of `UnixSystem.processIds`), and `Caller.processId` and `Caller.thread` read it back.
A thread's name is its process's own, so two processes may each have a thread the client calls `0`, and their callers differ.
Every syscall takes the caller as its first argument, and so do the return to user mode (`UnixSignal.onReturnToUser`), the client's report of a dispatch (`UnixScheduling.dispatch`) and `UnixSystem.step`.
A function that resumes a call paused to copy from the caller's memory takes the paused call rather than a caller, since the caller was checked as the call began (see "Calls that copy in from the caller's memory"): `UnixPathResolution.accessWithPath`, `UnixNamespace.renameWithDestination`, `UnixNamespace.linkWithDestination`, `UnixNamespace.symlinkWithPath`, `UnixNamespace.cloneFileWithSource`, `UnixNamespace.cloneFileWithDestination`, `UnixInotify.inotifyAddWatchWithPath`, `UnixSocket.bindWithAddress`, `UnixSocket.setsockoptWithValue`, `UnixSocket.getsockoptWithLength`, `UnixConnection.connectWithAddress`, `UnixReadWrite.writeWithBytes`, `UnixReadWrite.sendWithBytes` and `UnixReadWrite.pwriteWithBytes`.

Each of those calls checks its caller before it does anything else.
The caller's process must be one of the system's, and its thread one of that process's threads, parked in no syscall and owing no return to user mode (see "The return to user mode"); `UnixWait.finish` and the finishing functions `UnixDescriptor.flockAcquire`, `UnixConnection.finishAccept`, `UnixPoll.finishPoll`, `UnixPoll.finishEpollWait`, `UnixKqueue.finishKevent`, `UnixReadWrite.finishRead`, `UnixReadWrite.finishWrite` and `UnixSignal.finishSigsuspend` require the thread to be parked instead, in the call they finish, and woken (see "Sleeping and waking").
`UnixSignal.onReturnToUser` requires a thread parked in no syscall, whether or not it owes a return, and `UnixScheduling.dispatch` takes any thread of the process, parked or not.
A call made by any other caller is one no real kernel could receive, so it is a bug in the client, and throws `InvalidOperationException`.

`UnixSignal.pthreadKill`'s second argument, `target`, is the thread the signal is sent to, which need not be the caller.

A call the process made through its C library and one it made as a raw system call are the same call here, except where the two differ.
Where they do, the function says which it is, and the tables below mark it: (3) is the C library's function, and (2) the system call beneath it.

* `UnixSignal.sigaction` is `sigaction(3)`, which on Linux refuses the C library's own signals 32 and 33 before the kernel sees them; `UnixSignal.sigactionSyscall` is the system call (Linux's `rt_sigaction`).
* `UnixSignal.pthreadSigmask`, and on Linux `UnixSignal.sigprocmask`, drop 32 and 33 from a set as the C library does; `UnixSignal.rtSigprocmask` is Linux's `rt_sigprocmask(2)`, which can block them. `UnixSignal.rtSigsuspend` is Linux's `rt_sigsuspend(2)`, which differs from `UnixSignal.sigsuspend` only in taking the set's size.
* `UnixSignal.pthreadKill` is `pthread_kill(3)` and `raise(3)`; the `tgkill(2)` beneath them is not modelled.
* `UnixCredentials.setresuid`, `UnixCredentials.setresgid` and `UnixCredentials.setgroups` are the C library's functions, which change every thread of the process. Under Linux the system calls beneath them change only the calling thread, and are not modelled: glibc makes every other thread repeat the call by sending it signal 33, which ends or restarts a call the thread is asleep in, and with which the C library's function never returns while a thread blocks it. So under Linux each of the three is refused while another thread blocks signal 33, is asleep in a call, or owes a return to user mode, whatever the call would answer.
* `UnixDescriptor.terminalAttributes` is `tcgetattr(3)`, `UnixPathResolution.getcwd` is `getcwd(3)` (a library routine on Darwin), and `UnixDescriptor.posixFadvise` returns its error as `posix_fadvise(3)` does, rather than setting errno.

A client replaying a record of raw system calls, such as an `strace` log, uses the (2) forms.

### Answers, and what this library will not answer

A syscall answers what the kernel does: perhaps an errno (a `UnixError`), or the calling thread asleep (see "Sleeping and waking"). Either way it comes with the system after the call; a failing call can still change the system, just as a real one can.

A call that can end the process answers a `ProcessFate`: `ProcessFate.Continues (outcome, system)`, with the call's own outcome and the system the process carries on as, or `ProcessFate.ProcessEnded (ended, system)`, with how the process ended and the system without it, since the process is gone from the system as it ends (see "Threads, and the end of the process").
Those calls are a write or `send` that raises `SIGPIPE`, `kill` and `pthreadKill`, the return to user mode, and a thread's exit.

A syscall's errno is the `Failed` case of the call's own answer, such as `SyscallAnswer.Failed`, `DescriptorAnswer.Failed` or `ClockGettimeAnswer.Failed`, and never the `Error` of a `Result`.
A failing call comes back with the system wherever a succeeding one does, unchanged where the failure changed nothing.
`pthread_kill(3)`, `pthread_sigmask(3)` and `posix_fadvise(3)` return their error rather than setting errno, and their answers' `Failed` cases say so.
A function that cannot fail, such as `UnixClock.gettimeofday`, answers its value alone.
The errors of the parsers that build a value, such as `UnixByteString.ofString`'s, say what was wrong with the input.

Where this library will not say what the kernel does, the call throws `UnmodelledException`, and the docstrings say the call is refused.
Nobody has measured what a real kernel does there, on the platform being simulated, or the model cannot hold what the answer needs.
That is a feature request for this library, not a condition a client handles in normal operation, and retrying will not help.

* Any call may throw `UnmodelledException`, and a minor version may add or remove the places that do: each newly measured behaviour, such as a difference between Linux and Darwin, can bring a new one, and each newly modelled one removes one.
* Its message is for a human, and has no stable structure. It names the function that threw and says what the library knows about why; it does not know what the client called the value, or which of the client's own entry points made the call, and the client adds those.
* A throw leaves nothing behind. Every value this library takes is immutable, so a client may catch the exception and carry on from the state it passed in.

A call that no client following the documentation could make throws the exception .NET uses for that mistake instead, and its docstring says so: `ArgumentException` or `ArgumentOutOfRangeException` for a value no machine of the flavour could have, such as a boot setter's contradictory setting; `InvalidOperationException` for a call made where the documentation rules it out, such as the exit of a thread parked in a syscall; and `PlatformNotSupportedException` for a call the flavour does not have, such as `epoll_create1` on Darwin, which a client could have checked for first.

```fsharp
open System.Collections.Immutable
open WoofWare.PosixKernel

let system : UnixSystem<int, unit> =
    let launch =
        ProcessLaunch.create SimulatedUnixPlatform.linuxX64 UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial SimulatedUnixPlatform.linuxX64 |> UnixBootImage.boot launch

// Thread 0 of the process, its leader, makes each call.
let caller = Caller.make (Seq.exactlyOne (UnixSystem.processIds system)) 0

// socket(AF_INET, SOCK_STREAM, 0), in Linux's numbering.
let fd, socketSystem =
    match UnixSocket.socket caller 2 1 0 system with
    | DescriptorAnswer.Returned fd, system -> fd, system
    | DescriptorAnswer.Failed error, _ -> failwith $"socket failed with %O{error}"

// Linux's struct sockaddr_in: the family in host order, then the port and the address in network order.
let sockaddr (address : byte[]) : byte[] =
    Array.concat [ [| 2uy ; 0uy ; 0x13uy ; 0x88uy |] ; address ; Array.zeroCreate 8 ]

// bind(fd, &sockaddr, 16): the call stops where the kernel copies the sockaddr in, and
// bindWithAddress takes the bytes copyRange names.
let bind (address : byte[]) (system : UnixSystem<int, unit>) : BindAnswer * UnixSystem<int, unit> =
    match UnixSocket.bind caller fd UserBuffer.Mapped 16u system with
    | CallProgress.Answered answered -> answered
    | CallProgress.NeedsCopyIn paused ->
        let range = PausedBind.copyRange paused
        UnixSocket.bindWithAddress (ImmutableArray.Create (sockaddr address, range.FirstByte, range.ByteCount)) paused

// A bind to the multicast group 224.0.0.1 is not modelled: this library models no group membership.
let multicast =
    try
        Some (bind [| 224uy ; 0uy ; 0uy ; 1uy |] socketSystem)
    with :? UnmodelledException ->
        None

printfn "multicast bind answered: %b" multicast.IsSome

// The throw left socketSystem as it was, so the client carries on from it: bind 127.0.0.1:5000.
match bind [| 127uy ; 0uy ; 0uy ; 1uy |] socketSystem with
| BindAnswer.Bound (SocketAddress.Inet endpoint), _ ->
    printfn "bound %s:%d" (Ipv4Address.toString endpoint.Address) endpoint.Port
| answer, _ -> failwith $"unexpected bind: %A{answer}"

// Prints:
// multicast bind answered: false
// bound 127.0.0.1:5000
```

A few public types whose names end in "Refusal" or "Fault" are values a client holds rather than refusals: `BufferRefusal`, which classifies the client's own buffer; `Ipv4PrefixRefusal` and `SignalMaskRefusal`, the errors of parsers; `DirectorySourceRefusal` and `GetCwdDestinationFault`, flavours' rules; and `BindFault`, one of `bind(2)`'s checks.

The setters of the machine's boot configuration and of a process's launch refuse the same way.
A value this library has not measured or does not model throws `UnmodelledException`; one no machine of the flavour could have throws `ArgumentException` or `ArgumentOutOfRangeException`, naming the parameter.

A call that a real kernel would not let happen at all is a bug in the client, and throws `InvalidOperationException`: a thread making a syscall while it is asleep in another, or while it owes a return to user mode (see "The return to user mode"), the finish of a call nothing has woken, a name that is no thread, a caller in a process the system does not hold, or `UnixScheduling.getcpu` of a thread that is not running.
A value no `parse` could have produced, such as one built with `Unchecked.defaultof`, is a bug in the client too.
The functions that check for one, such as the setters, the functions that resume a paused call, and each type's `assertValid`, throw `ArgumentException` for it, or `ArgumentNullException` for a null reference, naming the parameter it was passed as.
The parsers that throw rather than answer a `Result`, such as `DirectoryEntryName.parseOrFail`, throw `ArgumentException` or `ArgumentOutOfRangeException` naming the value they were handed.

### Unions that gain cases

From version 1.0, adding a case to any union whose cases are public is a breaking change, and comes only in a major version.
F# code compiled against a union dispatches on its case numbers, so code built against an older version can silently run the wrong arm for a new case.
The model will still grow: a refusal becomes an answer once its behaviour is measured, and each newly measured difference between Linux and Darwin adds a place that throws `UnmodelledException` (see "Answers, and what this library will not answer"), which needs no new case.
Cases that are certain to appear are already present, and nothing produces them yet: `InodeContent.Socket`, `InodeContent.Fifo`, `DirectoryEntryKind.Socket`, `DirectoryEntryKind.Fifo`, `CharacterDevice.Zero`, `CharacterDevice.Random`, `CharacterDevice.Tty`, `OpenFileTarget.Fifo`, `ParkedSyscall.Sleep`, `ParkedSyscall.FifoOpen`, `ParkedSyscall.Select`, `ParkedSyscall.SignalWait`, `ParkedSyscall.DatagramReceive`, `ParkedSyscall.DatagramSend`, `ParkedSyscall.Connect`, `FinishedCall.Sleep`, `FinishedCall.FifoOpen`, `FinishedCall.Select`, `FinishedCall.SignalWait`, `FinishedCall.DatagramReceive`, `FinishedCall.DatagramSend`, `FinishedCall.Connect`, `SocketPhase.Connecting`, `WakePrimitive.FifoPartnerOpened`, `WakePrimitive.AwaitedSignalPending`, `WakePrimitive.AcceptQueueHasRoom` and `TerminalAttributesAnswer.Attributes`.
So are the cases of the calls not modelled yet that `Syscall` and `SteppedCall` reserve, eleven in each (see "One entry point"), from `Syscall.Nanosleep` and `SteppedCall.Nanosleep` to `Syscall.SendMsg` and `SteppedCall.SendMsg`; and since `Syscall` has a case for every call a thread makes, a call this library comes to model, such as `fork`, is a new case of each.
Removing a case, changing a case's fields, or changing the shape of any other type is breaking too.

The defects the `checkInvariants` functions report (`UnixSystemDefect` and `VirtualFileSystemDefect`) are open too, and have no patterns at all.
A defect is a bug in this library, and the thing to do with one is report it with its `describe`; no client needs to branch on which rule broke.
So any version may add a defect, and any version may remove one, as it will when the types come to make the state it forbids unrepresentable.

Before 1.0, any version may change anything.

### The syscalls

In each table, the function's last argument, the system, is left out, and so are the type arguments `'Thread` and `'Handler`: `UnixSystem` is `UnixSystem<'Thread, 'Handler>`, a paused call such as `PausedWrite` is `PausedWrite<'Thread, 'Handler>`, and `ProcessFate<WriteOutcome>` is `ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>`.
A path is the argument's bytes (`PathArgumentBytes`), which the kernel copies in where the call's kernel does.
A buffer is a `UserBuffer` (see "User memory"), which says whether the address the caller passed is mapped; the bytes it holds cross the API separately.

A `SyscallAnswer` is the `int64` a call returns (`SyscallAnswer.Completed`), or the errno it fails with (`SyscallAnswer.Failed`).
A `SyscallOutcome` is a `SyscallAnswer` (`SyscallOutcome.Answered`), the thread asleep (`SyscallOutcome.WouldBlock`), or the call interrupted by a signal (`SyscallOutcome.Interrupted`), whose end the thread's return to user mode says (see "The return to user mode").
A `DescriptorAnswer` is the descriptor a call that makes one returns (`DescriptorAnswer.Returned`), or the errno it fails with (`DescriptorAnswer.Failed`); an `OpenOutcome` is a `DescriptorAnswer` (`OpenOutcome.Answered`) or the thread asleep (`OpenOutcome.WouldBlock`).

#### Descriptors

| Call | Function | Answers |
| --- | --- | --- |
| `dup(2)` | `UnixDescriptor.dup (caller : Caller) (fd : int)` | `DescriptorAnswer * UnixSystem` |
| `dup2(2)` | `UnixDescriptor.dup2 (caller : Caller) (oldFd : int) (newFd : int)` | `DescriptorAnswer * UnixSystem` |
| `dup3(2)` | `UnixDescriptor.dup3 (caller : Caller) (oldFd : int) (newFd : int) (flags : int)` | `DescriptorAnswer * UnixSystem` |
| `fcntl(2)`: `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_SETFL` | `UnixDescriptor.fcntl (caller : Caller) (fd : int) (command : int) (argument : int)` | `SyscallAnswer * UnixSystem` |
| `fcntl(F_SETFL)` of `fcntl(F_GETFL)` with `O_NONBLOCK` changed | `UnixDescriptor.setNonBlocking (caller : Caller) (fd : int) (isNonBlocking : bool)` | `SetNonBlockingAnswer * UnixSystem` |
| `O_NONBLOCK` in `fcntl(F_GETFL)` | `UnixDescriptor.isNonBlocking (caller : Caller) (fd : int)` | `bool option` |
| `lseek(2)` | `UnixDescriptor.lseek (caller : Caller) (fd : int) (offset : int64) (whence : int)` | `SyscallAnswer * UnixSystem` |
| `flock(2)` | `UnixDescriptor.flock (caller : Caller) (fd : int) (operation : int)` | `SyscallOutcome * UnixSystem` |
| `ftruncate(2)` | `UnixDescriptor.ftruncate (caller : Caller) (fd : int) (length : int64)` | `SyscallAnswer * UnixSystem` |
| `posix_fadvise(3)` | `UnixDescriptor.posixFadvise (caller : Caller) (fd : int) (offset : int64) (length : int64) (advice : int)` | `FileAdviceAnswer` |
| `close(2)` | `UnixDescriptor.close (caller : Caller) (fd : int)` | `SyscallAnswer * UnixSystem` |
| `ioctl(FIONREAD)` | `UnixDescriptor.bytesAvailable (caller : Caller) (fd : int) (destination : UserBuffer)` | `BytesAvailableAnswer` |
| `ioctl(FICLONE)` | `UnixDescriptor.fileClone (caller : Caller) (destination : int) (source : int)` | `SyscallAnswer * UnixSystem` |
| `tcgetattr(3)`, `isatty(3)` | `UnixDescriptor.terminalAttributes (caller : Caller) (fd : int)` | `TerminalAttributesAnswer` |

#### Paths and their files

| Call | Function | Answers |
| --- | --- | --- |
| `stat(2)` (`SymlinkPolicy.Follow`), `lstat(2)` (`SymlinkPolicy.NoFollowFinal`) | `UnixPathResolution.stat (caller : Caller) (policy : SymlinkPolicy) (path : PathArgumentBytes)` | `FileStatusAnswer` |
| `fstat(2)` | `UnixPathResolution.fstat (caller : Caller) (fd : int)` | `FileStatusAnswer` |
| `fstatat(2)` | `UnixPathResolution.fstatat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (flags : int)` | `FileStatusAnswer` |
| `chmod(2)` | `UnixPathResolution.chmod (caller : Caller) (path : PathArgumentBytes) (mode : int)` | `SyscallAnswer * UnixSystem` |
| `fchmod(2)` | `UnixPathResolution.fchmod (caller : Caller) (fd : int) (mode : int)` | `SyscallAnswer * UnixSystem` |
| `fchmodat(2)` | `UnixPathResolution.fchmodat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (mode : int) (flags : int)` | `SyscallAnswer * UnixSystem` |
| `chown(2)` | `UnixPathResolution.chown (caller : Caller) (path : PathArgumentBytes) (user : UserId option) (group : GroupId option)` | `SyscallAnswer * UnixSystem` |
| `lchown(2)` | `UnixPathResolution.lchown (caller : Caller) (path : PathArgumentBytes) (user : UserId option) (group : GroupId option)` | `SyscallAnswer * UnixSystem` |
| `fchown(2)` | `UnixPathResolution.fchown (caller : Caller) (fd : int) (user : UserId option) (group : GroupId option)` | `SyscallAnswer * UnixSystem` |
| `fchownat(2)` | `UnixPathResolution.fchownat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (user : UserId option) (group : GroupId option) (flags : int)` | `SyscallAnswer * UnixSystem` |
| `utimensat(2)`, and Linux's `futimens(3)` | `UnixPathResolution.utimensat (caller : Caller) (dirfd : int) (path : NullablePathArgument) (times : TimesArgument) (flags : int)` | `SyscallAnswer * UnixSystem` |
| `statfs(2)` | `UnixPathResolution.statfs (caller : Caller) (path : PathArgumentBytes)` | `FileSystemStatisticsAnswer` |
| `fstatfs(2)` | `UnixPathResolution.fstatfs (caller : Caller) (fd : int)` | `FileSystemStatisticsAnswer` |
| `getcwd(3)` | `UnixPathResolution.getcwd (caller : Caller) (destination : UserBuffer) (capacity : uint64)` | `GetCwdAnswer` |
| `chdir(2)` | `UnixPathResolution.chdir (caller : Caller) (path : PathArgumentBytes)` | `SyscallAnswer * UnixSystem` |
| `access(2)` | `UnixPathResolution.access (caller : Caller) (mode : int)` | `CallProgress<PausedAccess, SyscallAnswer>` |
| `faccessat(2)` | `UnixPathResolution.faccessat (caller : Caller) (dirfd : int) (mode : int) (flags : int)` | `CallProgress<PausedAccess, SyscallAnswer>` |
| `access(2)` or `faccessat(2)`, given the path | `UnixPathResolution.accessWithPath (path : PathArgumentBytes) (paused : PausedAccess)` | `SyscallAnswer` |

`UnixPathResolution.currentDirectoryPath (pid : ProcessId)` is the process's current directory's path, for a client that wants it without a buffer.

A symbolic link's own mode is `UnixPathResolution.fchmodat` with `AT_SYMLINK_NOFOLLOW`: Linux answers `EOPNOTSUPP`, and Darwin changes it.
There is no `lchmod` function, since neither kernel has that syscall.
On Linux, glibc's `lchmod(3)` is that `fchmodat` from `AT_FDCWD`, so a client implementing it calls `fchmodat`.
Darwin's C library implements it with `setattrlist(2)` instead, which answers a non-owner `EACCES` rather than `EPERM`, and refuses `S_ISGID` outside the inode's group with `EPERM` rather than dropping the bit; this library does not model `setattrlist`.

#### Names in the filesystem

| Call | Function | Answers |
| --- | --- | --- |
| `open(2)` | `UnixNamespace.openPath (caller : Caller) (path : PathArgumentBytes) (flags : int) (mode : int)` | `OpenOutcome * UnixSystem` |
| `openat(2)` | `UnixNamespace.openat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (flags : int) (mode : int)` | `OpenOutcome * UnixSystem` |
| `readlink(2)` | `UnixNamespace.readlink (caller : Caller) (path : PathArgumentBytes) (destination : UserBuffer) (capacity : int)` | `ReadLinkAnswer` |
| `readlinkat(2)` | `UnixNamespace.readlinkat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (destination : UserBuffer) (capacity : int)` | `ReadLinkAnswer` |
| one entry of `getdents(2)` or `getdirentries(2)`, without its byte layout | `UnixNamespace.readDirectoryEntry (caller : Caller) (fd : int)` | `ReadDirectoryAnswer * UnixSystem` |
| `mkdir(2)` | `UnixNamespace.mkdir (caller : Caller) (path : PathArgumentBytes) (mode : int)` | `SyscallAnswer * UnixSystem` |
| `mkdirat(2)` | `UnixNamespace.mkdirat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (mode : int)` | `SyscallAnswer * UnixSystem` |
| `mknod(2)`, regular files only | `UnixNamespace.mknod (caller : Caller) (path : PathArgumentBytes) (mode : int) (dev : uint32)` | `SyscallAnswer * UnixSystem` |
| `mknodat(2)`, regular files only | `UnixNamespace.mknodat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (mode : int) (dev : uint32)` | `SyscallAnswer * UnixSystem` |
| `unlink(2)` | `UnixNamespace.unlink (caller : Caller) (path : PathArgumentBytes)` | `SyscallAnswer * UnixSystem` |
| `rmdir(2)` | `UnixNamespace.rmdir (caller : Caller) (path : PathArgumentBytes)` | `SyscallAnswer * UnixSystem` |
| `unlinkat(2)` | `UnixNamespace.unlinkat (caller : Caller) (dirfd : int) (path : PathArgumentBytes) (flags : int)` | `SyscallAnswer * UnixSystem` |
| `rename(2)` | `UnixNamespace.rename (caller : Caller) (source : PathArgumentBytes)` | `CallProgress<PausedRename, SyscallAnswer * UnixSystem>` |
| `renameat(2)` | `UnixNamespace.renameat (caller : Caller) (olddirfd : int) (oldpath : PathArgumentBytes) (newdirfd : int)` | `CallProgress<PausedRename, SyscallAnswer * UnixSystem>` |
| `rename(2)` or `renameat(2)`, given the destination | `UnixNamespace.renameWithDestination (destination : PathArgumentBytes) (paused : PausedRename)` | `SyscallAnswer * UnixSystem` |
| Darwin's `clonefile(2)` | `UnixNamespace.cloneFile (caller : Caller) (flags : int)` | `CallProgress<PausedCloneFileSource, SyscallAnswer * UnixSystem>` |
| `clonefile(2)`, given the source | `UnixNamespace.cloneFileWithSource (source : PathArgumentBytes) (paused : PausedCloneFileSource)` | `CallProgress<PausedCloneFile, SyscallAnswer * UnixSystem>` |
| `clonefile(2)`, given the destination | `UnixNamespace.cloneFileWithDestination (destination : PathArgumentBytes) (paused : PausedCloneFile)` | `SyscallAnswer * UnixSystem` |
| `symlink(2)` | `UnixNamespace.symlink (caller : Caller) (target : PathArgumentBytes)` | `CallProgress<PausedSymlink, SyscallAnswer * UnixSystem>` |
| `symlinkat(2)` | `UnixNamespace.symlinkat (caller : Caller) (target : PathArgumentBytes) (dirfd : int)` | `CallProgress<PausedSymlink, SyscallAnswer * UnixSystem>` |
| `symlink(2)` or `symlinkat(2)`, given the link's path | `UnixNamespace.symlinkWithPath (path : PathArgumentBytes) (paused : PausedSymlink)` | `SyscallAnswer * UnixSystem` |
| `link(2)` | `UnixNamespace.link (caller : Caller) (oldpath : PathArgumentBytes)` | `CallProgress<PausedLink, SyscallAnswer * UnixSystem>` |
| `linkat(2)` | `UnixNamespace.linkat (caller : Caller) (olddirfd : int) (oldpath : PathArgumentBytes) (newdirfd : int) (flags : int)` | `CallProgress<PausedLink, SyscallAnswer * UnixSystem>` |
| `link(2)` or `linkat(2)`, given the new path | `UnixNamespace.linkWithDestination (newpath : PathArgumentBytes) (paused : PausedLink)` | `SyscallAnswer * UnixSystem` |

`UnixNamespace.openPath` and `UnixNamespace.openat` answer an `OpenOutcome` because an open can sleep: a blocking open of one end of a FIFO waits until the other end is opened.
Nothing makes a FIFO yet, so both always answer `OpenOutcome.Answered`.

A Linux directory compares names byte for byte.
Darwin's APFS takes a name as reaching the entry bound under any canonically equivalent Unicode spelling of it: `é` as U+00E9 and as `e` followed by U+0301, or `K` and U+212A KELVIN SIGN.
It keeps the spelling a name was bound under, which `UnixNamespace.readDirectoryEntry` reports, and holds one spelling of a name in a directory.
This library holds no Unicode tables, so on Darwin a call throws `UnmodelledException` when its path looks up a name that a directory does not bind byte for byte while binding another name that might be an equivalent spelling of it.
Two names might be equivalent when they decompose to the same ASCII, or when each holds a character whose decomposition is not ASCII and their ASCII ends do not tell them apart: the longest run of ASCII each ends with is the same, and the longest run of ASCII one begins with begins the other's, reading U+037E, U+1FEF and U+212A as the ASCII they decompose to.
So `café.txt` and `naïve.txt` can share a Darwin directory, but `é` and `中` cannot.

An inode may be a socket file (`InodeContent.Socket`), which a directory entry reports as `DirectoryEntryKind.Socket`, or a FIFO (`InodeContent.Fifo`), which a directory entry reports as `DirectoryEntryKind.Fifo`.
Nothing produces either yet: `mknod` of `S_IFSOCK` or `S_IFIFO`, and a Unix-domain `bind`, are refused.
The cases exist so that a client's matches already handle them when pathname sockets and FIFOs arrive.

#### Reading and writing

| Call | Function | Answers |
| --- | --- | --- |
| `read(2)` | `UnixReadWrite.read (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64)` | `ReadOutcome * UnixSystem` |
| `recv(2)` | `UnixReadWrite.recv (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64) (flags : int)` | `ReadOutcome * UnixSystem` |
| `pread(2)` | `UnixReadWrite.pread (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64) (offset : int64)` | `ReadAnswer * UnixSystem` |
| `write(2)` | `UnixReadWrite.write (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64)` | `CallProgress<PausedWrite, ProcessFate<WriteOutcome>>` |
| `write(2)` or `send(2)`, woken | `UnixReadWrite.finishWrite (caller : Caller)` | `CallProgress<PausedWrite, ProcessFate<WriteOutcome>>` |
| `write(2)`, given the bytes | `UnixReadWrite.writeWithBytes (bytes : ImmutableArray<byte>) (paused : PausedWrite)` | `ProcessFate<WriteOutcome> * Delivery option` |
| `send(2)` | `UnixReadWrite.send (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64) (flags : int)` | `CallProgress<PausedSend, ProcessFate<WriteOutcome>>` |
| `send(2)`, given the bytes | `UnixReadWrite.sendWithBytes (bytes : ImmutableArray<byte>) (paused : PausedSend)` | `ProcessFate<WriteOutcome>` |
| `pwrite(2)` | `UnixReadWrite.pwrite (caller : Caller) (fd : int) (buffer : UserBuffer) (count : uint64) (offset : int64)` | `CallProgress<PausedPWrite, WriteAnswer * UnixSystem>` |
| `pwrite(2)`, given the bytes | `UnixReadWrite.pwriteWithBytes (bytes : ImmutableArray<byte>) (paused : PausedPWrite)` | `WriteAnswer * UnixSystem` |
| `copy_file_range(2)` | `UnixReadWrite.copyFileRange (caller : Caller) (inFd : int) (outFd : int) (length : uint64) (flags : int)` | `SyscallAnswer * UnixSystem` |
| `pipe2(2)`, and `pipe(2)` as `pipe2` with no flags | `UnixPipe.pipe2 (caller : Caller) (flags : int) (destination : UserBuffer)` | `Pipe2Answer * UnixSystem` |

#### Sockets

| Call | Function | Answers |
| --- | --- | --- |
| `socket(2)` | `UnixSocket.socket (caller : Caller) (domain : int) (socketType : int) (protocol : int)` | `DescriptorAnswer * UnixSystem` |
| `bind(2)` | `UnixSocket.bind (caller : Caller) (fd : int) (address : UserBuffer) (declaredLength : uint32)` | `CallProgress<PausedBind, BindAnswer * UnixSystem>` |
| `bind(2)`, given the bytes | `UnixSocket.bindWithAddress (copied : ImmutableArray<byte>) (paused : PausedBind)` | `BindAnswer * UnixSystem` |
| `connect(2)` | `UnixConnection.connect (caller : Caller) (fd : int) (address : UserBuffer) (declaredLength : uint32)` | `CallProgress<PausedConnect, SyscallOutcome * UnixSystem>` |
| `connect(2)`, given the bytes | `UnixConnection.connectWithAddress (copied : ImmutableArray<byte>) (paused : PausedConnect)` | `SyscallOutcome * UnixSystem` |
| `listen(2)` | `UnixSocket.listen (caller : Caller) (fd : int) (backlog : int)` | `ListenAnswer * UnixSystem` |
| `accept(2)` | `UnixConnection.accept (caller : Caller) (fd : int) (destination : UserBuffer) (declaredLength : uint32)` | `AcceptOutcome * UnixSystem` |
| `shutdown(2)` | `UnixConnection.shutdown (caller : Caller) (fd : int) (how : int)` | `ShutdownAnswer * UnixSystem` |
| `getsockname(2)` | `UnixSocket.getsockname (caller : Caller) (fd : int) (destination : UserBuffer) (declaredLength : uint32)` | `GetSockNameAnswer` |
| `getpeername(2)` | `UnixSocket.getpeername (caller : Caller) (fd : int) (destination : UserBuffer) (declaredLength : uint32)` | `GetSockNameAnswer` |
| `setsockopt(2)` | `UnixSocket.setsockopt (caller : Caller) (fd : int) (level : int) (optionName : int) (value : UserBuffer) (optionLength : uint32)` | `CallProgress<PausedSetSockOpt, SetSockOptAnswer * UnixSystem>` |
| `setsockopt(2)`, given the bytes | `UnixSocket.setsockoptWithValue (copied : ImmutableArray<byte>) (paused : PausedSetSockOpt)` | `SetSockOptAnswer * UnixSystem` |
| `getsockopt(2)` | `UnixSocket.getsockopt (caller : Caller) (fd : int) (level : int) (optionName : int) (value : UserBuffer) (length : UserBuffer)` | `CallProgress<PausedGetSockOpt, GetSockOptAnswer * UnixSystem>` |
| `getsockopt(2)`, given the length | `UnixSocket.getsockoptWithLength (declaredLength : uint32) (paused : PausedGetSockOpt)` | `GetSockOptAnswer * UnixSystem` |

An address crosses the syscall boundary as bytes, laid out as the platform's `struct sockaddr`: `bind` and `connect` take them, and `getsockname`, `getpeername` and `accept` answer them.
Where the kernel hands out an address already decoded, in an answer or a socket's `SocketPhase.DatagramPeer`, it is a `SocketAddress`: an `Ipv4Endpoint`, an `Ipv6Endpoint`, or a `UnixSocketName`, whose representation is hidden and which `UnixSocketName.view` reads as a path or a Linux abstract name (`UnixSocketNameView`).
`BindAnswer.Bound` and `ListenAnswer.Listening` carry the address as `getsockname` would report it at once, and so in the socket's own family: a dual-mode IPv6 socket (`IPV6_V6ONLY` off) bound to an IPv4 address answers it v4-mapped, `::ffff:a.b.c.d`.
This kernel's IPv6 sockets reach only IPv4 peers, through v4-mapped addresses, so a refused `connect` names the IPv4 endpoint it resolved, even from an IPv6 socket.
A refused TCP `connect` gives the socket's port back (`PortHold.GivenBack`), which `getsockname` goes on reporting: on Linux unless `bind` chose the port, and on Darwin whatever chose it. Another socket may then bind that port. A Linux socket that has given its port back binds, listens and connects as one with no port would, at the address it reports; a refused Darwin socket answers `EINVAL` to `bind` and `listen` and `EISCONN` to `connect`, as any refused Darwin socket does.
A connect can sleep: under Linux, a blocking connect to a listener whose accept queue is full waits for room. The paused call holds the caller's thread, so the connect `UnixConnection.connectWithAddress` finishes is the one that would park it. No connect sleeps in this version (that one is refused), so both always answer `SyscallOutcome.Answered`, with 0 or the errno the call leaves; `EINPROGRESS` is such an errno, and the connection it defers is already settled on the socket.
A Linux TCP connect left in flight against a full listener, non-blocking or interrupted by a signal without `SA_RESTART`, will put its socket in `SocketPhase.Connecting`, whose `ConnectAttempt` has an internal representation. The phase is reserved: nothing puts a socket in it yet, and `UnixSystem.checkInvariants` reports a socket in it as a defect.
It binds no Unix-domain socket yet, so nothing it hands out holds a `UnixSocketName`.
A socket's own state, which `UnixSystem.socket` reads, keeps its local address in its domain's own types: `SocketAddressing.Inet` holds an IPv4 binding, `SocketAddressing.Inet6DualMode` a `DualModeBinding`, `SocketAddressing.Inet6V6Only` an IPv6 binding, and `SocketAddressing.Unix` a `UnixSocketName`, each as an option that is `None` while the socket is unbound. An IP binding is an `InetBinding` over the family's endpoint and address types, so an IPv4 socket cannot hold an IPv6 address.
A dual-mode socket bound to an IPv4 address holds it as `DualModeBinding.Mapped`, the IPv4 transport, and presents it v4-mapped.
Only IPv4 bindings are made yet: `UnixSystem.checkInvariants` reports an IPv6 binding or a Unix-domain name as a defect, as it does a datagram peer outside its socket's family.
A socket also carries a uid, `SocketDescription.Uid`, fixed for its life: the effective uid of the process that made it, whatever that process's credentials become later. An accepted socket carries its listener's uid on Darwin, and on Linux the accepting process's effective uid at the `accept`.
Darwin's `bind` consults it: a socket whose uid is not root's, binding beside a socket of another uid at an overlapping address that is not the wildcard on both sides, is answered `EADDRINUSE`, whatever either's `SO_REUSEADDR`. The same holds beside a TCP end whose socket has closed, in `TIME_WAIT` or not, which carries the uid its socket carried; beside such an end of root's the answer is unmeasured, and the bind throws `UnmodelledException`.
Linux compares uids only for `SO_REUSEPORT`, which this kernel does not model; its sockets carry their uid all the same, so the field means the same on both flavours.

A connected TCP socket's `read` and `write` move bytes through its connection, which holds each direction's bytes in the sender's send buffer and the receiver's receive buffer, sized from the machine's TCP sysctls, each direction's FIN (not sent, queued behind unsent bytes, or arrived), and each end's state: open, reset, or closed. A close over bytes left unread resets the peer; otherwise it sends a FIN behind what it had sent. A close under `SO_LINGER` {1, 0} resets the peer unless both FINs have arrived, when it is the ordinary close, and frees the closer's endpoint at once wherever it resets (and, under Darwin, even where it does not); a client that resets while its connection waits in an accept queue leaves the accept a reset socket. A listener's last close resets every client still in its accept queue, oldest first, whatever the listener's `SO_LINGER`. Each queued connection keeps the options the listener held when it completed (`QueuedConnection`), so a change to a listener's options does not reach the connections already queued, and the socket `accept` makes for one holds them; under Darwin a listener lingering for no time gives it a linger of 120 seconds. `poll`, epoll and kqueue read a connected socket's readiness from the same state, and each transfer wakes the waiters each flavour wakes: every arrival of bytes, and room freed in a send buffer (on Linux once after a write ran out of room, when the buffer has drained to two thirds full; on Darwin as bytes leave it). `FIONREAD` reports what waits to be read, and `SO_ERROR` takes a reset's error. A blocking read with nothing to answer sleeps until bytes, a FIN or a reset arrive; a blocking write takes what fits and sleeps for the rest, woken on Linux once its send buffer has drained to two thirds full and on Darwin once there is room for it to take something, and it returns once every byte is taken, unless something ends it first; under Linux, one whose own bytes reset the connection, because its peer has closed or resets what arrives, returns the count it took without sleeping. Every thread asleep on a socket wakes for what it waits on.

`shutdown` shuts a connected TCP socket's sides by each flavour's measured rules: shutting the send side sends a FIN behind what is still unsent, and every later write answers `EPIPE`; shutting the receive side makes reads answer end of file once what was queued is read, which Darwin discards, and an arrival at a Darwin socket shut for receiving, or a Linux one shut both ways, resets the connection. Linux answers 0 to every call on a connection neither reset nor done with its FINs, and `ENOTCONN` otherwise; Darwin answers `ENOTCONN` to a side already shut and applies `SHUT_RDWR` side by side. The socket's readiness, its waiters, its sleeping reads and writes, `getpeername`, Darwin's `setsockopt` and the endpoint it holds follow: an end whose FIN was made after the peer's and has arrived frees its endpoint, open or closed (on Linux, an explicitly bound port only once the socket closes), where one made first holds it. While an end holds its endpoint, a `bind` of it is refused as one over a connected socket is, whether the end's socket is open or has closed: on Linux unless both that socket and the new one carry `SO_REUSEADDR` (a closed end keeps the flag its socket carried), and on Darwin unless the new one does. Linux judges an end in `TIME_WAIT` by the flag it had on entering it, so a Linux `setsockopt` changing the flag there is refused. A connection is forgotten once neither socket refers to it, and if both its FINs had arrived, the end whose FIN was made first is then left in `TIME_WAIT`, unless a Darwin close under `SO_LINGER` {1, 0} freed its endpoint. A FIN still queued behind bytes the peer's closed socket never read does not arrive, so a Darwin connection left so holds neither end's port once both sockets have closed. An end in `TIME_WAIT` holds its endpoint and its four-tuple as it did once its socket had closed, with the `SO_REUSEADDR` that socket carried, against `bind`, `listen` and every search for a port, but for one place: Linux's connect search, which shares a port connect's own bind chose with connections to other destinations, also takes the end's four-tuple over, on loopback, once `net.ipv4.tcp_tw_reuse_delay` (1000 ms) has passed since it entered `TIME_WAIT`, unless it entered it in the machine's first second of uptime. A connect towards its peer from a socket bound at its endpoint takes the four-tuple over at once on Linux, and on Darwin answers `EADDRINUSE`, the socket left bound and unconnected; and a connect from its peer's endpoint to its own ends the `TIME_WAIT` on both, accepted or refused. The end entered `TIME_WAIT` once both FINs had arrived, and it holds for as long as it was measured to hold at least, counted from then: 60 seconds on Linux (`TCP_TIMEWAIT_LEN`), and twice `net.inet.tcp.msl` (15000 ms) on Darwin. When it ends after that is unmeasured, so a call whose answer then depends on it throws `UnmodelledException`, as does a Linux connect that would take its four-tuple over off loopback, from a search within 10 ms of the reuse delay, or from a bound socket where the end entered `TIME_WAIT` in the first second of uptime. The machine's `TIME_WAIT` sysctls are each flavour's defaults, which no setter changes yet. No other TCP timer is modelled, so an end that still holds its endpoint once its socket has closed goes on holding it until a reset reaches the connection, its passive FIN arrives, or its peer's socket closes too. Refused: a listener, a Linux socket with no connection (whose `ENOTCONN` still shuts its sides), and Darwin's receive side shut before the peer's unsent bytes, after which only a timer decides; so is Darwin's close behind its own queued FIN once the peer's has arrived, over bytes unread.

`recv` and `send` reach a connected TCP socket through the same transfer, sleep and wake as `read` and `write`, and take their flag word raw, in the flavour's numbering (`MessageFlag.number`). `MSG_PEEK` answers bytes without taking them, `MSG_DONTWAIT` makes a `recv`, and a Linux `send`, non-blocking (Darwin's `send` ignores it), and `MSG_NOSIGNAL` keeps an `EPIPE` from raising `SIGPIPE`; any other flag is refused, naming it. Where they part from `read` and `write` is measured: Linux screens their buffer before it looks up the descriptor, a Linux `recv` of nothing waits as a longer one would, and Darwin's `send` marks no description written.

#### Waiting for several things

| Call | Function | Answers |
| --- | --- | --- |
| `poll(2)` | `UnixPoll.poll (caller : Caller) (entries : PollEntry list) (milliseconds : int)` | `PollOutcome * UnixSystem` |
| `epoll_create1(2)` | `UnixPoll.epollCreate1 (caller : Caller) (flags : int)` | `DescriptorAnswer * UnixSystem` |
| `epoll_ctl(2)` | `UnixPoll.epollCtl (caller : Caller) (epfd : int) (op : int) (fd : int) (event : EpollEventArgument)` | `EpollCtlAnswer * UnixSystem` |
| `epoll_wait(2)` | `UnixPoll.epollWait (caller : Caller) (epfd : int) (maxEvents : int) (buffer : UserBuffer) (milliseconds : int)` | `EpollWaitOutcome * UnixSystem` |
| Darwin's `kqueue(2)` | `UnixKqueue.kqueue (caller : Caller)` | `DescriptorAnswer * UnixSystem` |
| Darwin's `kevent(2)` | `UnixKqueue.kevent (caller : Caller) (kq : int) (nchanges : int) (changes : Kevent list) (nevents : int) (eventlist : UserBuffer) (timeout : TimespecArgument)` | `KeventOutcome * UnixSystem` |

An epoll registration is level-triggered, or edge-triggered with `EPOLLET`, and with `EPOLLONESHOT` it reports once until an `EPOLL_CTL_MOD` re-arms it, all as Linux's are. A registration with `EPOLLEXCLUSIVE` or `EPOLLWAKEUP` is refused, as is one of another epoll instance, of a pipe the process made, or of an `AF_UNIX` `SOCK_SEQPACKET` socket.

#### Watching the filesystem

Linux's inotify.
An instance is an open file description, `OpenFileTarget.Inotify`, holding its watches and the records it has queued (`InotifyState`); a `dup` of its descriptor shares it, and it goes with its last reference.
`read(2)` takes whole records from it, each laid out as `struct inotify_event` (`InotifyRecord.toBytes`), and answers `EINVAL` if the oldest does not fit; with none queued it answers `EAGAIN` through a non-blocking description and otherwise sleeps.
`poll(2)` and epoll report it readable while it holds a record, and `ioctl(FIONREAD)` (`UnixDescriptor.bytesAvailable`) reports the bytes it holds.
Each user's instances and watches count against the machine's `InotifyLimits`, in every process.
A change to the filesystem, made by any process, queues a record on every instance watching what it changed whose watch asks for any of its events, carrying all of them, in Linux's order:
a name created, removed or renamed is `IN_CREATE`, `IN_DELETE`, or `IN_MOVED_FROM` and `IN_MOVED_TO` sharing a cookie, at the watch on its directory, with `IN_ISDIR` for a directory;
an inode's gained or lost link (a hard link, an unlink, a rename over it) is `IN_ATTRIB` at its own watch;
and `chmod`, `chown`, `utimensat` or an `open` with `O_TRUNC` through a path is one record, `IN_ATTRIB` or `IN_MODIFY` as Linux chooses, at the watch on the directory of the name the path reached and then at the inode's own.
A change made through a descriptor (`write`, `pwrite`, `copy_file_range`, `ftruncate`, `fchmod`, `fchown`, `futimens`, or the empty path under `AT_EMPTY_PATH`) is reported the same way, under the name the descriptor was opened through, which each open file description records:
a rename of that name moves it, and an unlink of it, a `rmdir` of it or a rename over it leaves it in place, unlinked, and the change is still reported there, except that a watch with `IN_EXCL_UNLINK`, on the directory or on the inode, hears nothing of a write through an unlinked name (it does hear its `ftruncate`, `fchmod` and the rest, and the `IN_ATTRIB` of the set-ID bits a write clears).
A file unlinked while open holds the directory it was named in, as Linux's does, so that directory outlives its own `rmdir` until the file is closed.
A record repeating the newest queued is dropped, and a full queue takes one `IN_Q_OVERFLOW` record; `inotify_rm_watch` queues `IN_IGNORED`.
A rename is `IN_MOVE_SELF` at the moved inode's own watch, after the other records of the rename.
A watched inode goes, for inotify, when a name of it goes while it has no link left, as Linux's dentry does, rather than when the inode itself does:
an unlink, `rmdir` or rename over a name no description was opened through, or the close of the last description opened through a name since unlinked (a name linked again is another name).
Its watches then queue `IN_DELETE_SELF` if they ask for it, and `IN_IGNORED`, and end, before the `IN_DELETE` of the name at its directory; afterwards `inotify_rm_watch` of one answers `EINVAL`.
So a file opened through one name and unlinked through another goes at that unlink, though the descriptor still reads it; a directory, having one name, goes when nothing holds it, a process standing in it included.
A change to a directory whose last name has gone (by `rmdir`, or a rename over it), reached by "." or ".." (from the current directory, say) or through a descriptor opened that way, is reported as one through a name since unlinked: at the watch on the directory it was last named in, under the name it had when that name went, and then at its own.
A watch asking for an event this kernel does not raise, `IN_ACCESS`, `IN_OPEN`, `IN_CLOSE_WRITE`, `IN_CLOSE_NOWRITE` or `IN_UNMOUNT`, or carrying `IN_ONESHOT`, is refused.
Darwin has no inotify, and every call throws `PlatformNotSupportedException`.

| Call | Function | Answers |
| --- | --- | --- |
| `inotify_init1(2)` | `UnixInotify.inotifyInit1 (caller : Caller) (flags : int)` | `DescriptorAnswer * UnixSystem` |
| `inotify_add_watch(2)` | `UnixInotify.inotifyAddWatch (caller : Caller) (fd : int) (mask : uint32)` | `CallProgress<PausedInotifyAddWatch, SyscallAnswer * UnixSystem>` |
| `inotify_add_watch(2)`, given the path | `UnixInotify.inotifyAddWatchWithPath (path : PathArgumentBytes) (paused : PausedInotifyAddWatch)` | `SyscallAnswer * UnixSystem` |
| `inotify_rm_watch(2)` | `UnixInotify.inotifyRmWatch (caller : Caller) (fd : int) (wd : int)` | `SyscallAnswer * UnixSystem` |

#### Futexes

Linux's `futex(2)`, for the operations a private lock, condition variable or semaphore is built on: `FUTEX_WAIT_PRIVATE` (128), `FUTEX_WAKE_PRIVATE` (129), `FUTEX_WAIT_BITSET_PRIVATE` (137, or 393 with `FUTEX_CLOCK_REALTIME`) and `FUTEX_WAKE_BITSET_PRIVATE` (138), which `op` takes raw, with the call's sixth argument, `val3`, the bitset of a bitset wait or wake.
A process's waiters on one address form one queue, in the order they began to wait, which no other process reaches.
The kernel holds no word: the word is the caller's memory.
A wait screens its timeout, then its bitset (`EINVAL` for 0), then its address, and stops where the kernel reads the word (`UnixFutex.futexWithWord`), answering `EAGAIN` if it does not hold `value` and otherwise sleeping.
A `FUTEX_WAIT_PRIVATE`'s timeout is a length of time on the monotonic clock; a `FUTEX_WAIT_BITSET_PRIVATE`'s is an instant on the monotonic clock, or with `FUTEX_CLOCK_REALTIME` on the realtime clock, which the park holds as nanoseconds since boot (`FutexTimeout.At`), less the boot time; a timeout of zero, or an instant already passed, sleeps too, as Linux's does.
A wait or a wake screens the address: `EINVAL` if it is not a multiple of 4, and then `EFAULT` if its four bytes do not lie in user space (`UnixBootImage.withUserAddressLimit`); a bitset wake screens its bitset first (`EINVAL` for 0).
A wake takes up to `value` waiters off the queue, one if `value` is 0 or less, passing over any whose bitset shares no bit with its own (a plain wait or wake has every bit), and answers how many it took; a waiter something else has woken keeps its place until its wait is finished, and a taken waiter's wait answers 0 whatever else woke it.
A timeout Linux saturates, of `KTIME_SEC_MAX` (9223372036) seconds or more or a relative one that ends past the last instant the clock can represent, never expires: the park's timeout is `FutexTimeout.Unbounded`, and `UnixWait.deadlines` holds nothing for it. Any other timeout expires at its instant (`FutexTimeout.Until` for a relative one, `FutexTimeout.At` for an absolute one), however far off.
A timeout beats a signal; a signal ends a wait with no timeout with `EINTR`, or restarts it under `SA_RESTART`, and one with a timeout, even one that never expires, with `EINTR`.
A restarted wait reads its word again, so the client makes the call again with its first arguments; a bitset wait whose waking signal has gone by the time it is finished restarts so, naming the same instant, but a `FUTEX_WAIT_PRIVATE` with a deadline, which Linux would restart with its first deadline, throws `UnmodelledException`. One whose timeout never expires restarts, as one with no timeout does.
An `op` Linux does not decode answers `ENOSYS`, as `FUTEX_CLOCK_REALTIME` on any command but a bitset wait does, after the timeout of a command that takes one is screened.
Every other command Linux has, and any command without `FUTEX_PRIVATE_FLAG`, throws `UnmodelledException`, and Darwin, which has no `futex`, throws `PlatformNotSupportedException`.

| Call | Function | Answers |
| --- | --- | --- |
| Linux's `futex(2)` | `UnixFutex.futex (caller : Caller) (address : uint64) (op : int) (value : int) (word : UserBuffer) (timeout : TimespecArgument) (val3 : uint32)` | `CallProgress<PausedFutexWait, SyscallOutcome * UnixSystem>` |
| `futex(2)`'s wait, given the word | `UnixFutex.futexWithWord (word : uint32) (paused : PausedFutexWait)` | `SyscallOutcome * UnixSystem` |

#### Signals

| Call | Function | Answers |
| --- | --- | --- |
| `kill(2)` | `UnixSignal.kill (caller : Caller) (pid : int) (signo : int)` | `ProcessFate<KillAnswer>` |
| `pthread_kill(3)`, `raise(3)` | `UnixSignal.pthreadKill (caller : Caller) (target : 'Thread) (signo : int)` | `ProcessFate<KillAnswer>` |
| `sigaction(3)` | `UnixSignal.sigaction (caller : Caller) (signo : int) (newAction : SignalDisposition option)` | `SigactionAnswer * UnixSystem` |
| `sigaction(2)`: Linux's `rt_sigaction` | `UnixSignal.sigactionSyscall (caller : Caller) (signo : int) (newAction : SignalDisposition option)` | `SigactionAnswer * UnixSystem` |
| `pthread_sigmask(3)` | `UnixSignal.pthreadSigmask (caller : Caller) (how : int) (set : SignalMask option)` | `SignalMaskAnswer * UnixSystem` |
| `sigprocmask(3)` on Linux, `sigprocmask(2)` on Darwin | `UnixSignal.sigprocmask (caller : Caller) (how : int) (set : SignalMask option)` | `SignalMaskAnswer * UnixSystem` |
| Linux's `rt_sigprocmask(2)` | `UnixSignal.rtSigprocmask (caller : Caller) (how : int) (set : SignalMask option) (sigsetSize : uint64)` | `SignalMaskAnswer * UnixSystem` |
| `sigpending(2)` | `UnixSignal.sigpending (caller : Caller)` | `SignalMask` |
| `sigsuspend(2)` | `UnixSignal.sigsuspend (caller : Caller) (mask : SignalMask)` | `SigsuspendOutcome * UnixSystem` |
| Linux's `rt_sigsuspend(2)` | `UnixSignal.rtSigsuspend (caller : Caller) (mask : SignalMask) (sigsetSize : uint64)` | `SigsuspendOutcome * UnixSystem` |
| `pause(2)` | `UnixSignal.pause (caller : Caller)` | `SigsuspendOutcome * UnixSystem` |
| the return to user mode | `UnixSignal.onReturnToUser (caller : Caller)` | `ProcessFate<ReturnToUserOutcome>` |
| `sigreturn(2)` | `UnixSignal.sigreturn (caller : Caller) (frame : HandlerFrameId)` | `UnixSystem` |

A signal mask crosses the API as a `SignalMask`, the bits of a `sigset_t` under one numbering (`SignalMask.ofWord`, `SignalMask.toWord`, `SignalMask.ofSignals`), because Darwin keeps a bit that names no signal.
A signal number is raw, under the process's own numbering: `Signal.toRawSignoUnder` and `Signal.ofRawSignoUnder` convert, with the numbering from `SimulatedUnixPlatform.signalNumbering`.
`how` is raw too: `SIG_BLOCK`, `SIG_UNBLOCK` and `SIG_SETMASK` are 0, 1 and 2 on Linux, and 1, 2 and 3 on Darwin.

#### Time, entropy, identity and threads

| Call | Function | Answers |
| --- | --- | --- |
| `clock_gettime(2)` | `UnixClock.clockGettime (caller : Caller) (clockId : int)` | `ClockGettimeAnswer` |
| `gettimeofday(2)` | `UnixClock.gettimeofday (caller : Caller)` | `UnixTimestamp` |
| Linux's `getrandom(2)` | `UnixEntropy.getRandom (caller : Caller) (buffer : UserBuffer) (count : uint64) (flags : uint32)` | `GetRandomAnswer * UnixSystem` |
| Darwin's `getentropy(2)` | `UnixEntropy.getEntropy (caller : Caller) (buffer : UserBuffer) (length : uint64)` | `GetEntropyAnswer * UnixSystem` |
| `getpid(2)` | `UnixSystem.processId (caller : Caller)` | `ProcessId` |
| `umask(2)` | `UnixSystem.umask (caller : Caller) (mask : int)` | `PermissionBits * UnixSystem` |
| `geteuid(2)` | `UnixCredentials.geteuid (caller : Caller)` | `UserId` |
| `getegid(2)` | `UnixCredentials.getegid (caller : Caller)` | `GroupId` |
| `getgroups(2)` | `UnixCredentials.getgroups (caller : Caller) (destination : UserBuffer) (size : int)` | `GetGroupsAnswer` |
| `getresuid(2)` | `UnixCredentials.getresuid (caller : Caller) (real : UserBuffer) (effective : UserBuffer) (saved : UserBuffer)` | `GetIdsAnswer<UserId>` |
| `getresgid(2)` | `UnixCredentials.getresgid (caller : Caller) (real : UserBuffer) (effective : UserBuffer) (saved : UserBuffer)` | `GetIdsAnswer<GroupId>` |
| `setresuid(3)` | `UnixCredentials.setresuid (caller : Caller) (real : UserId option) (effective : UserId option) (saved : UserId option)` | `SyscallAnswer * UnixSystem` |
| `setresgid(3)` | `UnixCredentials.setresgid (caller : Caller) (real : GroupId option) (effective : GroupId option) (saved : GroupId option)` | `SyscallAnswer * UnixSystem` |
| `setgroups(3)` | `UnixCredentials.setgroups (caller : Caller) (size : int) (words : GroupListWords)` | `SyscallAnswer * UnixSystem` |
| `clone(2)` with `CLONE_THREAD`, as `pthread_create(3)` makes it | `UnixThreadLifecycle.spawn (caller : Caller) (child : 'Thread) (cpu : CpuId)` | `SpawnAnswer * UnixSystem` |
| Linux's thread `exit(2)`, as `pthread_exit(3)` makes it | `UnixThreadLifecycle.exitThread (caller : Caller) (status : int)` | `ProcessFate<unit>` |
| `exit_group(2)`, as `exit(3)` and `_exit(2)` make it | `UnixThreadLifecycle.exitGroup (caller : Caller) (status : int)` | `EndedProcess * UnixSystem` |
| the client's report that a thread runs on a processor | `UnixScheduling.dispatch (caller : Caller) (cpu : CpuId)` | `UnixSystem` |
| where a thread is running | `UnixScheduling.runningOn (caller : Caller)` | `CpuId option` |
| Linux's `getcpu(2)` | `UnixScheduling.getcpu (caller : Caller)` | `GetCpuAnswer` |

`UnixEntropy.getRandomMaxTransfer` is the most one `getrandom` moves.
`gettid(2)` is `UnixThreadState.osThreadId` of the thread, and `getuid(2)` and `getgid(2)` are fields of `UnixSystem.credentials` of the process (`Credentials.RealUser`, `Credentials.RealGroup`).
`uname(2)` reports the platform: `SimulatedUnixPlatform.unixRelease` and `SimulatedUnixPlatform.architecture` of `UnixSystem.platform`.

#### What is not modelled

These calls have no function, and a client should refuse them rather than guess: `getppid`, `nanosleep` and `clock_nanosleep` (a client can sleep a thread as a `poll` of nothing with a timeout), `select`, `pselect` and `ppoll`, `readv` and `writev`, `sendto`, `recvfrom`, `sendmsg` and `recvmsg`, `socketpair`, `truncate`, `fsync` and `fdatasync`, `getrlimit` and `setrlimit`, `sched_yield`, `futex` operations other than a private wait and wake and their bitset forms, Darwin's `__ulock` and `__psynch` calls, `mmap` and its kin, `fork`, `exec` and `wait`, `sigaltstack`, and the timers (`alarm`, `setitimer`, `timer_create`).
"What the kernel leaves to the client" says which of those are the client's by design.

#### Calls that copy in from the caller's memory

A real kernel copies an argument in from the caller's memory at a point in the call, and what happens before that point is observable: a bad descriptor is `EBADF` whatever the buffer holds.
So a call that copies bytes in stops there.
`UnixReadWrite.write`, `UnixReadWrite.send`, `UnixReadWrite.finishWrite`, `UnixReadWrite.pwrite`, `UnixSocket.bind`, `UnixConnection.connect`, `UnixSocket.setsockopt` and `UnixSocket.getsockopt` answer a `CallProgress`, and `UnixWait.finish` holds `finishWrite`'s in `FinishedCall.PipeWrite` and `FinishedCall.ConnectionWrite`: the call's answer, reached before the copy (`CallProgress.Answered`), or the call stopped at the copy (`CallProgress.NeedsCopyIn`), holding the system and everything the call has decided.
The paused call's `copyRange` says which bytes of the caller's buffer to copy, and its resume function (`UnixReadWrite.writeWithBytes`, `sendWithBytes`, `pwriteWithBytes`, `UnixSocket.bindWithAddress`, `UnixConnection.connectWithAddress`, `UnixSocket.setsockoptWithValue`) takes exactly those and finishes the call, answering the same type `CallProgress.Answered` carries; `writeWithBytes` answers beside it the bytes the write delivered out of the machine (see "The far end of a launched pipe").
A `getsockopt` stops where the kernel reads the caller's length cell instead, and `UnixSocket.getsockoptWithLength` takes the `socklen_t` it holds.
Nothing else can be done to the system in between, since the paused call holds it.

A call whose pathname is copied in after something observable stops there too, and takes that pathname in its resume function: `rename` and `renameat` stop before the destination (`UnixNamespace.renameWithDestination`), `link` and `linkat` before the new path (`UnixNamespace.linkWithDestination`), `symlink` and `symlinkat` before the link's own path (`UnixNamespace.symlinkWithPath`), `access` and `faccessat` before the path (`UnixPathResolution.accessWithPath`), since Linux answers a bad mode or flag word without reading it, and `inotify_add_watch` before the path (`UnixInotify.inotifyAddWatchWithPath`), since Linux answers a bad mask or descriptor without reading it.
A futex wait stops where the kernel reads its word, once its timeout, bitset and address have passed their screens, and `UnixFutex.futexWithWord` takes what the word holds, read as that is called.
`clonefile` stops twice: before the source (`UnixNamespace.cloneFileWithSource`) and before the destination (`UnixNamespace.cloneFileWithDestination`).
A client that holds every argument already, such as a replayer, makes the call through `UnixSystem.step`, whose `Syscall` case holds what each copy reads (see "One entry point"), or resumes each paused call as soon as it is answered.

#### One entry point

`UnixSystem.step (caller : Caller) (call : Syscall)` makes any call a thread makes through one function, for a client that wants to log, replay or generate calls, and answers a `SteppedCall`.
`Syscall` has a case for each function in the tables above that a thread calls as a syscall, named for the call (`Syscall.MkDirAt` for `UnixNamespace.mkdirat`, `Syscall.Open` for `UnixNamespace.openPath`) and holding its arguments in the order the call's C prototype takes them.
`step` makes the call through that function, and answers the `SteppedCall` case of the same name, which holds exactly what the function answers: `SteppedCall.MkDirAt` holds a `SyscallAnswer` and the system, and `SteppedCall.GetEffectiveUserId` a `UserId` alone, since `geteuid` changes nothing.
`SteppedCall.system madeIn stepped` is the system after the call, whatever its case: the one `stepped` holds, or `madeIn`, the system `step` made the call in, where `stepped` holds none.
An argument the call copies in from the caller's memory is what that memory held: a pathname is its bytes, and a buffer the call reads, such as `write`'s, is a `CopiedArgument`, which holds the bytes (`CopiedArgument.Readable`) or why there are none, as `UserBuffer`'s cases say.
`step` hands the function's resumptions what each copy reads, and so never stops at a copy: `SteppedCall.FAccessAt` holds what `UnixPathResolution.accessWithPath` answers.
A buffer's copy is the bytes of `CopiedArgument.Readable` that the paused call's `copyRange` names, so the contents hold at least as many bytes as the call copies, and may hold more, which it does not read; `step` throws `InvalidOperationException` for contents that end before the bytes it copies.
A buffer the call writes to stays a `UserBuffer`, since what the call writes is in its answer.
The finishing functions, the return to user mode, `UnixScheduling.dispatch`, `UnixDescriptor.setNonBlocking` and `UnixDescriptor.isNonBlocking` have no case: no thread makes any of them as a call of its own.
`Syscall.Nanosleep`, `Syscall.ClockNanosleep`, `Syscall.Select`, `Syscall.PSelect`, `Syscall.SigWait`, `Syscall.SigWaitInfo`, `Syscall.SigTimedWait`, `Syscall.RecvFrom`, `Syscall.RecvMsg`, `Syscall.SendTo` and `Syscall.SendMsg` are reserved for calls this library does not model yet (see "What is not modelled"): the types their arguments and answers are held in have internal representations, nothing makes one, and `step` throws `UnmodelledException` for one.
Whatever the call, `getpid` included, `caller` must be one of the process's threads, not asleep in another call and owing no return to user mode, and `step` throws `InvalidOperationException` otherwise, as the call's own function does.

A call that can end the process answers through `step` as through its own function: `SteppedCall.Kill`, `SteppedCall.PthreadKill` and `SteppedCall.ExitThread` hold a `ProcessFate`, which is `ProcessFate.ProcessEnded` where the call ended the process, and `SteppedCall.ExitGroup` holds the ended process beside the system without it.
So does a call that sleeps, or that a signal interrupts: `SteppedCall.Accept` may hold `AcceptOutcome.WouldBlock`, which `UnixWait.finish` finishes once the thread is woken, and `SteppedCall.SigSuspend` may hold `SigsuspendOutcome.Interrupted`.
The client's loop is the same as for the calls' own functions (see "The return to user mode"): make the call; once it has ended, return the thread to user mode; and on `InterruptedCall.Restarts`, step the same `Syscall` again.
This client's second thread sleeps in an `accept` that a signal whose handler was installed with `SA_RESTART` interrupts, and the client steps the `accept` again:

```fsharp
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64
let numbering = SimulatedUnixPlatform.signalNumbering platform

let booted : UnixSystem<int, string> =
    let launch =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial platform |> UnixBootImage.boot launch

let pid = Seq.exactlyOne (UnixSystem.processIds booted)
let first = Caller.make pid 0
let second = Caller.make pid 1
let usr1 = Signal.toRawSignoUnder numbering Signal.SIGUSR1

// A thread's return to user mode, as in "The return to user mode": each handler it
// pushes runs and returns at once. The first return says how an interrupted call ends.
let rec returnToUser (caller : Caller<int>) (system : UnixSystem<int, string>) : InterruptedCall option * UnixSystem<int, string> =
    match UnixSignal.onReturnToUser caller system with
    | ProcessFate.Continues (ReturnToUserOutcome.Resumes interrupted, system) -> interrupted, system
    | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, interrupted), system) ->
        let system =
            (system, frames)
            ||> List.fold (fun system frame ->
                printfn "handler %s runs" frame.Action.Handler
                UnixSignal.sigreturn caller frame.Id system |> returnToUser caller |> snd
            )

        interrupted, system
    | other -> failwith $"unexpected at the return to user mode: %A{other}"

// The client's loop, for the calls this client makes: step the call, and unless its
// thread sleeps, return to user mode.
let make (caller : Caller<int>) (call : Syscall<int, string>) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
    match UnixSystem.step caller call system with
    | SteppedCall.Accept (AcceptOutcome.WouldBlock _, asleep) ->
        printfn "thread %d sleeps in accept" (Caller.thread caller)
        asleep
    | SteppedCall.SigAction (SigactionAnswer.Completed _, system)
    | SteppedCall.Listen (ListenAnswer.Listening _, system)
    | SteppedCall.Spawn (SpawnAnswer.Spawned _, system)
    | SteppedCall.PthreadKill (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) ->
        snd (returnToUser caller system)
    | stepped -> failwith $"unexpected from %A{call}: %A{stepped}"

// Once a wake has ended a thread's sleep: finish its call, and return to user mode;
// on a restart, step the same call again.
let resume (caller : Caller<int>) (call : Syscall<int, string>) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
    match UnixWait.finish caller system with
    | FinishedCall.Accept (AcceptOutcome.Interrupted, system) ->
        match returnToUser caller system with
        | Some InterruptedCall.Restarts, system ->
            printfn "the accept restarts"
            make caller call system
        | ending, _ -> failwith $"expected the accept to restart: %A{ending}"
    | finished -> failwith $"unexpected finish: %A{finished}"

// Thread 0 installs a handler for SIGUSR1 under SA_RESTART, and makes a socket:
// socket(AF_INET, SOCK_STREAM, 0), in Linux's numbering.
let listener, opened =
    let restarting = SignalDisposition.Catch { SignalCatch.ofHandler "on-usr1" with Restart = true }
    let installed = make first (Syscall.SigAction (usr1, Some restarting)) booted

    match UnixSystem.step first (Syscall.Socket (2, 1, 0)) installed with
    | SteppedCall.Socket (DescriptorAnswer.Returned fd, system) -> fd, snd (returnToUser first system)
    | stepped -> failwith $"unexpected from socket: %A{stepped}"

// It listens on the socket, which nothing will connect to, and starts thread 1, which
// accepts on it and sleeps. Thread 0 sends thread 1 SIGUSR1.
let accept = Syscall.Accept (listener, UserBuffer.Mapped, 16u)

let signalled =
    opened
    |> make first (Syscall.Listen (listener, 1))
    |> make first (Syscall.Spawn (1, CpuId 0))
    |> make second accept
    |> make first (Syscall.PthreadKill (1, usr1))

// The signal wakes thread 1, and the client resumes its accept, which restarts and
// sleeps again.
match UnixWait.wake signalled with
| [ woken, _ ], system when woken = second -> resume second accept system |> ignore
| wakes, _ -> failwith $"expected thread 1 to wake: %A{wakes}"

// Prints:
// thread 1 sleeps in accept
// handler on-usr1 runs
// the accept restarts
// thread 1 sleeps in accept
```

### Checking the tables

`UnixSystem.checkInvariants` lists every way a system's tables disagree with each other.
No sequence of syscalls should ever produce one: a defect is a bug in this library.
Each kind of defect has a `describe`, such as `UnixSystemDefect.describe`, which names the rule that does not hold and the values that break it, for a bug report; a client cannot match a defect's cases (see "Unions that gain cases").
It holds the machine's tables to each other and to every process on it, each process to the machine, each process's descriptor table to the open file descriptions it names, the open file descriptions to every process's descriptors, and each process to the process ID it is held under.
The filesystem's own rules are checked apart from these, by `VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes system) (UnixSystem.fileSystem system)`.
A fact a syscall needs about other processes is kept on the machine's object rather than derived from the processes: each open file description counts the descriptors naming it and the holds of calls in flight on it, the thread ID allocator records which IDs live threads hold, a kqueue records the process that owns it, whose descriptor numbers its registrations name, and each kqueue registration records the socket it is attached to.

Every descriptor lies below `SimulatedUnixPlatform.descriptorBound`, the soft `RLIMIT_NOFILE` a process of the flavour starts with (1024 on Linux, 256 on Darwin): the library assumes the process's limit is at least that, and refuses a call that would put a descriptor at or above it, whose answer would depend on the limit.

## Moving bytes

This library never reads or writes user memory.
A call that moves bytes takes them or returns them, and the client copies them to or from the process's memory.

**Reading.** `UnixReadWrite.read` answers a `ReadOutcome`.
`ReadOutcome.Answered` holds a `ReadAnswer`: the bytes read (`ReadAnswer.Completed`), for the client to copy into the caller's buffer, and whose length the call returns; or, for `/dev/urandom`, a draw from the entropy pool (`ReadAnswer.Drawn`), whose bytes the client takes with `EntropyDraw.bytes` and whose length is `EntropyDraw.count`; or an errno (`ReadAnswer.Failed`).
`ReadOutcome.WouldBlock` is a read that sleeps, and `ReadOutcome.Interrupted` one a signal interrupted, which fails with `EINTR` or restarts as the thread's return to user mode says.

**Writing.** A write stops where the kernel copies from the caller's buffer, as every call that copies in does (see "Calls that copy in from the caller's memory").

1. `UnixReadWrite.write` answers a `CallProgress`, before the kernel reads the caller's buffer: `CallProgress.Answered` is the call's answer, with no bytes read, and `CallProgress.NeedsCopyIn paused` is the call stopped at the copy. `PausedWrite.copyRange paused` says which bytes: the client copies exactly those from the caller's buffer and passes them to `UnixReadWrite.writeWithBytes`, which finishes the call. A blocking write with room for only part of it copies that part, and sleeps for the rest; a blocking write of more than a pipe holds (64 KiB on Linux) does that at once.
2. A write that sleeps answers `WriteOutcome.WouldBlock`, before or after the copy. Once `UnixWait.wake` wakes it, `UnixReadWrite.finishWrite` answers a `CallProgress` again, as `UnixWait.finish` does in `FinishedCall.PipeWrite` or `FinishedCall.ConnectionWrite`: the call's answer, or the call stopped at the copy of its next bytes, which start `copyRange.Offset` bytes into the caller's buffer, past those already written. That may sleep again, and the client repeats this step.

Every answer is a `ProcessFate<WriteOutcome>` (`writeWithBytes` answers a `Delivery option` beside it, as "The far end of a launched pipe" describes): the process ended (`ProcessFate.ProcessEnded (ended, system)`), because the write raised `SIGPIPE` at its default (see "Ending the process"), or it carries on with one of these, and the system:

* `WriteOutcome.Returns answer`: the call answers.
* `WriteOutcome.ReturnsRaising (answer, signal)`: the call answers, and raised `signal`, which is now pending (or was discarded). The one signal a write raises is `SIGPIPE`, with `EPIPE`, for a write into a pipe with no reader, into a Linux stream socket with no peer, or to a connection that was reset.
* `WriteOutcome.WouldBlock condition`: the call sleeps, as above.
* `WriteOutcome.Interrupted`: a signal interrupted the sleep before anything was written, and the call fails with `EINTR` or restarts as the thread's return to user mode says. Only `finishWrite` answers this.

`send` is the same with `UnixReadWrite.send` and `UnixReadWrite.sendWithBytes`, and is woken with `finishWrite` as a write is; `pwrite` with `UnixReadWrite.pwrite` and `UnixReadWrite.pwriteWithBytes`, never sleeps or raises a signal, and answers `WriteAnswer * UnixSystem`.

**Buffers.** Where a real kernel would check a buffer's address, the client describes the address as a `UserBuffer`, and the library decides whether and when the call answers `EFAULT`, against the limit set by `UnixBootImage.withUserAddressLimit`.
A client with a flat address space uses `UserBuffer.Mapped` for an address whose bytes it can read or write and `UserBuffer.Unmapped address` for one it cannot.
An `EFAULT` is not always a call that changed nothing: a `write` or `pwrite` of at least one byte to a regular file, through an unmapped address within the limit, strips the file's set-ID bits as a successful write would and grows the file to the write's offset before its copy faults, and moves the file's `mtime` and `ctime` on Linux always and on Darwin when the write reaches past the file's end. Darwin's answer is measured only for an unprivileged writer who owns the file, and any other writer's such write throws `UnmodelledException`.
The other two cases, `UserBuffer.Opaque` and `UserBuffer.Addressless`, are for a client whose pointers are not always numbers.

## Sleeping and waking

A call that would block does not block.
It answers `WouldBlock` with a `WakeCondition`, and the system that comes with it records the calling thread as parked in that call (`UnixThreadState.parkedIn`).
That is the state the kernel sleeps in, which can differ from the one the call arrived with: `flock` gives up the caller's old lock before it waits for the new one.

The library has no scheduler, and does not want one.
Waking is pulled rather than pushed: nothing that makes a sleeping call able to go on wakes it.
After each step, the client asks `UnixWait.wake`, which wakes every sleeping thread that may go on now, and answers each, by its `Caller`, in the order they parked, with the system in which they are woken.
A woken thread stays parked until its call is finished, and the client finishes the call when it chooses, with `UnixWait.finish`; only a woken thread's call may be finished.
A park records whether its thread has been woken (`ThreadPark.State`, `ParkState.Asleep` or `ParkState.Woken` with what woke it), so the client keeps no set of sleeping threads of its own; one it has woken and does not finish yet, it simply does not finish.
A woken thread is not woken again, and where a kernel wakes one waiter of a queue at a time, as for an epoll instance, a listener or a Linux pipe, a woken thread that has not finished its call stands for whatever woke it, so no other waiter on that queue wakes meanwhile; one a signal or its deadline alone woke stands for nothing on the queue, and the next thing to take from it wakes another waiter.
`UnixWait.satisfied` asks of one thread whether its call could get any further, and changes nothing: it is cheaper, but does not decide which of several waiters on one queue wakes, which only `wake` chooses.

A client that asks `wake` after every step, as one that interleaves instructions does, mostly asks of a system in which nothing has changed, so that is made cheap.
A system remembers the last sweep of it that woke nobody, and `wake` answers from that, asking no wake condition and answering the very system it was given, while nothing a condition reads has changed since but the clock, which has not reached any sleeping thread's deadline.
Advancing the clock, a call that changes nothing, and dispatching a thread to the processor it is on leave the memo answering; a call that changes the system, and a dispatch that moves a thread to another processor, make the next `wake` sweep.
A sweep that wakes nobody answers a new system, equal to the one it was given, which remembers the sweep: so the client keeps the system `wake` answers, as it keeps every other.
What a system remembers is no part of its value, and two systems that differ only in that are equal.

`UnixWait.finish caller` finishes the call the woken thread `caller` names is parked in, through the finishing function of the call's family.
It answers a `FinishedCall`, whose case is named as the thread's `ParkedSyscall` case is and holds exactly what that function answers: the call's answer, the thread parked again, asleep, for a new wake, or the call interrupted by a signal (`Interrupted`), whose end the thread's return to user mode says (see "The return to user mode").
A client that wants a family's own answer type calls its finishing function instead:

| The thread is parked in (`ParkedSyscall`) | Finish it with |
| --- | --- |
| `ParkedSyscall.Flock` | `UnixDescriptor.flockAcquire (caller : Caller)` |
| `ParkedSyscall.Poll`, and `ParkedSyscall.KqueuePoll` (Darwin's `poll`) | `UnixPoll.finishPoll (caller : Caller)` |
| `ParkedSyscall.EpollWait` | `UnixPoll.finishEpollWait (caller : Caller)` |
| `ParkedSyscall.Kevent` | `UnixKqueue.finishKevent (caller : Caller)` |
| `ParkedSyscall.Accept` | `UnixConnection.finishAccept (caller : Caller)` |
| `ParkedSyscall.PipeRead`, `ParkedSyscall.ConnectionRead`, `ParkedSyscall.InotifyRead` (a `read` or `recv`) | `UnixReadWrite.finishRead (caller : Caller)` |
| `ParkedSyscall.PipeWrite`, `ParkedSyscall.ConnectionWrite` (a `write` or `send`) | `UnixReadWrite.finishWrite (caller : Caller)`, then, if it stops at the copy, `UnixReadWrite.writeWithBytes (bytes : ImmutableArray<byte>) (paused : PausedWrite)` |
| `ParkedSyscall.SigSuspend` (a `sigsuspend`, `rt_sigsuspend` or `pause`) | `UnixSignal.finishSigsuspend (caller : Caller)` |
| `ParkedSyscall.Futex` (a `futex` wait) | `UnixFutex.finishFutexWait (caller : Caller)` |

Each answers what the call that parked answered, as in the tables above, and `UnixWait.finish` holds that answer in the `FinishedCall` case of the same name.

`ParkedSyscall.Sleep` (a `nanosleep` or `clock_nanosleep`, carrying a `ParkedSleep`), `ParkedSyscall.FifoOpen` (a blocking `open` of one end of a FIFO, carrying a `ParkedFifoOpen`), `ParkedSyscall.Select` (a `select` or `pselect`, carrying a `ParkedSelect`, whose representation is internal), `ParkedSyscall.SignalWait` (a `sigwait`, `sigwaitinfo` or `sigtimedwait`, carrying a `ParkedSignalWait`), `ParkedSyscall.DatagramReceive` (a blocking receive on a datagram socket, carrying a `ParkedDatagramReceive`), `ParkedSyscall.DatagramSend` (a blocking Linux Unix-domain datagram send, carrying a `ParkedDatagramSend`) and `ParkedSyscall.Connect` (a blocking Linux `connect` to a full listener, carrying a `ParkedConnect`) are reserved: nothing parks a thread in any of them yet, and none has a finishing function, so `UnixWait.finish` throws `UnmodelledException` for a thread parked in one, and `UnixSystem.checkInvariants` reports a thread parked in one as a defect.
The payloads of the datagram parks and the connect park have internal representations too, as do `FinishedSleep`, `FinishedFifoOpen`, `FinishedSelect`, `FinishedSignalWait`, `FinishedDatagramReceive`, `FinishedDatagramSend` and `FinishedConnect`, which `FinishedCall.Sleep`, `FinishedCall.FifoOpen` and the other cases named for the reserved parks hold.
So are the primitives a FIFO open, a signal wait and a Unix-domain connect wait for, `WakePrimitive.FifoPartnerOpened`, `WakePrimitive.AwaitedSignalPending` and `WakePrimitive.AcceptQueueHasRoom`, which no condition contains yet.
The cases exist so that a client's matches already handle them when sleeps, FIFOs, `select`, signal waits, datagram transfers and sleeping connects arrive.

A call that waits with a timeout (`poll`, `epoll_wait`, `kevent`, a `futex` wait) wakes once its deadline passes.
With nothing runnable, the client asks `UnixWait.deadlines`, which answers each sleeping call's deadline as an instant, in nanoseconds since boot.
The earliest is when the first of those calls times out: the client advances the clock by it less `UnixSystem.nanosecondsSinceBoot`, and asks `UnixWait.wake` again.
A `futex` wait whose timeout never expires (`FutexTimeout.Unbounded`, see "Futexes") has no deadline there: advancing the clock never ends it, as no real machine stays up long enough to.

A parked call holds the open file descriptions it waits on (`ParkedSyscall.descriptions`), as a real one holds a reference to each file: a description goes when no descriptor names it and no call holds it, so one closed under a sleeping call goes when the call returns.

This client makes a pipe, parks a second thread on reading it, wakes it with a write, and ends the process:

```fsharp
open System.Collections.Immutable
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64

let booted : UnixSystem<int, unit> =
    let launch =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial platform |> UnixBootImage.boot launch

// Every call ends with the calling thread's return to user mode, where it takes
// its signals. This client installs no handler, so it expects none to run.
let resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
    match UnixSignal.onReturnToUser caller system with
    | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
    | other -> failwith $"unexpected at the return to user mode: %A{other}"

// The process's two threads, as callers: thread 0, its leader, and thread 1,
// which thread 0 starts below. UnixSystem.processIds holds the one process.
let pid = Seq.exactlyOne (UnixSystem.processIds booted)
let first = Caller.make pid 0
let second = Caller.make pid 1

// pipe2(fds, 0) by thread 0. UserBuffer.Mapped: the array for the two
// descriptors is writable.
let readFd, writeFd, piped =
    match UnixPipe.pipe2 first 0 UserBuffer.Mapped booted with
    | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, resume first system
    | answer, _ -> failwith $"unexpected from pipe2: %A{answer}"

// Thread 0 starts a thread, which this client names 1, on processor 0.
let spawned =
    match UnixThreadLifecycle.spawn first 1 (CpuId 0) piped with
    | SpawnAnswer.Spawned _, system -> resume first system
    | answer, _ -> failwith $"unexpected from spawn: %A{answer}"

// Thread 1 reads the empty pipe, and sleeps.
let parked =
    match UnixReadWrite.read second readFd UserBuffer.Mapped 64UL spawned with
    | ReadOutcome.WouldBlock _, system -> system
    | outcome, _ -> failwith $"expected the read to sleep: %A{outcome}"

// Thread 0 writes "hello": the call stops where the kernel copies from the
// caller's buffer, and writeWithBytes takes the bytes copyRange names.
let written =
    let payload = "hello"B

    match UnixReadWrite.write first writeFd UserBuffer.Mapped (uint64 payload.Length) parked with
    | CallProgress.NeedsCopyIn paused ->
        let range = PausedWrite.copyRange paused

        match UnixReadWrite.writeWithBytes (ImmutableArray.Create (payload, range.FirstByte, range.ByteCount)) paused with
        | ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed n), system), None ->
            printfn "thread 0 wrote %d bytes" n
            resume first system
        | outcome -> failwith $"unexpected write: %A{outcome}"
    | CallProgress.Answered outcome -> failwith $"unexpected before the copy: %A{outcome}"

// The write lets thread 1 go on: the client wakes it, and finishes its call, a
// read of a pipe.
let woken =
    match UnixWait.wake written with
    | [ woken, _ ], written when woken = second ->
        match UnixWait.finish second written with
        | FinishedCall.PipeRead (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) ->
            printfn "thread 1 read %s" (System.Text.Encoding.ASCII.GetString (bytes.AsSpan ()))
            resume second system
        | finished -> failwith $"unexpected finish: %A{finished}"
    | wakes, _ -> failwith $"expected thread 1 to wake: %A{wakes}"

// Thread 1 exits, and then thread 0 calls exit_group(3), which ends the process:
// it closes the process's descriptors, and answers the system without it.
let ended, remaining =
    match UnixThreadLifecycle.exitThread second 0 woken with
    | ProcessFate.Continues ((), system) -> UnixThreadLifecycle.exitGroup first 3 system
    | other -> failwith $"thread 0 is still running, so expected the process to continue: %A{other}"

let termination = EndedProcess.termination ended

printfn "the process ended: shell status %d" (ProcessTermination.shellStatus (SimulatedUnixPlatform.signalNumbering platform) termination)
printfn "processes left: %d" (UnixSystem.processIds remaining).Count

// Prints:
// thread 0 wrote 5 bytes
// thread 1 read hello
// the process ended: shell status 3
// processes left: 0
```

## Signals

`UnixSignal.kill` and `UnixSignal.pthreadKill` generate a signal, and answer a `ProcessFate<KillAnswer>`: the process runs on (`KillAnswer.Completed KillOutcome.ProcessRuns`), with the signal pending or discarded; the signal stopped it (`KillAnswer.Completed (KillOutcome.ProcessStopped _)`); the signal killed it at once (`ProcessFate.ProcessEnded`); or the call failed, sending nothing (`KillAnswer.Failed`).
`kill` of a pid that names no process on the machine, and under Linux no thread either, is `ESRCH` (under Darwin, a number that is no signal is `EINVAL` first); a process that has ended is gone, as if its parent had reaped it.
`kill` of another process, of a process group, of process 1 (which every real machine has, and a `UnixSystem` never holds), or under Linux of a thread's ID, is refused.
Under Linux a pending signal counts against `RLIMIT_SIGPENDING`, the receiving process's limit on the signals queued for its real user in all that user's processes (`ProcessLaunch.withPendingSignalLimit`, by default `UnixSystem.defaultPendingSignalLimit`).
Past it, a real-time signal sent by `pthreadKill` is `EAGAIN`, and one sent by `kill` is lost, or pending without its sender's information if its signal was not pending in its set; a standard signal is pending as before.
A signal the process ignores, and a `SIGCONT` at its default, which has nothing to resume, are discarded as they are sent, unless the thread they are aimed at blocks them: for a signal sent to the process, that is the leader under Linux and every thread under Darwin. So such a signal never wakes a sleeping call.
One sent while blocked stays pending, and is discarded as a thread takes it.
Under Linux, `kill` of such a signal that the leader blocks while another thread does not is refused, as a caught one is: Linux would queue it for that other thread, and this library delivers a process's signals to its leader only.
Under Linux, `kill` of a caught signal is refused too while the leader is not running (it is asleep in a call, or `UnixScheduling.runningOn` answers `None`), already has a signal to take, and another thread does not block it, unless the signal is a standard one already pending on the process: Linux then wakes that other thread as well, and which of the two takes which signal depends on which returns to user mode first.
`UnixSignal.sigaction` installs a `SignalDisposition`: `SignalDisposition.Default`, `SignalDisposition.Ignore`, or `SignalDisposition.Catch` of a `SignalCatch`, made with `SignalCatch.ofHandler`, which holds the client's `'Handler`.
A client reads a signal's disposition without making a call through `SignalState.disposition numbering signal (UnixSystem.signals pid system)`, whatever its threads are doing: none need be one that may make a call, as asking `sigaction` needs. It answers what `sigaction` reports, except that it reads SIGKILL and SIGSTOP as `SignalDisposition.Default` on Darwin too, which refuses to report them.

`UnixSignal.sigprocmask` changes every thread's mask on Darwin, as Darwin's does, and refuses a call that would unblock a signal pending for a thread other than the caller: Darwin was measured neither to wake that thread for it nor always to deliver it as the thread next returns to user mode, both of which this library would do.
`UnixSignal.sigsuspend` replaces a thread's mask until a signal ends the call, and keeps the mask it replaced in the signal state (`SignalState.maskToRestore`) rather than in the park, because the call's answer comes before the thread's return to user mode, which is what restores it: the first handler frame that return pushes saves the mask from before the call.

### The return to user mode

A signal is taken as a thread returns to user mode, so after each call a thread makes, and before it runs any of its own code, the client asks `UnixSignal.onReturnToUser caller`, the caller naming the thread.
It answers a `ProcessFate<ReturnToUserOutcome>`: the process ended (`ProcessFate.ProcessEnded (ended, system)`), because a signal whose default action terminates the process killed it (see below), or it carries on (`ProcessFate.Continues (outcome, system)`) with one of these outcomes:

* `ReturnToUserOutcome.Resumes interrupted`: the thread took nothing the client acts on, and runs its own code next.
* `ReturnToUserOutcome.RunHandlers (frames, interrupted)`: the frames the kernel pushed, innermost first, each with the signal, the disposition and the mask to restore. The client runs each handler, and when one returns it calls `UnixSignal.sigreturn` with that frame's `HandlerFrame.Id` and asks `onReturnToUser` again.
* `ReturnToUserOutcome.ProcessStopped signal`: a signal whose default action stops the process stopped it (see below). Where another signal is still deliverable to the thread, its return is not over, and a client that carries on asks `onReturnToUser` again.
* `ReturnToUserOutcome.ContinueDiscarded signal`: the kernel discarded a `SIGCONT` at its default, pending while the thread blocked it, as the thread took it, and the client asks `onReturnToUser` again, since the return goes on, under a `sigsuspend`'s temporary mask if the thread is returning from one.

`interrupted` is `Some` only for the return from a call that answered `Interrupted`: as it was finished (through `UnixWait.finish` or its family's finishing function), or, for a `sigsuspend` or `pause`, as it was made with a signal already pending.
Such a call ends here, as a real kernel ends it as the thread returns, from the signals as they are now, which another thread may have changed since the call was interrupted.
`Some InterruptedCall.FailsWithEintr` is the call returning -1 with `EINTR`, once every handler pushed has returned.
`Some InterruptedCall.Restarts` is the call restarting: once every handler pushed has returned, the client makes the same call again, with the arguments it was first made with, as a real kernel rewinds the thread to make it again.
The handlers that run decide by their `SA_RESTART`, as `SyscallInterruption.ruleOf` says of the call.
When none runs, because another thread has since ignored the signal or reset it to a default that discards it, the call restarts, except Linux's `epoll_wait` and Darwin's `poll` and `kevent`, which fail with `EINTR`; a default that terminates the process ends it, as at any return.
The same holds where another thread ignores the signal after it has woken the thread and before the call's finishing function runs: that function answers `Interrupted` for Linux's `epoll_wait` and Darwin's `poll` and `kevent`, whose return then fails them with `EINTR`, and puts any other call back to sleep, which is its restart; it refuses an `epoll_wait`, `kevent` or Darwin `poll` with a timeout, for which what happens then is unmeasured.
The return is refused for an interrupted call where the first signal it takes stops or continues the process, where the handlers it runs disagree about `SA_RESTART` for a call that restarts under it, where no handler runs for a Linux `poll` with a timeout (which Linux restarts with what is left of its timeout) or for an `epoll_wait`, `kevent` or Darwin `poll` with one, under Darwin where the end it gives differs from the end the return would have given as the call was interrupted, since Darwin may decide as the woken thread runs, and where no handler runs for a `sigsuspend` or `pause` and the mask the return gives back lets through a signal the call's temporary mask kept pending, which is unmeasured.

A thread owes its return to user mode after a call that answered `Interrupted`, and from the moment a signal is deliverable to it: pending where it takes signals from, and not blocked by its mask.
A real thread takes such a signal before it runs more of its own code, whichever thread sent it: one that is running is interrupted to take it, and one that is not takes it as it is next scheduled.
A signal becomes deliverable to a thread as it is sent to the thread, by `pthreadKill` or a Linux write's `SIGPIPE`, or to the process, by `kill` or a Darwin write's or close's `SIGPIPE`, whose leader takes it unless it blocks it; as a mask call or a `sigreturn` unblocks it; under Linux, as the frames a leader's return pushes come to block one of the process's that another thread does not block, which that thread then takes; and, for a signal that became deliverable to a thread asleep in a call, as the call answers or is interrupted.
Until the thread has returned, any other call it makes throws `InvalidOperationException`.
So the client's loop is: make the call, or finish it with `UnixWait.finish` once it is woken; return to user mode, running the handlers that return pushes; and on `InterruptedCall.Restarts` make the call again.
A call by one thread can leave another owing its return, so before a thread runs more of its own code, the client asks `UnixSignal.owesReturn caller`, and returns the thread to user mode where it answers `true`.
It answers `true` exactly when any call the thread made now would throw for the return it owes, and changes nothing; it answers `false` for a thread asleep in a call, which owes nothing until the call has answered, and for a name that is no thread of the process.
`onReturnToUser` may be asked at any other time the thread is in no syscall, as at a preemption point, and answers `Resumes None` for a thread that takes nothing.

A signal whose default terminates the process ends it where the library applies the default: at generation, when some thread can take it (from `kill`, `pthreadKill`, or a write that raises `SIGPIPE`), and otherwise when a thread that blocked it can take it, as the thread returns to user mode (from `onReturnToUser`): after a mask call or a `sigreturn` that unblocks it, or from a `sigsuspend` whose temporary mask lets it through.
For a signal sent to the process while every thread blocked it, that thread may be any of the process's threads under Linux, whose threads all take from the process's pending set; a signal whose default stops the process is taken the same way.
Under Darwin, which put such a signal in its leader's own set as it was sent, a thread other than the leader that unblocks it does not take it, and while it is pending so, `onReturnToUser` refuses every thread.
Either answer is `ProcessFate.ProcessEnded` of the `EndedProcess`, killed by the signal (`ProcessTermination.Signaled`, with the core flag), and the system without the process, which ended as an exit ends it; no handler runs, not even one whose frame was pushed at the same return.

A signal whose default stops the process is reported (`KillOutcome.ProcessStopped`, `ReturnToUserOutcome.ProcessStopped`) for the client to act on.
The library holds no stopped state, and nothing here continues a stopped process, so a client should refuse a stop rather than carry on as if the process were still running.

This client blocks `SIGTERM`, sends it to itself, and dies of it as it unblocks it:

```fsharp
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64
let numbering = SimulatedUnixPlatform.signalNumbering platform

let booted : UnixSystem<int, unit> =
    let launch =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial platform |> UnixBootImage.boot launch

// Thread 0 of the process, its leader, makes each call.
let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0

let returnToUser (system : UnixSystem<int, unit>) : ProcessFate<ReturnToUserOutcome<int, unit>, int, unit> =
    UnixSignal.onReturnToUser leader system

let resumed (fate : ProcessFate<ReturnToUserOutcome<int, unit>, int, unit>) : UnixSystem<int, unit> =
    match fate with
    | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
    | other -> failwith $"unexpected at the return to user mode: %A{other}"

// pthread_sigmask(how, {SIGTERM}, NULL), with `how` under Linux's numbering:
// SIG_BLOCK is 0 and SIG_UNBLOCK 1. Its errno is SignalMaskAnswer.Failed.
let sigterm = SignalMask.ofSignals numbering (Set.singleton Signal.SIGTERM)

let mask (how : int) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
    match UnixSignal.pthreadSigmask leader how (Some sigterm) system with
    | SignalMaskAnswer.Completed _previous, system -> system
    | SignalMaskAnswer.Failed errno, _ -> failwith $"pthread_sigmask failed: %O{errno}"

let blocked = booted |> mask 0 |> returnToUser |> resumed

// kill(getpid(), SIGTERM): the signal stays pending, because thread 0 blocks it.
let pending =
    let pid = ProcessId.toInt32 (UnixSystem.processId leader blocked)
    let signo = Signal.toRawSignoUnder numbering Signal.SIGTERM

    match UnixSignal.kill leader pid signo blocked with
    | ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system) -> system |> returnToUser |> resumed
    | ProcessFate.Continues (KillAnswer.Failed errno, _) -> failwith $"kill failed: %O{errno}"
    | outcome -> failwith $"unexpected kill: %A{outcome}"

// Unblocking it: as thread 0 returns to user mode it takes SIGTERM, whose
// default action ends the process.
match pending |> mask 1 |> returnToUser with
| ProcessFate.ProcessEnded (ended, _) ->
    let termination = EndedProcess.termination ended

    printfn "%A" termination
    printfn "shell status %d" (ProcessTermination.shellStatus numbering termination)
| other -> failwith $"expected SIGTERM to end the process: %A{other}"

// Prints:
// Signaled (SIGTERM, false)
// shell status 143
```

This client's second thread sleeps in a `read` of an empty pipe, a signal whose handler was installed with `SA_RESTART` interrupts it, and the thread's return to user mode runs the handler and restarts the read, which the client makes again:

```fsharp
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64
let numbering = SimulatedUnixPlatform.signalNumbering platform

let booted : UnixSystem<int, string> =
    let launch =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    UnixSystem.initial platform |> UnixBootImage.boot launch

let pid = Seq.exactlyOne (UnixSystem.processIds booted)
let first = Caller.make pid 0
let second = Caller.make pid 1
let usr1 = Signal.toRawSignoUnder numbering Signal.SIGUSR1

// A thread's return to user mode: each handler it pushes, innermost first, runs and
// returns at once, and its sigreturn is a return to user mode of its own. The first
// return says how an interrupted call ends.
let rec returnToUser (caller : Caller<int>) (system : UnixSystem<int, string>) : InterruptedCall option * UnixSystem<int, string> =
    match UnixSignal.onReturnToUser caller system with
    | ProcessFate.Continues (ReturnToUserOutcome.Resumes interrupted, system) -> interrupted, system
    | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, interrupted), system) ->
        let system =
            (system, frames)
            ||> List.fold (fun system frame ->
                printfn "handler %s runs for %A" frame.Action.Handler frame.Entry.Signal
                UnixSignal.sigreturn caller frame.Id system |> returnToUser caller |> snd
            )

        interrupted, system
    | other -> failwith $"unexpected at the return to user mode: %A{other}"

// Thread 0 installs a handler for SIGUSR1 under SA_RESTART, makes a pipe, and starts
// thread 1, returning to user mode after each call.
let handled =
    let action = SignalDisposition.Catch { SignalCatch.ofHandler "on-usr1" with Restart = true }

    match UnixSignal.sigaction first usr1 (Some action) booted with
    | SigactionAnswer.Completed _, system -> snd (returnToUser first system)
    | SigactionAnswer.Failed errno, _ -> failwith $"sigaction failed: %O{errno}"

let readFd, piped =
    match UnixPipe.pipe2 first 0 UserBuffer.Mapped handled with
    | Pipe2Answer.Created (readFd, _), system -> readFd, snd (returnToUser first system)
    | answer, _ -> failwith $"unexpected from pipe2: %A{answer}"

let spawned =
    match UnixThreadLifecycle.spawn first 1 (CpuId 0) piped with
    | SpawnAnswer.Spawned _, system -> snd (returnToUser first system)
    | answer, _ -> failwith $"unexpected from spawn: %A{answer}"

// Thread 1 reads the empty pipe, and sleeps; thread 0 sends it SIGUSR1.
let read (system : UnixSystem<int, string>) = UnixReadWrite.read second readFd UserBuffer.Mapped 64UL system

let signalled =
    match read spawned with
    | ReadOutcome.WouldBlock _, asleep ->
        match UnixSignal.pthreadKill first 1 usr1 asleep with
        | ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system) -> snd (returnToUser first system)
        | other -> failwith $"unexpected from pthread_kill: %A{other}"
    | outcome, _ -> failwith $"expected the read to sleep: %A{outcome}"

// The signal wakes thread 1, and its read, finished, was interrupted. Its return to
// user mode runs the handler and says how the read ends.
let restarted =
    match UnixWait.wake signalled with
    | [ woken, _ ], woken' when woken = second ->
        match UnixWait.finish second woken' with
        | FinishedCall.PipeRead (ReadOutcome.Interrupted, system) ->
            printfn "the read was interrupted"

            match returnToUser second system with
            | Some InterruptedCall.Restarts, system ->
                printfn "the read restarts"
                system
            | ending, _ -> failwith $"expected the read to restart: %A{ending}"
        | finished -> failwith $"unexpected finish: %A{finished}"
    | wakes, _ -> failwith $"expected thread 1 to wake: %A{wakes}"

// The client makes the read again, as the restart says, and it sleeps again.
match read restarted with
| ReadOutcome.WouldBlock _, _ -> printfn "thread 1 sleeps in its read again"
| outcome, _ -> failwith $"unexpected from the read made again: %A{outcome}"

// Prints:
// the read was interrupted
// handler on-usr1 runs for SIGUSR1
// the read restarts
// thread 1 sleeps in its read again
```

## Threads, and the end of the process

`UnixThreadLifecycle.spawn caller child cpu` starts a thread the client names `child`, on processor `cpu`, with a copy of the caller's signal mask, and answers its thread ID, an `OsThreadId` (`SpawnAnswer.Spawned`).
`UnixThreadLifecycle.exitThread caller status` ends the caller's thread, and answers `ProcessFate.Continues` with the process carrying on, or `ProcessFate.ProcessEnded` if it was the last.
It throws `InvalidOperationException` for a thread parked in a syscall, and refuses the process's leader while any other thread lives and, on Darwin, the process's last thread: a Darwin client ends a process with `exitGroup`, never by its last thread exiting.
`UnixThreadLifecycle.exitGroup caller status` ends every thread at once, parked ones included.

A process ends in the call that ends it: `exitGroup`, an `exitThread` of the last thread, a `kill`, `pthreadKill`, write or `send` whose signal killed it, and a return to user mode that takes such a signal.
That call answers an `EndedProcess` beside the system without the process, in which every other process is as the call left it: `exitGroup` answers the pair, and the others `ProcessFate.ProcessEnded (ended, system)`.
`EndedProcess.termination` is how the process ended (`ProcessTermination.Exited` or `ProcessTermination.Signaled`), which is what its parent's `wait` reads; `ProcessTermination.waitpidStatus` encodes it as `waitpid(2)` would.
`EndedProcess.processId` is which process it was.

The end is what a real kernel does at exit, where another process can see it: every thread goes, with what only the process's calls held, and then every descriptor is closed, in the order each kernel measurably closes them (Linux drops them lowest first and releases the last let go of first; Darwin closes them highest first), as `close` closes each: sending its peers their FINs, or resets where it left bytes unread, resetting the clients left in its listeners' accept queues, whichever process holds them, and letting its locks, pipes, listeners and event queues go.
The process is then gone: no `wait` is modelled, so nothing keeps it for a parent to reap, and no call can be made in it.
A call refuses to end a process where a close would refuse: so far, the last close of a connected socket whose `SO_LINGER` would make it wait, and two Darwin closes whose outcome waits on a timer or on the peer's reads.
Such a call throws `UnmodelledException`, and, as for any refusal, the system it was given still holds the process.

## Several processes

A `UnixSystem` holds every process on its machine.
`UnixSystem.processIds` lists them, and `UnixSystem.launch launch` starts another from a `ProcessLaunch`, whose current directory (`ProcessLaunch.withCurrentDirectory`) must exist in the machine's filesystem: it answers the process ID the kernel chose, as Linux does from its thread ID counter and Darwin from a process ID counter of its own, and the system with the process on it.
Each process names its own threads: two processes may both call a thread `0`, and their callers differ.

Every call names its caller's process, and is made in that process: it can read and change that process's own state and the machine, and no other process's own state, and the system it answers holds every other process as it was.
So a client keeps one system, and makes each process's calls in it in whatever order it interleaves them.
Everything one process's call does to another goes through the machine they share: ports, connections, pipes, files and their locks, the open file descriptions, the directories processes stand in, the thread and process IDs, and the processors.
A dispatch can displace another process's thread from its processor.
`UnixSystem.checkInvariants` holds every process to the machine and to each other.

This client launches a second process beside the first, has each duplicate its standard output, and ends the second:

```fsharp
open WoofWare.PosixKernel

let platform = SimulatedUnixPlatform.linuxX64

// A process with the three piped standard streams, and one thread, which this
// client names 0 in every process, on processor 0.
let launch : ProcessLaunch<int> =
    ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

let booted : UnixSystem<int, unit> =
    UnixSystem.initial platform |> UnixBootImage.boot launch

let first = Seq.exactlyOne (UnixSystem.processIds booted)

// The kernel chooses the second process's ID, and answers the system with it on.
let second, both = UnixSystem.launch launch booted

// dup(1), made by thread 0 of the process `pid`.
let dup (pid : ProcessId) (system : UnixSystem<int, unit>) : int * UnixSystem<int, unit> =
    match UnixSystem.step (Caller.make pid 0) (Syscall.Dup 1) system with
    | SteppedCall.Dup (DescriptorAnswer.Returned fd, system) -> fd, system
    | _ -> failwith "unexpected from dup"

// Each process numbers its own descriptors, so each gets 3.
let firstFd, afterFirst = dup first both
let secondFd, afterSecond = dup second afterFirst
printfn "process %O got %d, process %O got %d" first firstFd second secondFd

// The second process's thread 0 calls exit_group(0), which ends the process
// and answers the system without it.
let ended, remaining = UnixThreadLifecycle.exitGroup (Caller.make second 0) 0 afterSecond
let termination = EndedProcess.termination ended

printfn "shell status %d" (ProcessTermination.shellStatus (SimulatedUnixPlatform.signalNumbering platform) termination)
printfn "processes left: %A" (UnixSystem.processIds remaining |> Seq.map ProcessId.toInt32 |> List.ofSeq)

// Prints:
// process 4242 got 3, process 4243 got 3
// shell status 0
// processes left: [4242]
```

A call asleep in one process wakes for what another process's call does: a connection queued on its listener, bytes arriving on its socket or room freed in its send buffer, a peer's FIN or reset, a lock let go of.
`UnixWait.wake` wakes the sleeping threads of every process at once.
Each sleeping thread's condition is asked of its own process, and where a kernel wakes one waiter of a queue at a time, the one is chosen across every process by the machine's park order; a woken thread that has not finished its call holds such a queue, in whichever process, if something to take from the queue woke it.
A woken call is finished by `UnixWait.finish` of its own thread's caller, in whichever process.
A kqueue registration, and a filter a sleeping Darwin `poll` registered, is attached to the socket its descriptor named, as XNU attaches a knote to the socket, so an event on the socket reaches it whichever process caused the event; a sleeping Darwin poll's kqueue (`PollQueue`) is the machine's for as long as the call sleeps.
A client reads that kqueue through `UnixSystem.pollQueue`, then `PollQueue.registered`, `PollQueue.entry` and `PollQueue.activated`.
A kqueue's own registrations, and what each is attached to, are not public (`KqueueState`'s representation is internal), so a later version can attach a registration to a pipe or a timer without a change of shape.
`KqueueFilter.Timer` is reserved: `kevent` refuses `EVFILT_TIMER`, and a poll registers only `KqueueFilter.Read` and `KqueueFilter.Write`, so nothing registers a timer yet.

Nothing passes a descriptor from one process to another (no `fork`, no `SCM_RIGHTS`, and a launched pipe's other end is the client's), so no pipe, listener or epoll instance is shared, and `kill` of another process is refused.

## What the kernel leaves to the client

A running process relies on more than its kernel, and this library is only the kernel.
Each part below is something a real process has which this library does not do, so the client must.
For each part, this section says what the part is, why it belongs to the client, and how the client and the library meet at that line.
Where a part was placed by a decision, that is said; where it is only how things stand today, that is said instead.

### User memory

**What.** The process's address space, and the calls that change it: `mmap`, `munmap`, `mprotect`, `brk`.
A thread's stack and its thread-local storage are part of it.

**Why the client's.** The client runs the process's code, so it already holds every byte that code loads and stores.
A second copy in the kernel would have to agree with the client's after every store.
A syscall needs only the bytes it moves, and the client can hand those over.

**Where they meet.** See "Moving bytes": the library takes and returns the bytes a call moves, and decides from a `UserBuffer` whether and when a call answers `EFAULT`.
A pointer that a C library function dereferences in the process itself, before it makes any system call, is the client's to answer for, since no kernel is involved.

A mapping of a file is not modelled, and a client should refuse one rather than copy the file's bytes into memory of its own.
Its pages are the file's bytes, and it holds the file's open file description as a descriptor does, so it crosses this line: a private copy would not see later writes through a descriptor, and the library would not count the mapping as holding the file open.
Nothing here maps a file.

### Blocks inside the process

**What.** A thread that waits without asking the kernel to watch a descriptor or a clock: Darwin's `__psynch_*` and `__ulock_*` calls, Linux's `futex` operations other than a private wait and wake and their bitset forms, and the mutexes, condition variables and timed waits that the C library builds on them.

**Why the client's, for now.** Each is keyed by a user address and reads or writes user memory, which is the client's (see above).
Linux's private `futex` wait and wake, and their bitset forms, are the kernel's (see "Futexes"): the client hands over the word it reads, as it hands over any bytes a call copies in.
The rest the client keeps itself for now; the long-term plan is to model them in the kernel too, so that every block happens there and the client has no blocked threads of its own (see [the tracking issue](https://github.com/Smaug123/WoofWare.PawPrint/issues/1726)).

**Where they meet.** A thread the client holds blocked is parked in no call this library knows of, so as far as the library knows it could run.
The client removes such threads from the set this library would call runnable (see the next part).
`UnixWait.wake` decides only the parks this library recorded: whether a signal or a deadline ends one of the client's own blocks is the client's to decide.
When nothing can run, the client advances the clock to the earlier of its own deadlines and those `UnixWait.deadlines` reports.

### Which thread runs

**What.** Choosing the next thread to run, and on which processor.

**Why the client's.** By decision: the kernel never chooses which thread runs.
It answers which threads could run (not parked in the kernel; the client subtracts its own blocked threads), and records what the client says happened.
Choosing is policy, and a client that explores schedules, or a harness that steers one from outside, must own it; the kernel keeps only the facts a choice is made from.

**Where they meet.** `UnixSystem.threads` lists a process's threads, and `UnixThreadState.parkedIn` says which are parked in a syscall.
The client asks `UnixWait.wake`, which wakes the parked threads that may go on now and records them woken; it decides when a woken thread finishes its call (`UnixWait.finish`).
Which processor a thread belongs on is the client's policy too.
The client reports each thread it runs with `UnixScheduling.dispatch caller cpu`: "the thread `caller` names is now running on processor c".
The kernel keeps what Linux keeps.
Each thread has a processor, the one it last ran on, or before it first runs, the one its creator named (`ProcessLaunch.create`, `UnixThreadLifecycle.spawn`); `UnixThreadState.cpu` reports it, for a thread found in `UnixSystem.threads`.
Each processor runs at most one thread, so a dispatch displaces whichever thread the processor ran before, whatever process it belongs to; that thread keeps the processor as its own, as a preempted thread does.
A thread stops running when it parks in a syscall, and when it exits or its process ends; a parked thread may still be dispatched, which is how a woken thread gets back onto a processor to finish its call.
`UnixScheduling.runningOn` says where a thread is running, and `UnixScheduling.getcpu` answers only for a running thread, throwing `InvalidOperationException` for any other: a thread making a syscall is running, so a client whose records say otherwise has a bug.
Nothing else requires its caller to have been dispatched, so a client that never reads placement need never report it, and a woken thread's call can be finished without a dispatch first.
Every processor named must be one the machine has (`UnixSystem.processorCount`).
Not built yet: recording the processor time a thread used, and a default policy (round-robin, and PCT, probabilistic concurrency testing) as a module that knows nothing of the kernel.

### When time passes

**What.** How far the clock moves, and when.

**Why the client's.** Only the client knows how long the process's code took to run, and how fast its simulated machine is.
Nothing in this library moves the clock on its own.
By decision, `UnixSystem.advanceClock` stays a function from one system to the next, with no other result.
If clock-driven signals (`alarm`, `setitimer`, `timer_create`) are modelled later, an expiry will be written into the state as a pending signal, which the client finds through `UnixWait.wake` as it finds a passed deadline.

**Where they meet.** The client calls `UnixSystem.advanceClock nanoseconds` between syscalls, to move the clock on by that many nanoseconds, and reads the time with `UnixSystem.nanosecondsSinceBoot`.
With nothing runnable, the earliest of `UnixWait.deadlines` is the instant the first sleeping call times out (see "Sleeping and waking").
An administrator's write of Linux's `kernel.pid_max` is the outside world acting on the machine in the same way: `UnixSystem.writePidMaxSysctl`.

### The errno slot

**What.** The per-thread `errno` that a C program reads after a failed call.

**Why the client's.** On a real Unix, `errno` lives in the C library rather than in the kernel: the kernel returns an error code, and the syscall wrapper stores it.
The same goes for the C library's other state in user space, such as the copy of the environment that `setenv` and `putenv` change.

**Where they meet.** A failed call answers `Failed` with a `UnixError`.
The client converts it to a number with `UnixError.toRawErrnoUnder` and stores it wherever its C library would.
The environment the library holds is the one the process was started with (`ProcessLaunch.withEnvironment`).

### Running a signal handler

**What.** Running the handler's code on the thread, on some stack, with the arguments it expects.

**Why the client's.** The handler is the process's code, and the client runs that code.
The library never learns what a handler is: it stores whatever the client passes as `'Handler` and hands it back.

**Where they meet.** `UnixSignal.onReturnToUser` answers the frames to run, and `UnixSignal.sigreturn` pops one (see "The return to user mode").
A `SignalCatch` holds only the flags that change what the kernel does (`SA_NODEFER`, `SA_RESETHAND`, `SA_RESTART`); `SA_SIGINFO` and `SA_ONSTACK` choose how and on which stack the client calls its handler, so a client that honours them keeps them with its `'Handler`.
A handler that leaves by `siglongjmp` instead of returning has no operation yet.

### The alternate signal stack

**What.** `sigaltstack`, which names a region of memory for handlers to run on.

**Why the client's.** The region is user memory, and the answers `sigaltstack` gives (`SS_ONSTACK`, and `EPERM` for changing the stack while on it) depend on the user stack pointer, which only the client knows.
If a client needs it answered, a form that takes the client's stack pointer as an argument would be small.

**Where they meet.** Nowhere yet: the library has no `sigaltstack`, and runs no handler, so it never chooses a stack.

### Starting and ending processes

**What.** Creating a process, choosing the program it runs, and collecting its exit status.

**Why the client's.** There is no `fork`, `exec` or `wait`.
Loading and running a program is the client's, as running any of the process's code is, and `fork`'s copy of the address space would be a copy of user memory.
The descriptor table, signal dispositions, mask and credentials that `fork` and `exec` pass on are the kernel's, so those calls would be the library's to model; they are not modelled, and a client should refuse a process's request to create or replace a process.

**Where they meet.** The client starts a process with `UnixSystem.launch` and a `ProcessLaunch`, which sets up what a launcher fixes before `exec`; the kernel chooses the process ID.
The call that ends a process closes its descriptors and removes it, and answers an `EndedProcess` beside the system without it: `EndedProcess.termination` is how it ended, a `ProcessTermination` holding the status a parent's `wait` would read.
No `wait` is modelled, so nothing keeps the ended process for a parent to reap, and reporting its status is the client's.

### The far end of a launched pipe

**What.** Whatever sits outside the simulated machine at the other end of a process's launch descriptors, such as its standard streams.

**Why the client's.** It is the outside world, which the client stands in for.
The pipe itself is the kernel's: its capacity, atomic writes and `EPIPE` are measured rules that the library holds and tests.
So the client chooses only what its end does: supply bytes (`LaunchDescriptor.Supplied`), read every byte (`LaunchDescriptor.Drained`), or be closed already (`LaunchDescriptor.Gone`).

**Where they meet.** The client reads what the process wrote as the process writes it: `UnixReadWrite.writeWithBytes` answers, beside the write's fate, the `Delivery` it made into a pipe the client drains, naming the client's end and holding the bytes (`SteppedCall.Write` carries it too).
The kernel keeps no record of what it delivered, since those bytes have left the machine; a client that wants a process's whole output keeps the deliveries itself, in the order the writes answered.

## Flavours and divergence from host platforms

WoofWare.PosixKernel's behaviour does not depend on the host platform; indeed, it probably works on Windows.
However, POSIX is extremely underspecified (and implementations frequently diverge from their documentation!),
and I only have easy access to a few flavours.

A `SimulatedUnixPlatform` names the kernel being simulated: its flavour (Linux or Darwin) and the version of the source it was built from (`LinuxKernelVersion` or `DarwinKernelVersion`), its architecture, its page size and its release.
The release is only what `uname` reports; where a kernel's behaviour changed between versions, the platform's version decides which answer applies.
Only the combinations that have been measured can be built: Linux on x86-64 and on aarch64 with 4 KiB pages, and Darwin on arm64 with 16 KiB pages.
`SimulatedUnixPlatform.linuxX64`, `SimulatedUnixPlatform.linuxArm64` and `SimulatedUnixPlatform.macOsArm64` are the presets.
Where the flavours disagree, the platform says which answer applies, down to whose numbering an errno or a signal is reported in.
The filesystem type is chosen separately (see "Giving the machine files"), from those its flavour has been seen to report.

The kernel mounts a device filesystem over `/dev` at boot, as a real one does.
On Linux it is a devtmpfs holding a node for each device the kernel has a driver for (`/dev/null` and `/dev/urandom`); since a real devtmpfs holds hundreds, any other name in it is refused rather than answered ENOENT, and so are listing it and adding or removing a name in it.
Opening a node gives a descriptor whose syscalls are the driver's: `/dev/null` reads nothing and swallows every write, and `/dev/urandom` reads from the same entropy pool `getrandom` draws on.
Every time on `/dev` and its nodes is the epoch, whatever `withFileSystem` and `withBootTime` say: a devtmpfs makes them before the realtime clock is first set, which on a measured aarch64 machine left them within a few milliseconds of the epoch. No read or write moves them, and mounting `/dev` moves none of the root directory's times.
`CharacterDevice.Zero`, `CharacterDevice.Random` and `CharacterDevice.Tty` exist too, so that a client's matches already handle them when their drivers arrive, but nothing produces them yet: `CharacterDevice.all` does not list them, so no node names any of them.
On Darwin it is devfs, which is not modelled, so any path that reaches `/dev` is refused.

Some interfaces are one flavour's alone, and the other flavour refuses every call of them rather than answering: no kernel of that flavour has the call, so there is no answer to measure.
Linux has epoll and inotify, and Darwin kqueue.

WoofWare.PosixKernel is intended to be fully POSIX-compliant eventually.
A design goal of WoofWare.PosixKernel is that the library refuses rather than providing an answer which has not been measured on the platform it's been told to simulate.
It is fully deterministic, so e.g. it chooses a traversal order for directory listing even though that is POSIX-unspecified.
We try very hard to return only values that we have observed from a real system using that platform, rather than just copying semantics from the docs.

Where real platforms of a given flavour have been observed to disagree, we choose a permitted answer (generally an *inconvenient* one, since I want to help you avoid accidentally relying on unspecified behaviour).
For example, directory enumeration order has been observed to be extremely odd on Linux: we've even seen `..` and `.` appear at the *end* of the enumeration, in the GitHub Actions ext4 runner!

## Changing its API

The library's public API is recorded in `SurfaceBaseline.txt`, beside its project file, and a test in `WoofWare.PosixKernel.Test` fails whenever the compiled API differs from it.
After an intended change to the API, regenerate the file and commit it with the change:

```sh
nix develop -c dotnet test WoofWare.PosixKernel.Test/WoofWare.PosixKernel.Test.fsproj --filter "FullyQualifiedName~TestSurface&Name~Update"
```

(The NUnit adapter cannot parse a filter value containing spaces, so the filter cannot give the test's full name, which has them.)
A conflict in `SurfaceBaseline.txt` after a rebase is resolved by regenerating the file, never by hand.

The file also records the order of each union's cases: F# numbers the cases of a union of more than one case in a nested `Tags` class, and the file gives each tag's value, as in `WoofWare.PosixKernel.AbsoluteUnixPathError+Tags.ContainsNul [static field]: int = 2`.
A second test fails if a union has lost or reordered cases, or has gained a case anywhere but at its end, since the version the file records.
Code built against the recorded version would then misread the cases it already knew, which an appended case does not make it do.
From 1.0 an appended case is a major version too (see "Unions that gain cases" above), and the first test already fails on one.
It also fails if a union whose cases the file records as public no longer has public cases, which is expected when a union becomes internal, or is deleted or renamed.
Before 1.0 such a change may still be made deliberately, by the same command.

A third test fails if a public record that the file does not list, or a field that a listed record has gained, uses a field label that another listed record already has.
F# resolves a label that several records share to the most recently declared of them, in a record pattern, in a `x.Label` access on a value whose type is not yet inferred, and in a record expression whose labels do not single out one record.
So a reused label can change which record a client's existing code means, and that code can stop compiling.
Labels that listed records already share, such as `Address` in `Ipv4Endpoint` and `Ipv6Endpoint`, are allowed.
Before 1.0 the fix is to rename the field; regenerating the file instead allows the collision from then on, and is a deliberate choice.

## Licence

MIT.
