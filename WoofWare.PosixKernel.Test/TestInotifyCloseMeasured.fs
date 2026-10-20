namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.Text
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyReplay

/// What an open file description's release queues on the inotify instances
/// watching it, replayed against what Linux 6.18.5 aarch64 answered in
/// docs/probes/inotify-close/inotify-close-probe.c: `IN_CLOSE_WRITE` for a
/// description opened for writing, written through or not, and
/// `IN_CLOSE_NOWRITE` for any other, as one through the name it was opened
/// through, when its last reference goes. Each test makes the probe's calls on
/// the model, renders each row as the probe printed it, and compares the rows
/// with the recorded ones.
///
/// Rows are skipped, each named, where the model cannot make the call: an open
/// with `O_APPEND` or `O_PATH`, and of a FIFO, which it does not model; a
/// `fork`, which it leaves to the client; and a write to `/dev/null`, whose
/// `IN_MODIFY` at the device's own watch it does not raise.
///
/// The probe removes and remakes one directory per case; the replay boots a
/// machine per case instead.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestInotifyCloseMeasured =

    let private probe = lazy recorded "WoofWare.PosixKernel.Test.inotifyClose.linux.txt"

    let private exclUnlink : uint32 = 0x04000000u

    let private directoryFlags : OpenFlags =
        { openFlags FileAccessMode.ReadOnly false false false with
            Directory = true
        }

    let private readOnly : OpenFlags =
        openFlags FileAccessMode.ReadOnly false false false

    let private writeOnly : OpenFlags =
        openFlags FileAccessMode.WriteOnly false false false

    let private readWrite : OpenFlags =
        openFlags FileAccessMode.ReadWrite false false false

    let private expected (section : string) (skipped : string list) : (string * string) list =
        rows probe section skipped

    let private actual (skipped : string list) (produced : (string * string) seq) : (string * string) list =
        produced
        |> List.ofSeq
        |> List.filter (fun (case, _) -> not (List.contains case skipped))

    /// Records `case` with the drained records of `fd`, after `prefix`.
    let private rowOf
        (produced : ResizeArray<string * string>)
        (fd : int)
        (case : string)
        (prefix : string)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let drained, system = drain fd system
        produced.Add (case, $"%s{prefix}%s{drained}")
        system

    /// What a read of up to `count` bytes through `fd` returned.
    let private readCount
        (fd : int)
        (count : int)
        (system : UnixSystem<int, string>)
        : int64 * UnixSystem<int, string>
        =
        match UnixReadWrite.tryRead (Callers.thread 0 system) fd UserBuffer.Mapped (uint64 count) system with
        | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) -> int64 bytes.Length, system
        | other -> failwith $"read(%d{fd}): %A{other}"

    /// What a write of `text` through `fd` returned.
    let private writeCount
        (fd : int)
        (text : string)
        (system : UnixSystem<int, string>)
        : int64 * UnixSystem<int, string>
        =
        let bytes = ImmutableArray.CreateRange (Encoding.ASCII.GetBytes text)

        match
            WriteOutcomes.admitThenWrite 0 fd UserBuffer.Mapped bytes system
            |> WriteOutcomes.returned
        with
        | Ok (WriteAnswer.Completed count, system) -> count, system
        | other -> failwith $"write(%d{fd}): %A{other}"

    let private sizeOf (path : string) (system : UnixSystem<int, string>) : int64 =
        match UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.Follow (PathArg.ofText path) system with
        | Ok (FileStatusAnswer.Reported status) -> status.Size
        | other -> failwith $"stat(%s{path}): %A{other}"

    let private dupIn (pid : ProcessId) (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixDescriptor.tryDup (Caller.make pid 0) fd system with
        | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
        | other -> failwith $"dup(%d{fd}): %A{other}"

    let private dup (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        dupIn (Lone.pid system) fd system

    /// `flock(fd, operation)` by `thread` of the process `pid`: whether it
    /// slept.
    let private flockIn
        (pid : ProcessId)
        (thread : int)
        (fd : int)
        (operation : int)
        (system : UnixSystem<int, string>)
        : bool * UnixSystem<int, string>
        =
        match UnixDescriptor.tryFlock (Caller.make pid thread) fd operation system with
        | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> false, system
        | Ok (SyscallOutcome.WouldBlock _, system) -> true, system
        | other -> failwith $"flock(%d{fd}, %d{operation}) by thread %d{thread}: %A{other}"

    let private lockEx : int = 2
    let private lockUn : int = 8

    /// "a/f", holding "abc", watched with its parent "a"; the instance and
    /// both watches, nothing queued.
    let private watchedFile () : int * int * int * UnixSystem<int, string> =
        let system = boot root [ "a", directory 0o777 [ "f", file "abc" ] ]
        let fd, system = init1 nonblock system
        let wa, system = watch fd "a" closeEvents system
        let wf, system = watch fd "a/f" closeEvents system
        let _, system = drain fd system
        fd, wa, wf, system

    [<Test>]
    let ``section A: the access mode a description was opened with`` () : unit =
        let skipped = [ "rdonly-append" ; "path" ]

        let produced =
            [
                for name, flags, act in
                    [
                        "rdonly", readOnly, None
                        "rdonly-read", readOnly, Some 'r'
                        "wronly-unwritten", writeOnly, None
                        "wronly-written", writeOnly, Some 'w'
                        "rdwr-unused", readWrite, None
                        "rdwr-read", readWrite, Some 'r'
                        "rdonly-trunc", openFlags FileAccessMode.ReadOnly false false true, None
                        "wronly-trunc", openFlags FileAccessMode.WriteOnly false false true, None
                    ] do
                    let fd, wa, wf, system = watchedFile ()
                    let f, system = openFd flags "a/f" 0 system

                    let acted, system =
                        match act with
                        | Some 'r' -> readCount f 8 system
                        | Some 'w' -> writeCount f "x" system
                        | _ -> 0L, system

                    let opened, system = drain fd system
                    let system = close f system
                    let closed, system = drain fd system
                    let size = sizeOf "a/f" system

                    name, $"a=%d{wa} f=%d{wf} act=%d{acted} size=%d{size}; opened: %s{opened}; closed: %s{closed}"
            ]

        actual skipped produced |> shouldEqual (expected "A" skipped)

    [<Test>]
    let ``section K: a directory, the watched directory, and /dev/null`` () : unit =
        let skipped = [ "fifo-rdwr" ; "fifo-rdonly" ; "dev-null" ; "dev-null-again" ]
        let produced = ResizeArray<string * string> ()

        let system = boot root [ "k", directory 0o777 [ "d", directory 0o755 [] ] ]
        let fd, system = init1 nonblock system
        let wk, system = watch fd "k" closeEvents system
        let wd, system = watch fd "k/d" closeEvents system
        let d, system = openFd directoryFlags "k/d" 0 system
        let system = close d system |> rowOf produced fd "directory" $"k=%d{wk} d=%d{wd}: "
        let d, system = openFd directoryFlags "k" 0 system
        let system = close d system |> rowOf produced fd "watched-directory" ""
        let system = chdir "k/d" system
        let d, system = openFd directoryFlags "." 0 system
        let system = close d system |> rowOf produced fd "directory-by-dot" ""
        let system = chdir "/" system
        let system = close fd system

        let fd, system = init1 nonblock system
        let _, system = watch fd "/dev" closeEvents system
        let _, system = watch fd "/dev/null" closeEvents system
        let n, system = openFd readOnly "/dev/null" 0 system
        let system = close n system |> rowOf produced fd "dev-null-rdonly" ""
        let system = chmod "/dev/null" 0o666 system |> rowOf produced fd "dev-null-chmod" ""
        // The probe's write, without its `IN_MODIFY` at the device's own
        // watch: the close of a description opened for writing.
        let n, system = openFd writeOnly "/dev/null" 0 system
        let _, system = writeCount n "x" system
        let _, system = drain fd system
        let system = close n system
        let closed, _ = drain fd system

        actual skipped produced |> shouldEqual (expected "K" skipped)

        // The probe's rows for that close.
        for case in [ "dev-null" ; "dev-null-again" ] do
            let _, text = expected "K" [] |> List.find (fun (c, _) -> c = case)

            text.Substring (text.IndexOf "closed: " + "closed: ".Length)
            |> shouldEqual closed

    [<Test>]
    let ``section M: a watch asking for one close event, or both`` () : unit =
        let produced = ResizeArray<string * string> ()
        let system = boot root [ "m", directory 0o777 [ "f", file "abc" ] ]
        let fd, system = init1 nonblock system

        let openClose (flags : OpenFlags) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let f, system = openFd flags "m/f" 0 system
            close f system

        let w, system = watch fd "m" closeWrite system

        let system =
            system
            |> openClose readOnly
            |> openClose writeOnly
            |> rowOf produced fd "close-write-only" $"m=%d{w}: "

        let _, system = watch fd "m" closeNoWrite system

        let system =
            system
            |> openClose readOnly
            |> openClose writeOnly
            |> rowOf produced fd "close-nowrite-only" ""

        let _, system = watch fd "m" (closeWrite ||| closeNoWrite) system

        system
        |> openClose writeOnly
        |> openClose readOnly
        |> rowOf produced fd "close-both" ""
        |> ignore<UnixSystem<int, string>>

        actual [] produced |> shouldEqual (expected "M" [])

    /// What a child process does with its descriptors before it exits.
    [<RequireQualifiedAccess>]
    type private ChildStep =
        /// Opens the name in the watched directory.
        | Open of name : string * flags : OpenFlags
        /// Closes the descriptor the `index`th step made.
        | Close of index : int
        /// Dups the descriptor the `index`th step made.
        | Dup of index : int

    [<Test>]
    let ``section R: the references a description has, and the order a process's end releases them in`` () : unit =
        let skipped = [ "fork-child-exit" ; "fork-parent-close" ]
        let produced = ResizeArray<string * string> ()

        let system =
            boot root [ "r", directory 0o777 [ "f", file "abc" ; "g", file "abc" ] ]

        let fd, system = init1 nonblock system
        let w, system = watch fd "r" closeEvents system

        let openClose (path : string) (flags : OpenFlags) (system : UnixSystem<int, string>) =
            let f, system = openFd flags path 0 system
            close f system

        let system =
            system
            |> openClose "r/f" readOnly
            |> openClose "r/f" readOnly
            |> rowOf produced fd "two-nowrite-merge" $"r=%d{w}: "
            |> openClose "r/f" writeOnly
            |> openClose "r/f" writeOnly
            |> rowOf produced fd "two-write-merge" ""
            |> openClose "r/f" readOnly
            |> openClose "r/f" writeOnly
            |> openClose "r/f" readOnly
            |> rowOf produced fd "alternating" ""
            |> openClose "r/f" readOnly
            |> openClose "r/g" readOnly
            |> openClose "r/f" readOnly
            |> rowOf produced fd "two-files" ""

        let f1, system = openFd readOnly "r/f" 0 system
        let f2, system = openFd readOnly "r/f" 0 system
        let system = close f1 system |> rowOf produced fd "two-descriptions-first" ""
        let system = close f2 system |> rowOf produced fd "two-descriptions-second" ""
        let f, system = openFd writeOnly "r/f" 0 system
        let g, system = dup f system
        let system = close f system |> rowOf produced fd "dup-first" ""

        close g system
        |> rowOf produced fd "dup-second" ""
        |> ignore<UnixSystem<int, string>>

        // The probe's children, each forked holding the parent's instance at
        // descriptor 3 and closing every other descriptor but it; here each is
        // a process of its own beside the instance's, whose descriptors 0 to 2
        // are its standard streams and 3 a stand-in for the instance. What the
        // child's descriptors were, and what the instance, watching `watched`,
        // held after its exit, renumbered as the probe's instance numbered its
        // watch on `watched`, `probeWd`.
        let child (watched : string) (probeWd : int) (steps : ChildStep list) : int list * string =
            let pids, machine = Machines.withThreads SimulatedUnixPlatform.linuxArm64 2 1
            let child, parent = pids.[0], pids.[1]

            let machine =
                Machines.doIn
                    child
                    (fun view ->
                        let view = mkdirIn child $"/%s{watched}" 0o777 view

                        ([ "f" ; "g" ; "h" ], view)
                        ||> List.foldBack (fun name view -> writeFileIn child $"/%s{watched}/%s{name}" "abc" view)
                    )
                    machine

            let (instance, wd), machine =
                Machines.inProcess
                    parent
                    (fun view ->
                        let instance, view = init1In parent nonblock view
                        let wd, view = watchIn parent instance $"/%s{watched}" closeEvents view
                        (instance, wd), view
                    )
                    machine

            let standIn, machine = openFdIn child readOnly "/dev/null" 0 machine

            if standIn <> 3 then
                failwith $"the child's first descriptor of its own is %d{standIn}, where the probe's instance is at 3"

            let opened, machine =
                (([], machine), steps)
                ||> List.fold (fun (opened, machine) step ->
                    match step with
                    | ChildStep.Open (name, flags) ->
                        let fd, machine = openFdIn child flags $"/%s{watched}/%s{name}" 0 machine
                        opened @ [ fd ], machine
                    | ChildStep.Close index -> opened @ [ -1 ], closeIn child (List.item index opened) machine
                    | ChildStep.Dup index ->
                        let fd, machine = dupIn child (List.item index opened) machine
                        opened @ [ fd ], machine
                )

            let machine =
                match UnixThreadLifecycle.tryExitGroup (Caller.make child 0) 0 (Machines.viewOf child machine) with
                | Ok (ended, machine) when (EndedProcess.termination ended).IsExited -> machine
                | other -> failwith $"the child's exit: %A{other}"

            Machines.assertClean machine
            let drained, _ = Machines.inProcess parent (drain instance) machine
            opened, drained.Replace ($"wd=%d{wd} ", $"wd=%d{probeWd} ")

        let opened, drained =
            child
                "r"
                w
                [
                    ChildStep.Open ("g", readOnly)
                    ChildStep.Open ("f", writeOnly)
                    ChildStep.Open ("f", readOnly)
                ]

        produced.Add ("exit-descriptors", $"g=%d{opened.[0]} f=%d{opened.[1]} f-again=%d{opened.[2]} inotify=3")
        produced.Add ("exit", drained)

        // The probe's instance watched "r" first, and "o" second.
        let wo = w + 1

        let opened, drained =
            child
                "o"
                wo
                [
                    ChildStep.Open ("g", readOnly)
                    ChildStep.Open ("f", readOnly)
                    ChildStep.Close 0
                    ChildStep.Open ("h", readOnly)
                ]

        produced.Add ("exit-reused-slot-descriptors", $"f=%d{opened.[1]} h=%d{opened.[3]} inotify=3")
        produced.Add ("exit-reused-slot", $"o=%d{wo}: %s{drained}")

        let opened, drained =
            child
                "o"
                wo
                [
                    ChildStep.Open ("g", readOnly)
                    ChildStep.Open ("f", readOnly)
                    ChildStep.Dup 0
                ]

        produced.Add ("exit-dup-last-descriptors", $"g=%d{opened.[0]} f=%d{opened.[1]} g-dup=%d{opened.[2]} inotify=3")
        produced.Add ("exit-dup-last", drained)

        let _, drained =
            child
                "o"
                wo
                [
                    ChildStep.Open ("g", readOnly)
                    ChildStep.Open ("f", writeOnly)
                    ChildStep.Open ("h", readOnly)
                    ChildStep.Open ("g", writeOnly)
                ]

        produced.Add ("exit-four", drained)

        actual skipped produced |> shouldEqual (expected "R" skipped)

    [<Test>]
    let ``section U: the name a description was opened through, renamed, moved and unlinked since`` () : unit =
        let produced = ResizeArray<string * string> ()

        let fd, wa, wf, system = watchedFile ()
        let f, system = openFd writeOnly "a/f" 0 system
        let _, system = system |> rename "a/f" "a/g" |> drain fd
        close f system |> rowOf produced fd "renamed" $"a=%d{wa} f=%d{wf}: " |> ignore

        let fd, _, _, system = watchedFile ()
        let system = mkdir "b" 0o777 system
        let wb, system = watch fd "b" closeEvents system
        let f, system = openFd readOnly "a/f" 0 system
        let _, system = system |> rename "a/f" "b/h" |> drain fd
        close f system |> rowOf produced fd "moved" $"b=%d{wb}: " |> ignore

        let fd, _, _, system = watchedFile ()
        let f, system = openFd writeOnly "a/f" 0 system
        let system = unlink "a/f" system |> rowOf produced fd "unlinked-unlink" ""
        close f system |> rowOf produced fd "unlinked-close" "" |> ignore

        for case, watched in [ "excl-unlink-parent", "a" ; "excl-unlink-own", "a/f" ] do
            let fd, _, _, system = watchedFile ()
            let _, system = watch fd watched (closeEvents ||| exclUnlink) system
            let f, system = openFd writeOnly "a/f" 0 system
            let _, system = system |> unlink "a/f" |> drain fd
            close f system |> rowOf produced fd case "" |> ignore

        let fd, _, _, system = watchedFile ()
        let system = link "a/f" "a/f2" system
        let f, system = openFd readOnly "a/f" 0 system
        let _, system = system |> unlink "a/f" |> drain fd
        close f system |> rowOf produced fd "one-of-two-names-unlinked" "" |> ignore

        for excl, suffix in [ 0u, "" ; exclUnlink, "-excl" ] do
            let system = boot root [ "u", directory 0o777 [ "d", directory 0o755 [] ] ]
            let fd, system = init1 nonblock system
            let wu, system = watch fd "u" (closeEvents ||| excl) system
            let wd, system = watch fd "u/d" (closeEvents ||| excl) system
            let byName, system = openFd directoryFlags "u/d" 0 system
            let _, system = system |> chdir "u/d" |> rmdir "../d" |> drain fd
            let byDot, system = openFd directoryFlags "." 0 system

            let system =
                close byDot system
                |> rowOf produced fd $"removed-directory-by-dot%s{suffix}" $"u=%d{wu} d=%d{wd}: "

            system
            |> chdir "/"
            |> close byName
            |> rowOf produced fd $"removed-directory-by-name%s{suffix}" ""
            |> ignore

        actual [] produced |> shouldEqual (expected "U" [])

    [<Test>]
    let ``section L: a close while another thread's flock, asleep, holds the description`` () : unit =
        let produced = ResizeArray<string * string> ()
        let system = boot root [ "l", directory 0o777 [ "f", file "abc" ] ]
        let pid = Lone.pid system
        let fd, system = init1 nonblock system
        let w, system = watch fd "l" closeEvents system
        let holder, system = openFd readOnly "l/f" 0 system
        let _, system = flockIn pid 0 holder lockEx system
        let lockFd, system = openFd writeOnly "l/f" 0 system
        let slept, system = flockIn pid 1 lockFd lockEx system

        if not slept then
            failwith "the second thread's flock did not sleep behind the holder's lock"

        let closed, system =
            match UnixDescriptor.tryClose (Callers.leader system) lockFd system with
            | Ok answered -> answered
            | Error refusal -> failwith $"close(%d{lockFd}): %A{refusal}"

        // The second thread is still asleep: the probe's -2.
        let system =
            rowOf produced fd "close-under-flock" $"l=%d{w} close=%s{rc closed} flock returned=-2: " system

        let _, system = flockIn pid 0 holder lockUn system
        let system = Machines.waking [ pid, 1 ] system

        let system =
            match UnixDescriptor.tryFlockAcquire (Caller.make pid 1) system with
            | Ok (SyscallOutcome.Answered answer, system) ->
                rowOf produced fd "flock-returns" $"flock=%s{rc answer}: " system
            | other -> failwith $"the woken flock: %A{other}"

        close holder system |> rowOf produced fd "holder-close" "" |> ignore

        actual [] produced |> shouldEqual (expected "L" [])

    [<Test>]
    let ``section X: a process's end releases what its calls in flight held before what its descriptors did``
        ()
        : unit
        =
        let pids, machine = Machines.withThreads SimulatedUnixPlatform.linuxArm64 2 2
        let child, parent = pids.[0], pids.[1]

        let machine =
            Machines.doIn
                parent
                (fun view ->
                    view
                    |> mkdirIn parent "/x" 0o777
                    |> writeFileIn parent "/x/x" "abc"
                    |> writeFileIn parent "/x/y" "abc"
                )
                machine

        let (instance, w, holder), machine =
            Machines.inProcess
                parent
                (fun view ->
                    let instance, view = init1In parent nonblock view
                    let w, view = watchIn parent instance "/x" closeEvents view
                    let holder, view = openFdIn parent readOnly "/x/x" 0 view
                    let _, view = flockIn parent 0 holder lockEx view
                    (instance, w, holder), view
                )
                machine

        let lockFd, machine = openFdIn child writeOnly "/x/x" 0 machine
        let _, machine = openFdIn child readOnly "/x/y" 0 machine
        let slept, machine = flockIn child 1 lockFd lockEx machine

        if not slept then
            failwith "the child's flock did not sleep behind the parent's lock"

        let machine = closeIn child lockFd machine

        let machine =
            match UnixThreadLifecycle.tryExitGroup (Caller.make child 0) 0 (Machines.viewOf child machine) with
            | Ok (ended, machine) when (EndedProcess.termination ended).IsExited -> machine
            | other -> failwith $"the child's exit: %A{other}"

        Machines.assertClean machine
        let drained, machine = Machines.inProcess parent (drain instance) machine
        closeIn parent holder machine |> ignore<UnixSystem<int, string>>

        // Every one of the probe's runs released x first; the replay's one run
        // is held to the first of them.
        let _, measured = expected "X" [] |> List.exactlyOne
        let prefix = $"x=%d{w}; x first=200 y first=0 other=0; first run: "

        if not (measured.StartsWith prefix) then
            failwith $"row exit-parked-flock reads %s{measured}"

        drained |> shouldEqual (measured.Substring prefix.Length)
