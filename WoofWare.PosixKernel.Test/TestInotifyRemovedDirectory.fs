namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyReplay

/// A change through a directory `rmdir` removed, reached by "." or through a
/// descriptor opened by ".", through each entry point that makes one: Linux
/// reports it at the watch on the directory it was last named in, under the
/// name it had there, and then at its own watch, as it does a change through
/// a descriptor opened by that name before the removal (measured,
/// `TestInotifyRemovedDirectoryMeasured` for `chmod`, `fchmod` and
/// `utimensat`; the other entry points make the same change).
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestInotifyRemovedDirectory =

    let private seed : (string * SeedEntry) list =
        [
            "a", directory 0o755 [ "x", file "x" ]
            "b", directory 0o755 []
            "u", directory 0o755 []
        ]

    /// What a change of attributes to `gone` queues: at the watch on the root,
    /// where it was named, under that name, and then at its own.
    let private attributesChanged : string =
        "wd=1 mask=ATTRIB+ISDIR cookie=0 len=16 name=\"gone\" | wd=2 mask=ATTRIB+ISDIR cookie=0 len=0 name=\"\""

    /// A machine whose process stands in `gone`, which `rmdir` has removed,
    /// with an instance watching `.` (the old parent) and `gone` itself for
    /// every event, and nothing queued.
    let private standingInRemoved () : int * UnixSystem<int, string> =
        let system = boot root seed |> mkdir "gone" 0o755
        let instance, system = init1 nonblock system
        let _, system = watch instance "." modelledEvents system
        let _, system = watch instance "gone" modelledEvents system
        let system = system |> chdir "gone" |> rmdir "../gone"
        let _, system = drain instance system
        instance, system

    let private completed (call : string) (result : Result<SyscallAnswer * UnixSystem<int, string>, 'r>) =
        match result with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"%s{call}: %A{other}"

    [<Test>]
    let ``a change through a removed current directory is reported under the name it had, through each path entry point``
        ()
        : unit
        =
        let instance, system = standingInRemoved ()

        let calls : (string * (UnixSystem<int, string> -> UnixSystem<int, string>)) list =
            [
                "chmod(.)", chmod "." 0o700
                "utimensat(AT_FDCWD, .)",
                fun system ->
                    UnixPathResolution.tryUtimensat
                        (Callers.leader system)
                        -100
                        (NullablePathArgument.NotNull (PathArg.ofText "."))
                        TimesArgument.Null
                        0
                        system
                    |> completed "utimensat"
                // `fchmodat`'s empty path from `AT_FDCWD` under `AT_EMPTY_PATH`
                // is ".".
                "fchmodat(AT_FDCWD, \"\", AT_EMPTY_PATH)",
                fun system ->
                    UnixPathResolution.tryFchmodat
                        (Callers.leader system)
                        -100
                        (PathArg.ofText "")
                        0o750
                        atEmptyPath
                        system
                    |> completed "fchmodat"
                "chown(., root, -1)", chown "." (Some 0u) None
            ]

        (system, calls)
        ||> List.fold (fun system (call, make) ->
            let drained, system = make system |> drain instance
            (call, drained) |> shouldEqual (call, attributesChanged)
            system
        )
        |> ignore

    [<Test>]
    let ``a change through a descriptor opened by "." of a removed directory is reported under the name it had, through each descriptor entry point``
        ()
        : unit
        =
        let instance, system = standingInRemoved ()

        let fd, system =
            openFd (openFlags FileAccessMode.ReadOnly false false false) "." 0 system

        let system = chdir "/" system

        let calls : (string * (UnixSystem<int, string> -> UnixSystem<int, string>)) list =
            [
                "fchmod", fchmod fd 0o700
                "fchown", fchown fd (Some 0u) None
                "futimens", futimens fd TimesArgument.Null
                // `fchmodat`'s empty path under Linux's `AT_EMPTY_PATH` is the
                // descriptor.
                "fchmodat(fd, \"\", AT_EMPTY_PATH)",
                fun system ->
                    UnixPathResolution.tryFchmodat
                        (Callers.leader system)
                        fd
                        (PathArg.ofText "")
                        0o750
                        atEmptyPath
                        system
                    |> completed "fchmodat"
            ]

        (system, calls)
        ||> List.fold (fun system (call, make) ->
            let drained, system = make system |> drain instance
            (call, drained) |> shouldEqual (call, attributesChanged)
            system
        )
        |> ignore

    [<Test>]
    let ``the public entry point answers a change through a removed directory`` () : unit =
        let instance, system = standingInRemoved ()

        match UnixPathResolution.chmod (Callers.leader system) (PathArg.ofText ".") 0o700 system with
        | SyscallAnswer.Completed 0L, system ->
            modeOf "." system |> shouldEqual 0o700
            drain instance system |> fst |> shouldEqual attributesChanged
        | other, _ -> failwith $"chmod(.): %A{other}"

    [<Test>]
    let ``a change through a removed current directory goes through where no instance exists`` () : unit =
        let system = boot root seed |> mkdir "gone" 0o755 |> chdir "gone" |> rmdir "../gone"
        let system = chmod "." 0o700 system
        modeOf "." system |> shouldEqual 0o700
