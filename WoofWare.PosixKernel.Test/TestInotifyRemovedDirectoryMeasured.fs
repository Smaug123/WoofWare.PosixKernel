namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyReplay

/// Which name a change to a removed directory is reported under, when it
/// reached the directory by "." or "..", or through a descriptor opened that
/// way, after its last name had gone, replayed against what Linux 6.18.5
/// aarch64 answered in
/// docs/probes/inotify-removed-directory/inotify-removed-directory-probe.c:
/// the name it had when that name went, in the directory it was named in then.
/// Each test makes the probe's calls on the model, renders each row as the
/// probe printed it, and compares the rows with the recorded ones.
///
/// The probe removes and remakes one directory per case; the replay gives each
/// case a directory of its own instead, whose name no record carries.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestInotifyRemovedDirectoryMeasured =

    let private probe =
        lazy recorded "WoofWare.PosixKernel.Test.inotifyRemovedDirectory.linux.txt"

    let private exclUnlink : uint32 = 0x04000000u

    let private directoryFlags : OpenFlags =
        { openFlags FileAccessMode.ReadOnly false false false with
            Directory = true
        }

    /// The probe's `%o` of a mode.
    let private octal (mode : int) : string = System.Convert.ToString (mode, 8)

    /// The probe's `%o` of the mode of ".", and of "..".
    let private modeOfDot (system : UnixSystem<int, string>) : string = octal (modeOf "." system)
    let private modeOfDotDot (system : UnixSystem<int, string>) : string = octal (modeOf ".." system)

    let private expected (section : string) : (string * string) list =
        rows probe section [] |> normaliseCookies

    let private actual (produced : (string * string) seq) : (string * string) list =
        produced |> List.ofSeq |> normaliseCookies

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

    [<Test>]
    let ``section N: the name a removed directory had when its last name went`` () : unit =
        let produced = ResizeArray<string * string> ()

        let mutable system =
            boot
                root
                [
                    "n1", directory 0o777 [ "a", directory 0o755 [] ]
                    "n2", directory 0o777 [ "a", directory 0o755 [] ]
                    "n3", directory 0o777 [ "a", directory 0o755 [] ]
                    "m3", directory 0o777 []
                    "n4", directory 0o777 [ "x", directory 0o755 [] ; "y", directory 0o755 [] ]
                ]

        // Named "a" throughout.
        let fd, s = init1 nonblock system
        let wn, s = watch fd "n1" modelledEvents s
        let wa, s = watch fd "n1/a" modelledEvents s
        system <- s |> chdir "n1/a" |> rmdir "../a"
        system <- rowOf produced fd "as-named-rmdir" $"n=%d{wn} a=%d{wa}: " system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "as-named-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system <- system |> chdir "/" |> close fd

        // Renamed "a" to "b" within its parent, then removed as "b".
        let fd, s = init1 nonblock system
        let wn, s = watch fd "n2" modelledEvents s
        let wa, s = watch fd "n2/a" modelledEvents s
        system <- s |> chdir "n2/a" |> rename "../a" "../b" |> rmdir "../b"
        system <- rowOf produced fd "renamed-rmdir" $"n=%d{wn} a=%d{wa}: " system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "renamed-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system <- system |> chdir "/" |> close fd

        // Moved to another parent as "c", then removed there.
        let fd, s = init1 nonblock system
        let wn, s = watch fd "n3" modelledEvents s
        let wm, s = watch fd "m3" modelledEvents s
        let wa, s = watch fd "n3/a" modelledEvents s
        system <- s |> chdir "n3/a" |> rename "../a" "../../m3/c" |> rmdir "../c"
        system <- rowOf produced fd "moved-rmdir" $"n=%d{wn} m=%d{wm} a=%d{wa}: " system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "moved-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system <- system |> chdir "/" |> close fd

        // Displaced: "x" renamed over "y", the current directory.
        let fd, s = init1 nonblock system
        let wn, s = watch fd "n4" modelledEvents s
        let wx, s = watch fd "n4/x" modelledEvents s
        let wy, s = watch fd "n4/y" modelledEvents s
        system <- s |> chdir "n4/y" |> rename "../x" "../y"
        system <- rowOf produced fd "displaced-rename" $"n=%d{wn} x=%d{wx} y=%d{wy}: " system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "displaced-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system <- system |> chdir "/" |> close fd

        actual produced |> shouldEqual (expected "N")

    [<Test>]
    let ``section U: the old parent removed too`` () : unit =
        let produced = ResizeArray<string * string> ()

        let mutable system =
            boot
                root
                [
                    "u", directory 0o777 [ "par", directory 0o755 [ "child", directory 0o755 [] ] ]
                ]

        let fd, s = init1 nonblock system
        let wu, s = watch fd "u" modelledEvents s
        let wp, s = watch fd "u/par" modelledEvents s
        let wc, s = watch fd "u/par/child" modelledEvents s
        system <- s |> chdir "u/par/child" |> rmdir "../child"
        system <- rowOf produced fd "child-rmdir" $"u=%d{wu} par=%d{wp} child=%d{wc}: " system
        system <- rmdir "../../par" system
        system <- rowOf produced fd "parent-rmdir" "" system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "child-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system <- chmod ".." 0o700 system

        system <- rowOf produced fd "parent-chmod-by-dotdot" $"chmod=0 mode=%s{modeOfDotDot system}: " system

        system <- chdir "/" system
        system <- rowOf produced fd "after-leaving" "" system
        close fd system |> ignore

        actual produced |> shouldEqual (expected "U")

    [<Test>]
    let ``section E: IN_EXCL_UNLINK on the old parent's watch`` () : unit =
        let produced = ResizeArray<string * string> ()
        let mutable system = boot root [ "e", directory 0o777 [ "a", directory 0o755 [] ] ]
        let fd, s = init1 nonblock system
        let we, s = watch fd "e" (modelledEvents ||| exclUnlink) s
        let wa, s = watch fd "e/a" (modelledEvents ||| exclUnlink) s
        system <- s |> chdir "e/a" |> rmdir "../a"
        system <- rowOf produced fd "excl-unlink-rmdir" $"e=%d{we} a=%d{wa}: " system
        system <- chmod "." 0o700 system
        system <- rowOf produced fd "excl-unlink-chmod" $"chmod=0 mode=%s{modeOfDot system}: " system
        system |> chdir "/" |> close fd |> ignore

        actual produced |> shouldEqual (expected "E")

    [<Test>]
    let ``section F: descriptors opened by name before the removal, and by "." after`` () : unit =
        let produced = ResizeArray<string * string> ()
        let mutable system = boot root [ "f", directory 0o777 [ "a", directory 0o755 [] ] ]
        let fd, s = init1 nonblock system
        let wf, s = watch fd "f" modelledEvents s
        let wa, s = watch fd "f/a" modelledEvents s
        let byName, s = openFd directoryFlags "f/a" 0 s
        system <- s |> chdir "f/a" |> rmdir "../a"
        system <- rowOf produced fd "rmdir" $"f=%d{wf} a=%d{wa}: " system
        let byDot, s = openFd directoryFlags "." 0 system
        system <- rowOf produced fd "open-dot" "fd=ok errno=0: " s
        system <- fchmod byName 0o700 system
        system <- rowOf produced fd "fchmod-by-name" $"fchmod=0 mode=%s{modeOfDot system}: " system
        system <- fchmod byDot 0o750 system
        system <- rowOf produced fd "fchmod-by-dot" $"fchmod=0 mode=%s{modeOfDot system}: " system
        system <- chdir "/" system

        let byAt, s =
            match
                OpenOutcomes.openat
                    byName
                    (PathArg.ofText ".")
                    (OpenFlagWords.encode (UnixSystem.platform system) directoryFlags)
                    0
                    system
            with
            | Ok (DescriptorAnswer.Returned byAt, s) -> byAt, s
            | other -> failwith $"openat(%d{byName}, \".\"): %A{other}"

        system <- rowOf produced fd "openat-dot" "fd=ok errno=0: " s
        system <- fchmod byAt 0o755 system

        // The probe reads the mode back with `fstat(byAt)`, the current
        // directory being the root by then.
        let mode =
            match UnixPathResolution.tryFstat (Callers.leader system) byAt system with
            | Ok (FileStatusAnswer.Reported status) -> status.Mode &&& 0o7777
            | other -> failwith $"fstat(%d{byAt}): %A{other}"

        system <- rowOf produced fd "fchmod-by-openat-dot" $"fchmod=0 mode=%s{octal mode}: " system

        system <-
            match
                UnixPathResolution.tryUtimensat
                    (Callers.leader system)
                    byName
                    (NullablePathArgument.NotNull (PathArg.ofText "."))
                    TimesArgument.Null
                    0
                    system
            with
            | Ok (SyscallAnswer.Completed _, s) -> s
            | other -> failwith $"utimensat(%d{byName}, \".\"): %A{other}"

        system <- rowOf produced fd "utimensat-at-dot" "utimensat=0: " system
        system <- system |> close byAt |> close byDot |> close byName
        system <- rowOf produced fd "closed" "" system
        close fd system |> ignore

        actual produced |> shouldEqual (expected "F")
