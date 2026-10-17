namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Runtime.InteropServices
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `fcntl(2)`'s status and descriptor flags against the Linux kernel this test
/// runs on: CI's x86-64, whose numbering the committed probe (measured on
/// aarch64) does not cover, and aarch64 where it is run by hand.
///
/// Every host descriptor here is one the test opened itself, and only those are
/// closed. `dup2` and `F_DUPFD` are deliberately absent: they place a descriptor
/// at a number the caller names or the rest of the table decides, and in a test
/// host that number can belong to the runtime or to another test running
/// alongside, which `dup2` would silently close. `TestFcntlMeasured` replays
/// them from the committed probe instead.
///
/// Linux only. `fcntl` is variadic, and Darwin's arm64 ABI passes a variadic
/// argument on the stack where a P/Invoke passes it in a register, so a call
/// from here would not reach Darwin's kernel with its argument; Linux's x86-64
/// and aarch64 ABIs pass an `int` the same way either side. Darwin's column is
/// `TestFcntlMeasured`'s.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFcntlAgainstHost =

    /// Run `action` on this Linux host's preset, or skip.
    let private onLinux (action : SimulatedUnixPlatform -> unit) : unit =
        HostPlatform.onUnixHostPreset (fun platform ->
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin ->
                Assert.Ignore
                    "fcntl is variadic, which a P/Invoke cannot call on Darwin arm64; TestFcntlMeasured holds Darwin"
            | SimulatedUnixFlavour.Linux -> action platform
        )

    /// What a host call answered: "ok 0x..." or the model's name for its errno.
    let private hostWord (platform : SimulatedUnixPlatform) (result : int) : string =
        if result >= 0 then
            $"ok 0x%x{result}"
        else
            let errno = Marshal.GetLastPInvokeError ()

            match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) errno with
            | Some error -> $"%A{error}"
            | None -> $"errno %d{errno}"

    /// The kinds compared: each makes a host descriptor and the model's.
    let private kinds : string list =
        [
            "file-rdwr"
            "file-rdonly"
            "dir-o_directory"
            "pipe-r"
            "pipe-w"
            "inet-stream"
            "unix-stream"
        ]

    /// A fresh host descriptor of `kind`, and every descriptor to close after.
    let private hostMake (platform : SimulatedUnixPlatform) (directory : string) (kind : string) : int * int list =
        let file = Path.Combine (directory, "f")
        let dir = Path.Combine (directory, "d")

        let directoryFlag = OpenFlagWords.bitOf platform OpenFlagBit.Directory

        let fd, extra =
            match kind with
            | "file-rdwr" -> HostCalls.openFile (file, 2, 0), []
            | "file-rdonly" -> HostCalls.openFile (file, 0, 0), []
            | "dir-o_directory" -> HostCalls.openFile (dir, directoryFlag, 0), []
            | "pipe-r"
            | "pipe-w" ->
                let fds = [| -1 ; -1 |]
                HostCalls.pipe fds |> shouldEqual 0

                if kind = "pipe-r" then
                    fds.[0], [ fds.[1] ]
                else
                    fds.[1], [ fds.[0] ]
            | "inet-stream" -> HostCalls.socket (2, 1, 0), []
            | "unix-stream" -> HostCalls.socket (1, 1, 0), []
            | other -> failwith $"unknown kind %s{other}"

        if fd < 0 then
            failwith $"making %s{kind} on the host failed with errno %d{Marshal.GetLastPInvokeError ()}"

        fd, fd :: extra

    let private withHostDirectory (action : string -> unit) : unit =
        let directory =
            Path.Combine (Path.GetTempPath (), $"fcntl-%s{Guid.NewGuid().ToString ()}")

        Directory.CreateDirectory directory |> ignore
        File.WriteAllBytes (Path.Combine (directory, "f"), "abcdefgh"B)
        Directory.CreateDirectory (Path.Combine (directory, "d")) |> ignore

        try
            action directory
        finally
            Directory.Delete (directory, true)

    let private runFor (platform : SimulatedUnixPlatform) : FcntlWorld.Run =
        {
            Name = "host"
            Platform = platform
            Caller = Owners.root
            Lines = []
        }

    [<Test>]
    let ``F_GETFL of every kind is the host's`` () : unit =
        onLinux (fun platform ->
            withHostDirectory (fun directory ->
                for kind in kinds do
                    let fd, opened = hostMake platform directory kind
                    let host = hostWord platform (HostCalls.fcntl (fd, FcntlWorld.GetFl, 0))
                    List.iter (HostCalls.close >> ignore) opened

                    match FcntlWorld.make kind (FcntlWorld.system (runFor platform)) with
                    | Some (fd, system) -> (kind, FcntlWorld.statusFlags fd system) |> shouldEqual (kind, host)
                    | None -> failwith $"the model makes no %s{kind}"
            )
        )

    /// Each bit on its own beside the word `F_GETFL` reported, on a fresh
    /// descriptor of each kind: what the host's `F_SETFL` answered and left,
    /// against the model's, wherever the model does not refuse the word. A
    /// refused word must hold a flag the model does not model.
    [<Test>]
    let ``F_SETFL of every bit on every kind answers and leaves what the host's does`` () : unit =
        onLinux (fun platform ->
            withHostDirectory (fun directory ->
                let mutable compared = 0

                for kind in kinds do
                    for bit in 0..31 do
                        let fd, opened = hostMake platform directory kind
                        let before = HostCalls.fcntl (fd, FcntlWorld.GetFl, 0)
                        let word = before ||| (1 <<< bit)
                        let set = hostWord platform (HostCalls.fcntl (fd, FcntlWorld.SetFl, word))
                        let after = hostWord platform (HostCalls.fcntl (fd, FcntlWorld.GetFl, 0))
                        List.iter (HostCalls.close >> ignore) opened

                        match FcntlWorld.make kind (FcntlWorld.system (runFor platform)) with
                        | None -> failwith $"the model makes no %s{kind}"
                        | Some (fd, system) ->

                        match UnixDescriptor.tryFcntl (Callers.leader system) fd FcntlWorld.SetFl word system with
                        | Error (FcntlRefusal.UnmodelledStatusFlags _) -> ()
                        | Error refusal -> failwith $"%s{kind} bit %d{bit}: %s{FcntlRefusal.describe refusal}"
                        | Ok (answer, system) ->
                            compared <- compared + 1

                            (kind, bit, FcntlWorld.word answer, FcntlWorld.statusFlags fd system)
                            |> shouldEqual (kind, bit, set, after)

                compared |> shouldBeGreaterThan 150
            )
        )

    /// F_SETFD of every bit, and F_GETFD after it.
    [<Test>]
    let ``F_SETFD keeps the bits the host's keeps`` () : unit =
        onLinux (fun platform ->
            withHostDirectory (fun directory ->
                for word in [ 0 ; -1 ] @ [ for bit in 0..31 -> 1 <<< bit ] do
                    let fd, opened = hostMake platform directory "file-rdwr"
                    let set = hostWord platform (HostCalls.fcntl (fd, FcntlWorld.SetFd, word))
                    let after = hostWord platform (HostCalls.fcntl (fd, FcntlWorld.GetFd, 0))
                    List.iter (HostCalls.close >> ignore) opened

                    let fd, system =
                        FcntlWorld.make "file-rdwr" (FcntlWorld.system (runFor platform)) |> Option.get

                    let answer, system = FcntlWorld.fcntl fd FcntlWorld.SetFd word system

                    (word, FcntlWorld.word answer, FcntlWorld.descriptorFlags fd system)
                    |> shouldEqual (word, set, after)
            )
        )
