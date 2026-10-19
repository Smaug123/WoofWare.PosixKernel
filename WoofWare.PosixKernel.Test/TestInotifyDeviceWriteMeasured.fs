namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.Text
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyReplay

/// What a write to a character device queues on the inotify instances
/// watching it, replayed against what Linux 6.18.5 aarch64 answered in
/// docs/probes/inotify-device-write/inotify-device-write-probe.c: one
/// `IN_MODIFY` at the device's own watch, and none at the watch on the
/// directory of the name it was written through, for each write that moved a
/// byte; none for one that moved nothing; and none at an `IN_EXCL_UNLINK`
/// watch once that name is unlinked. Each test makes the probe's calls on the
/// model, renders each row as the probe printed it, and compares the rows with
/// the recorded ones.
///
/// Rows are skipped, each named, where the model cannot make the call: those
/// of `/dev/zero`, which it has no driver for; and a `writev`, which it does
/// not model. Section N is not replayed, since the model refuses `mknod` of a
/// character device, nor most of section E, since it refuses to make or remove
/// a name on the device filesystem; its test replays the records of a write
/// through an unlinked name as the notice such a write would commit.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestInotifyDeviceWriteMeasured =

    let private probe =
        lazy recorded "WoofWare.PosixKernel.Test.inotifyDeviceWrite.linux.txt"

    let private exclUnlink : uint32 = 0x04000000u

    let private writeOnly : OpenFlags =
        openFlags FileAccessMode.WriteOnly false false false

    /// `(void*)-1`, which Linux's screen ahead of the driver refuses.
    let private kernelAddress : UserBuffer = UserBuffer.Unmapped System.UInt64.MaxValue

    /// A user address with nothing mapped at it, which passes that screen.
    let private unmappedUserAddress : UserBuffer = UserBuffer.Unmapped 0x1000UL

    /// The rows of `section` but `skipped`, each without the inode numbers
    /// the probe printed (see `identity`).
    let private expected (section : string) (skipped : string list) : (string * string) list =
        rows probe section skipped
        |> List.map (fun (case, text) -> case, Regex.Replace (text, "ino=[0-9]+ ", ""))

    let private actual (skipped : string list) (produced : (string * string) seq) : (string * string) list =
        produced
        |> List.ofSeq
        |> List.filter (fun (case, _) -> not (List.contains case skipped))

    /// What a write of `text` from `buffer` through `fd` returned, as the
    /// probe prints it.
    let private writeFrom
        (buffer : UserBuffer)
        (fd : int)
        (text : string)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        let bytes = ImmutableArray.CreateRange (Encoding.ASCII.GetBytes text)

        match WriteOutcomes.admitThenWrite 0 fd buffer bytes system |> WriteOutcomes.returned with
        | Ok (WriteAnswer.Completed count, system) -> $"%d{count}", system
        | Ok (WriteAnswer.Failed error, system) ->
            $"errno%d{UnixError.toRawErrnoUnder RawErrnoNumbering.Linux error}", system
        | other -> failwith $"write(%d{fd}): %A{other}"

    let private writeText (fd : int) (text : string) (system : UnixSystem<int, string>) =
        writeFrom UserBuffer.Mapped fd text system

    /// What a `pwrite` of `text` at `offset` through `fd` returned.
    let private pwriteText
        (fd : int)
        (text : string)
        (offset : int64)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        let bytes = ImmutableArray.CreateRange (Encoding.ASCII.GetBytes text)

        match WriteOutcomes.admitThenPwrite 0 fd bytes offset system with
        | Ok (WriteAnswer.Completed count, system) -> $"%d{count}", system
        | other -> failwith $"pwrite(%d{fd}): %A{other}"

    /// The probe's `identity` without its inode number, which this kernel
    /// chooses its own way: the device number and link count `path` names,
    /// `st_rdev` in glibc's `major` and `minor`.
    let private identity (path : string) (system : UnixSystem<int, string>) : string =
        match UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.Follow (PathArg.ofText path) system with
        | Ok (FileStatusAnswer.Reported status) ->
            let rdev = uint64 status.SpecialFileDevice
            let major = ((rdev >>> 32) &&& 0xFFFFF000UL) ||| ((rdev >>> 8) &&& 0xFFFUL)
            let minor = ((rdev >>> 12) &&& 0xFFFFFF00UL) ||| (rdev &&& 0xFFUL)
            $"rdev=%d{major},%d{minor} nlink=%d{status.LinkCount}"
        | other -> failwith $"stat(%s{path}): %A{other}"

    /// The probe's `deviceRows` for `/dev/<name>`, but its `writev`.
    let private deviceRows
        (name : string)
        (produced : ResizeArray<string * string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let path = $"/dev/%s{name}"
        let fd, system = init1 nonblock system
        let wdev, system = watch fd "/dev" closeEvents system
        let wown, system = watch fd path closeEvents system
        let n, system = openFd writeOnly path 0 system
        let opened, system = drain fd system

        let row (case : string) (text : string) (system : UnixSystem<int, string>) =
            let drained, system = drain fd system
            produced.Add ($"%s{name}-%s{case}", $"%s{text}%s{drained}")
            system

        let r, system = writeText n "x" system

        let system =
            row "write" $"%s{identity path system} dev=%d{wdev} own=%d{wown} opened: %s{opened}; write=%s{r}: " system

        let r, system = writeText n "" system
        let system = row "empty" $"write=%s{r}: " system
        let r1, system = writeText n "x" system
        let r2, system = writeText n "yz" system
        let system = row "twice" $"write=%s{r1} write=%s{r2}: " system
        let r, system = writeFrom kernelAddress n "x" system
        let system = row "fault" $"write=%s{r}: " system
        let r, system = writeFrom unmappedUserAddress n "x" system
        let system = row "unmapped" $"write=%s{r}: " system
        let r, system = pwriteText n "x" 5L system
        let system = row "pwrite" $"pwrite=%s{r}: " system
        let system = close n system
        let system = row "close" "" system
        close fd system

    [<Test>]
    let ``section D: a write to /dev/null and /dev/urandom is heard at the device's own watch`` () : unit =
        let skipped =
            [
                yield!
                    [
                        "write"
                        "empty"
                        "twice"
                        "fault"
                        "unmapped"
                        "pwrite"
                        "writev"
                        "close"
                    ]
                    |> List.map (fun case -> $"zero-%s{case}")
                "null-writev"
                "urandom-writev"
            ]

        let produced = ResizeArray<string * string> ()

        boot root []
        |> deviceRows "null" produced
        |> deviceRows "urandom" produced
        |> ignore

        actual skipped produced |> shouldEqual (expected "D" skipped)

    /// The records `plain` and `excl` hold after a write that moved bytes to
    /// `/dev/urandom` through a description opened through its name, which is
    /// `unlinked` if so: the notice such a write commits, committed, as the
    /// probe prints them.
    let private deviceWrittenThrough
        (unlinked : bool)
        (plain : int)
        (excl : int)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        let dentry : Dentry =
            {
                Parent = numberOf "/dev" system
                Name = name "urandom"
            }

        let notice =
            ChangeNotice.DeviceWritten (numberOf "/dev/urandom" system, ReachedThrough.Name (dentry, unlinked))

        let system =
            system
            |> Kernel.mapMachine (fun machine ->
                UnixMachineState.commitFileSystem notice (VirtualFileSystem.unchanged machine.FileSystem) machine
            )

        let plainDrained, system = drain plain system
        let exclDrained, system = drain excl system
        $"plain: %s{plainDrained}; excl: %s{exclDrained}", system

    [<Test>]
    let ``section E: a device write through an unlinked name is hidden by IN_EXCL_UNLINK`` () : unit =
        // The model refuses to unlink a device's node, so no description
        // reaches one through an unlinked name: the probe's write through such
        // a name is replayed as the notice that write would commit, beside the
        // same write through the name still linked.
        let system = boot root []
        let plain, system = init1 nonblock system
        let excl, system = init1 nonblock system
        let _, system = watch plain "/dev" closeEvents system
        let _, system = watch plain "/dev/urandom" closeEvents system
        let _, system = watch excl "/dev" (closeEvents ||| exclUnlink) system
        let _, system = watch excl "/dev/urandom" (closeEvents ||| exclUnlink) system

        let linked, system = deviceWrittenThrough false plain excl system
        let unlinked, _ = deviceWrittenThrough true plain excl system

        let recorded (case : string) : string =
            let _, text = expected "E" [] |> List.find (fun (c, _) -> c = case)
            text.Substring (text.IndexOf "plain: ")

        [ linked ; unlinked ]
        |> shouldEqual [ recorded "urandom-self-linked" ; recorded "urandom-self-unlinked" ]
