namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Runtime.InteropServices
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Measures the host's `/dev` and checks the model's device filesystem against
/// it: the device nodes' stat fields, the filesystem type `/dev` reports, and
/// `EXDEV` for a rename across it (on a Linux host; a Darwin host's rename row
/// checks only the model, whose replays of measured rows are `TestDevfs`').
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDeviceFileSystemAgainstHost =

    let private context : string = "TestDeviceFileSystemAgainstHost"

    let private booted (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private modelStatus (system : UnixSystem<int, string>) (path : string) : Result<FileStatusAnswer, StatRefusal> =
        UnixPathResolution.tryStat (Callers.leader system) SymlinkPolicy.NoFollowFinal (PathArg.ofText path) system

    [<Test>]
    let ``each device node's link count, device number and mode are the host's`` () : unit =
        HostStat.onMeasuredHost (fun flavour ->
            let system = booted flavour

            for path in [ "/dev/null" ; "/dev/urandom" ] do
                match modelStatus system path with
                | Ok (FileStatusAnswer.Reported status) ->
                    HostStat.ofModel status |> shouldEqual (HostStat.lstat flavour path)

                    let hostMode = int (File.GetUnixFileMode path)

                    if status.Mode &&& 0o7777 <> hostMode then
                        failwith
                            $"%s{path}: the model's permission bits are 0o%o{status.Mode &&& 0o7777}, the host's 0o%o{hostMode}"
                | other -> failwith $"%s{path} on %O{flavour}: expected a status, got %A{other}"
        )

    [<Test>]
    let ``dev reports the host's filesystem type`` () : unit =
        HostStat.onMeasuredHost (fun flavour ->
            let system = booted flavour

            match UnixPathResolution.tryStatfs (Callers.leader system) (PathArg.ofText "/dev/null") system with
            | Ok (FileSystemStatisticsAnswer.Reported statistics) ->
                // O_RDONLY: the host's /dev/null is readable by everyone.
                let fd = HostCalls.openFile ("/dev/null", 0, 0)

                if fd < 0 then
                    failwith $"opening the host's /dev/null failed: errno %d{Marshal.GetLastPInvokeError ()}"

                try
                    HostFileSystemType.typeFieldsFor flavour fd
                    |> shouldEqual (Ok (FileSystemStatistics.typeFields statistics))
                finally
                    HostCalls.close fd |> ignore<int>
            | other -> failwith $"statfs on %O{flavour}: expected an answer, got %A{other}"
        )

    [<Test>]
    let ``a rename into dev is EXDEV here exactly when the model says so`` () : unit =
        HostPlatform.onUnixHost (fun flavour ->
            let system = booted flavour

            // A name no real /dev holds, so that the host's rename cannot
            // succeed and the model's walk must answer without knowing it.
            let unique () = Guid.NewGuid().ToString "N"
            let destination = $"/dev/posixkernel-%s{unique ()}"

            let model =
                Eager.tryRename (PathArg.ofText "/nonexistent") (PathArg.ofText destination) system

            match flavour with
            | SimulatedUnixFlavour.Darwin ->
                // Darwin looks the source up first, so a missing one is ENOENT
                // before the walk reaches /dev (measured, `devices.c` NS rows).
                match model with
                | Ok (SyscallAnswer.Failed UnixError.ENOENT, _) -> ()
                | other -> failwith $"rename on Darwin: expected ENOENT, got %A{other}"
            | SimulatedUnixFlavour.Linux ->

            let source = Path.Combine (Path.GetTempPath (), $"posixkernel-%s{unique ()}")

            File.WriteAllBytes (source, [||])

            try
                Marshal.SetLastPInvokeError 0
                let result = HostCalls.rename (source, destination)
                let errno = Marshal.GetLastPInvokeError ()

                if result = 0 then
                    failwith $"the host renamed %s{source} into its /dev; this test assumes it cannot"

                UnixError.ofRawErrnoUnder RawErrnoNumbering.Linux errno
                |> shouldEqual (Some UnixError.EXDEV)

                match model with
                | Ok (SyscallAnswer.Failed UnixError.EXDEV, _) -> ()
                | other -> failwith $"rename on Linux: expected EXDEV, got %A{other}"
            finally
                File.Delete source
        )
