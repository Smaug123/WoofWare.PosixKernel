namespace WoofWare.PosixKernel.Test

open System
open System.Runtime.InteropServices
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSocket.socket` against the kernel running the suite, over the same
/// arguments as the checked-in sweeps, wherever the library answers rather than
/// refuses.
///
/// The sweeps were taken on one Linux kernel and one Darwin one. A Linux kernel
/// built differently -- CI's, with modules this one lacked -- is exactly where an
/// answer the library gives as the kernel's own could turn out to be that
/// build's, so this runs the whole grid again on whichever host it finds.
///
/// A sandbox can refuse a socket with EPERM before the kernel reads the
/// arguments, so a call the host refuses that way, where the sweep measured
/// something other than EPERM, is not compared. Every other call still is, and
/// a disagreement among them still fails the test; otherwise a host that
/// refused any call skips the test rather than passing it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSocketSyscallAgainstHost =

    [<Literal>]
    let private F_GETFL = 3

    /// `SOL_SOCKET`, `SO_TYPE` and `O_NONBLOCK`, which differ between the
    /// flavours.
    let private constants (flavour : SimulatedUnixFlavour) : int * int * int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 1, 3, 0x800
        | SimulatedUnixFlavour.Darwin -> 0xffff, 0x1008, 0x4

    /// What the host answered, in the vocabulary the library's answer is
    /// compared in: the created socket's type and non-blocking flag, or the raw
    /// errno.
    let private hostAnswer (flavour : SimulatedUnixFlavour) (domain : int) (kind : int) (protocol : int) =
        let solSocket, soType, nonBlock = constants flavour
        let fd = HostCalls.socket (domain, kind, protocol)

        if fd < 0 then
            Error (Marshal.GetLastPInvokeError ())
        else
            try
                let mutable value = 0
                let mutable length = 4u

                if HostCalls.getSockOptInt (fd, solSocket, soType, &value, &length) <> 0 then
                    failwith $"getsockopt(SO_TYPE) failed with errno %d{Marshal.GetLastPInvokeError ()}"

                let flags = HostCalls.fcntl (fd, F_GETFL, 0)

                if flags < 0 then
                    failwith $"fcntl(F_GETFL) failed with errno %d{Marshal.GetLastPInvokeError ()}"

                Ok (value, flags &&& nonBlock <> 0)
            finally
                HostCalls.close fd |> ignore<int>

    [<Test>]
    let ``every call the library answers is answered the same by this host`` () : unit =
        HostPlatform.onUnixHost (fun flavour ->
            let platform = HostPlatform.platformOf flavour

            let system : UnixSystem<int, string> =
                UnixSystem.initial platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let numbering =
                match flavour with
                | SimulatedUnixFlavour.Linux -> RawErrnoNumbering.Linux
                | SimulatedUnixFlavour.Darwin -> RawErrnoNumbering.Darwin

            let file =
                match flavour with
                | SimulatedUnixFlavour.Linux -> "linux.tsv"
                | SimulatedUnixFlavour.Darwin -> "darwin.tsv"

            let eperm = UnixError.toRawErrnoUnder numbering UnixError.EPERM

            let mutable compared = 0
            let disagreements = ResizeArray ()
            let refusedByHost = ResizeArray ()

            for (domain, kind, protocol), measured in SocketSweep.load file do
                let library =
                    match UnixSocket.trySocket (Callers.leader system) domain kind protocol system with
                    | Error _ -> None
                    | Ok (DescriptorAnswer.Failed error, _) -> Some (Error (UnixError.toRawErrnoUnder numbering error))
                    | Ok (DescriptorAnswer.Returned fd, after) ->
                        let socket =
                            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors after) with
                            | Some (OpenFileTarget.Socket socketId) ->
                                UnixMachineState.socket socketId (Kernel.machine after)
                            | other -> failwith $"descriptor %d{fd} names %A{other}"

                        let soType =
                            match socket.Kind with
                            | SocketKind.Stream -> 1
                            | SocketKind.Datagram -> 2
                            | SocketKind.SeqPacket -> 5

                        Some (Ok (soType, UnixDescriptor.isNonBlocking (Callers.leader after) fd after = Some true))

                match library with
                | None -> ()
                | Some library ->
                    let host = hostAnswer flavour domain kind protocol
                    let call = $"socket(%d{domain}, 0x%x{kind}, %d{protocol})"

                    // A sandbox such as Codex's (macOS seatbelt) refuses a
                    // socket it denies with EPERM before the kernel looks at
                    // the arguments: a bad domain is EPERM there rather than
                    // EAFNOSUPPORT. Where the sweep measured something other
                    // than EPERM, the host's EPERM is the sandbox's and says
                    // nothing about the kernel; where the sweep measured
                    // EPERM, the call is compared like any other.
                    if
                        host <> library
                        && host = Error eperm
                        && measured <> MeasuredSocketAnswer.Failed eperm
                    then
                        refusedByHost.Add call
                    else
                        compared <- compared + 1

                        if host <> library then
                            disagreements.Add $"%s{call}: host %A{host}, library %A{library}"

            disagreements |> List.ofSeq |> List.truncate 20 |> shouldEqual []

            if refusedByHost.Count > 0 then
                Assert.Ignore
                    $"this host refused %d{refusedByHost.Count} of the sockets with EPERM (the first: %s{refusedByHost.[0]}), as a sandbox such as Codex's does before the kernel reads the arguments, so those calls cannot be compared with the library; the other %d{compared} agreed"

            // Not vacuous: most of the sweep is answered.
            compared |> shouldBeGreaterThan 240_000
        )
