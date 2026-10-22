namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open WoofWare.PosixKernel

/// The `Syscall` a test hands `UnixWait.finish` for a thread it parked through
/// a call's own function rather than through `UnixSystem.step`.
[<RequireQualifiedAccess>]
module internal ParkedCall =

    /// A buffer of `count` bytes, each its offset into the buffer, so that the
    /// same range of it gives the same bytes to every resumption.
    let buffer (count : int) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (Array.init count byte)

    /// A `Syscall` of a case that parks a thread in `parked`, or, for a reserved
    /// park, of the reserved case naming the same call. Only its case is
    /// meant: its arguments are placeholders, except that a write's buffer
    /// holds `buffer` of the write's whole count.
    let ofPark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (parked : ParkedSyscall)
        : Syscall<'Thread, 'Handler>
        =
        match parked with
        | ParkedSyscall.EpollWait _ -> Syscall.EpollWait (0, UserBuffer.Mapped, 1, -1)
        | ParkedSyscall.Kevent _ -> Syscall.Kevent (0, [], 0, UserBuffer.Mapped, 1, TimespecArgument.Null)
        | ParkedSyscall.Flock _ -> Syscall.FLock (0, 0)
        | ParkedSyscall.Poll _
        | ParkedSyscall.KqueuePoll _ -> Syscall.Poll ([], -1)
        | ParkedSyscall.Accept _ -> Syscall.Accept (0, UserBuffer.Mapped, Some 16u, 0)
        | ParkedSyscall.PipeRead _
        | ParkedSyscall.InotifyRead _ -> Syscall.Read (0, UserBuffer.Mapped, 0UL)
        | ParkedSyscall.ConnectionRead read ->
            match read.Call with
            | TcpReceiveCall.Read -> Syscall.Read (0, UserBuffer.Mapped, 0UL)
            | TcpReceiveCall.Receive
            | TcpReceiveCall.Peek -> Syscall.Recv (0, UserBuffer.Mapped, 0UL, 0)
        | ParkedSyscall.PipeWrite write ->
            Syscall.Write (0, CopiedArgument.Readable (buffer write.Count), uint64 write.Count)
        | ParkedSyscall.ConnectionWrite write ->
            let contents = CopiedArgument.Readable (buffer write.Count)

            match write.Call with
            | TcpSendCall.Write -> Syscall.Write (0, contents, uint64 write.Count)
            | TcpSendCall.Send _ -> Syscall.Send (0, contents, uint64 write.Count, 0)
        | ParkedSyscall.SigSuspend -> Syscall.Pause
        | ParkedSyscall.Futex _ -> Syscall.Futex (0UL, 0, 0, CopiedArgument.Readable 0u, TimespecArgument.Null, 0u)
        | ParkedSyscall.Sleep _ -> Syscall.Nanosleep NanosleepArguments.NanosleepArguments
        | ParkedSyscall.FifoOpen _ -> Syscall.Open (PathArgumentBytes.Unreadable, 0, 0)
        | ParkedSyscall.Select _ -> Syscall.Select SelectArguments.SelectArguments
        | ParkedSyscall.SignalWait _ -> Syscall.SigWait SigWaitArguments.SigWaitArguments
        | ParkedSyscall.DatagramReceive _ ->
            Syscall.RecvFrom (0, UserBuffer.Mapped, 0UL, 0, UserBuffer.Unmapped 0UL, CopiedArgument.Unmapped 0UL)
        | ParkedSyscall.DatagramSend _ ->
            Syscall.SendTo (0, CopiedArgument.Readable (buffer 0), 0UL, 0, CopiedArgument.Unmapped 0UL, 0u)
        | ParkedSyscall.Connect _ -> Syscall.Connect (0, CopiedArgument.Addressless, 0u)

    /// `ofPark` of the park the thread `caller` names is in, or `None` if the
    /// system holds no such thread or it is not parked.
    let tryOfThread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Syscall<'Thread, 'Handler> option
        =
        let pid = Caller.processId caller

        if Set.contains pid (UnixSystem.processIds system) then
            Map.tryFind (Caller.thread caller) (UnixSystem.threads pid system)
            |> Option.bind UnixThreadState.parkedIn
            |> Option.map ofPark
        else
            None

    /// `ofPark` of the park the thread `caller` names is in. Fails loudly unless
    /// it is parked.
    let ofThread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Syscall<'Thread, 'Handler>
        =
        match tryOfThread caller system with
        | Some call -> call
        | None -> failwith $"ParkedCall.ofThread: %O{caller} is not parked"
