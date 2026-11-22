namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// The inode numbers `fstat(2)` reports for a pipe's two ends.
///
/// Minted by this kernel, as every other inode number is: no real kernel's
/// numbers are reproducible, since Linux takes them from a machine-wide counter
/// and Darwin reports a hash of a kernel address. What each flavour does
/// reproducibly is the shape, and a process can see it by comparing the ends.
[<RequireQualifiedAccess>]
type PipeInodes =
    /// Linux: both ends report this one number. Measured on 6.18.5, the ends of
    /// one pipe share an `st_ino`, and a second pipe has another.
    | Shared of InodeNumber
    /// Darwin: each end reports a number of its own. Measured on 27.0.0, the two
    /// ends of one pipe report different `st_ino`.
    | PerEnd of readEnd : InodeNumber * writeEnd : InodeNumber

/// The timestamps `fstat(2)` reports for a pipe's ends, and what moves them.
///
/// On Linux the two ends are one inode with one set of times, which no
/// transfer moves: measured on 6.18.5, reads, writes, short writes, `EAGAIN`
/// and `EFAULT` in either direction all leave every timestamp of both ends at
/// the pipe's creation. Changing the inode itself does move them, as for a
/// file: `fchmod(2)` and `fchown(2)` the status-change time, `utimensat(2)`
/// whichever it is asked to. On Darwin they move per end, as `UnixPipe`
/// describes.
type PipeTimes =
    {
        /// When the pipe was created: every timestamp of both ends starts here.
        /// On Darwin it is also the write end's `st_atime` for the pipe's whole
        /// life, since nothing reads through the write end.
        Created : UnixTimestamp
        /// The read end's `st_atime`, and on Linux the write end's too.
        ReadEndAccess : UnixTimestamp
        /// `st_mtime` of both ends.
        Modification : UnixTimestamp
        /// `st_ctime` of both ends.
        StatusChange : UnixTimestamp
    }

/// What `fstat(2)` reports about a pipe the process made with `UnixPipe.pipe2`.
type PipeStatus =
    {
        /// The `st_ino` each end reports.
        Inodes : PipeInodes
        /// The `st_uid` and `st_gid` both ends report: the effective user and
        /// group of the process that created the pipe. Measured on Linux 6.18.5
        /// with real IDs 0 and effective IDs 1000 and 2000: 1000 and 2000.
        Owner : InodeOwner
        /// The permission bits both ends report: `UnixPipe.pipe2` creates a
        /// pipe with its flavour's, and on Linux `fchmod(2)` through either end
        /// changes them for both.
        Permissions : PermissionBits
        /// The timestamps both ends report.
        Times : PipeTimes
    }

/// The end of a launched pipe that stays outside the machine, on the client's
/// side. It is named by the process into which the pipe was launched, and by
/// the descriptor that the launch table (`ProcessLaunch.create`, used by
/// `UnixBootImage.boot` or `UnixSystem.launch`) gave that process onto the
/// pipe's other end.
///
/// So a client that launched process `pid` with its output on descriptor 1
/// finds what the process wrote there under `ExternalEndpoint (pid, 1)`,
/// whatever the process has since done with descriptor 1, and separately from
/// what any other process wrote on its own descriptor 1.
[<Struct>]
type ExternalEndpoint =
    | ExternalEndpoint of launchedInto : ProcessId * launchedOn : int

    override this.ToString () : string =
        match this with
        | ExternalEndpoint (pid, fd) -> $"the client's end of process %O{pid}'s launch descriptor %d{fd}"

/// What one descriptor of a launch table is: an end of a pipe that exists
/// before the process starts, whose other end is outside the machine, on the
/// client's side.
///
/// The client does nothing at that outside end itself. It chooses one of these
/// cases at launch, and the kernel then acts at the outside end as the case
/// says, as a program outside the machine would.
///
/// Each entry makes a pipe of its own, with a description of its own, so no two
/// launch descriptors share a description or a pipe.
[<RequireQualifiedAccess ; NoComparison>]
type LaunchDescriptor =
    /// The read end of a pipe, opened `O_RDONLY`. The kernel puts `bytes` into
    /// the pipe as one blocking `write(2)` at the outside end would, and then
    /// closes the outside end.
    ///
    /// Bytes that the pipe cannot hold yet go in as the process reads, so a
    /// read finds the pipe as full as that sleeping write could have made it,
    /// and end of file comes only once the process has read every byte. With
    /// no bytes, a read answers end of file at once.
    ///
    /// A launch supplying more bytes than one `write(2)` moves on the platform
    /// (`SimulatedUnixPlatform.transferCountLimit`) is refused:
    /// `UnixBootImage.tryBoot` and `UnixSystem.tryLaunch` answer the refusal,
    /// and `UnixBootImage.boot` and `UnixSystem.launch` throw
    /// `UnmodelledException`.
    | Supplied of bytes : ImmutableArray<byte>
    /// The write end of a pipe, opened `O_WRONLY`. The outside end reads every
    /// byte the moment it is written, so a blocking write is never short and
    /// never waits. Each write hands its bytes to the client as the `Delivery`
    /// that `UnixReadWrite.writeWithBytes` answers beside the write's fate.
    | Drained
    /// The write end of a pipe, opened `O_WRONLY`, whose outside end was closed
    /// before the process started. Nothing will ever read it, so a write
    /// answers `EPIPE` and raises `SIGPIPE`, as `UnixReadWrite.write` describes.
    | Gone

/// The supplied bytes that are not yet in a launched pipe, oldest first
/// (`ClientEnd.Supplying`). Never none: once the last byte is in, the outside
/// end is closed instead.
///
/// Two are equal when they hold the same bytes.
[<CustomEquality ; NoComparison>]
type UnwrittenBytes =
    private
        {
            /// Every byte the client's write was given.
            All : ImmutableArray<byte>
            /// How many of `All` are already in the pipe or read; less than
            /// `All`'s length.
            Written : int
        }

    /// How many bytes are still to be written.
    member this.Length : int = this.All.Length - this.Written

    /// The bytes still to be written, oldest first.
    member this.ToImmutableArray () : ImmutableArray<byte> =
        ImmutableArray.Create (this.All, this.Written, this.Length)

    override this.Equals (other : obj) : bool =
        match other with
        | :? UnwrittenBytes as other ->
            this.Length = other.Length
            && System.MemoryExtensions.SequenceEqual (
                this.All.AsSpan (this.Written, this.Length),
                other.All.AsSpan (other.Written, other.Length)
            )
        | _ -> false

    override this.GetHashCode () : int = this.Length

/// The outside end of a launched pipe (see `LaunchDescriptor`), as it stands
/// now. The kernel acts at this end; the client only reads it.
[<RequireQualifiedAccess>]
type ClientEnd =
    /// The read end, which takes every byte the moment it is written
    /// (`LaunchDescriptor.Drained`).
    | Draining
    /// The write end, in the middle of the one write of the supplied bytes
    /// (`LaunchDescriptor.Supplied`): the pipe has had no room for
    /// `unwritten`, the rest of them. The kernel puts more in each time a read
    /// makes room, and closes this end once the last byte is in.
    | Supplying of unwritten : UnwrittenBytes
    /// Nothing: the write end is closed, either because every supplied byte
    /// went in, or because no reader was left to take the rest.
    | WriteEndClosed
    /// Nothing: the read end was closed before the process started
    /// (`LaunchDescriptor.Gone`), so the pipe has no reader outside the
    /// process.
    | ReadEndClosed

/// Where a pipe came from, and so what is known about it besides its bytes.
[<RequireQualifiedAccess>]
type PipeOrigin =
    /// `UnixPipe.pipe2`, in this process, which is why this kernel knows what
    /// `fstat(2)` reports about it.
    | Made of status : PipeStatus
    /// The launch table's entry for `endpoint`'s descriptor, before the process
    /// started. The pipe's other end is outside the machine, and `client` is
    /// what that end is doing now.
    ///
    /// Its owner and timestamps are the launcher's, which the launch table does
    /// not state, so `fstat(2)`, and `fchmod(2)` where it would consult the
    /// owner, are refused rather than invented.
    | Launched of endpoint : ExternalEndpoint * client : ClientEnd

/// A pipe, as the kernel's pipe table holds it: the bytes in flight between its
/// ends, and where it came from. A client reads the table with
/// `UnixSystem.pipes`.
///
/// It does not record which of its ends are open, because only the machine's
/// open file descriptions can say that truthfully. An end is open while some
/// open file description names it, or while it is held open outside the
/// machine (`PipeState.heldByClient`).
[<NoComparison>]
type PipeState =
    {
        /// The bytes written and not yet read, stored as the flavour stores them.
        Buffer : PipeBuffer
        /// Who made the pipe, and what that says about it.
        Origin : PipeOrigin
        /// How many reads by the process have taken bytes from the pipe.
        ///
        /// Darwin wakes every writer asleep on a pipe at each such read, room
        /// or not, and one that still cannot write either sleeps again or,
        /// through a description that has become non-blocking, gives up; a
        /// write's park records this count, so that its wake condition can say
        /// whether a read has happened since (`WakePrimitive.PipeReadWhileNonBlocking`).
        Reads : int64
    }

/// What a client asleep in a write did when a read made room in its pipe.
[<Struct>]
type internal ClientWriteProgress =
    {
        /// It wrote bytes into a pipe the read had emptied, which wakes the
        /// read end's waiters.
        WroteIntoEmpty : bool
        /// It wrote its last byte and closed its end, which wakes the read
        /// end's waiters whatever they wait for.
        Closed : bool
    }

[<RequireQualifiedAccess>]
module internal PipeTimes =
    /// The times as an inode's, as Linux keeps them, one set for both ends:
    /// the read end's access time is the pipe's, and its creation its birth.
    let asInodeTimes (times : PipeTimes) : InodeTimes =
        {
            Access = times.ReadEndAccess
            Modification = times.Modification
            StatusChange = times.StatusChange
            Birth = times.Created
        }

    /// `times` with the access, modification and status-change times of
    /// `changed`, an inode's times as `asInodeTimes` gave them and a change
    /// moved them.
    let withInodeTimes (changed : InodeTimes) (times : PipeTimes) : PipeTimes =
        { times with
            ReadEndAccess = changed.Access
            Modification = changed.Modification
            StatusChange = changed.StatusChange
        }

[<RequireQualifiedAccess>]
module internal PipeStatus =
    /// `status` with its status-change time moved to `now`, as a change to
    /// the pipe's inode moves it.
    let statusChangedAt (now : UnixTimestamp) (status : PipeStatus) : PipeStatus =
        { status with
            Times =
                { status.Times with
                    StatusChange = now
                }
        }

[<RequireQualifiedAccess>]
module PipeState =
    /// Whether `pipeEnd` of `pipe` is held open outside the machine: the read
    /// end of a drained pipe, the write end of a supplied pipe whose bytes are
    /// not all in yet, and no other. A pipe that the process made has no end
    /// outside it.
    let heldByClient (pipeEnd : PipeEnd) (pipe : PipeState) : bool =
        match pipe.Origin, pipeEnd with
        | PipeOrigin.Launched (_, ClientEnd.Draining), PipeEnd.Read
        | PipeOrigin.Launched (_, ClientEnd.Supplying _), PipeEnd.Write -> true
        | PipeOrigin.Launched (_, ClientEnd.Draining), PipeEnd.Write
        | PipeOrigin.Launched (_, ClientEnd.Supplying _), PipeEnd.Read
        | PipeOrigin.Launched (_, ClientEnd.WriteEndClosed), _
        | PipeOrigin.Launched (_, ClientEnd.ReadEndClosed), _
        | PipeOrigin.Made _, _ -> false

    /// The outside end that reads `pipe` as fast as it is written, if the pipe
    /// was launched as `LaunchDescriptor.Drained`.
    let drainedBy (pipe : PipeState) : ExternalEndpoint option =
        match pipe.Origin with
        | PipeOrigin.Launched (endpoint, ClientEnd.Draining) -> Some endpoint
        | PipeOrigin.Launched (_, ClientEnd.Supplying _)
        | PipeOrigin.Launched (_, ClientEnd.WriteEndClosed)
        | PipeOrigin.Launched (_, ClientEnd.ReadEndClosed)
        | PipeOrigin.Made _ -> None

    /// The pipe `descriptor` makes for launch descriptor `fd` of process `pid`
    /// on a machine of `platform`, as it stands when the process starts, and
    /// which of its ends the process is given.
    ///
    /// A pipe the client supplies holds what the client's write put in before
    /// it slept: the whole of it if it fits. The caller has already refused a
    /// launch supplying more bytes than one `write(2)` moves.
    let internal launch
        (platform : SimulatedUnixPlatform)
        (pid : ProcessId)
        (fd : int)
        (descriptor : LaunchDescriptor)
        : PipeState * PipeEnd
        =
        let endpoint = ExternalEndpoint (pid, fd)
        let empty = PipeBuffer.empty platform

        match descriptor with
        | LaunchDescriptor.Drained ->
            {
                Buffer = empty
                Origin = PipeOrigin.Launched (endpoint, ClientEnd.Draining)
                Reads = 0L
            },
            PipeEnd.Write
        | LaunchDescriptor.Gone ->
            {
                Buffer = empty
                Origin = PipeOrigin.Launched (endpoint, ClientEnd.ReadEndClosed)
                Reads = 0L
            },
            PipeEnd.Write
        | LaunchDescriptor.Supplied bytes ->
            if bytes.IsDefault then
                failwith
                    $"PipeState.launch: launch descriptor %d{fd} supplies the default ImmutableArray, whose underlying array is null. To supply nothing, pass ImmutableArray<byte>.Empty."

            let maxTransfer =
                TransferCountLimit.maxTransfer (SimulatedUnixPlatform.transferCountLimit platform)

            if bytes.Length > maxTransfer then
                failwith
                    $"PipeState.launch: launch descriptor %d{fd} supplies %d{bytes.Length} bytes, more than the %d{maxTransfer} that one write(2) moves on this platform, which ProcessLaunch.launchOnto refuses before making any pipe (this is a bug in this library)."

            // The client's write starts as any write into an empty pipe does.
            let written, buffer = PipeBuffer.write bytes empty

            let client =
                if written = bytes.Length then
                    ClientEnd.WriteEndClosed
                else
                    ClientEnd.Supplying
                        {
                            All = bytes
                            Written = written
                        }

            {
                Buffer = buffer
                Origin = PipeOrigin.Launched (endpoint, client)
                Reads = 0L
            },
            PipeEnd.Read

    /// `pipe` once a client asleep in a write into it has written what the
    /// pipe now has room for, and closed its end if that was the last; and what
    /// it did. A pipe with no such client is returned as it is.
    ///
    /// For the read operation to call after taking bytes out of the pipe: the
    /// client writes before the process's next call, as fast as a real writer
    /// woken by that read could.
    let internal afterRead (pipe : PipeState) : PipeState * ClientWriteProgress =
        match pipe.Origin with
        | PipeOrigin.Made _
        | PipeOrigin.Launched (_, ClientEnd.Draining)
        | PipeOrigin.Launched (_, ClientEnd.WriteEndClosed)
        | PipeOrigin.Launched (_, ClientEnd.ReadEndClosed) ->
            pipe,
            {
                WroteIntoEmpty = false
                Closed = false
            }
        | PipeOrigin.Launched (endpoint, ClientEnd.Supplying unwritten) ->
            let wasEmpty = PipeBuffer.held pipe.Buffer = 0
            let taken, buffer = PipeBuffer.resume unwritten.All unwritten.Written pipe.Buffer
            let written = unwritten.Written + taken
            let closed = written = unwritten.All.Length

            let client =
                if closed then
                    ClientEnd.WriteEndClosed
                else
                    ClientEnd.Supplying
                        { unwritten with
                            Written = written
                        }

            { pipe with
                Buffer = buffer
                Origin = PipeOrigin.Launched (endpoint, client)
            },
            {
                WroteIntoEmpty = wasEmpty && taken > 0
                Closed = closed
            }

    /// `pipe` once its read end has closed for good: a client asleep in a write
    /// into it is woken with `EPIPE`, and closes its end.
    let internal readEndClosed (pipe : PipeState) : PipeState =
        match pipe.Origin with
        | PipeOrigin.Launched (endpoint, ClientEnd.Supplying _) ->
            { pipe with
                Origin = PipeOrigin.Launched (endpoint, ClientEnd.WriteEndClosed)
            }
        | PipeOrigin.Made _
        | PipeOrigin.Launched (_, ClientEnd.Draining)
        | PipeOrigin.Launched (_, ClientEnd.WriteEndClosed)
        | PipeOrigin.Launched (_, ClientEnd.ReadEndClosed) -> pipe

    /// Whether a client asleep in a write into `pipe` could write now: if so,
    /// it would not be asleep. False for a pipe with no such client.
    let internal clientWriteCouldProceed (pipe : PipeState) : bool =
        match pipe.Origin with
        | PipeOrigin.Launched (_, ClientEnd.Supplying unwritten) ->
            fst (PipeBuffer.resume unwritten.All unwritten.Written pipe.Buffer) > 0
        | PipeOrigin.Made _
        | PipeOrigin.Launched (_, ClientEnd.Draining)
        | PipeOrigin.Launched (_, ClientEnd.WriteEndClosed)
        | PipeOrigin.Launched (_, ClientEnd.ReadEndClosed) -> false

/// The bytes one `write(2)` delivered to a client that drains a pipe: what the
/// client read, as `UnixReadWrite.writeWithBytes` answers it beside the write's
/// fate.
///
/// One per write that moved bytes, and never coalesced across writes, because a
/// write's boundaries are what a reader draining the pipe as fast as it is
/// written observes. The kernel keeps no record of it, since the bytes have left
/// the machine: a client that wants what a process wrote keeps the deliveries
/// itself, in the order the writes answered them.
[<NoComparison>]
type Delivery =
    {
        /// The client's end the bytes reached.
        Endpoint : ExternalEndpoint
        /// The bytes, every one of them that the write moved.
        Bytes : ImmutableArray<byte>
    }
