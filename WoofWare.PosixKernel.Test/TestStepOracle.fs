namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Text
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSystem.step` of each call it makes is that call made through its own
/// function: the same answer in the same `SteppedCall` case, the same refusal,
/// or the same exception. `reference` makes each call as a client holding
/// every argument would, through the call's function and then each
/// resumption, and each property generates calls of one case, by any thread,
/// on worlds a few generated calls have moved.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestStepOracle =

    let private context : string = "TestStepOracle"

    /// What `copied` raises where a buffer's contents end before the bytes a
    /// paused call copies, for which `step` throws `InvalidOperationException`.
    type private ShortContentsException (message : string) =
        inherit Exception (message)

    /// The `UserBuffer` a client passes a call's own function for a buffer
    /// whose contents it holds as `argument`.
    let private bufferOf<'T> (argument : CopiedArgument<'T>) : UserBuffer =
        match argument with
        | CopiedArgument.Readable _ -> UserBuffer.Mapped
        | CopiedArgument.Unmapped address -> UserBuffer.Unmapped address
        | CopiedArgument.Opaque -> UserBuffer.Opaque
        | CopiedArgument.Addressless -> UserBuffer.Addressless

    /// What a client holding `argument` copies for a paused call: the bytes
    /// `range` names.
    let private copied (argument : CopiedArgument<ImmutableArray<byte>>) (range : CopyRange) : ImmutableArray<byte> =
        match argument with
        | CopiedArgument.Readable contents ->
            if range.FirstByte + range.ByteCount > contents.Length then
                raise (
                    ShortContentsException $"the call copies %A{range}, but the buffer holds %d{contents.Length} bytes"
                )

            contents
            |> Seq.skip range.FirstByte
            |> Seq.take range.ByteCount
            |> ImmutableArray.CreateRange
        | other -> failwith $"the call stopped to copy from %A{other}, which no call should copy from"

    /// What a client holding the cell `argument` hands a paused call that reads
    /// it.
    let private cell<'T> (argument : CopiedArgument<'T>) : 'T =
        match argument with
        | CopiedArgument.Readable value -> value
        | other -> failwith $"the call stopped to read %A{other}, which no call should read"

    /// Each call the way a client makes it through the call's own function,
    /// and its resumptions, as the `SteppedCall` case `step` answers.
    let private reference
        (caller : Caller<int>)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Result<SteppedCall<int, string>, SyscallRefusal<int>>
        =
        match call with
        | Syscall.Dup fd ->
            UnixDescriptor.tryDup caller fd system
            |> Result.map SteppedCall.Dup
            |> Result.mapError SyscallRefusal.Dup
        | Syscall.Dup2 (oldFd, newFd) ->
            UnixDescriptor.tryDup2 caller oldFd newFd system
            |> Result.map SteppedCall.Dup2
            |> Result.mapError SyscallRefusal.Dup2
        | Syscall.Dup3 (oldFd, newFd, flags) ->
            UnixDescriptor.tryDup3 caller oldFd newFd flags system
            |> Result.map SteppedCall.Dup3
            |> Result.mapError SyscallRefusal.Dup3
        | Syscall.Fcntl (fd, command, argument) ->
            UnixDescriptor.tryFcntl caller fd command argument system
            |> Result.map SteppedCall.Fcntl
            |> Result.mapError SyscallRefusal.Fcntl
        | Syscall.LSeek (fd, offset, whence) ->
            UnixDescriptor.tryLseek caller fd offset whence system
            |> Result.map SteppedCall.LSeek
            |> Result.mapError SyscallRefusal.LSeek
        | Syscall.FLock (fd, operation) ->
            UnixDescriptor.tryFlock caller fd operation system
            |> Result.map SteppedCall.FLock
            |> Result.mapError SyscallRefusal.FLock
        | Syscall.FTruncate (fd, length) ->
            UnixDescriptor.tryFtruncate caller fd length system
            |> Result.map SteppedCall.FTruncate
            |> Result.mapError SyscallRefusal.FTruncate
        | Syscall.PosixFAdvise (fd, offset, length, advice) ->
            UnixDescriptor.tryPosixFadvise caller fd offset length advice system
            |> Result.map SteppedCall.PosixFAdvise
            |> Result.mapError SyscallRefusal.PosixFAdvise
        | Syscall.Close fd ->
            UnixDescriptor.tryClose caller fd system
            |> Result.map SteppedCall.Close
            |> Result.mapError SyscallRefusal.Close
        | Syscall.BytesAvailable (fd, destination) ->
            UnixDescriptor.tryBytesAvailable caller fd destination system
            |> Result.map SteppedCall.BytesAvailable
            |> Result.mapError SyscallRefusal.BytesAvailable
        | Syscall.FileClone (destination, source) ->
            UnixDescriptor.tryFileClone caller destination source system
            |> Result.map SteppedCall.FileClone
            |> Result.mapError SyscallRefusal.FileClone
        | Syscall.TerminalAttributes fd ->
            Ok (SteppedCall.TerminalAttributes (UnixDescriptor.terminalAttributes caller fd system))
        | Syscall.GetEffectiveUserId ->
            Ok (SteppedCall.GetEffectiveUserId (UnixDescriptor.effectiveUserId caller system))
        | Syscall.GetEffectiveGroupId ->
            Ok (SteppedCall.GetEffectiveGroupId (UnixDescriptor.effectiveGroupId caller system))
        | Syscall.GetGroups (size, destination) ->
            UnixDescriptor.tryGetgroups caller destination size system
            |> Result.map SteppedCall.GetGroups
            |> Result.mapError SyscallRefusal.GetGroups
        | Syscall.Stat (policy, path) ->
            UnixPathResolution.tryStat caller policy path system
            |> Result.map SteppedCall.Stat
            |> Result.mapError SyscallRefusal.Stat
        | Syscall.FStat fd ->
            UnixPathResolution.tryFstat caller fd system
            |> Result.map SteppedCall.FStat
            |> Result.mapError SyscallRefusal.FStat
        | Syscall.FStatAt (dirfd, path, flags) ->
            UnixPathResolution.tryFstatat caller dirfd path flags system
            |> Result.map SteppedCall.FStatAt
            |> Result.mapError SyscallRefusal.FStatAt
        | Syscall.ChMod (path, mode) ->
            UnixPathResolution.tryChmod caller path mode system
            |> Result.map SteppedCall.ChMod
            |> Result.mapError SyscallRefusal.ChMod
        | Syscall.FChMod (fd, mode) ->
            UnixPathResolution.tryFchmod caller fd mode system
            |> Result.map SteppedCall.FChMod
            |> Result.mapError SyscallRefusal.FChMod
        | Syscall.FChModAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFchmodat caller dirfd path mode flags system
            |> Result.map SteppedCall.FChModAt
            |> Result.mapError SyscallRefusal.FChModAt
        | Syscall.ChOwn (path, user, group) ->
            UnixPathResolution.tryChown caller path user group system
            |> Result.map SteppedCall.ChOwn
            |> Result.mapError SyscallRefusal.ChOwn
        | Syscall.LChOwn (path, user, group) ->
            UnixPathResolution.tryLchown caller path user group system
            |> Result.map SteppedCall.LChOwn
            |> Result.mapError SyscallRefusal.LChOwn
        | Syscall.FChOwn (fd, user, group) ->
            UnixPathResolution.tryFchown caller fd user group system
            |> Result.map SteppedCall.FChOwn
            |> Result.mapError SyscallRefusal.FChOwn
        | Syscall.FChOwnAt (dirfd, path, user, group, flags) ->
            UnixPathResolution.tryFchownat caller dirfd path user group flags system
            |> Result.map SteppedCall.FChOwnAt
            |> Result.mapError SyscallRefusal.FChOwnAt
        | Syscall.UTimensAt (dirfd, path, times, flags) ->
            UnixPathResolution.tryUtimensat caller dirfd path times flags system
            |> Result.map SteppedCall.UTimensAt
            |> Result.mapError SyscallRefusal.UTimensAt
        | Syscall.StatFs path ->
            UnixPathResolution.tryStatfs caller path system
            |> Result.map SteppedCall.StatFs
            |> Result.mapError SyscallRefusal.StatFs
        | Syscall.FStatFs fd -> Ok (SteppedCall.FStatFs (UnixPathResolution.fstatfs caller fd system))
        | Syscall.GetCwd (destination, capacity) ->
            UnixPathResolution.tryGetcwd caller destination capacity system
            |> Result.map SteppedCall.GetCwd
            |> Result.mapError SyscallRefusal.GetCwd
        | Syscall.ChDir path ->
            UnixPathResolution.tryChdir caller path system
            |> Result.map SteppedCall.ChDir
            |> Result.mapError SyscallRefusal.ChDir
        | Syscall.Access (path, mode) ->
            UnixPathResolution.tryAccess caller mode system
            |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)
            |> Result.map SteppedCall.Access
            |> Result.mapError SyscallRefusal.Access
        | Syscall.FAccessAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFaccessat caller dirfd mode flags system
            |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)
            |> Result.map SteppedCall.FAccessAt
            |> Result.mapError SyscallRefusal.FAccessAt
        | Syscall.Open (path, flags, mode) ->
            UnixNamespace.tryOpenPath caller flags path mode system
            |> Result.map SteppedCall.Open
            |> Result.mapError SyscallRefusal.Open
        | Syscall.OpenAt (dirfd, path, flags, mode) ->
            UnixNamespace.tryOpenat caller dirfd path flags mode system
            |> Result.map SteppedCall.OpenAt
            |> Result.mapError SyscallRefusal.OpenAt
        | Syscall.ReadLink (path, destination, capacity) ->
            UnixNamespace.tryReadlink caller path destination capacity system
            |> Result.map SteppedCall.ReadLink
            |> Result.mapError SyscallRefusal.ReadLink
        | Syscall.ReadLinkAt (dirfd, path, destination, capacity) ->
            UnixNamespace.tryReadlinkat caller dirfd path destination capacity system
            |> Result.map SteppedCall.ReadLinkAt
            |> Result.mapError SyscallRefusal.ReadLinkAt
        | Syscall.ReadDirectoryEntry fd ->
            UnixNamespace.tryReadDirectoryEntry caller fd system
            |> Result.map SteppedCall.ReadDirectoryEntry
            |> Result.mapError SyscallRefusal.ReadDirectoryEntry
        | Syscall.MkDir (path, mode) ->
            UnixNamespace.tryMkdir caller path mode system
            |> Result.map SteppedCall.MkDir
            |> Result.mapError SyscallRefusal.MkDir
        | Syscall.MkDirAt (dirfd, path, mode) ->
            UnixNamespace.tryMkdirat caller dirfd path mode system
            |> Result.map SteppedCall.MkDirAt
            |> Result.mapError SyscallRefusal.MkDirAt
        | Syscall.MkNod (path, mode, dev) ->
            UnixNamespace.tryMknod caller path mode dev system
            |> Result.map SteppedCall.MkNod
            |> Result.mapError SyscallRefusal.MkNod
        | Syscall.MkNodAt (dirfd, path, mode, dev) ->
            UnixNamespace.tryMknodat caller dirfd path mode dev system
            |> Result.map SteppedCall.MkNodAt
            |> Result.mapError SyscallRefusal.MkNodAt
        | Syscall.Unlink path ->
            UnixNamespace.tryUnlink caller path system
            |> Result.map SteppedCall.Unlink
            |> Result.mapError SyscallRefusal.Unlink
        | Syscall.RmDir path ->
            UnixNamespace.tryRmdir caller path system
            |> Result.map SteppedCall.RmDir
            |> Result.mapError SyscallRefusal.RmDir
        | Syscall.UnlinkAt (dirfd, path, flags) ->
            UnixNamespace.tryUnlinkat caller dirfd path flags system
            |> Result.map SteppedCall.UnlinkAt
            |> Result.mapError SyscallRefusal.UnlinkAt
        | Syscall.Rename (source, destination) ->
            UnixNamespace.tryRename caller source system
            |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination destination)
            |> Result.map SteppedCall.Rename
            |> Result.mapError SyscallRefusal.Rename
        | Syscall.RenameAt (olddirfd, oldpath, newdirfd, newpath) ->
            UnixNamespace.tryRenameat caller olddirfd oldpath newdirfd system
            |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination newpath)
            |> Result.map SteppedCall.RenameAt
            |> Result.mapError SyscallRefusal.RenameAt
        | Syscall.CloneFile (source, destination, flags) ->
            UnixNamespace.tryCloneFile caller flags system
            |> CallProgress.resumeWith (fun paused ->
                UnixNamespace.tryCloneFileWithSource source paused
                |> CallProgress.resumeWith (UnixNamespace.tryCloneFileWithDestination destination)
            )
            |> Result.map SteppedCall.CloneFile
            |> Result.mapError SyscallRefusal.CloneFile
        | Syscall.Symlink (target, path) ->
            Ok (UnixNamespace.symlink caller target system)
            |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)
            |> Result.map SteppedCall.Symlink
            |> Result.mapError SyscallRefusal.Symlink
        | Syscall.SymlinkAt (target, dirfd, path) ->
            Ok (UnixNamespace.symlinkat caller target dirfd system)
            |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)
            |> Result.map SteppedCall.SymlinkAt
            |> Result.mapError SyscallRefusal.SymlinkAt
        | Syscall.Link (oldpath, newpath) ->
            UnixNamespace.tryLink caller oldpath system
            |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)
            |> Result.map SteppedCall.Link
            |> Result.mapError SyscallRefusal.Link
        | Syscall.LinkAt (olddirfd, oldpath, newdirfd, newpath, flags) ->
            UnixNamespace.tryLinkat caller olddirfd oldpath newdirfd flags system
            |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)
            |> Result.map SteppedCall.LinkAt
            |> Result.mapError SyscallRefusal.LinkAt
        | Syscall.Read (fd, buffer, count) ->
            UnixReadWrite.tryRead caller fd buffer count system
            |> Result.map SteppedCall.Read
            |> Result.mapError SyscallRefusal.Read
        | Syscall.Recv (fd, buffer, count, flags) ->
            UnixReadWrite.tryRecv caller fd buffer count flags system
            |> Result.map SteppedCall.Recv
            |> Result.mapError SyscallRefusal.Recv
        | Syscall.PRead (fd, buffer, count, offset) ->
            UnixReadWrite.tryPread caller fd buffer count offset system
            |> Result.map SteppedCall.PRead
            |> Result.mapError SyscallRefusal.PRead
        | Syscall.Write (fd, buffer, count) ->
            UnixReadWrite.tryWrite caller fd (bufferOf buffer) count system
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.tryWriteWithBytes (copied buffer (PausedWrite.copyRange paused)) paused
            )
            |> Result.map SteppedCall.Write
            |> Result.mapError SyscallRefusal.Write
        | Syscall.Send (fd, buffer, count, flags) ->
            UnixReadWrite.trySend caller fd (bufferOf buffer) count flags system
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.trySendWithBytes (copied buffer (PausedSend.copyRange paused)) paused
            )
            |> Result.map SteppedCall.Send
            |> Result.mapError SyscallRefusal.Send
        | Syscall.PWrite (fd, buffer, count, offset) ->
            UnixReadWrite.tryPwrite caller fd (bufferOf buffer) count offset system
            |> CallProgress.resumeWith (fun paused ->
                UnixReadWrite.tryPwriteWithBytes (copied buffer (PausedPWrite.copyRange paused)) paused
            )
            |> Result.map SteppedCall.PWrite
            |> Result.mapError SyscallRefusal.PWrite
        | Syscall.CopyFileRange (inFd, outFd, length, flags) ->
            UnixReadWrite.tryCopyFileRange caller inFd outFd length flags system
            |> Result.map SteppedCall.CopyFileRange
            |> Result.mapError SyscallRefusal.CopyFileRange
        | Syscall.Pipe2 (destination, flags) ->
            UnixPipe.tryPipe2 caller flags destination system
            |> Result.map SteppedCall.Pipe2
            |> Result.mapError SyscallRefusal.Pipe2
        | Syscall.Bind (fd, address, declaredLength) ->
            UnixSocket.tryBind caller fd (bufferOf address) declaredLength system
            |> CallProgress.resumeWith (fun paused ->
                UnixSocket.tryBindWithAddress (copied address (PausedBind.copyRange paused)) paused
            )
            |> Result.map SteppedCall.Bind
            |> Result.mapError SyscallRefusal.Bind
        | Syscall.Connect (fd, address, declaredLength) ->
            UnixConnection.tryConnect caller fd (bufferOf address) declaredLength system
            |> CallProgress.resumeWith (fun paused ->
                UnixConnection.tryConnectWithAddress (copied address (PausedConnect.copyRange paused)) paused
            )
            |> Result.map SteppedCall.Connect
            |> Result.mapError SyscallRefusal.Connect
        | Syscall.SetSockOpt (fd, level, optionName, value, optionLength) ->
            UnixSocket.trySetsockopt caller fd level optionName (bufferOf value) optionLength system
            |> CallProgress.resumeWith (fun paused ->
                UnixSocket.trySetsockoptWithValue (copied value (PausedSetSockOpt.copyRange paused)) paused
            )
            |> Result.map SteppedCall.SetSockOpt
            |> Result.mapError SyscallRefusal.SetSockOpt
        | Syscall.GetSockOpt (fd, level, optionName, value, length) ->
            UnixSocket.tryGetsockopt caller fd level optionName value (bufferOf length) system
            |> CallProgress.resumeWith (fun paused -> UnixSocket.tryGetsockoptWithLength (cell length) paused)
            |> Result.map SteppedCall.GetSockOpt
            |> Result.mapError SyscallRefusal.GetSockOpt
        | Syscall.InotifyInit1 flags ->
            UnixInotify.tryInotifyInit1 caller flags system
            |> Result.map SteppedCall.InotifyInit1
            |> Result.mapError SyscallRefusal.InotifyInit1
        | Syscall.InotifyAddWatch (fd, path, mask) ->
            Eager.tryInotifyAddWatchAs caller fd path mask system
            |> Result.map SteppedCall.InotifyAddWatch
            |> Result.mapError SyscallRefusal.InotifyAddWatch
        | Syscall.InotifyRmWatch (fd, wd) ->
            UnixInotify.tryInotifyRmWatch caller fd wd system
            |> Result.map SteppedCall.InotifyRmWatch
            |> Result.mapError SyscallRefusal.InotifyRmWatch
        | Syscall.GetProcessId -> Ok (SteppedCall.GetProcessId (UnixSystem.processId caller system))
        | Syscall.UMask mask -> Ok (SteppedCall.UMask (UnixSystem.umask caller mask system))
        | Syscall.SetResUid (real, effective, saved) ->
            UnixCredentials.trySetresuid caller real effective saved system
            |> Result.map SteppedCall.SetResUid
            |> Result.mapError SyscallRefusal.SetResUid
        | Syscall.SetResGid (real, effective, saved) ->
            UnixCredentials.trySetresgid caller real effective saved system
            |> Result.map SteppedCall.SetResGid
            |> Result.mapError SyscallRefusal.SetResGid
        | Syscall.SetGroups (size, words) ->
            UnixCredentials.trySetgroups caller size words system
            |> Result.map SteppedCall.SetGroups
            |> Result.mapError SyscallRefusal.SetGroups
        | other -> failwith $"%s{UnionCaseName.ofValue other} is no call step makes yet"

    /// What a call answered, as values to compare: the `SteppedCall`'s case
    /// and fields, or the refusal, or the type and message of what it threw.
    let private observe
        (f : unit -> Result<SteppedCall<int, string>, SyscallRefusal<int>>)
        : Result<Result<string * obj list, SyscallRefusal<int>>, string * string>
        =
        try
            Ok (f () |> Result.map Stepped.view)
        with e ->
            Error (e.GetType().FullName, e.Message)

    /// The system a call left, if it answered without parking its thread.
    let private carriedOn (stepped : SteppedCall<int, string>) : UnixSystem<int, string> option =
        match stepped with
        | SteppedCall.FLock (SyscallOutcome.Answered _, system) -> Some system
        | SteppedCall.FLock _ -> None
        | SteppedCall.InotifyInit1 (Ok (_, system)) -> Some system
        | SteppedCall.InotifyInit1 (Error _) -> None
        | SteppedCall.UMask (_, system) -> Some system
        | SteppedCall.Open (SyscallOutcome.Answered _, system)
        | SteppedCall.OpenAt (SyscallOutcome.Answered _, system)
        | SteppedCall.Connect (SyscallOutcome.Answered _, system) -> Some system
        | SteppedCall.Open _
        | SteppedCall.OpenAt _
        | SteppedCall.Connect _ -> None
        | SteppedCall.ReadDirectoryEntry (_, system) -> Some system
        | SteppedCall.Read (ReadOutcome.Answered _, system)
        | SteppedCall.Recv (ReadOutcome.Answered _, system) -> Some system
        | SteppedCall.Read _
        | SteppedCall.Recv _ -> None
        | SteppedCall.PRead (_, system) -> Some system
        // A write that raised a signal leaves its thread owing a return to user
        // mode, which no call here makes.
        | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns _, system))
        | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns _, system)) -> Some system
        | SteppedCall.Write _
        | SteppedCall.Send _ -> None
        | SteppedCall.PWrite (_, system) -> Some system
        | SteppedCall.Pipe2 (_, system) -> Some system
        | SteppedCall.Bind (_, system) -> Some system
        | SteppedCall.SetSockOpt (_, system) -> Some system
        | SteppedCall.GetSockOpt (_, system) -> Some system
        | stepped ->
            match Stepped.syscallAnswer stepped with
            | Some (_, system) -> system
            | None -> None

    // ------------------------------------------------------------- worlds

    let private name (text : string) : DirectoryEntryName =
        DirectoryEntryName.parseOrFail context text

    let private owner (id : uint32) : InodeOwner =
        {
            User = UserId.parseOrFail context id
            Group = GroupId.parseOrFail context id
        }

    let private bytes (text : string) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Encoding.ASCII.GetBytes text)

    /// `/f` and `/d/g` files, `/d/e` an empty directory, `/l` a link to `f`,
    /// `/dangling` a link to nothing, and `/theirs` and `/sticky/theirs` files
    /// another user owns, in a sticky directory for the second.
    let private seed : Map<DirectoryEntryName, SeedEntry> =
        let other = owner 1234u

        Map.ofList
            [
                name "f", SeedEntry.file (bytes "hello")
                name "d",
                SeedEntry.directory (
                    Map.ofList
                        [
                            name "g", SeedEntry.file (bytes "g")
                            name "e", SeedEntry.directory Map.empty
                        ]
                )
                name "l", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "f", None)
                name "dangling", SeedEntry.Symlink (SymlinkTarget.parseOrFail context "nx", None)
                name "theirs", SeedEntry.File (bytes "t", PermissionBits.parseOrFail context 0o640, Some other)
                name "sticky",
                SeedEntry.Directory (
                    Map.ofList
                        [
                            name "theirs",
                            SeedEntry.File (bytes "t", PermissionBits.parseOrFail context 0o644, Some other)
                        ],
                    PermissionBits.parseOrFail context 0o1777,
                    None
                )
            ]

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    /// The calls of a world are made by thread 0, its leader, or thread 1.
    let private threads : int list = [ 0 ; 1 ]

    /// The address the world's listener is bound to.
    let private listening : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback 5000us

    /// `system` with four TCP sockets, made by its leader: 8, fresh from
    /// `socket(2)`; 9, listening at `listening`; 10, connected to 9; and 11,
    /// the server end 9 accepted.
    let private withSockets
        (platform : SimulatedUnixPlatform)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let stream (expected : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system with
            | fd, system when fd = expected -> system
            | fd, _ -> failwith $"setting up, socket: %d{fd}, not %d{expected}"

        let system = system |> stream 8 |> stream 9

        let system =
            match CopyIn.bind 9 UserBuffer.Mapped 16u (CopyIn.inet platform listening) system with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"setting up, bind: %A{other}"

        let system =
            match UnixSocket.tryListen (Callers.leader system) 9 8 system with
            | Ok (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"setting up, listen: %A{other}"

        let system = stream 10 system

        let system =
            match CopyIn.connect 10 UserBuffer.Mapped 16u (CopyIn.inet platform listening) system with
            | Ok (SyscallAnswer.Completed 0L, system) -> system
            | other -> failwith $"setting up, connect: %A{other}"

        match UnixConnection.tryAccept (Callers.leader system) 9 UserBuffer.Mapped 16u system with
        | Ok (AcceptOutcome.Accepted (11, _, _), system) -> system
        | other -> failwith $"setting up, accept: %A{other}"

    /// A booted process on `platform`, as root or as the flavour's default
    /// user, owning the seeded tree, with two threads, and with `/f` open
    /// read-write as 3, `/d` as 4, `/d/g` as 5 and `/f` again, read-only, as
    /// 6. Under Linux, 7 is an inotify instance watching `/d` as watch 1, and
    /// under Darwin, `/d/e`. Then 8 to 11 are the sockets of `withSockets`.
    let private world (platform : SimulatedUnixPlatform) (privileged : bool) : UnixSystem<int, string> =
        let flavour = SimulatedUnixPlatform.flavour platform
        let ordinary = UnixSystem.defaultCredentials flavour

        let credentials =
            if privileged then
                Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []
            else
                ordinary

        let opened (path : string) (flags : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixNamespace.openPath (Callers.leader system) flags (PathArg.ofText path) 0 system with
            | SyscallOutcome.Answered (SyscallAnswer.Completed _), system -> system
            | other -> failwith $"setting up, open(%s{path}): %A{other}"

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.fileSystem (UnixTimestamp.ofMillisecondsSinceEpoch 0L) (InodeOwner.ofProcess ordinary) seed
            |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure 1
            |> opened "/f" 2
            |> opened "/d" 0
            |> opened "/d/g" 0
            |> opened "/f" 0

        let system =
            match flavour with
            | SimulatedUnixFlavour.Darwin -> opened "/d/e" 0 system
            | SimulatedUnixFlavour.Linux ->
                match UnixInotify.inotifyInit1 (Callers.leader system) 0 system with
                | Ok (7, system) ->
                    // IN_CREATE.
                    match Eager.tryInotifyAddWatch 7 (PathArg.ofText "/d") 0x100u system with
                    | Ok (SyscallAnswer.Completed 1L, system) -> system
                    | other -> failwith $"setting up, inotify_add_watch: %A{other}"
                | other -> failwith $"setting up, inotify_init1: %A{other}"

        withSockets platform system

    let private worlds : Lazy<Map<SimulatedUnixFlavour * bool, UnixSystem<int, string>>> =
        lazy
            Map.ofList
                [
                    for platform in platforms do
                        for privileged in [ true ; false ] do
                            yield (SimulatedUnixPlatform.flavour platform, privileged), world platform privileged
                ]

    // ------------------------------------------------------------- generators

    let private fdGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        Gen.frequency
            [
                8, Gen.choose (0, 12)
                1, Gen.elements [ -1 ; 99 ; 1023 ; 1024 ]
                2, Gen.constant (AtDirectory.atFdCwd flavour)
            ]

    let private pathTexts : string list =
        [
            "/f"
            "/d"
            "/d/g"
            "/d/e"
            "/d/e/"
            "/l"
            "/dangling"
            "/nx"
            "/nx/y"
            "f"
            "d"
            "g"
            "e"
            "new"
            "/d/new"
            "/new"
            "/f/"
            "."
            ".."
            "/theirs"
            "/sticky"
            "/sticky/theirs"
            "/sticky/new"
            ""
        ]

    let private pathGen : Gen<PathArgumentBytes> =
        Gen.frequency
            [
                12, Gen.elements pathTexts |> Gen.map PathArg.ofText
                1, Gen.constant PathArgumentBytes.Unreadable
            ]

    let private modeGen : Gen<int> =
        Gen.frequency
            [
                3, Gen.elements [ 0 ; 0o644 ; 0o700 ; 0o755 ; 0o777 ; 0o1777 ; 0o2755 ; 0o4755 ]
                1, Gen.choose (0, 0o7777)
                1, Gen.choose (Int32.MinValue, Int32.MaxValue)
            ]

    /// Flag words of both flavours' `*at` calls, and anything else.
    let private atFlagsGen : Gen<int> =
        Gen.frequency
            [
                4, Gen.constant 0
                3, Gen.elements [ 0x4 ; 0x10 ; 0x20 ; 0x40 ; 0x80 ; 0x100 ; 0x200 ; 0x400 ; 0x800 ; 0x1000 ]
                1, Gen.choose (0, 0xFFFF)
            ]

    let private userGen : Gen<UserId option> =
        Gen.elements [ None ; Some 0u ; Some 501u ; Some 1000u ; Some 1234u ]
        |> Gen.map (Option.map (UserId.parseOrFail context))

    let private groupGen : Gen<GroupId option> =
        Gen.elements [ None ; Some 0u ; Some 12u ; Some 20u ; Some 1000u ; Some 1234u ]
        |> Gen.map (Option.map (GroupId.parseOrFail context))

    let private offsetGen : Gen<int64> =
        Gen.frequency
            [
                4, Gen.choose (-3, 40) |> Gen.map int64
                1, Gen.elements [ Int64.MinValue ; -1L ; Int64.MaxValue ]
            ]

    let private timespecGen : Gen<TimespecFields> =
        Gen.map2
            (fun seconds nanoseconds ->
                {
                    Seconds = seconds
                    Nanoseconds = nanoseconds
                }
            )
            (Gen.elements [ -1L ; 0L ; 1L ; 1_000_000_000L ; Int64.MaxValue ])
            (Gen.elements
                [
                    -2L
                    -1L
                    0L
                    999_999_999L
                    1_000_000_000L
                    (1L <<< 30) - 2L
                    (1L <<< 30) - 1L
                ])

    /// Mostly the world's sockets, for a call that asks a socket something.
    let private socketFdGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        Gen.frequency [ 3, Gen.choose (8, 11) ; 1, fdGen flavour ]

    /// Mostly the world's connected sockets, for a call that moves bytes
    /// through one.
    let private connectedFdGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        Gen.frequency [ 3, Gen.elements [ 10 ; 11 ] ; 1, socketFdGen flavour ]

    /// Mostly what the world can write to: `/f` through 3, the drained
    /// standard output and error, and the connected sockets.
    let private writableFdGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        Gen.frequency [ 3, Gen.elements [ 1 ; 2 ; 3 ; 3 ; 10 ; 11 ] ; 1, fdGen flavour ]

    /// Two values of `gen` that differ, so that an arm passing one where the
    /// other belongs is caught.
    let private distinct2<'T when 'T : equality> (first : Gen<'T>) (second : Gen<'T>) : Gen<'T * 'T> =
        Gen.zip first second |> Gen.filter (fun (a, b) -> a <> b)

    /// Three values that differ pairwise, as `distinct2`'s two do.
    let private distinct3<'T when 'T : equality>
        (first : Gen<'T>)
        (second : Gen<'T>)
        (third : Gen<'T>)
        : Gen<'T * 'T * 'T>
        =
        Gen.zip3 first second third
        |> Gen.filter (fun (a, b, c) -> a <> b && b <> c && a <> c)

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform =
        platforms
        |> List.find (fun platform -> SimulatedUnixPlatform.flavour platform = flavour)

    /// A buffer a call writes to.
    let private userBufferGen : Gen<UserBuffer> =
        Gen.frequency
            [
                8, Gen.constant UserBuffer.Mapped
                2,
                Gen.elements [ 0UL ; 0x1000UL ; UInt64.MaxValue - 7UL ]
                |> Gen.map UserBuffer.Unmapped
                1, Gen.constant UserBuffer.Opaque
                1, Gen.constant UserBuffer.Addressless
            ]

    /// What a call reads from the caller's memory: what `contents` makes, or
    /// one of the reasons there is nothing to read.
    let private copiedGen<'T> (contents : Gen<'T>) : Gen<CopiedArgument<'T>> =
        Gen.frequency
            [
                8, contents |> Gen.map CopiedArgument.Readable
                2,
                Gen.elements [ 0UL ; 0x1000UL ; UInt64.MaxValue - 7UL ]
                |> Gen.map CopiedArgument.Unmapped
                1, Gen.constant CopiedArgument.Opaque
                1, Gen.constant CopiedArgument.Addressless
            ]

    let private bytesGen : Gen<ImmutableArray<byte>> =
        gen {
            let! length = Gen.choose (0, 24)
            let! bytes = Gen.arrayOfLength length (Gen.choose (0, 255))
            return ImmutableArray.CreateRange (Array.map byte bytes)
        }

    /// A buffer a call reads, and the count it is asked to read of it: mostly
    /// within what a readable buffer holds, sometimes past it, and sometimes
    /// more than a call moves.
    let private bufferAndCountGen : Gen<CopiedArgument<ImmutableArray<byte>> * uint64> =
        gen {
            let! buffer = copiedGen bytesGen

            let held =
                match buffer with
                | CopiedArgument.Readable contents -> contents.Length
                | CopiedArgument.Unmapped _
                | CopiedArgument.Opaque
                | CopiedArgument.Addressless -> 8

            let! count =
                Gen.frequency
                    [
                        6, Gen.choose (0, held) |> Gen.map uint64
                        1, Gen.choose (held + 1, held + 4) |> Gen.map uint64
                        1, Gen.elements [ 0x7FFF_FFFFUL ; 0x8000_0000UL ; UInt64.MaxValue ]
                    ]

            return buffer, count
        }

    let private countGen : Gen<uint64> =
        Gen.frequency
            [
                6, Gen.elements [ 0UL ; 1UL ; 3UL ; 5UL ; 16UL ; 100UL ]
                1, Gen.elements [ 0x7FFF_FFFFUL ; 0x8000_0000UL ; UInt64.MaxValue ]
            ]

    /// `recv(2)` and `send(2)` flag words in `flavour`'s numbering: `MSG_PEEK`,
    /// `MSG_DONTWAIT`, `MSG_NOSIGNAL`, and `MSG_OOB`, which is refused.
    let private messageFlagsGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        let dontWait, noSignal =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 0x40, 0x4000
            | SimulatedUnixFlavour.Darwin -> 0x80, 0x80000

        Gen.elements [ 0 ; 2 ; dontWait ; noSignal ; dontWait ||| noSignal ; 2 ||| dontWait ; 1 ]

    /// `open(2)` flag words on `platform`: an access mode and a few of the
    /// bits its `<fcntl.h>` defines.
    let private openFlagsGen (platform : SimulatedUnixPlatform) : Gen<int> =
        let bits = OpenFlagWords.table platform |> List.map (fun (bit, _, _) -> bit)

        gen {
            let! access = Gen.frequency [ 6, Gen.choose (0, 2) ; 1, Gen.constant 3 ]
            let! count = Gen.frequency [ 3, Gen.constant 0 ; 3, Gen.constant 1 ; 2, Gen.constant 2 ]
            let! chosen = Gen.listOfLength count (Gen.elements bits)
            return List.fold (|||) access chosen
        }

    /// A `struct sockaddr` a caller holds for `platform`: an IPv4 one naming
    /// the world's listener, another port, the wildcard or an address the
    /// machine does not have; one of another family; or any bytes.
    let private sockaddrGen (platform : SimulatedUnixPlatform) : Gen<ImmutableArray<byte>> =
        let endpoints =
            [
                listening
                Ipv4Endpoint.ofParts Ipv4Address.loopback 5001us
                Ipv4Endpoint.ofParts Ipv4Address.loopback 0us
                Ipv4Endpoint.ofParts Ipv4Address.any 0us
                Ipv4Endpoint.ofParts (Ipv4Address 0x0A010203u) 80us
            ]

        Gen.frequency
            [
                6,
                Gen.elements endpoints
                |> Gen.map (fun endpoint -> ImmutableArray.CreateRange (CopyIn.inet platform endpoint))
                1,
                Gen.elements endpoints
                |> Gen.map (fun endpoint -> ImmutableArray.CreateRange (CopyIn.blob platform 99 endpoint))
                2, bytesGen
            ]

    let private sockaddrLengthGen : Gen<uint32> =
        Gen.frequency
            [
                4, Gen.constant 16u
                3, Gen.elements [ 0u ; 1u ; 2u ; 8u ; 15u ; 17u ; 28u ; 128u ; 255u ; 256u ; UInt32.MaxValue ]
            ]

    /// A socket option level and name on `platform`: mostly the pairs this
    /// kernel models, and otherwise any level beside any name.
    let private socketOptionGen (platform : SimulatedUnixPlatform) : Gen<int * int> =
        let socketLevel = SimulatedUnixPlatform.socketOptionLevel platform
        let tcpLevel = SimulatedUnixPlatform.tcpOptionLevel platform
        let ipv6Level = SimulatedUnixPlatform.ipv6OptionLevel platform

        let names =
            [
                SimulatedUnixPlatform.reuseAddressOption platform
                SimulatedUnixPlatform.socketErrorOption platform
                SimulatedUnixPlatform.noDelayOption platform
                SimulatedUnixPlatform.ipv6OnlyOption platform
                SimulatedUnixPlatform.lingerOption platform
                999
            ]

        Gen.frequency
            [
                4,
                Gen.elements
                    [
                        socketLevel, SimulatedUnixPlatform.reuseAddressOption platform
                        socketLevel, SimulatedUnixPlatform.lingerOption platform
                        socketLevel, SimulatedUnixPlatform.socketErrorOption platform
                        tcpLevel, SimulatedUnixPlatform.noDelayOption platform
                        ipv6Level, SimulatedUnixPlatform.ipv6OnlyOption platform
                    ]
                1, Gen.zip (Gen.elements [ socketLevel ; tcpLevel ; ipv6Level ; 0 ; -1 ]) (Gen.elements names)
            ]

    /// A socket option's value as a caller holds it: a C `int`, a
    /// `struct linger`, or any bytes.
    let private optionValueGen (platform : SimulatedUnixPlatform) : Gen<ImmutableArray<byte>> =
        let encoded (values : int list) : ImmutableArray<byte> =
            values
            |> List.collect (SimulatedUnixPlatform.encodeCInt platform >> List.ofArray)
            |> ImmutableArray.CreateRange

        Gen.frequency
            [
                4, Gen.elements [ 0 ; 1 ; 2 ; -1 ] |> Gen.map (List.singleton >> encoded)
                2,
                Gen.zip (Gen.elements [ 0 ; 1 ]) (Gen.elements [ 0 ; 5 ; -1 ; 40000 ])
                |> Gen.map (fun (onOff, time) -> encoded [ onOff ; time ])
                1, bytesGen
            ]

    /// A `mknod(2)` mode: a regular file's, the file types this kernel
    /// refuses or answers for, or any mode.
    let private nodeModeGen : Gen<int> =
        Gen.frequency
            [
                4, Gen.elements [ 0o100644 ; 0o100000 ; 0o010644 ; 0o140644 ; 0o020644 ; 0o040755 ; 0o644 ; 0 ]
                1, modeGen
            ]

    let private nodeDeviceGen : Gen<uint32> =
        Gen.elements [ 0u ; 1u ; 0x0103u ; UInt32.MaxValue ]

    /// `pipe2(2)` flag words in `flavour`'s numbering: `O_CLOEXEC`,
    /// `O_NONBLOCK`, Linux's `O_DIRECT` and `O_NOTIFICATION_PIPE`, and a word
    /// either rejects.
    let private pipeFlagsGen (flavour : SimulatedUnixFlavour) : Gen<int> =
        match flavour with
        | SimulatedUnixFlavour.Linux -> Gen.elements [ 0 ; 0x80000 ; 0x800 ; 0x80800 ; 0x4000 ; 0x80 ; 0x1 ]
        | SimulatedUnixFlavour.Darwin -> Gen.elements [ 0 ; 0x1000000 ; 0x4 ; 0x1000004 ; 0x1 ]

    let private optionLengthGen : Gen<uint32> =
        Gen.frequency
            [
                4, Gen.elements [ 4u ; 8u ]
                2, Gen.elements [ 0u ; 1u ; 16u ; 0x8000_0000u ; UInt32.MaxValue ]
            ]

    /// A generator of calls of each case `step` makes, by the case's name.
    let private callGens (flavour : SimulatedUnixFlavour) : (string * Gen<Syscall<int, string>>) list =
        let fd = fdGen flavour
        let socketFd = socketFdGen flavour
        let connectedFd = connectedFdGen flavour
        let writableFd = writableFdGen flavour
        let platform = platformOf flavour
        let paths = distinct2 pathGen pathGen

        // A socket, an option's level and its name, all different.
        let socketOption : Gen<int * int * int> =
            Gen.zip socketFd (socketOptionGen platform)
            |> Gen.map (fun (fd, (level, optionName)) -> fd, level, optionName)
            |> Gen.filter (fun (fd, level, optionName) -> fd <> level && level <> optionName && fd <> optionName)

        [
            "Dup", fd |> Gen.map Syscall.Dup
            "Dup2", Gen.map2 (fun oldFd newFd -> Syscall.Dup2 (oldFd, newFd)) fd fd
            "Dup3",
            Gen.map3
                (fun oldFd newFd flags -> Syscall.Dup3 (oldFd, newFd, flags))
                fd
                fd
                (Gen.elements [ 0 ; 1 ; 0x800 ; 0x80000 ; -1 ])
            "Fcntl",
            Gen.map3
                (fun fd command argument -> Syscall.Fcntl (fd, command, argument))
                fd
                (Gen.frequency
                    [
                        4, Gen.choose (0, 12)
                        1, Gen.elements [ -1 ; 67 ; 1024 ; 1025 ; 1030 ; 1031 ; 1032 ; 1033 ; 1034 ]
                    ])
                (Gen.frequency
                    [
                        3, Gen.choose (-1, 10)
                        2, Gen.elements [ 0x4 ; 0x400 ; 0x800 ; 0x2000 ; 0x40000 ; 0x80000 ]
                        1, Gen.choose (Int32.MinValue, Int32.MaxValue)
                    ])
            "LSeek",
            Gen.map3 (fun fd offset whence -> Syscall.LSeek (fd, offset, whence)) fd offsetGen (Gen.choose (-1, 5))
            "FLock",
            Gen.map2
                (fun fd operation -> Syscall.FLock (fd, operation))
                fd
                (Gen.frequency [ 6, Gen.choose (0, 15) ; 1, Gen.elements [ -1 ; 16 ; 32 ] ])
            "FTruncate", Gen.map2 (fun fd length -> Syscall.FTruncate (fd, length)) fd offsetGen
            "PosixFAdvise",
            gen {
                let! fd, advice = distinct2 fd (Gen.elements [ 0 ; 1 ; 2 ; 3 ; 4 ; 5 ; 6 ; -1 ])
                let! offset, length = distinct2 offsetGen offsetGen
                return Syscall.PosixFAdvise (fd, offset, length, advice)
            }
            "Close", fd |> Gen.map Syscall.Close
            "BytesAvailable",
            Gen.map2 (fun fd destination -> Syscall.BytesAvailable (fd, destination)) socketFd userBufferGen
            "FileClone", Gen.map2 (fun destination source -> Syscall.FileClone (destination, source)) fd fd
            "TerminalAttributes", fd |> Gen.map Syscall.TerminalAttributes
            "GetEffectiveUserId", Gen.constant Syscall.GetEffectiveUserId
            "GetEffectiveGroupId", Gen.constant Syscall.GetEffectiveGroupId
            "GetGroups",
            Gen.map2
                (fun size destination -> Syscall.GetGroups (size, destination))
                (Gen.elements [ -1 ; 0 ; 1 ; 2 ; 16 ; 65537 ])
                userBufferGen
            "Stat",
            Gen.map2
                (fun policy path -> Syscall.Stat (policy, path))
                (Gen.elements [ SymlinkPolicy.Follow ; SymlinkPolicy.NoFollowFinal ])
                pathGen
            "FStat", fd |> Gen.map Syscall.FStat
            "FStatAt",
            gen {
                let! dirfd, flags = distinct2 fd atFlagsGen
                let! path = pathGen
                return Syscall.FStatAt (dirfd, path, flags)
            }
            "ChMod", Gen.map2 (fun path mode -> Syscall.ChMod (path, mode)) pathGen modeGen
            "FChMod", Gen.map2 (fun fd mode -> Syscall.FChMod (fd, mode)) fd modeGen
            "FChModAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! mode = modeGen
                let! flags = atFlagsGen
                return Syscall.FChModAt (dirfd, path, mode, flags)
            }
            "ChOwn", Gen.map3 (fun path user group -> Syscall.ChOwn (path, user, group)) pathGen userGen groupGen
            "LChOwn", Gen.map3 (fun path user group -> Syscall.LChOwn (path, user, group)) pathGen userGen groupGen
            "FChOwn", Gen.map3 (fun fd user group -> Syscall.FChOwn (fd, user, group)) fd userGen groupGen
            "FChOwnAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! user = userGen
                let! group = groupGen
                let! flags = atFlagsGen
                return Syscall.FChOwnAt (dirfd, path, user, group, flags)
            }
            "UTimensAt",
            gen {
                let! dirfd = fd

                let! path =
                    Gen.frequency
                        [
                            1, Gen.constant NullablePathArgument.Null
                            6, pathGen |> Gen.map NullablePathArgument.NotNull
                        ]

                let! times =
                    Gen.frequency
                        [
                            1, Gen.constant TimesArgument.Null
                            1, Gen.constant TimesArgument.Unreadable
                            4,
                            Gen.map2
                                (fun access modification -> TimesArgument.Fields (access, modification))
                                timespecGen
                                timespecGen
                        ]

                let! flags = atFlagsGen
                return Syscall.UTimensAt (dirfd, path, times, flags)
            }
            "StatFs", pathGen |> Gen.map Syscall.StatFs
            "FStatFs", fd |> Gen.map Syscall.FStatFs
            "GetCwd",
            Gen.map2
                (fun destination capacity -> Syscall.GetCwd (destination, capacity))
                userBufferGen
                (Gen.elements [ 0UL ; 1UL ; 2UL ; 5UL ; 4096UL ; UInt64.MaxValue ])
            "ChDir", pathGen |> Gen.map Syscall.ChDir
            "Access",
            Gen.map2
                (fun path mode -> Syscall.Access (path, mode))
                pathGen
                (Gen.frequency [ 6, Gen.choose (0, 7) ; 1, Gen.elements [ -1 ; 8 ; 0x100 ] ])
            "FAccessAt",
            gen {
                let! dirfd = fd
                let! path = pathGen
                let! mode = Gen.frequency [ 6, Gen.choose (0, 7) ; 1, Gen.elements [ -1 ; 8 ; 0x100 ] ]
                let! flags = atFlagsGen
                return Syscall.FAccessAt (dirfd, path, mode, flags)
            }
            "Open",
            gen {
                let! flags, mode = distinct2 (openFlagsGen platform) modeGen
                let! path = pathGen
                return Syscall.Open (path, flags, mode)
            }
            "OpenAt",
            gen {
                let! dirfd, flags, mode = distinct3 fd (openFlagsGen platform) modeGen
                let! path = pathGen
                return Syscall.OpenAt (dirfd, path, flags, mode)
            }
            "ReadLink",
            Gen.map3
                (fun path destination capacity -> Syscall.ReadLink (path, destination, capacity))
                pathGen
                userBufferGen
                (Gen.elements [ -1 ; 0 ; 1 ; 3 ; 64 ; Int32.MaxValue ])
            "ReadLinkAt",
            gen {
                let! dirfd, capacity = distinct2 fd (Gen.elements [ -1 ; 0 ; 1 ; 3 ; 64 ; Int32.MaxValue ])
                let! path = pathGen
                let! destination = userBufferGen
                return Syscall.ReadLinkAt (dirfd, path, destination, capacity)
            }
            "ReadDirectoryEntry", fd |> Gen.map Syscall.ReadDirectoryEntry
            "MkDir", Gen.map2 (fun path mode -> Syscall.MkDir (path, mode)) pathGen modeGen
            "MkDirAt", Gen.map3 (fun dirfd path mode -> Syscall.MkDirAt (dirfd, path, mode)) fd pathGen modeGen
            "MkNod", Gen.map3 (fun path mode dev -> Syscall.MkNod (path, mode, dev)) pathGen nodeModeGen nodeDeviceGen
            "MkNodAt",
            gen {
                let! dirfd, mode = distinct2 fd nodeModeGen
                let! path = pathGen
                let! dev = nodeDeviceGen
                return Syscall.MkNodAt (dirfd, path, mode, dev)
            }
            "Unlink", pathGen |> Gen.map Syscall.Unlink
            "RmDir", pathGen |> Gen.map Syscall.RmDir
            "UnlinkAt", Gen.map3 (fun dirfd path flags -> Syscall.UnlinkAt (dirfd, path, flags)) fd pathGen atFlagsGen
            "Rename", paths |> Gen.map Syscall.Rename
            "RenameAt",
            gen {
                let! olddirfd, newdirfd = distinct2 fd fd
                let! oldpath, newpath = paths
                return Syscall.RenameAt (olddirfd, oldpath, newdirfd, newpath)
            }
            "CloneFile",
            Gen.map3
                (fun source destination flags -> Syscall.CloneFile (source, destination, flags))
                pathGen
                pathGen
                (Gen.elements [ 0 ; 1 ; 2 ; 4 ; 8 ; 0x10 ])
            "Symlink", paths |> Gen.map Syscall.Symlink
            "SymlinkAt", Gen.map3 (fun target dirfd path -> Syscall.SymlinkAt (target, dirfd, path)) pathGen fd pathGen
            "Link", paths |> Gen.map Syscall.Link
            "LinkAt",
            gen {
                let! olddirfd = fd
                let! oldpath = pathGen
                let! newdirfd = fd
                let! newpath = pathGen
                let! flags = atFlagsGen
                return Syscall.LinkAt (olddirfd, oldpath, newdirfd, newpath, flags)
            }
            "Read", Gen.map3 (fun fd buffer count -> Syscall.Read (fd, buffer, count)) fd userBufferGen countGen
            "Recv",
            gen {
                let! fd, flags = distinct2 connectedFd (messageFlagsGen flavour)
                let! buffer = userBufferGen
                let! count = countGen
                return Syscall.Recv (fd, buffer, count, flags)
            }
            "PRead",
            gen {
                let! fd = fd
                let! buffer = userBufferGen
                let! count = countGen
                let! offset = offsetGen
                return Syscall.PRead (fd, buffer, count, offset)
            }
            "Write",
            gen {
                let! fd = writableFd
                let! buffer, count = bufferAndCountGen
                return Syscall.Write (fd, buffer, count)
            }
            "Send",
            gen {
                let! fd, flags = distinct2 connectedFd (messageFlagsGen flavour)
                let! buffer, count = bufferAndCountGen
                return Syscall.Send (fd, buffer, count, flags)
            }
            "PWrite",
            gen {
                let! fd = writableFd
                let! buffer, count = bufferAndCountGen
                let! offset = offsetGen
                return Syscall.PWrite (fd, buffer, count, offset)
            }
            "CopyFileRange",
            gen {
                let! inFd = fd
                let! outFd = fd
                let! length = Gen.elements [ 0UL ; 1UL ; 3UL ; 100UL ; UInt64.MaxValue ]
                let! flags = Gen.elements [ 0 ; 1 ]
                return Syscall.CopyFileRange (inFd, outFd, length, flags)
            }
            "Pipe2",
            Gen.map2 (fun destination flags -> Syscall.Pipe2 (destination, flags)) userBufferGen (pipeFlagsGen flavour)
            "Bind",
            Gen.map3
                (fun fd address declaredLength -> Syscall.Bind (fd, address, declaredLength))
                socketFd
                (copiedGen (sockaddrGen platform))
                sockaddrLengthGen
            "Connect",
            Gen.map3
                (fun fd address declaredLength -> Syscall.Connect (fd, address, declaredLength))
                socketFd
                (copiedGen (sockaddrGen platform))
                sockaddrLengthGen
            "SetSockOpt",
            gen {
                let! fd, level, optionName = socketOption
                let! value = copiedGen (optionValueGen platform)
                let! optionLength = optionLengthGen
                return Syscall.SetSockOpt (fd, level, optionName, value, optionLength)
            }
            "GetSockOpt",
            gen {
                let! fd, level, optionName = socketOption
                let! value = userBufferGen
                let! length = copiedGen optionLengthGen
                return Syscall.GetSockOpt (fd, level, optionName, value, length)
            }
            "InotifyInit1",
            Gen.elements [ 0 ; 1 ; 0x800 ; 0x4000 ; 0x80000 ; 0x80800 ]
            |> Gen.map Syscall.InotifyInit1
            "InotifyAddWatch",
            Gen.map3
                (fun fd path mask -> Syscall.InotifyAddWatch (fd, path, mask))
                fd
                pathGen
                (Gen.frequency
                    [
                        4,
                        Gen.elements
                            [
                                0x100u
                                0x200u
                                0x2u
                                0x4u
                                0x300u
                                0x1000100u
                                0x4000100u
                                0x20000100u
                            ]
                        1, Gen.elements [ 0u ; 0x1u ; 0x80000100u ; 0x10000100u ]
                    ])
            "InotifyRmWatch", Gen.map2 (fun fd wd -> Syscall.InotifyRmWatch (fd, wd)) fd (Gen.choose (-1, 3))
            "GetProcessId", Gen.constant Syscall.GetProcessId
            "UMask",
            Gen.frequency [ 3, Gen.choose (0, 0o777) ; 1, Gen.choose (Int32.MinValue, Int32.MaxValue) ]
            |> Gen.map Syscall.UMask
            "SetResUid",
            Gen.map3 (fun real effective saved -> Syscall.SetResUid (real, effective, saved)) userGen userGen userGen
            "SetResGid",
            Gen.map3 (fun real effective saved -> Syscall.SetResGid (real, effective, saved)) groupGen groupGen groupGen
            "SetGroups",
            gen {
                let! words =
                    Gen.listOf (Gen.oneof [ Gen.elements [ 0u ; 20u ; UInt32.MaxValue ] ; CredentialsGen.rawId ])

                let! faults = Gen.elements [ true ; false ]

                return
                    if faults then
                        Syscall.SetGroups (List.length words + 1, GroupListWords.FaultsAfter words)
                    else
                        Syscall.SetGroups (List.length words, GroupListWords.Readable words)
            }
        ]

    [<Test>]
    let ``every case step makes has a generator here`` () : unit =
        for platform in platforms do
            callGens (SimulatedUnixPlatform.flavour platform)
            |> List.map fst
            |> shouldEqual TestSyscall.wired

    // ------------------------------------------------------------- the property

    /// Whether `call`, one that copies a buffer or a cell in, made by `caller`
    /// through its own function with the `UserBuffer` its argument is, stops
    /// at its copy.
    let private stopsAtCopy
        (caller : Caller<int>)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : bool
        =
        let stopped (progress : Result<CallProgress<'Paused, 'Answer>, 'Refusal>) : bool =
            match progress with
            | Ok (CallProgress.NeedsCopyIn _) -> true
            | Ok (CallProgress.Answered _)
            | Error _ -> false

        match call with
        | Syscall.Write (fd, buffer, count) ->
            UnixReadWrite.tryWrite caller fd (bufferOf buffer) count system |> stopped
        | Syscall.Send (fd, buffer, count, flags) ->
            UnixReadWrite.trySend caller fd (bufferOf buffer) count flags system |> stopped
        | Syscall.PWrite (fd, buffer, count, offset) ->
            UnixReadWrite.tryPwrite caller fd (bufferOf buffer) count offset system
            |> stopped
        | Syscall.Bind (fd, address, declaredLength) ->
            UnixSocket.tryBind caller fd (bufferOf address) declaredLength system |> stopped
        | Syscall.Connect (fd, address, declaredLength) ->
            UnixConnection.tryConnect caller fd (bufferOf address) declaredLength system
            |> stopped
        | Syscall.SetSockOpt (fd, level, optionName, value, optionLength) ->
            UnixSocket.trySetsockopt caller fd level optionName (bufferOf value) optionLength system
            |> stopped
        | Syscall.GetSockOpt (fd, level, optionName, value, length) ->
            UnixSocket.tryGetsockopt caller fd level optionName value (bufferOf length) system
            |> stopped
        | other -> failwith $"%s{UnionCaseName.ofValue other} copies no buffer in"

    /// The cases whose call copies a buffer or a cell in from the caller's
    /// memory, which `stopsAtCopy` asks about.
    let private copyingCases : string list =
        [
            "Write"
            "Send"
            "PWrite"
            "Bind"
            "Connect"
            "SetSockOpt"
            "GetSockOpt"
        ]

    let private agree (case : string) : unit =
        // How many of the samples' calls answered.
        let answered = ref 0
        // How many reached a copy from the caller's memory, of a case that has one.
        let reachedCopy = ref 0

        let sample =
            gen {
                let! platform = Gen.elements platforms
                let! privileged = Gen.elements [ true ; false ]
                let flavour = SimulatedUnixPlatform.flavour platform
                let gens = callGens flavour
                let caseGen = gens |> List.find (fun (name, _) -> name = case) |> snd
                let! prefixLength = Gen.choose (0, 4)
                let! prefix = Gen.listOfLength prefixLength (Gen.oneof (List.map snd gens))
                let! caller = Gen.frequency [ 8, Gen.elements threads ; 1, Gen.constant 99 ]
                let! call = caseGen
                return platform, privileged, prefix, caller, call
            }

        let property
            (platform : SimulatedUnixPlatform, privileged : bool, prefix : Syscall<int, string> list, caller : int, call)
            : unit
            =
            let start =
                Map.find (SimulatedUnixPlatform.flavour platform, privileged) worlds.Value

            // The prefix moves the world through the calls' own functions,
            // made by the leader, keeping whatever answered without parking.
            let system =
                (start, prefix)
                ||> List.fold (fun system call ->
                    try
                        match reference (Callers.leader system) call system with
                        | Ok stepped -> carriedOn stepped |> Option.defaultValue system
                        | Error _ -> system
                    with _ ->
                        system
                )

            let caller = Callers.thread caller system
            let viaStep = observe (fun () -> UnixSystem.tryStep caller call system)
            let direct = observe (fun () -> reference caller call system)

            if List.contains case copyingCases then
                let stopped =
                    try
                        stopsAtCopy caller call system
                    with _ ->
                        false

                if stopped then
                    reachedCopy.Value <- reachedCopy.Value + 1

            match viaStep with
            | Ok (Ok (stepped, _)) ->
                answered.Value <- answered.Value + 1
                stepped |> shouldEqual (UnionCaseName.ofValue call)
            | Ok (Error _)
            | Error _ -> ()

            match direct, viaStep with
            // The buffer ends before the bytes the call copies, which the
            // case says it holds: the caller's bug.
            | Error (thrown, _), Error (stepThrew, message) when thrown = typeof<ShortContentsException>.FullName ->
                if
                    stepThrew <> typeof<InvalidOperationException>.FullName
                    || not (message.Contains "hold only")
                then
                    failwith
                        $"%A{call} by %O{caller}: the buffer is too short, and step threw %s{stepThrew}: %s{message}"
            | _ ->
                if viaStep <> direct then
                    failwith
                        $"%A{call} by %O{caller}: step answered %A{viaStep}, and the call's own function %A{direct}"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 300, Prop.forAll (Arb.fromGen sample) property)

        // Not vacuous: the case answered, whatever else it did, and a call that
        // copies in reached its copy.
        answered.Value |> shouldBeGreaterThan 0

        if List.contains case copyingCases then
            reachedCopy.Value |> shouldBeGreaterThan 0

    let private wiredCases : string list = TestSyscall.wired

    [<TestCaseSource(nameof wiredCases)>]
    let ``step makes a call as its own function does`` (case : string) : unit = agree case

    // ------------------------------------------------------------- copy-ins

    /// `count` bytes from `first` up, then four bytes of 0xFF: a buffer that
    /// holds more than a call of `count` bytes copies.
    let private longer (first : byte) (count : int) : ImmutableArray<byte> =
        [ for i in 0 .. count - 1 -> first + byte i ] @ List.replicate 4 0xFFuy
        |> ImmutableArray.CreateRange

    /// A call of each case that copies a buffer in, as the world's leader makes
    /// it on `platform`, where it reaches its copy, its buffer holding
    /// `contents` and the call copying `count` bytes of it.
    let private copyingCalls
        (platform : SimulatedUnixPlatform)
        (contents : int -> CopiedArgument<ImmutableArray<byte>>)
        : Syscall<int, string> list
        =
        let level = SimulatedUnixPlatform.socketOptionLevel platform
        let reuse = SimulatedUnixPlatform.reuseAddressOption platform

        [
            Syscall.Write (3, contents 3, 3UL)
            Syscall.Send (10, contents 4, 4UL, 0)
            Syscall.PWrite (3, contents 2, 2UL, 1L)
            Syscall.Bind (8, contents 16, 16u)
            Syscall.Connect (8, contents 16, 16u)
            Syscall.SetSockOpt (8, level, reuse, contents 4, 4u)
        ]

    [<Test>]
    let ``step copies the bytes the paused call names from a longer buffer, and goes on as the call does`` () : unit =
        for platform in platforms do
            let system = Map.find (SimulatedUnixPlatform.flavour platform, true) worlds.Value
            let leader = Callers.leader system

            let sockaddr (length : int) : ImmutableArray<byte> =
                let laidOut =
                    CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 5001us)

                Seq.append (Seq.take length laidOut) (Seq.replicate 4 0xFFuy)
                |> ImmutableArray.CreateRange

            let reuse =
                Seq.append (SimulatedUnixPlatform.encodeCInt platform 1) (Seq.replicate 4 0xFFuy)
                |> ImmutableArray.CreateRange

            let calls =
                [
                    Syscall.Write (3, CopiedArgument.Readable (longer (byte 'a') 3), 3UL)
                    Syscall.Send (10, CopiedArgument.Readable (longer (byte 'a') 4), 4UL, 0)
                    Syscall.PWrite (3, CopiedArgument.Readable (longer (byte 'X') 2), 2UL, 1L)
                    Syscall.Bind (8, CopiedArgument.Readable (sockaddr 16), 16u)
                    Syscall.Connect (8, CopiedArgument.Readable (sockaddr 16), 16u)
                    Syscall.SetSockOpt (
                        8,
                        SimulatedUnixPlatform.socketOptionLevel platform,
                        SimulatedUnixPlatform.reuseAddressOption platform,
                        CopiedArgument.Readable reuse,
                        4u
                    )
                    Syscall.GetSockOpt (
                        8,
                        SimulatedUnixPlatform.socketOptionLevel platform,
                        SimulatedUnixPlatform.reuseAddressOption platform,
                        UserBuffer.Mapped,
                        CopiedArgument.Readable 4u
                    )
                ]

            for call in calls do
                // Not vacuous: the call reaches its copy.
                stopsAtCopy leader call system |> shouldEqual true

                UnixSystem.tryStep leader call system
                |> Stepped.resultShouldBe (reference leader call system)

            // What the writes put in the file and on the connection is the
            // first bytes of each buffer, and no others.
            let afterWrite =
                match UnixSystem.step leader calls.[0] system with
                | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed 3L), system)) ->
                    system
                | other -> failwith $"write: %A{Stepped.view other}"

            let afterPWrite =
                match UnixSystem.step leader calls.[2] afterWrite with
                | SteppedCall.PWrite (WriteAnswer.Completed 2L, system) -> system
                | other -> failwith $"pwrite: %A{Stepped.view other}"

            match UnixSystem.step leader (Syscall.PRead (6, UserBuffer.Mapped, 16UL, 0L)) afterPWrite with
            | SteppedCall.PRead (ReadAnswer.Completed read, _) ->
                List.ofSeq read |> shouldEqual (List.ofSeq (bytes "aXYlo"))
            | other -> failwith $"pread: %A{Stepped.view other}"

            let afterSend =
                match UnixSystem.step leader calls.[1] system with
                | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed 4L), system)) ->
                    system
                | other -> failwith $"send: %A{Stepped.view other}"

            match UnixSystem.step leader (Syscall.Recv (11, UserBuffer.Mapped, 16UL, 0)) afterSend with
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Completed read), _) ->
                List.ofSeq read |> shouldEqual (List.ofSeq (bytes "abcd"))
            | other -> failwith $"recv: %A{Stepped.view other}"

    [<Test>]
    let ``step throws for a readable buffer that ends before the bytes the call copies`` () : unit =
        for platform in platforms do
            let system = Map.find (SimulatedUnixPlatform.flavour platform, true) worlds.Value
            let leader = Callers.leader system

            let short (count : int) : CopiedArgument<ImmutableArray<byte>> =
                CopiedArgument.Readable (ImmutableArray.CreateRange (List.replicate (count - 1) 1uy))

            for call in copyingCalls platform short do
                stopsAtCopy leader call system |> shouldEqual true

                let thrown =
                    Assert.Throws<InvalidOperationException> (fun () -> UnixSystem.step leader call system |> ignore)

                thrown.Message |> shouldContainText $"Syscall.%s{UnionCaseName.ofValue call}"
                thrown.Message |> shouldContainText "hold only"

            // The default ImmutableArray is no buffer at all, however short.
            for call in
                copyingCalls platform (fun _ -> CopiedArgument.Readable Unchecked.defaultof<ImmutableArray<byte>>) do
                let thrown =
                    Assert.Throws<InvalidOperationException> (fun () -> UnixSystem.step leader call system |> ignore)

                thrown.Message |> shouldContainText "default ImmutableArray"

            // The contents matter only once the call reaches its copy: one
            // answered before it, through a descriptor that is not open, reads
            // nothing.
            for call in copyingCalls platform short do
                let call =
                    match call with
                    | Syscall.Write (_, buffer, count) -> Syscall.Write (99, buffer, count)
                    | Syscall.Send (_, buffer, count, flags) -> Syscall.Send (99, buffer, count, flags)
                    | Syscall.PWrite (_, buffer, count, offset) -> Syscall.PWrite (99, buffer, count, offset)
                    | Syscall.Bind (_, address, declaredLength) -> Syscall.Bind (99, address, declaredLength)
                    | Syscall.Connect (_, address, declaredLength) -> Syscall.Connect (99, address, declaredLength)
                    | Syscall.SetSockOpt (_, level, optionName, value, optionLength) ->
                        Syscall.SetSockOpt (99, level, optionName, value, optionLength)
                    | other -> failwith $"%A{other} copies no buffer in"

                stopsAtCopy leader call system |> shouldEqual false

                UnixSystem.tryStep leader call system
                |> Stepped.resultShouldBe (reference leader call system)

    [<Test>]
    let ``an in-pointer naming no storage answers as the call's own function does`` () : unit =
        for platform in platforms do
            let system = Map.find (SimulatedUnixPlatform.flavour platform, true) worlds.Value
            let leader = Callers.leader system
            let level = SimulatedUnixPlatform.socketOptionLevel platform
            let reuse = SimulatedUnixPlatform.reuseAddressOption platform

            for address in [ 0UL ; 0x1000UL ] do
                let unmapped = UserBuffer.Unmapped address

                let calls
                    : (Syscall<int, string> * (unit -> Result<SteppedCall<int, string>, SyscallRefusal<int>>)) list =
                    let answered
                        (progress : Result<CallProgress<'Paused, 'Answer>, 'Refusal>)
                        : Result<'Answer, 'Refusal>
                        =
                        match progress with
                        | Ok (CallProgress.Answered answer) -> Ok answer
                        | Ok (CallProgress.NeedsCopyIn _) -> failwith "the call stopped to copy from no storage"
                        | Error refusal -> Error refusal

                    [
                        Syscall.Write (3, CopiedArgument.Unmapped address, 3UL),
                        fun () ->
                            UnixReadWrite.tryWrite leader 3 unmapped 3UL system
                            |> answered
                            |> Result.map SteppedCall.Write
                            |> Result.mapError SyscallRefusal.Write
                        Syscall.Send (10, CopiedArgument.Unmapped address, 4UL, 0),
                        fun () ->
                            UnixReadWrite.trySend leader 10 unmapped 4UL 0 system
                            |> answered
                            |> Result.map SteppedCall.Send
                            |> Result.mapError SyscallRefusal.Send
                        Syscall.PWrite (3, CopiedArgument.Unmapped address, 2UL, 1L),
                        fun () ->
                            UnixReadWrite.tryPwrite leader 3 unmapped 2UL 1L system
                            |> answered
                            |> Result.map SteppedCall.PWrite
                            |> Result.mapError SyscallRefusal.PWrite
                        Syscall.Bind (8, CopiedArgument.Unmapped address, 16u),
                        fun () ->
                            UnixSocket.tryBind leader 8 unmapped 16u system
                            |> answered
                            |> Result.map SteppedCall.Bind
                            |> Result.mapError SyscallRefusal.Bind
                        Syscall.Connect (8, CopiedArgument.Unmapped address, 16u),
                        fun () ->
                            UnixConnection.tryConnect leader 8 unmapped 16u system
                            |> answered
                            |> Result.map SteppedCall.Connect
                            |> Result.mapError SyscallRefusal.Connect
                        Syscall.SetSockOpt (8, level, reuse, CopiedArgument.Unmapped address, 4u),
                        fun () ->
                            UnixSocket.trySetsockopt leader 8 level reuse unmapped 4u system
                            |> answered
                            |> Result.map SteppedCall.SetSockOpt
                            |> Result.mapError SyscallRefusal.SetSockOpt
                        Syscall.GetSockOpt (8, level, reuse, UserBuffer.Mapped, CopiedArgument.Unmapped address),
                        fun () ->
                            UnixSocket.tryGetsockopt leader 8 level reuse UserBuffer.Mapped unmapped system
                            |> answered
                            |> Result.map SteppedCall.GetSockOpt
                            |> Result.mapError SyscallRefusal.GetSockOpt
                    ]

                for call, direct in calls do
                    UnixSystem.tryStep leader call system |> Stepped.resultShouldBe (direct ())

                // Not vacuous: a write through it faults, having written nothing.
                match UnixSystem.step leader (fst calls.[0]) system with
                | SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Failed UnixError.EFAULT),
                                                            after)) -> after |> shouldEqual system
                | other -> failwith $"write through %O{unmapped}: %A{Stepped.view other}"
