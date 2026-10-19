namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Runtime.InteropServices
open System.Text
open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel
open WoofWare.PosixKernel.Test.InotifyDeliveryOps

/// Which records a filesystem change queues on the inotify instances watching
/// it, against a real Linux kernel: random sequences (`InotifyDeliveryOps`) of
/// path syscalls (creating, truncating, linking, unlinking, renaming, changing
/// modes, owners and times), of descriptors opened (by path, and onto a
/// directory by "." from another), written through, truncated, `fchmod`ed and
/// closed, and of watches added and removed, some with
/// `IN_EXCL_UNLINK` or `IN_DONT_FOLLOW`, on two instances, each made as one
/// `Syscall` on the model and on a fresh real temporary directory holding the
/// same tree.
/// Every call must answer alike, and after each, the records each instance
/// holds must be alike, cookies compared by which records share one.
///
/// Watches ask for the self events too (`IN_DELETE_SELF`, `IN_MOVE_SELF`),
/// and every `IN_IGNORED` is compared, that of a watched inode's going as
/// well as that of an `inotify_rm_watch`. Linux only; elsewhere the test is
/// ignored.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestInotifyDeliveryAgainstHost =

    [<DllImport("libc", EntryPoint = "link", SetLastError = true)>]
    extern int private hostLink(byte[] existing, byte[] path)

    [<DllImport("libc", EntryPoint = "symlink", SetLastError = true)>]
    extern int private hostSymlink(byte[] target, byte[] path)

    [<DllImport("libc", EntryPoint = "chmod", SetLastError = true)>]
    extern int private hostChmod(byte[] path, int mode)

    [<DllImport("libc", EntryPoint = "chown", SetLastError = true)>]
    extern int private hostChown(byte[] path, uint32 user, uint32 group)

    /// `times` is two `struct timespec`s: seconds and nanoseconds, twice.
    [<DllImport("libc", EntryPoint = "utimensat", SetLastError = true)>]
    extern int private hostUtimensat(int dirfd, byte[] path, int64[] times, int flags)

    [<DllImport("libc", EntryPoint = "fchmod", SetLastError = true)>]
    extern int private hostFchmod(int fd, int mode)

    [<DllImport("libc", EntryPoint = "openat", SetLastError = true)>]
    extern int private hostOpenat(int dirfd, byte[] path, int flags, int mode)

    let private context : string = "TestInotifyDeliveryAgainstHost"

    let private onLinux (action : SimulatedUnixPlatform -> unit) : unit =
        HostPlatform.onUnixHostKernel (fun platform ->
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin -> Assert.Ignore "inotify is Linux's"
            | SimulatedUnixFlavour.Linux -> action platform
        )

    /// Symbolic links' targets, relative and without "..", so that each side's
    /// resolves within its own tree: the host's tree is not at its root.
    let private targets : string list = [ "x" ; "a" ; "s" ; "s/x" ; "missing" ]

    [<RequireQualifiedAccess>]
    type private Label =
        | Record of RecordLabel
        /// A call through a kept descriptor that answered.
        | ThroughDescriptor

    /// A record as compared: the watch descriptor, the mask, the cookie's
    /// ordinal, the name field's length and the name.
    type private Compared = int * uint32 * uint32 * int * string

    let private compared (cookies : Cookies) (record : ReadRecord) : Compared =
        record.Wd, record.Mask, cookies.Ordinal record.Cookie, record.Len, record.Name

    /// `entries` made in the host's `directory`. Every name in `seed` is
    /// ASCII, so `System.IO` can make it.
    let rec private materialise (directory : string) (entries : Map<DirectoryEntryName, SeedEntry>) : unit =
        for KeyValue (name, entry) in entries do
            let path = Path.Combine (directory, PathText.ofName name)

            match entry with
            | SeedEntry.File (contents, permissions, None) ->
                File.WriteAllBytes (path, Seq.toArray contents)
                File.SetUnixFileMode (path, enum<UnixFileMode> (PermissionBits.toInt permissions))
            | SeedEntry.Directory (children, permissions, None) ->
                Directory.CreateDirectory path |> ignore<DirectoryInfo>
                materialise path children
                File.SetUnixFileMode (path, enum<UnixFileMode> (PermissionBits.toInt permissions))
            | other -> failwith $"the seed's %s{path} is %A{other}, which the host's tree is not made with"

    /// The bytes of `path`, which must be readable, and then a NUL.
    let private terminated (path : PathArgumentBytes) : byte[] =
        match path with
        | PathArgumentBytes.Bytes bytes -> Array.append (Seq.toArray (UnixByteString.toBytes bytes)) [| 0uy |]
        | PathArgumentBytes.Unreadable -> failwith "the operations make no call with an unreadable path"

    /// What the host answers `syscall`, made over the tree at `root` in the
    /// model's stead: each path, relative to the model's root, made under
    /// `root`, and each of the model's descriptors replaced by the host's that
    /// `hostFd` maps it to. A symbolic link's target is the model's. Its
    /// return, or the errno it set.
    let private onHost (root : string) (hostFd : int -> int) (syscall : Syscall<int, string>) : Result<int64, int> =
        let under (path : PathArgumentBytes) : byte[] =
            Array.append (Encoding.UTF8.GetBytes (root + "/")) (terminated path)

        // Read at once, before anything else can make a call that sets errno.
        let returned (result : int64) : Result<int64, int> =
            if result >= 0L then
                Ok result
            else
                Error (Marshal.GetLastPInvokeError ())

        match syscall with
        | Syscall.Open (path, flags, mode) -> returned (int64 (HostCalls.openFileBytes (under path, flags, mode)))
        | Syscall.MkDir (path, mode) -> returned (int64 (HostCalls.mkdirBytes (under path, uint32 mode)))
        | Syscall.RmDir path -> returned (int64 (HostCalls.rmdirBytes (under path)))
        | Syscall.Unlink path -> returned (int64 (HostCalls.unlinkBytes (under path)))
        | Syscall.Link (existing, path) -> returned (int64 (hostLink (under existing, under path)))
        | Syscall.Symlink (target, path) -> returned (int64 (hostSymlink (terminated target, under path)))
        | Syscall.Rename (source, destination) ->
            returned (int64 (HostCalls.renameBytes (under source, under destination)))
        | Syscall.ChMod (path, mode) -> returned (int64 (hostChmod (under path, mode)))
        | Syscall.ChOwn (path, user, group) ->
            let user = user |> Option.map UserId.toUInt32 |> Option.defaultValue UInt32.MaxValue

            let group =
                group |> Option.map GroupId.toUInt32 |> Option.defaultValue UInt32.MaxValue

            returned (int64 (hostChown (under path, user, group)))
        | Syscall.UTimensAt (dirfd,
                             NullablePathArgument.NotNull path,
                             TimesArgument.Fields (access, modification),
                             flags) when dirfd = linuxAtFdCwd ->
            let times =
                [|
                    access.Seconds
                    access.Nanoseconds
                    modification.Seconds
                    modification.Nanoseconds
                |]

            returned (int64 (hostUtimensat (dirfd, under path, times, flags)))
        | Syscall.InotifyAddWatch (fd, path, mask) ->
            returned (int64 (HostCalls.inotifyAddWatch (hostFd fd, under path, mask)))
        | Syscall.InotifyRmWatch (fd, wd) -> returned (int64 (HostCalls.inotifyRmWatch (hostFd fd, wd)))
        | Syscall.Write (fd, CopiedArgument.Readable bytes, count) ->
            returned (int64 (HostCalls.write (hostFd fd, Seq.toArray bytes, unativeint count)))
        | Syscall.FTruncate (fd, length) -> returned (int64 (HostCalls.ftruncate (hostFd fd, length)))
        | Syscall.FChMod (fd, mode) -> returned (int64 (hostFchmod (hostFd fd, mode)))
        // The path is relative to the descriptor, so it is not made under
        // `root`.
        | Syscall.OpenAt (dirfd, path, flags, mode) ->
            returned (int64 (hostOpenat (hostFd dirfd, terminated path, flags, mode)))
        | Syscall.Close fd -> returned (int64 (HostCalls.close (hostFd fd)))
        | other -> failwith $"the operations make no %A{other}"

    [<Test>]
    let ``a real inotify and the model queue alike for every path and descriptor change`` () : unit =
        onLinux (fun platform ->
            let numbering = SimulatedUnixPlatform.rawErrnoNumbering platform

            let owner : InodeOwner =
                {
                    User = UserId.parseOrFail context (HostCalls.getEUid ())
                    Group = GroupId.parseOrFail context (HostCalls.getEGid ())
                }

            let tree =
                seed
                |> List.map (fun (entry, seeded) -> DirectoryEntryName.parseOrFail context entry, seeded)
                |> Map.ofList

            let initial : UnixSystem<int, string> =
                UnixSystem.initial platform
                |> Launched.fileSystem (UnixTimestamp.ofMillisecondsSinceEpoch 0L) owner tree
                |> Launched.bootWith
                    (Launched.credentials (Credentials.ofIds owner.User owner.Group []))
                    UnixSystem.pipedStandardStreams
                    0
                    (CpuId 0)

            let hostError (errno : int) : UnixError =
                match UnixError.ofRawErrnoUnder numbering errno with
                | Some error -> error
                | None -> failwith $"the host answered errno %d{errno}, which the model has no name for"

            let property (cover : Label -> unit) (ops : Op list) : unit =
                let root =
                    Path.Combine (Path.GetTempPath (), "inotify-delivery-" + Guid.NewGuid().ToString "N")

                Directory.CreateDirectory root |> ignore<DirectoryInfo>
                materialise root tree

                let hostFds = [| HostCalls.inotifyInit1 0x800 ; HostCalls.inotifyInit1 0x800 |]

                if hostFds |> Array.exists (fun fd -> fd < 0) then
                    failwith "inotify_init1 failed on the host"

                let system = ref initial
                let modelFds = Array.zeroCreate<int> 2

                for i in 0..1 do
                    let fd, after = InotifyReplay.init1 0x800 system.Value
                    system.Value <- after
                    modelFds.[i] <- fd

                let hostCookies = Cookies ()
                let modelCookies = Cookies ()
                // The kept descriptors, oldest first: the host's and the model's.
                let kept = ResizeArray<int * int> ()

                let hostFd (modelFd : int) : int =
                    match Array.tryFindIndex ((=) modelFd) modelFds with
                    | Some instance -> hostFds.[instance]
                    | None ->
                        match kept |> Seq.tryFind (fun (_, keptFd) -> keptFd = modelFd) with
                        | Some (keptHostFd, _) -> keptHostFd
                        | None -> failwith $"the model's descriptor %d{modelFd} is neither an instance nor kept"

                let make (op : Op) (syscall : Syscall<int, string>) : unit =
                    let host =
                        match op, onHost root hostFd syscall with
                        // The descriptor a creating open answers is closed at
                        // once, as `answer` closes the model's.
                        | (Op.Create _ | Op.OpenTruncate _), Ok fd ->
                            HostCalls.close (int fd) |> ignore<int>
                            Ok 0L
                        | _, host -> host

                    let host = Result.mapError hostError host

                    let model =
                        match answer op syscall system.Value with
                        | SyscallAnswer.Completed value, after ->
                            system.Value <- after
                            Ok value
                        | SyscallAnswer.Failed error, after ->
                            system.Value <- after
                            Error error

                    match op, host, model with
                    | (Op.Open _ | Op.OpenDotAt _), Ok hostOpened, Ok modelOpened ->
                        kept.Add (int hostOpened, int modelOpened)
                    | _ ->

                    match op, host with
                    | (Op.Open _ | Op.OpenDotAt _), Ok hostOpened -> HostCalls.close (int hostOpened) |> ignore<int>
                    | Op.Close slot, _ -> kept.RemoveAt (slotIndex slot kept.Count)
                    | _ -> ()

                    if host <> model then
                        failwith $"%A{op}: the host answered %A{host}, the model %A{model}"

                try
                    for step, op in List.indexed ops do
                        match
                            syscallOf platform owner (List.ofArray modelFds) [ for _, modelFd in kept -> modelFd ] op
                        with
                        | None -> ()
                        | Some syscall ->
                            make op syscall

                            match op with
                            | Op.Write _
                            | Op.Ftruncate _
                            | Op.Fchmod _ -> cover Label.ThroughDescriptor
                            | _ -> ()

                        for instance in 0..1 do
                            let buffer = Array.zeroCreate<byte> 65536

                            let rec drainHost (acc : ReadRecord list) =
                                let n = HostCalls.read (hostFds.[instance], buffer, unativeint buffer.Length)

                                if n < 0n then
                                    acc
                                else
                                    drainHost (acc @ InotifyReplay.parse (ImmutableArray.Create (buffer, 0, int n)))

                            let host = drainHost [] |> List.map (compared hostCookies)

                            let records, after = InotifyReplay.drainRecords modelFds.[instance] system.Value
                            system.Value <- after
                            let model = records |> List.map (compared modelCookies)

                            if host <> model then
                                failwith
                                    $"step %d{step}, %A{op}: instance %d{instance}: the host queued %A{host}, the model %A{model}"

                            for _, mask, _, _, entry in host do
                                for label in recordLabels mask entry do
                                    cover (Label.Record label)
                finally
                    for fd in hostFds do
                        HostCalls.close fd |> ignore<int>

                    for keptHostFd, _ in kept do
                        HostCalls.close keptHostFd |> ignore<int>

                    Directory.Delete (root, true)

            let coverage =
                CoverageSample.check
                    (Config.QuickThrowOnFailure.WithMaxTest 200)
                    (Arb.fromGen (caseGen targets))
                    property

            for label in
                [
                    Label.Record RecordLabel.Create
                    Label.Record RecordLabel.Delete
                    Label.Record RecordLabel.Moved
                    Label.Record RecordLabel.AttribNamed
                    Label.Record RecordLabel.AttribSelf
                    Label.Record RecordLabel.Modify
                    Label.Record RecordLabel.Directory
                    Label.Record RecordLabel.Ignored
                    Label.Record RecordLabel.DeleteSelf
                    Label.Record RecordLabel.MoveSelf
                    Label.ThroughDescriptor
                ] do
                if coverage.Count label < 20 then
                    failwith $"the fixed sample reached %A{label} only %d{coverage.Count label} times"
        )
