namespace WoofWare.PosixKernel

/// A way in which a `VirtualFileSystem` fails to describe a filesystem any
/// kernel could produce. `VirtualFileSystem.checkInvariants` returns these;
/// none of the filesystem's mutators can produce one.
///
/// A defect is a bug in this library, and its cases are not public: a client
/// reports one with `VirtualFileSystemDefect.describe`, and has no reason to
/// branch on which rule broke. Any version may add a rule or remove one, for
/// instance when the types come to make a state it forbids unrepresentable.
[<RequireQualifiedAccess>]
type VirtualFileSystemDefect =
    internal
    /// `Root` names an inode the graph does not contain.
    | RootMissing of root : InodeNumber
    /// `Root` names something other than a directory.
    | RootIsNotDirectory of root : InodeNumber
    /// The root's `Parent` is not the root. On a real Unix "/.." is "/".
    | RootParentIsNotSelf of root : InodeNumber * recordedParent : InodeNumber
    /// Some directory holds an entry pointing at the root. The root is the one
    /// directory with *no* incoming entry link; giving it one would make the
    /// graph cyclic while leaving every individual link count plausible.
    | RootHasIncomingLink of parents : (InodeNumber * DirectoryEntryName) list
    /// A directory entry points at an inode the graph does not contain.
    | DanglingEntry of directory : InodeNumber * name : DirectoryEntryName * target : InodeNumber
    /// A directory's `Parent` names an inode the graph does not contain.
    | DanglingParent of directory : InodeNumber * recordedParent : InodeNumber
    /// A directory's `Parent` names something that is not a directory.
    | ParentIsNotDirectory of directory : InodeNumber * recordedParent : InodeNumber
    /// A directory's `Parent` disagrees with the directory that actually holds
    /// it, so ".." would walk somewhere the path did not come from.
    | ParentMismatch of directory : InodeNumber * recordedParent : InodeNumber * actualParent : InodeNumber
    /// A directory is held by more than one entry. Unix forbids hard links to
    /// directories precisely because they would make the graph a non-tree, and
    /// `Parent` could then name only one of them.
    | DirectoryMultiplyLinked of directory : InodeNumber * parents : (InodeNumber * DirectoryEntryName) list
    /// An inode no path from the root can reach, and which the caller did not
    /// declare pinned.
    ///
    /// Every inode in a real filesystem is reachable unless some process holds
    /// it open after its last link went away — which is exactly what
    /// `checkInvariants`'s `pinned` argument names. An unreachable inode nobody
    /// holds is a leak: nothing can ever name it again, and nothing will free
    /// it.
    | UnreachableFromRoot of inode : InodeNumber
    /// `NextInode` would hand out a number already in use.
    | NextInodeNotFresh of nextInode : InodeNumber * existing : InodeNumber
    /// The count `VirtualFileSystem.bindingCount` answers for `inode`
    /// disagrees with the number of directory entries that name it.
    ///
    /// `stored` is `None` where no count is stored, which the filesystem
    /// reads as zero. A stored `Some 0` is reported even though it agrees in
    /// value, because only non-zero counts are stored.
    | BindingCountMismatch of inode : InodeNumber * stored : int option * counted : int
    /// The names that reading `directory` walks
    /// (`UnixNamespace.readDirectoryEntry`) disagree with the names its
    /// entries bind.
    ///
    /// `stored` is `None` where none are stored, which the filesystem reads as
    /// binding nothing. A stored `Some []` is reported even though it agrees
    /// in content, because names are stored only for a directory that binds
    /// some. `bound` is empty for an inode that is not a directory, or that
    /// the graph does not contain.
    | SortedNamesMismatch of
        directory : InodeNumber *
        stored : DirectoryEntryName list option *
        bound : DirectoryEntryName list
    /// The count `VirtualFileSystem.subdirectoryCount` answers for
    /// `directory` disagrees with the number of its entries that name a
    /// directory.
    ///
    /// `stored` is `None` where no count is stored, which the filesystem
    /// reads as zero. A stored `Some 0` is reported even though it agrees in
    /// value, because only non-zero counts are stored.
    | SubdirectoryCountMismatch of directory : InodeNumber * stored : int option * counted : int
    /// A mounted filesystem's root is absent, or is not a directory.
    | MountRootNotDirectory of root : InodeNumber
    /// The inodes recorded as being on the filesystem mounted at `root` are not
    /// that root and everything below it.
    | MountMembershipMismatch of root : InodeNumber * recorded : Set<InodeNumber> * actual : Set<InodeNumber>
    /// The inode number a mount keeps for the directory it covers is also the
    /// number of an inode in the graph.
    | CoveredInodeInUse of root : InodeNumber * covered : InodeNumber
    /// An inode holds a kind of content that nothing in this version makes:
    /// `InodeContent.Socket` or `InodeContent.Fifo`.
    | ReservedContent of inode : InodeNumber
    /// `directory`, on a filesystem that matches names by canonical
    /// equivalence, binds both `first` and `second`, which might be two
    /// spellings of one name. Such a filesystem never holds two spellings of a
    /// name in one directory, and this library cannot tell whether these are
    /// two.
    | PossiblyEquivalentNames of directory : InodeNumber * first : DirectoryEntryName * second : DirectoryEntryName
    /// The graph records a name its last name had for `directory`
    /// (`recorded`) where the directory is still named, or is not a directory
    /// whose last name has gone; or records none where it is one.
    | RemovedDirectoryNameMismatch of directory : InodeNumber * recorded : DirectoryEntryName option

[<RequireQualifiedAccess>]
module VirtualFileSystemDefect =
    /// The defect, for a bug report: the rule that does not hold, by the name
    /// this library's source gives it, and the values that break it.
    let describe (defect : VirtualFileSystemDefect) : string =
        $"the filesystem is in a state no kernel could produce, which is a bug in this library: %A{defect}"

/// The inode graph and stored indexes inspected by `FileSystemInvariants.check`.
/// Counts and name lists retain every stored entry, including zero counts and
/// empty lists. Mounts record the inode numbers of the directories they cover.
type internal FileSystemSnapshot =
    {
        Inodes : Map<InodeNumber, Inode>
        Root : InodeNumber
        NextInode : InodeNumber
        BindingCounts : Map<InodeNumber, int>
        SortedNames : Map<InodeNumber, DirectoryEntryName list>
        SubdirectoryCounts : Map<InodeNumber, int>
        MountCoveredInodes : Map<InodeNumber, InodeNumber>
        MountMembers : Map<InodeNumber, InodeNumber>
        NameMatching : EntryNameMatching
        RemovedDirectoryNames : Map<InodeNumber, DirectoryEntryName>
    }

[<RequireQualifiedAccess>]
module internal FileSystemInvariants =
    let private tryGetContent (inode : InodeNumber) (inodes : Map<InodeNumber, Inode>) : InodeContent option =
        Map.tryFind inode inodes |> Option.map (fun entry -> entry.Content)

    let private tryGetDirectory (inode : InodeNumber) (inodes : Map<InodeNumber, Inode>) : DirectoryContent option =
        match tryGetContent inode inodes with
        | Some (InodeContent.Directory directory) -> Some directory
        | Some _
        | None -> None

    /// Every (directory, name, target) binding in the graph, including those in
    /// directories nothing can reach.
    let allBindings (inodes : Map<InodeNumber, Inode>) : (InodeNumber * DirectoryEntryName * InodeNumber) list =
        inodes
        |> Map.toList
        |> List.collect (fun (inode, entry) ->
            match entry.Content with
            | InodeContent.Directory directory ->
                directory.Entries
                |> Map.toList
                |> List.map (fun (name, target) -> inode, name, target)
            | InodeContent.RegularFile _
            | InodeContent.Socket _
            | InodeContent.Fifo _
            | InodeContent.CharacterDevice _
            | InodeContent.Symlink _ -> []
        )

    /// The names each directory in `inodes` binds, holding only directories
    /// that bind at least one, which is the form
    /// `VirtualFileSystem.SortedNames` is kept in.
    let boundNames (inodes : Map<InodeNumber, Inode>) : Map<InodeNumber, DirectoryEntryName list> =
        inodes
        |> Map.toSeq
        |> Seq.choose (fun (inode, entry) ->
            match entry.Content with
            | InodeContent.Directory directory when not (Map.isEmpty directory.Entries) ->
                Some (inode, directory.Entries |> Map.keys |> List.ofSeq)
            | InodeContent.Directory _
            | InodeContent.RegularFile _
            | InodeContent.Socket _
            | InodeContent.Fifo _
            | InodeContent.CharacterDevice _
            | InodeContent.Symlink _ -> None
        )
        |> Map.ofSeq

    /// How many of `bindings` name each target, holding only non-zero counts.
    let countBindings (bindings : (InodeNumber * DirectoryEntryName * InodeNumber) list) : Map<InodeNumber, int> =
        bindings |> List.countBy (fun (_, _, target) -> target) |> Map.ofList

    /// How many of `bindings` in each directory name a directory in `inodes`,
    /// holding only non-zero counts.
    let countSubdirectories
        (inodes : Map<InodeNumber, Inode>)
        (bindings : (InodeNumber * DirectoryEntryName * InodeNumber) list)
        : Map<InodeNumber, int>
        =
        bindings
        |> List.choose (fun (directory, _, target) ->
            match tryGetDirectory target inodes with
            | Some _ -> Some directory
            | None -> None
        )
        |> List.countBy id
        |> Map.ofList

    /// `root` and every inode below it: what its directories bind, and what
    /// theirs do, down to the leaves.
    let subtreeOf (root : InodeNumber) (inodes : Map<InodeNumber, Inode>) : Set<InodeNumber> =
        // A graph forged with a directory cycle is its own defect; `found`
        // keeps one from looping here.
        let rec gather (inode : InodeNumber) (found : Set<InodeNumber>) : Set<InodeNumber> =
            if Set.contains inode found then
                found
            else

            let found = Set.add inode found

            match tryGetDirectory inode inodes with
            | Some content -> content.Entries |> Map.fold (fun found _ child -> gather child found) found
            | None -> found

        gather root Set.empty

    let private isOrphanedDirectory (inode : InodeNumber) (vfs : FileSystemSnapshot) : bool =
        inode <> vfs.Root
        && Option.isSome (tryGetDirectory inode vfs.Inodes)
        && (Map.tryFind inode vfs.BindingCounts |> Option.defaultValue 0) = 0

    /// Every defect in the snapshot, in deterministic order. `pinned` excuses
    /// an inode's unreachability, as in `VirtualFileSystem.checkInvariants`.
    let check (pinned : Set<InodeNumber>) (vfs : FileSystemSnapshot) : VirtualFileSystemDefect list =
        let bindings = allBindings vfs.Inodes

        let rootDefects =
            match tryGetContent vfs.Root vfs.Inodes with
            | None -> [ VirtualFileSystemDefect.RootMissing vfs.Root ]
            | Some (InodeContent.RegularFile _)
            | Some (InodeContent.Socket _)
            | Some (InodeContent.Fifo _)
            | Some (InodeContent.CharacterDevice _)
            | Some (InodeContent.Symlink _) -> [ VirtualFileSystemDefect.RootIsNotDirectory vfs.Root ]
            | Some (InodeContent.Directory content) ->
                if content.Parent = vfs.Root then
                    []
                else
                    [ VirtualFileSystemDefect.RootParentIsNotSelf (vfs.Root, content.Parent) ]

        let danglingEntries =
            bindings
            |> List.filter (fun (_, _, target) -> not (Map.containsKey target vfs.Inodes))
            |> List.map VirtualFileSystemDefect.DanglingEntry

        /// Which directories hold each inode, so that the link-count rules and
        /// "the recorded parent is the real one" can all be decided.
        let holders : Map<InodeNumber, (InodeNumber * DirectoryEntryName) list> =
            bindings
            |> List.fold
                (fun acc (directory, name, target) ->
                    let existing = Map.tryFind target acc |> Option.defaultValue []
                    Map.add target ((directory, name) :: existing) acc
                )
                Map.empty
            |> Map.map (fun _ holders -> List.rev holders)

        let rootLinks =
            match Map.tryFind vfs.Root holders with
            | None -> []
            | Some parents -> [ VirtualFileSystemDefect.RootHasIncomingLink parents ]

        let parentDefects =
            vfs.Inodes
            |> Map.toList
            |> List.collect (fun (inode, entry) ->
                match entry.Content with
                | InodeContent.RegularFile _
                | InodeContent.Socket _
                | InodeContent.Fifo _
                | InodeContent.CharacterDevice _
                | InodeContent.Symlink _ -> []
                | InodeContent.Directory directory ->

                // The root's parent is checked above, where "is itself" is the
                // rule rather than "is whoever holds it".
                if inode = vfs.Root then
                    []
                else

                let recorded = directory.Parent

                let structural =
                    match tryGetContent recorded vfs.Inodes with
                    | None -> [ VirtualFileSystemDefect.DanglingParent (inode, recorded) ]
                    | Some (InodeContent.RegularFile _)
                    | Some (InodeContent.Socket _)
                    | Some (InodeContent.Fifo _)
                    | Some (InodeContent.CharacterDevice _)
                    | Some (InodeContent.Symlink _) ->
                        [ VirtualFileSystemDefect.ParentIsNotDirectory (inode, recorded) ]
                    | Some (InodeContent.Directory _) -> []

                match Map.tryFind inode holders with
                | None ->
                    // Held by nothing: reported as unreachable below, and there
                    // is no actual parent to disagree with.
                    structural
                | Some [ (actual, _) ] ->
                    if actual = recorded then
                        structural
                    else
                        structural
                        @ [ VirtualFileSystemDefect.ParentMismatch (inode, recorded, actual) ]
                | Some holders ->
                    structural
                    @ [ VirtualFileSystemDefect.DirectoryMultiplyLinked (inode, holders) ]
            )

        let reachable =
            // From the root through directory entries only.
            // Parent links deliberately do not count: a directory reachable
            // only by climbing out of an orphaned subtree is still orphaned.
            let rec explore (frontier : InodeNumber list) (seen : Set<InodeNumber>) : Set<InodeNumber> =
                match frontier with
                | [] -> seen
                | inode :: rest ->
                    if Set.contains inode seen then
                        explore rest seen
                    else

                    let children =
                        match tryGetContent inode vfs.Inodes with
                        | Some (InodeContent.Directory directory) -> directory.Entries |> Map.toList |> List.map snd
                        | Some _
                        | None -> []

                    explore (children @ rest) (Set.add inode seen)

            if Map.containsKey vfs.Root vfs.Inodes then
                explore [ vfs.Root ] Set.empty
            else
                Set.empty

        let unreachable =
            vfs.Inodes
            |> Map.toList
            |> List.map fst
            |> List.filter (fun inode -> not (Set.contains inode reachable))
            |> List.filter (fun inode -> not (Set.contains inode pinned))
            |> List.map VirtualFileSystemDefect.UnreachableFromRoot

        // Nothing in this version makes a socket inode or a FIFO inode:
        // `mknodat` of `S_IFSOCK` or `S_IFIFO`, and a Unix-domain `bind`, all
        // refuse. So one here came from a bug.
        let reservedContent =
            vfs.Inodes
            |> Map.toList
            |> List.choose (fun (inode, entry) ->
                match entry.Content with
                | InodeContent.Socket _
                | InodeContent.Fifo _ -> Some (VirtualFileSystemDefect.ReservedContent inode)
                | InodeContent.CharacterDevice _
                | InodeContent.RegularFile _
                | InodeContent.Directory _
                | InodeContent.Symlink _ -> None
            )

        let freshness =
            vfs.Inodes
            |> Map.toList
            |> List.map fst
            |> List.filter (fun inode -> inode >= vfs.NextInode)
            |> List.map (fun inode -> VirtualFileSystemDefect.NextInodeNotFresh (vfs.NextInode, inode))

        let bindingCounts =
            let counted = countBindings bindings

            Set.union (Map.keys counted |> Set.ofSeq) (Map.keys vfs.BindingCounts |> Set.ofSeq)
            |> Set.toList
            |> List.choose (fun inode ->
                let stored = Map.tryFind inode vfs.BindingCounts
                let counted = Map.tryFind inode counted |> Option.defaultValue 0

                if stored = (if counted = 0 then None else Some counted) then
                    None
                else
                    Some (VirtualFileSystemDefect.BindingCountMismatch (inode, stored, counted))
            )

        let sortedNames =
            let bound = boundNames vfs.Inodes

            Set.union (Map.keys bound |> Set.ofSeq) (Map.keys vfs.SortedNames |> Set.ofSeq)
            |> Set.toList
            |> List.choose (fun inode ->
                let stored = Map.tryFind inode vfs.SortedNames
                let bound = Map.tryFind inode bound

                if stored = bound then
                    None
                else
                    Some (VirtualFileSystemDefect.SortedNamesMismatch (inode, stored, bound |> Option.defaultValue []))
            )

        let subdirectoryCounts =
            let counted = countSubdirectories vfs.Inodes bindings

            Set.union (Map.keys counted |> Set.ofSeq) (Map.keys vfs.SubdirectoryCounts |> Set.ofSeq)
            |> Set.toList
            |> List.choose (fun directory ->
                let stored = Map.tryFind directory vfs.SubdirectoryCounts
                let counted = Map.tryFind directory counted |> Option.defaultValue 0

                if stored = (if counted = 0 then None else Some counted) then
                    None
                else
                    Some (VirtualFileSystemDefect.SubdirectoryCountMismatch (directory, stored, counted))
            )

        // A mounted filesystem holds its root and everything below it.
        let mountDefects =
            let recordedByRoot =
                vfs.MountMembers
                |> Map.toList
                |> List.groupBy snd
                |> List.map (fun (root, members) -> root, members |> List.map fst |> Set.ofList)
                |> Map.ofList

            Set.union (Map.keys vfs.MountCoveredInodes |> Set.ofSeq) (Map.keys recordedByRoot |> Set.ofSeq)
            |> Set.toList
            |> List.collect (fun root ->
                let mount = Map.tryFind root vfs.MountCoveredInodes

                let rootDefect, actual =
                    match mount, tryGetDirectory root vfs.Inodes with
                    | None, _ -> [], Set.empty
                    | Some _, None -> [ VirtualFileSystemDefect.MountRootNotDirectory root ], Set.empty
                    | Some _, Some _ -> [], subtreeOf root vfs.Inodes

                let recorded = Map.tryFind root recordedByRoot |> Option.defaultValue Set.empty

                let membership =
                    if recorded = actual then
                        []
                    else
                        [ VirtualFileSystemDefect.MountMembershipMismatch (root, recorded, actual) ]

                let covered =
                    match mount with
                    | Some covered when Map.containsKey covered vfs.Inodes ->
                        [ VirtualFileSystemDefect.CoveredInodeInUse (root, covered) ]
                    | Some covered when covered >= vfs.NextInode ->
                        [ VirtualFileSystemDefect.NextInodeNotFresh (vfs.NextInode, covered) ]
                    | Some _
                    | None -> []

                rootDefect @ membership @ covered
            )

        let equivalentNames =
            match vfs.NameMatching with
            | EntryNameMatching.Bytes -> []
            | EntryNameMatching.CanonicalEquivalence ->
                vfs.Inodes
                |> Map.toList
                |> List.choose (fun (inode, entry) ->
                    match entry.Content with
                    | InodeContent.Directory directory ->
                        EntryNameMatching.firstPossiblyEquivalentPair (Map.keys directory.Entries)
                        |> Option.map (fun (first, second) ->
                            VirtualFileSystemDefect.PossiblyEquivalentNames (inode, first, second)
                        )
                    | InodeContent.RegularFile _
                    | InodeContent.Socket _
                    | InodeContent.Fifo _
                    | InodeContent.CharacterDevice _
                    | InodeContent.Symlink _ -> None
                )

        let removedDirectoryNames =
            Set.union
                (vfs.Inodes
                 |> Map.keys
                 |> Seq.filter (fun inode -> isOrphanedDirectory inode vfs)
                 |> Set.ofSeq)
                (Map.keys vfs.RemovedDirectoryNames |> Set.ofSeq)
            |> Set.toList
            |> List.choose (fun inode ->
                let recorded = Map.tryFind inode vfs.RemovedDirectoryNames

                if recorded.IsSome = isOrphanedDirectory inode vfs then
                    None
                else
                    Some (VirtualFileSystemDefect.RemovedDirectoryNameMismatch (inode, recorded))
            )

        rootDefects
        @ rootLinks
        @ danglingEntries
        @ parentDefects
        @ unreachable
        @ reservedContent
        @ freshness
        @ bindingCounts
        @ sortedNames
        @ subdirectoryCounts
        @ mountDefects
        @ equivalentNames
        @ removedDirectoryNames
