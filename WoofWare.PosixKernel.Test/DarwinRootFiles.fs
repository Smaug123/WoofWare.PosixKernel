namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open WoofWare.PosixKernel

/// The `MAP` rows of `docs/probes/darwin-root/root-files.c`, run as root on
/// Darwin 27.0 (`root-files.darwin-27.0-root.txt` beside it): one call's
/// answer for each of the 4096 modes of one inode, as one caller.
[<RequireQualifiedAccess>]
module DarwinRootFiles =

    let private context : string = "DarwinRootFiles"

    /// What a row's inode is.
    [<RequireQualifiedAccess>]
    type Kind =
        | File
        | Dir
        | Link

    /// One `MAP` row.
    type Row =
        {
            /// `ACCESS`, `CHMOD`, `SETID` or `CLONE`.
            Section : string
            /// `root` or `u501`.
            Caller : string
            Kind : Kind
            Owner : InodeOwner
            /// The call, as the probe names it: `open(O_RDONLY)`, `chmod(N)`, ...
            Call : string
            /// What the call answered for each mode, indexed by the mode: `.`
            /// for success (or, for a mode change, the mode asked for), an
            /// errno letter (`A` EACCES, `P` EPERM), a digit for the set-ID
            /// and sticky bits a change dropped, or `-` where the row was not
            /// measured.
            Cells : char[]
        }

    let private lines : string list =
        let logicalName = "WoofWare.PosixKernel.Test.darwin-root.root-files.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream logicalName with
            | null -> failwith $"no embedded resource %s{logicalName}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private parseInode (text : string) : Kind * InodeOwner =
        // "file 502:7777", or "file 502:7777 from 0000" in CHMOD rows.
        match text.Split ' ' |> List.ofArray with
        | kind :: ids :: _ ->
            let kind =
                match kind with
                | "file" -> Kind.File
                | "dir" -> Kind.Dir
                | "link" -> Kind.Link
                | other -> failwith $"unexpected inode kind %s{other} in %s{text}"

            match ids.Split ':' with
            | [| user ; group |] ->
                kind,
                {
                    User = UserId.parseOrFail context (uint32 user)
                    Group = GroupId.parseOrFail context (uint32 group)
                }
            | _ -> failwith $"unexpected owner %s{ids} in %s{text}"
        | _ -> failwith $"unexpected inode %s{text}"

    // Each of the eight segments, one per value of the top three bits, is
    // either one character standing for all 512 of its modes or all 512.
    let private parseCells (text : string) : char[] =
        let cells =
            text.Split ' '
            |> Array.collect (fun segment ->
                match segment.Length with
                | 1 -> Array.replicate 512 segment.[0]
                | 512 -> segment.ToCharArray ()
                | other -> failwith $"a MAP segment is %d{other} characters long, not 1 or 512"
            )

        if cells.Length <> 4096 then
            failwith $"a MAP row holds %d{cells.Length} cells, not 4096"

        cells

    /// Every `MAP` row of the run.
    let rows : Row list =
        lines
        |> List.filter (fun line -> line.StartsWith "MAP\t")
        |> List.map (fun line ->
            match line.Split '\t' with
            | [| _ ; section ; caller ; inode ; call ; cells |] ->
                let kind, owner = parseInode inode

                {
                    Section = section
                    Caller = caller
                    Kind = kind
                    Owner = owner
                    Call = call
                    Cells = parseCells cells
                }
            | other -> failwith $"unexpected MAP row with %d{other.Length} fields: %s{line}"
        )

    /// The rows of one section.
    let section (name : string) : Row list =
        rows |> List.filter (fun row -> row.Section = name)

    /// The credentials each caller held (the run's `CRED` rows): root with its
    /// one group 0, and uid 501 in groups 20 and 701, 20 being its effective
    /// group.
    let credentialsOf (caller : string) : Credentials =
        match caller with
        | "root" -> Credentials.ofIds UserId.root (GroupId.parseOrFail context 0u) []
        | "u501" ->
            Credentials.ofIds
                (UserId.parseOrFail context 501u)
                (GroupId.parseOrFail context 20u)
                [ GroupId.parseOrFail context 701u ]
        | other -> failwith $"unexpected caller %s{other}"

    /// The cell an errno is recorded as.
    let cellOf (error : UnixError) : char =
        if error = UnixError.EACCES then
            'A'
        elif error = UnixError.EPERM then
            'P'
        else
            failwith $"no cell letter for %O{error} in root-files' MAP rows"
