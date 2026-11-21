namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `accept(2)` and its finishing call as a client makes them, through the
/// library's public protocol: the call, and if it stops for the length cell,
/// `acceptWithLength` of what the cell holds.
[<RequireQualifiedAccess>]
module internal AcceptCalls =

    /// Fails the test unless the length cell at `cell` is one a client can
    /// read, as it must be wherever a call stops for the client to read it.
    let private readable (cell : UserBuffer) : unit =
        match cell with
        | UserBuffer.Mapped -> ()
        | UserBuffer.Unmapped _
        | UserBuffer.Opaque
        | UserBuffer.Addressless ->
            failwith $"accept stopped for the client to read a length cell at %A{cell}, which no client can read"

    /// `accept(2)` as `caller` makes it, into the address buffer
    /// `destination`, through the length cell at `cell`, which holds
    /// `contents` wherever the kernel reads it.
    let tryAcceptThrough<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (cell : UserBuffer)
        (contents : uint32)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<AcceptOutcome * UnixSystem<'Thread, 'Handler>, AcceptRefusal>
        =
        UnixConnection.tryAccept caller fd destination cell flags system
        |> CallProgress.resumeWith (fun paused ->
            readable cell
            UnixConnection.tryAcceptWithLength contents paused
        )

    /// The cell a call names by `declared`: real storage holding it, or, for
    /// `None`, a NULL cell, as `accept(fd, NULL, NULL)` passes.
    let private cellOf (declared : uint32 option) : UserBuffer * uint32 =
        match declared with
        | Some contents -> UserBuffer.Mapped, contents
        | None -> UserBuffer.Unmapped 0UL, 0u

    /// `tryAcceptThrough` a cell of real storage holding the `Some` of
    /// `declared`, or a NULL cell for `None`.
    let tryAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (declared : uint32 option)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<AcceptOutcome * UnixSystem<'Thread, 'Handler>, AcceptRefusal>
        =
        let cell, contents = cellOf declared
        tryAcceptThrough caller fd destination cell contents flags system

    /// `tryAccept` through the public functions, which throw a refusal.
    let accept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (declared : uint32 option)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : AcceptOutcome * UnixSystem<'Thread, 'Handler>
        =
        let cell, contents = cellOf declared

        match UnixConnection.accept caller fd destination cell flags system with
        | CallProgress.Answered answer -> answer
        | CallProgress.NeedsCopyIn paused ->
            readable cell
            UnixConnection.acceptWithLength contents paused

    /// The woken `accept` in which `caller` sleeps, finished, and if it stops
    /// for its length cell, resumed with `contents`, what the cell holds now.
    let tryFinishAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (contents : uint32)
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<AcceptOutcome * UnixSystem<'Thread, 'Handler>, AcceptRefusal>
        =
        UnixConnection.tryFinishAccept caller system
        |> CallProgress.resumeWith (UnixConnection.tryAcceptWithLength contents)

    /// `tryFinishAccept` through the public functions, which throw a refusal.
    let finishAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (contents : uint32)
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : AcceptOutcome * UnixSystem<'Thread, 'Handler>
        =
        match UnixConnection.finishAccept caller system with
        | CallProgress.Answered answer -> answer
        | CallProgress.NeedsCopyIn paused -> UnixConnection.acceptWithLength contents paused

    /// The length cell of a sleeping accept on `platform` whose cell holds 16,
    /// for a test that forges the park: read already under Darwin, and still
    /// to be read under Linux.
    let forgedCellUnder (flavour : SimulatedUnixFlavour) : AcceptLengthCell =
        match flavour with
        | SimulatedUnixFlavour.Darwin -> AcceptLengthCell.Read 16u
        | SimulatedUnixFlavour.Linux -> AcceptLengthCell.Unread UserBuffer.Mapped

    /// `forgedCellUnder` the flavour of `platform`.
    let forgedCell (platform : SimulatedUnixPlatform) : AcceptLengthCell =
        forgedCellUnder (SimulatedUnixPlatform.flavour platform)
