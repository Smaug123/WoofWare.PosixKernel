namespace WoofWare.PosixKernel

/// Which of `O_SYNC` and `O_DSYNC` a Linux open file description carries.
/// Linux's `O_SYNC` is `O_DSYNC` with `__O_SYNC` beside it, so a description
/// carrying `O_SYNC` carries `O_DSYNC` too.
[<RequireQualifiedAccess>]
type LinuxSync =
    /// Neither.
    | NoSync
    /// `O_DSYNC` alone. Nothing in this version makes one: `open(2)` refuses
    /// `O_DSYNC` without `O_SYNC`, and Linux's `fcntl(F_SETFL)` changes
    /// neither.
    | DataSync
    /// `O_SYNC`, and with it `O_DSYNC`.
    | FullSync

/// The status an open file description carries besides its access mode,
/// `O_NONBLOCK` and its `flock`: the rest of what `fcntl(F_GETFL)` reports,
/// which each flavour keeps its own way. A description's status is its
/// machine's flavour's.
///
/// `O_APPEND`, `O_ASYNC`, Linux's `O_DIRECT` and `O_NOATIME` are absent
/// because no description this kernel makes carries them: `open(2)` refuses
/// each of them, and so does `fcntl(F_SETFL)`.
[<RequireQualifiedAccess>]
type OpenFileStatus =
    /// Linux's: `O_SYNC` and `O_DSYNC` as `sync` says, and whether `open(2)`
    /// was given `O_DIRECTORY` and `O_NOFOLLOW`, which Linux's `F_GETFL`
    /// reports back.
    | Linux of sync : LinuxSync * openedDirectory : bool * openedNoFollow : bool
    /// Darwin's: `O_SYNC` and `O_DSYNC`, which Darwin's `F_SETFL` sets apart;
    /// whether a `write(2)` or `pwrite(2)` through the description has returned
    /// having moved bytes, an `ftruncate(2)` through it has succeeded, or the
    /// `open(2)` that made it truncated a file that already existed
    /// (`written`); and whether an `flock(2)` lock has ever been granted to
    /// it, which releasing the lock does not undo (`flocked`).
    | Darwin of synchronous : bool * dataSynchronous : bool * written : bool * flocked : bool

/// What the syscalls do to an open file description's status, and what
/// `fcntl(F_GETFL)` reads of it.
[<RequireQualifiedAccess>]
module OpenFileStatus =
    /// The status `flavour` gives a description nothing has yet happened to,
    /// made by a call asking for none of these flags.
    let none (flavour : SimulatedUnixFlavour) : OpenFileStatus =
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            OpenFileStatus.Linux (sync = LinuxSync.NoSync, openedDirectory = false, openedNoFollow = false)
        | SimulatedUnixFlavour.Darwin ->
            OpenFileStatus.Darwin (synchronous = false, dataSynchronous = false, written = false, flocked = false)

    /// The flavour whose kernel keeps `status`.
    let flavour (status : OpenFileStatus) : SimulatedUnixFlavour =
        match status with
        | OpenFileStatus.Linux _ -> SimulatedUnixFlavour.Linux
        | OpenFileStatus.Darwin _ -> SimulatedUnixFlavour.Darwin

    /// The status `open(2)` under `flavour` gives the description it makes,
    /// asked for `O_SYNC` (`synchronous`), `O_DSYNC` (`dataSynchronous`),
    /// `O_DIRECTORY` (`directory`) and `O_NOFOLLOW` (`noFollow`).
    let internal opened
        (flavour : SimulatedUnixFlavour)
        (synchronous : bool)
        (dataSynchronous : bool)
        (directory : bool)
        (noFollow : bool)
        : OpenFileStatus
        =
        // Measured (`open-flags.c`): Linux keeps O_DIRECTORY and O_NOFOLLOW for
        // F_GETFL to report, and Darwin keeps neither.
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            let sync =
                if synchronous then LinuxSync.FullSync
                elif dataSynchronous then LinuxSync.DataSync
                else LinuxSync.NoSync

            OpenFileStatus.Linux (sync = sync, openedDirectory = directory, openedNoFollow = noFollow)
        | SimulatedUnixFlavour.Darwin ->
            OpenFileStatus.Darwin (
                synchronous = synchronous,
                dataSynchronous = dataSynchronous,
                written = false,
                flocked = false
            )

    /// `status` once its description has been written through: a `write(2)`
    /// or `pwrite(2)` through it returned having moved bytes, an
    /// `ftruncate(2)` through it succeeded, or the `open(2)` that made it
    /// truncated a file that already existed. Only Darwin records it.
    let internal markWritten (status : OpenFileStatus) : OpenFileStatus =
        // Measured on Darwin 27.0.0 (`fcntl-dup.c`, WRITTEN rows).
        match status with
        | OpenFileStatus.Linux _ -> status
        | OpenFileStatus.Darwin (synchronous = synchronous ; dataSynchronous = dataSynchronous ; flocked = flocked) ->
            OpenFileStatus.Darwin (
                synchronous = synchronous,
                dataSynchronous = dataSynchronous,
                written = true,
                flocked = flocked
            )

    /// `status` once an `flock(2)` lock has been granted to its description,
    /// blocking or not. Only Darwin records it, and nothing clears it.
    let internal recordFlockGrant (status : OpenFileStatus) : OpenFileStatus =
        // Measured on Darwin 27.0.0 (`fcntl-dup.c`, WRITTEN rows): a refused or
        // interrupted request does not set it, and LOCK_UN does not clear it.
        match status with
        | OpenFileStatus.Linux _ -> status
        | OpenFileStatus.Darwin (synchronous = synchronous ; dataSynchronous = dataSynchronous ; written = written) ->
            OpenFileStatus.Darwin (
                synchronous = synchronous,
                dataSynchronous = dataSynchronous,
                written = written,
                flocked = true
            )

    /// `status` as `fcntl(F_SETFL)` leaves it, given `word` in the numbering of
    /// the status's flavour: Darwin's sets `O_SYNC` and `O_DSYNC` from it, and
    /// Linux's changes neither. Which other bits of `word` the call reads is
    /// the caller's business.
    let internal setFlags (word : int) (status : OpenFileStatus) : OpenFileStatus =
        // Measured (`fcntl-dup.c`, SETFL rows, every bit on every kind).
        match status with
        | OpenFileStatus.Linux _ -> status
        | OpenFileStatus.Darwin (written = written ; flocked = flocked) ->
            OpenFileStatus.Darwin (
                synchronous = (word &&& OpenFlagNumbering.DarwinSynchronous <> 0),
                dataSynchronous = (word &&& OpenFlagNumbering.DarwinDataSynchronous <> 0),
                written = written,
                flocked = flocked
            )

    /// The bits `status` sets in the word `fcntl(F_GETFL)` reports, in the
    /// numbering of the status's flavour, on a kernel built for
    /// `architecture`.
    let internal flagBits (architecture : SimulatedUnixArchitecture) (status : OpenFileStatus) : int =
        let bit (condition : bool) (value : int) : int = if condition then value else 0

        // Measured (`fcntl-dup.c` and `open-flags.c`): Linux reports O_SYNC as
        // both of its bits, and O_DIRECTORY and O_NOFOLLOW as `open(2)` was
        // given them; Darwin reports neither of those, and two bits of its own.
        match status with
        | OpenFileStatus.Linux (sync = sync ; openedDirectory = openedDirectory ; openedNoFollow = openedNoFollow) ->
            let synchronisation =
                match sync with
                | LinuxSync.NoSync -> 0
                | LinuxSync.DataSync -> OpenFlagNumbering.LinuxDataSynchronous
                | LinuxSync.FullSync -> OpenFlagNumbering.LinuxSynchronous ||| OpenFlagNumbering.LinuxDataSynchronous

            synchronisation
            ||| bit openedDirectory (OpenFlagNumbering.linuxDirectory architecture)
            ||| bit openedNoFollow (OpenFlagNumbering.linuxNoFollow architecture)
        | OpenFileStatus.Darwin (
            synchronous = synchronous ; dataSynchronous = dataSynchronous ; written = written ; flocked = flocked) ->
            bit synchronous OpenFlagNumbering.DarwinSynchronous
            ||| bit dataSynchronous OpenFlagNumbering.DarwinDataSynchronous
            ||| bit written OpenFlagNumbering.DarwinWritten
            ||| bit flocked OpenFlagNumbering.DarwinFlocked
