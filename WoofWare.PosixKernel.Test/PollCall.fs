namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A caller of `poll(2)` whose array of `struct pollfd` is readable and holds
/// `entries`, for a test about what a poll reports rather than about its copy:
/// the call made through the library's public protocol, stopping at the copy
/// and then passing the entries.
[<RequireQualifiedAccess>]
module internal PollCall =

    /// `UnixPoll.tryPoll` of a readable array holding `entries`, and if it
    /// stops at the copy, `UnixPoll.tryPollWithEntries` of them.
    let tryPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<PollOutcome * UnixSystem<'Thread, 'Handler>, PollRefusal>
        =
        UnixPoll.tryPoll caller UserBuffer.Mapped (uint32 (List.length entries)) milliseconds system
        |> CallProgress.resumeWith (fun paused -> UnixPoll.tryPollWithEntries entries paused)

    /// `UnixPoll.poll` of a readable array holding `entries`, and if it stops
    /// at the copy, `UnixPoll.pollWithEntries` of them.
    let poll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : PollOutcome * UnixSystem<'Thread, 'Handler>
        =
        match UnixPoll.poll caller UserBuffer.Mapped (uint32 (List.length entries)) milliseconds system with
        | CallProgress.Answered answer -> answer
        | CallProgress.NeedsCopyIn paused -> UnixPoll.pollWithEntries entries paused

    /// `UnixPoll.tryPoll` of the array `fds` describes, with `nfds` entries,
    /// and if it stops at the copy, `UnixPoll.tryPollWithEntries` of the
    /// first `PausedPoll.count` entries `fds` holds; failing if the call
    /// stops at the copy of an array not given as readable, or holding too
    /// few entries.
    let tryPollCopied<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fds : CopiedArgument<PollEntry list>)
        (nfds : uint32)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<PollOutcome * UnixSystem<'Thread, 'Handler>, PollRefusal>
        =
        UnixPoll.tryPoll caller (CopiedArgument.userBuffer fds) nfds milliseconds system
        |> CallProgress.resumeWith (fun paused ->
            let count = PausedPoll.count paused

            match fds with
            | CopiedArgument.Readable entries when List.length entries >= count ->
                UnixPoll.tryPollWithEntries (List.truncate count entries) paused
            | other -> failwith $"poll stopped to copy %d{count} entries from %A{other}"
        )
