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
    /// first `nfds` entries `fds` holds. Fails unless the call stopped at the
    /// copy exactly when the array is readable and holds some entries and the
    /// count's screen did not answer (`EINVAL`, or a refusal of the count),
    /// and then named `nfds` entries of eight bytes; and if it stopped at the
    /// copy of an array holding too few entries.
    let tryPollCopied<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fds : CopiedArgument<PollEntry list>)
        (nfds : uint32)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<PollOutcome * UnixSystem<'Thread, 'Handler>, PollRefusal>
        =
        let progress =
            UnixPoll.tryPoll caller (CopiedArgument.userBuffer fds) nfds milliseconds system

        let paused =
            match progress with
            | Ok (CallProgress.NeedsCopyIn paused) ->
                if PausedPoll.count paused <> int nfds then
                    failwith $"the paused poll copies %d{PausedPoll.count paused} entries, not %d{nfds}"

                if
                    PausedPoll.copyRange paused
                    <> {
                           FirstByte = 0
                           ByteCount = 8 * int nfds
                       }
                then
                    failwith $"the paused poll copies %A{PausedPoll.copyRange paused}, not %d{nfds} entries of 8 bytes"

                true
            | _ -> false

        let answer =
            progress
            |> CallProgress.resumeWith (fun paused ->
                match fds with
                | CopiedArgument.Readable entries when List.length (List.truncate (int nfds) entries) = int nfds ->
                    UnixPoll.tryPollWithEntries (List.truncate (int nfds) entries) paused
                | other -> failwith $"poll stopped to copy %d{nfds} entries from %A{other}"
            )

        let screenAnswered =
            match answer with
            | Ok (PollOutcome.Failed UnixError.EINVAL, _)
            | Error (PollRefusal.UnmodelledEntryCount _) -> true
            | _ -> false

        let shouldPause =
            match fds with
            | CopiedArgument.Readable _ -> nfds > 0u && not screenAnswered
            | _ -> false

        if paused <> shouldPause then
            failwith
                $"the poll of %d{nfds} entries from %A{fds} paused=%b{paused}, where it should have been %b{shouldPause}"

        answer
