namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A thread inside a signal handler, for a test of handler frames, or one that
/// needs a thread to block signals the way a handler's mask blocks them.
/// (`UnixSignal.pthreadSigmask` blocks them without a handler.)
[<RequireQualifiedAccess>]
module HandlerFrames =

    /// The signal these helpers deliver to put a thread in a handler: SIGPROF.
    /// A test that uses them does not use it otherwise.
    let carrier : Signal = Signal.SIGPROF

    /// `state` with `thread` inside a handler for `carrier`, whose `sa_mask` is
    /// `mask` and which has `SA_NODEFER`: `thread`'s mask becomes its old mask
    /// with `mask` added, and `carrier` is in it only if `mask` names it. The
    /// carrier's disposition is put back as it was. `None` if the return to
    /// user mode that delivers the carrier would deliver anything else too.
    ///
    /// `numbering`, `leader` and `threads` are as `SignalState.onReturnToUser`
    /// takes them.
    let tryEnterVia<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (numbering : SignalNumbering)
        (carrier : Signal)
        (handler : 'Handler)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (mask : Set<Signal>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler> option
        =
        let before = SignalState.disposition numbering carrier state

        let action =
            { SignalCatch.ofHandler handler with
                Mask = SignalMask.ofSignals numbering mask
                NoDefer = true
            }

        let sent =
            state
            |> SignalState.setDisposition numbering carrier (SignalDisposition.Catch action)
            |> SignalState.enqueue
                numbering
                {
                    Signal = carrier
                    Target = ValueSome thread
                }

        match SignalState.onReturnToUser numbering CoreDumps.Suppressed leader threads thread sent with
        | Ok (Some (SignalDelivery.RunHandlers [ frame ]), state) when frame.Entry.Signal = carrier ->
            Some (SignalState.setDisposition numbering carrier before state)
        | _ -> None

    /// `tryEnterVia` with the usual `carrier`.
    let tryEnter<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (numbering : SignalNumbering)
        (handler : 'Handler)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (mask : Set<Signal>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler> option
        =
        tryEnterVia numbering carrier handler leader threads thread mask state

    /// `tryEnterVia`, failing the test if anything but the carrier would be
    /// delivered: set up the frames before the signals the test is about are
    /// generated.
    let enterVia<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (numbering : SignalNumbering)
        (carrier : Signal)
        (handler : 'Handler)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (mask : Set<Signal>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        match tryEnterVia numbering carrier handler leader threads thread mask state with
        | Some state -> state
        | None -> failwith $"expected the carrier %O{carrier} alone to be delivered to %O{thread}"

    /// `enterVia` with the usual `carrier`.
    let enter<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (numbering : SignalNumbering)
        (handler : 'Handler)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (mask : Set<Signal>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        enterVia numbering carrier handler leader threads thread mask state

    /// `thread` returns from its innermost handler.
    let leave<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        match SignalState.framesOf thread state with
        | innermost :: _ -> SignalState.sigreturn thread innermost.Id state
        | [] -> failwith $"%O{thread} is in no handler"

    /// `enter` for a thread of `system`, whose leader and threads it takes.
    let enterIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (handler : 'Handler)
        (thread : 'Thread)
        (mask : Set<Signal>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let threads = Lone.threads system |> Map.keys |> Set.ofSeq
        let numbering = SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals = enter numbering handler (Lone.leader system) threads thread mask proc.Signals
            }
        )
