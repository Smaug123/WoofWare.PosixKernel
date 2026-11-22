namespace WoofWare.PosixKernel

/// The last datagram a Darwin machine answered with an ICMP port-unreachable
/// error.
type internal DarwinUnreachableAnswer =
    {
        /// The datagram's source, as the datagram carried it.
        Source : Ipv4Endpoint
        /// Where the datagram was sent.
        Destination : Ipv4Endpoint
        /// When, by the kernel clock (`UnixSchedulingState.NanosecondsSinceBoot`).
        At : int64
    }

/// Which of the datagrams that reach no socket a machine answers with an ICMP
/// port-unreachable error, by its flavour's rules, and what it remembers of
/// those it has answered.
[<RequireQualifiedAccess>]
type internal PortUnreachableReplies =
    /// Linux answers every one sent over loopback, and remembers none.
    | Linux
    /// Darwin answers one unless it is on the four-tuple of `last`, the last
    /// one it answered, and less than `window` nanoseconds have passed since
    /// it: `net.inet.udp.port_unreach_rlc_bucket_ms`, while
    /// `net.inet.udp.port_unreach_rlc_enable` is set.
    | Darwin of window : int64 * last : DarwinUnreachableAnswer option

[<RequireQualifiedAccess>]
module internal PortUnreachableReplies =

    /// What a freshly booted machine of `flavour` answers and remembers, its
    /// sysctls at their measured defaults.
    let defaultFor (flavour : SimulatedUnixFlavour) : PortUnreachableReplies =
        match flavour with
        | SimulatedUnixFlavour.Linux -> PortUnreachableReplies.Linux
        // Measured on Darwin 27.0.0 (`udp-error.c` Y0, in
        // docs/plans/2026-10-18-udp-data-path):
        // `net.inet.udp.port_unreach_rlc_enable` 1 and
        // `net.inet.udp.port_unreach_rlc_bucket_ms` 100.
        | SimulatedUnixFlavour.Darwin -> PortUnreachableReplies.Darwin (100_000_000L, None)

    /// Whether the machine answers a datagram from `source` to `destination`,
    /// which no socket took, at `now` by the kernel clock; and what it
    /// remembers afterwards.
    let answer
        (now : int64)
        (source : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        (replies : PortUnreachableReplies)
        : bool * PortUnreachableReplies
        =
        match replies with
        // Measured (`udp-transfer.c` X1, X3 and X4, in
        // docs/plans/2026-10-18-udp-data-path): an error for every send, at
        // 15 ms apart and with 80 sockets sending at once, under an
        // `icmp_ratelimit` of 1000 ms and an `icmp_msgs_burst` of 50, from
        // which loopback is exempt.
        | PortUnreachableReplies.Linux -> true, replies
        | PortUnreachableReplies.Darwin (window, last) ->
            // Measured (X1, X4, X5, X6 and X8): one record for the whole
            // machine, of the four-tuple, not the socket. A datagram on it
            // 98 ms after it was suppressed, and one 100 ms after answered; a
            // datagram the record suppresses leaves it as it was; one on
            // another four-tuple is answered and replaces it.
            let suppressed =
                match last with
                | Some last when last.Source = source && last.Destination = destination ->
                    if now < last.At then
                        failwith
                            $"PortUnreachableReplies.answer: the kernel clock reads %d{now} ns, before the %d{last.At} ns at which the machine answered the datagram it remembers; the clock never moves backwards (this is a bug in this library)."

                    now - last.At < window
                | Some _
                | None -> false

            if suppressed then
                false, replies
            else
                true,
                PortUnreachableReplies.Darwin (
                    window,
                    Some
                        {
                            Source = source
                            Destination = destination
                            At = now
                        }
                )
