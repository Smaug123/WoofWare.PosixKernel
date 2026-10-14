# Testing a kernel fact: choosing a tier

Four kinds of test in `WoofWare.PosixKernel.Test` can observe a kernel fact, and
each one is blind to something the others see. Picking wrong wastes a cycle. A
fact is usually owned by more than one: a replay pins the rows a probe measured,
a property extends the rule past them, and a host test checks the column the
machine running it can falsify.

## Unit and property tests

Most of the suite. They build a `UnixSystem` (or call a rules module such as
`CreatingOpenRules` or `PipeBuffer` directly), make the call, and assert the
answer and the state left behind. Two shapes recur:

- **Measured rows as literals**, both flavours' columns, so a row the host
  cannot reach (the flavour it is not running on, the real root, uid 0, a
  second user) is still asserted. `TestMkDirRules`, `TestUnlinkRules` and
  `TestOpenDirRules` carry exactly the rows their host oracles structurally
  cannot.
- **A property against a reference**: a naive statement of the rule, written
  for obviousness and in a different representation from the library's, and
  generated inputs on which the two must agree (`PipeBufferReference` in
  `TestPipeBuffer.fs`, `TcpTransferReference` behind `TestBlockingConnection`,
  the store-everything oracle in `TestSignalState`). This is how a rule is held
  beyond the rows anybody measured.

Their blind spot is that they state the rule as the test's author understood
it. Where the author misread the kernel, the literal and the code agree with
each other and both are wrong; only a host test or a replay catches that.

**Write the literal from the measurement, never from the code.** A table
computed from the function under test (`afterTruncation`, say) passes whatever
that function does; `TestVirtualFileSystem`'s truncation table is octal
literals for that reason.

## Host-equality tests (`*AgainstHost`)

`TestVirtualFileSystemAgainstHost`, `TestPipeAgainstHost`,
`TestSockOptAgainstHost` and the rest: the same call made on the kernel running
the suite (through `DllImport`) and on the model, compared. For any fact
measurable on the machine running the test this is the strongest form, and the
assertion should be **equality against the host**, not a bracketing check:

```fsharp
let modelled = SimulatedUnixPlatform.pathLimits (hostPlatform ())
if measured <> modelled then failwith $"...; %d{measured} is the measured answer."
```

The dev machine is macOS and CI is Linux, so each flavour's column is checked on
the machine that can actually falsify it, and neither rests on anybody's
say-so. **Make the failure message report the measured value**, so one CI run
corrects a wrong constant rather than merely rejecting it. This is also the
right home for *divergent* rows, not only unanimous ones.

Details that are easy to get wrong:

- Ask `HostPlatform` which flavour the host is, through a **function**, not a
  module-level value: F# module values initialise on first touch of the file,
  so a `failwith` for "not a Unix" fires before the test's own
  `Assert.Ignore`. A test that measures the host skips through
  `HostPlatform.onUnixHost`; one that only asks whether a comparison is
  meaningful should branch and still assert something everywhere.
- **The test must not construct the expected value itself.** Obtain it from the
  platform, or the test pins behaviour under a constant no real kernel has.
- **Prefer a host entry point whose output has one layout.** `struct stat`
  differs per platform and per architecture, and a transcription of it is one
  more thing to get wrong. `TestPipeAgainstHost` reads `fstat` through .NET's
  `System.Native` library, which states every field in fixed-width types on
  every platform.
- A random sequence of calls against both (`TestPipeAgainstHost`,
  `TestSockOptAgainstHost`, `TestInotifyDeliveryAgainstHost`) finds orderings
  nobody would have written a row for. Generate the sequence once and replay it
  on each side; the failure then names the sequence.

The oracle covers only the host's column. A mutant that swaps two answers the
host gives identically survives it on that host; the other flavour's literals,
or CI's Linux run, are what kill it. Host tests and literal rows are
complementary across environments, not redundant.

`TestVirtualFileSystemAgainstHost` cannot express `FinalNavigation.Root`: it
prefixes every path with a temporary directory, so `/` arrives as a named
component. A rule that depends on the real root needs a literal row.

## Replays of committed probe outputs (`*Measured`)

`TestTcpTransferMeasured`, `TestInotifyMeasured`, `TestConnectLadderMeasured`,
`TestKeventMeasured` and their siblings, and others that replay a committed
output under another name (`TestSignalPickOrder` over `signalOrder/*.txt`,
`TestSocketSyscall` over `socketSyscall/*.tsv`, `TestPipeBufferCorpus`). A C
probe in `docs/plans/…` or `docs/probes/…` was run on each platform, its output
was committed beside it, and the test embeds that output (an `EmbeddedResource`
in the `.fsproj`) and replays every row call by call against the model.

This is the only tier that holds the model to **both** flavours' real answers on
every machine, including the flavour the machine is not. Its blind spot is time:
the output is a measurement of one kernel version on one date, and a kernel that
changed since is caught only by a host test. So a replay's docstring names its
probe, the platforms and the date, and a row the model refuses is asserted as a
refusal by its label, with the reason (`TestDualModeMeasured`,
`TestConnectLadderMeasured`), never skipped silently.

## Fuzzers (`TestSocketFuzz`, `TestSignalFuzz`)

Generated sequences of syscalls run on a real kernel by a C harness
(`socketFuzz/harness.c`, `signalFuzz/harness.c`) and on the model, whose
transcripts must agree. Each has two halves:

- **The corpus**, which runs everywhere: transcripts a real kernel produced,
  committed under `socketFuzzCorpus/` and `signalFuzzCorpus/`, replayed against
  the model.
- **The live run**, which needs a real kernel of the right flavour. The socket
  fuzzer measures Linux's epoll inside a `gcc:14` container and is opt-in
  (`POSIXKERNEL_SOCKET_FUZZ=1`, with `POSIXKERNEL_SOCKET_FUZZ_SEED`,
  `…_SEQUENCES` and `…_WRITE_CORPUS`; see
  `docs/plans/2026-08-22-socket-epoll-fuzzer.md`). The signal fuzzer builds its
  harness with the host's C compiler and checks the host's own flavour
  (`POSIXKERNEL_SIGNAL_FUZZ_SEED`, `…_SEQUENCES`); it skips where there is no C
  compiler, unless `POSIXKERNEL_REQUIRE_C_COMPILER=1`, which the devshell sets
  so that a run there cannot silently check nothing.

A divergence the live run finds belongs in the corpus once it is fixed, so that
every later run replays it without a container.

## A host replay that flakes: run its probe first

When a replay of a committed probe against the host fails now and then, run
the probe itself many times, several copies at once, and compare each run with
its recording before suspecting the replay's timing. A recording is one run of
the probe's procedure, and that procedure may not pin the state it meant to
measure: `TestShutdownAgainstHost`'s flakes on a loaded Mac were the probe's
own, reproduced by `tcp-shutdown.c` alone in a few runs in a hundred, where
its fill sometimes left Darwin free to grow the reader's buffer, or its settles
left an acknowledgement still to go out before a reset. Find what separates
the runs that answer as recorded (count it against the answer, as
`fill-settling.c` does), then have the replay wait for it where time brings it
about, or detect it and run the scenario again on fresh sockets where time does
not, failing after a bounded number of runs.

## A port another address already holds

On both flavours, a bind of 127.0.0.1:0 can be given a port that a socket at
another of the host's addresses already holds (a browser's connection from the
Wi-Fi address, say), and that socket refuses a later wildcard bind of the port
while letting every bind at 127.0.0.1 through (`port-held-elsewhere.c`, beside
`tcp-shutdown.c`). So a host replay whose pair took its port that way can see a
wildcard bind refused where the probe measured it binding: in about two runs in
a hundred of `bind-held-endpoint.c`'s replay on a desktop Mac, depending on
what else holds ports there. To find such a holder, Linux lists every socket in
`/proc/net/tcp`, but Darwin 27's `net.inet.tcp.pcblist64` sysctl lists only the
calling process's own (and `netstat` shows none at all), so instead bind the
port, without `SO_REUSEADDR`, at each of the host's addresses outside
127.0.0.0/8: a socket there or at the wildcard refuses that bind, and a pair's
own sockets at 127.0.0.1 never do. `TestShutdownAgainstHost`'s `heldElsewhere`
does this, and its `hostReplay` runs such a scenario again.

## The set-ID caveat that looks like a flake

A host-touching test can run in two environments: unsandboxed (`nix develop
--command dotnet test`, real Linux semantics, set-ID bits work) and, in a `nix
build` that runs the tests, inside Nix's Linux sandbox. That sandbox installs a
seccomp filter returning `EPERM` for `chmod`/`fchmod`/`fchmodat`/`fchmodat2`
whenever the mode sets `S_ISUID` or `S_ISGID` — unconditional, not
row-dependent, and `File.SetUnixFileMode` therefore *throws*
`UnauthorizedAccessException`, which a "did the chmod stick?" read-back guard
does not catch. `listxattr` and friends return `ENOTSUP` there too.

So a host-touching test needing set-ID bits must catch the refusal and skip,
not merely read the mode back, as `TestVirtualFileSystemAgainstHost`'s
`trySetMode` does. Skipping costs nothing: the unsandboxed run still measures
those rows.
