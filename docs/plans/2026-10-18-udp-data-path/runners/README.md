# The UDP probes on GitHub's runners

The Linux probes beside this directory (`udp-capacity.c`, `udp-truesize.c`,
`udp-release.c`, `udp-transfer.c` and `udp-source.c`), run on GitHub Actions'
`ubuntu-24.04` (x86-64) and `ubuntu-24.04-arm` (aarch64) runners on
2026-10-20. Each file's name says the kernel release, the architecture and the
`net.core.rmem_default` it ran at: the runners' own 1048576, or 212992, the
kernel's default, set with `sudo sysctl -w net.core.rmem_default=212992`
before the probes ran. The fleet was moving from 6.17 to 7.0, so runs landed on
both. Each probe was built with the runner image's `gcc` as its header says,
and run as the runner's own user.

`TestDatagramReceiver` replays the capacity, truesize and release files, each
at its kernel's version and build. The transfer and source files are kept as
evidence that nothing else in the data path differs on these kernels.

`udp-sendto.c` ran on the same runners on 2026-10-21, at their own
`net.core.rmem_default`, which none of its rows depends on. Its files are
named by kernel release and architecture alone. `TestDatagramSendToProbe`
replays them, each at its kernel's version: they differ from 6.18.5's only in
when a `recvfrom` that faults copying the source address writes the length
cell. They predate the probe's sections Z5 and Z6.
