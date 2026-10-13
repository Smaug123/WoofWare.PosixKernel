# WoofWare.PosixKernel

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="WoofWare.PosixKernel/logos/dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="WoofWare.PosixKernel/logos/light.svg">
  <img alt="Project logo: minimalistic face of a cartoon Shiba Inu, drawn in outline, sitting at the centre of three concentric rings." src="WoofWare.PosixKernel/logos/light.svg" width="300">
</picture>

A deterministic, purely functional simulation of a POSIX process: its filesystem, file descriptors, pipes, sockets, `poll`/epoll/kqueue, inotify, signals, tasks, clock and entropy, on a Linux or a Darwin kernel whose divergences were each measured on the real thing.
It performs no I/O and makes no host reads, so a replay never depends on the machine that produced it.

The library's own README, [`WoofWare.PosixKernel/README.md`](WoofWare.PosixKernel/README.md), is the account of how a client uses it, and is also the package's README on [NuGet](https://www.nuget.org/packages/WoofWare.PosixKernel).

## Building and testing

Everything runs inside the Nix devshell, which pins the .NET SDK and provides the C compiler and Python the host-comparison tests start.

```sh
nix develop -c dotnet build
nix develop -c dotnet test WoofWare.PosixKernel.Test/WoofWare.PosixKernel.Test.fsproj
# The large-memory fixtures (about 6.5 GB peak) are explicit; run them on their own.
nix develop -c dotnet test WoofWare.PosixKernel.Test/WoofWare.PosixKernel.Test.fsproj --filter "TestCategory=LargeMemory"
nix flake check
```

[`AGENTS.md`](AGENTS.md) has the rest: the repository's layout, its checks, and how changes are made.

## History

This library was developed inside [WoofWare.PawPrint](https://github.com/Smaug123/WoofWare.PawPrint), a deterministic .NET runtime, and moved here with its history.
In commit messages from before the move, `Smaug123/WoofWare.PawPrint#N` is a PawPrint pull request or issue, and `Smaug123/WoofWare.PawPrint@<hash>` a PawPrint commit.
[`docs/README.md`](docs/README.md) says how to read the design documents written there.

## Licence

MIT; see [`LICENCE.md`](LICENCE.md).
