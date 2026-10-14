# Design notes

These are the options documents behind the library's API decisions: for each question, what was measured, the options weighed, and what was decided.
They were written while the kernel lived in [WoofWare.PawPrint](https://github.com/Smaug123/WoofWare.PawPrint), and are kept as they were written then.

- They name PawPrint paths, pull requests, branches and worktrees as they were then, and they use the library's old vocabulary: a "task" is what the library now calls a thread (`UnixTask.fs` is now `UnixThread.fs`, and so on).
- An unqualified `#N` in them is a WoofWare.PawPrint pull request or issue.
- [`docs/README.md`](../README.md) says how to read a path they name that does not exist in this repository.
- A `*-raw/` directory beside a note holds the probes, scripts and raw outputs that note cites.
- A few notes cite documents that are not here: `failwith-audit-2026-10-07.md` (a point-in-time inventory of the library's throw sites), `../pawprint-signals-research/`, and the scratchpads of the sessions that wrote them.
