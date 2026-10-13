# docs

- `probes/`: small C and Python programs, each measuring one kernel behaviour on Linux and on Darwin, with their recorded outputs. The tests replay many of those outputs, and the library's docstrings cite them.
- `plans/`: design documents, with their own probes and measurements in a directory of the same name.
- `design/`: the options documents behind the API's decisions, with the raw measurements they cite. Its README says how to read them.

## Documents written in WoofWare.PawPrint

Every plan and design note here, and many probes, was written while this library lived in [WoofWare.PawPrint](https://github.com/Smaug123/WoofWare.PawPrint), and some of them describe work on both sides of the line between the kernel and that client.
So a path they name that does not exist in this repository (`WoofWare.PawPrint/...`, `WoofWare.PawPrint.Test/...`, `docs/divergences.md`, another plan, a skill under `.claude/skills/`) is a path in WoofWare.PawPrint, and `#N` in them is a PawPrint pull request or issue.
Read such a path at the PawPrint commit the move was made from, since PawPrint has moved on: the commit that added this file names it
(`git log --diff-filter=A -- docs/README.md`).
