# Which spellings of a name reach its entry, measured

`name-equivalence.c` is the probe behind `EntryNameMatching` and the refusal
`PathRefusal.UndecidedNameEquivalence`. Its header says how to build and run it
and what each row prints; `TestNameEquivalence` replays every row of the
case-sensitive APFS and tmpfs outputs.

| file | envelope |
| --- | --- |
| `measured-darwin-27.0-apfs-case-sensitive.txt` | Darwin 27.0.0 arm64, uid 501, a fresh 20 MB case-sensitive APFS disk image (`f_fssubtype` 0), measured 2026-10-13 |
| `measured-darwin-27.0-apfs-case-insensitive.txt` | the same machine's default volume (`f_fssubtype` 1), the same day |
| `measured-linux-6.18.5-aarch64.txt` | Linux 6.18.5 aarch64 in Apple's `container` VM, root: tmpfs (`/dev/shm`) and then ext4 (`/var`), whose rows agree |

What the outputs say:

* **APFS, in both variants, takes a name as reaching the entry bound under any
  canonically equivalent spelling of it.** NFC and NFD `é` reach one entry,
  within a longer name too, and so do two orders of combining marks, a Hangul
  syllable and its jamo, `K` and U+212A KELVIN SIGN, `;` and U+037E, `` ` ``
  and U+1FEF, U+2126 OHM SIGN and U+03A9, U+212B ANGSTROM SIGN and U+00C5, and
  U+F900 and U+8C48. `stat` finds the entry, `O_CREAT|O_EXCL` answers EEXIST,
  and `mkdir`, `link` and `symlink` answer EEXIST; `unlink`, `rmdir`, `chdir`,
  `open(O_CREAT)` and either side of `rename` act on the entry; an interior
  component is looked up the same way.
* **It keeps the spelling a name was bound under**, which `readdir` reports.
  A `rename` onto another spelling of an existing name keeps the existing
  spelling. A `rename` of a name to another spelling of itself changes nothing
  on the case-sensitive volume, and respells it on the case-insensitive one.
* **Compatibility equivalents are different names** on the case-sensitive
  volume: U+FB01 and `fi`, U+FF21 and `A`, U+00BD and `1⁄2`. The
  case-insensitive volume folds case as well, and its folding takes U+FB01 to
  `fi` and U+212A to `k`.
* **A name that is not UTF-8 reaches nothing it is not byte for byte**, even
  beside the name a lenient decoder would make of it (Latin-1, CESU-8, an
  overlong encoding): `stat` is ENOENT and creating it EILSEQ.
* **Linux's tmpfs and ext4 compare bytes**: every pair is two names.

The library models case-sensitive APFS on Darwin. It holds no Unicode tables, so
it refuses a lookup that finds no entry under exactly the bytes looked up while
the directory binds a name that might be equivalent; see `NameDecomposition`, in
`EntryNameMatching.fs`, for the rule and the three-entry table it uses.
