# Boot-image setters: throw or refuse? (decided 2026-10-07, on Fable's recommendation; Patrick away)

Question raised by the throw-site audit (failwith-audit-2026-10-07.md). Several `UnixBootImage.withX`
setters throw (with a `context` string) on configuration the library can't model, while their docstrings
say "refuses"; `withFileSystemAndCurrentDirectory` already returns `Result<_, CurrentDirectoryFault>`.

Options:
- A. Keep throwing as a documented precondition; fix docstrings to say "throws".
- B. Typed refusal from each setter: `Result<UnixBootImage<_,_>, XRefusal>`, one small DU per setter with `describe`.
- C. Parse-don't-validate input types that can only hold modelled values. Rejected: the flavour is a runtime
  value (`SimulatedUnixPlatform.create` returns Result), so C still ends in a runtime check; it only moves it.
- D. Setters total, `boot` returns Result collecting everything. Rejected: the image would hold unvalidated
  knobs (illegal states inside the library) and `withFileSystemAndCurrentDirectory` would have to be undone.

Decision: B, uniformly: any rejection of a well-formed value is a refusal (not only "unmeasured" ones),
because the module already chose that for CurrentDirectoryFault, and the unmeasured/contradictory line is
fragile (six setters say "not measured", not three). Forgery checks (`Unchecked.defaultof`) stay throws with `context`.

Crux if Patrick disagrees: whether a configuration no machine could have is client *bug* (throw) or client
*input* (refuse). If "bug": stop after PR 1 and fix the remaining docstrings to say "throws".

Plan:
1. After #1766 (ApiSurface) merges; regenerate the baseline once.
2. PR 1: withCredentials, withUserAddressLimit, withSoMaxConn, withTcpSendSpace, withBootTime, withLeaderThreadId
   (+ a test-project `expectOk` helper; ~72 call sites, withCredentials 42 of them).
3. PR 2: withProcessId, withUmask, withProcessorCount, withEphemeralPortRange, withMount, withProtectedFiles,
   withPipeDevice; withLocalAddresses/Ipv4Prefix as its own parse-don't-validate change.
4. PawPrint: KernelConfig.toKernel matches each refusal and failwiths naming the knob (as for CurrentDirectoryFault);
   TestKernelConfig's pinned prefixes survive, Darwin 17 groups becomes "KernelConfig.SupplementaryGroups: ".
Coordination: the multi-process session may make credentials/pid/leader tid per-process; check before starting.
Full recommendation: Fable's report in session bdc6ffd7 (2026-10-07).

Update 2026-10-07: withLocalAddresses needed no refusal after all. Ipv4Prefix became a private struct with
`create : uint32 -> int -> Result<_, Ipv4PrefixRefusal>` (length out of range; host bits set — Linux's own
route rule in fib_frontend.c), so every prefix is valid by construction; overlapping/duplicate routes are what
real machines hold, so there is no list-level refusal and withLocalAddresses is total (branch pk-ipv4prefix).
