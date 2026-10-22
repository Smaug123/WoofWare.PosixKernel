# `sendmsg` and `recvmsg` on UDP sockets

Stage U5 of `docs/plans/2026-10-18-udp-data-path.md`, whose section 3.6 leaves
the calls' argument shape, and what the kernel does with control messages, to
a design note of their own. This is that note. Section 2.12 (`udp-transfer.c`
section P) is its measured input so far; section 3 below lists what is still
to measure.

## 1. What exists

- `Syscall.SendMsg` and `Syscall.RecvMsg` are reserved, with argument records
  of internal representation, and `UnixSystem.step` refuses them.
- `sendto` and `recvfrom` (U3) are modelled on IPv4 UDP sockets, with each
  flavour's failure ladder measured (2.15). A blocking `recvfrom` sleeps (U4),
  and `FinishedDatagramReceive` is a union by call, to which U5 appends
  `RecvMsg`.
- Every call that reads the caller's memory stops where the kernel reads it
  (`docs/plans/2026-10-13-copy-in-pauses-and-process-fate.md`): it answers
  `CallProgress`, whose paused type says what to copy, so that the client
  reads only what a real kernel would, and only when. The paused type names
  the copy; there is deliberately no union of copy requests.
- The kernel never learns an address: a pointer reaches it as a `UserBuffer`
  the client has classified (`Mapped`, `Unmapped`, `Opaque`, `Addressless`),
  and a copy as a `CopyRange` into an argument the call was given.

## 2. What the calls read and write

A `struct msghdr` is seven fields. Their widths are each flavour's, on the
64-bit ABIs this kernel models:

| field | Linux (56 bytes) | Darwin (48 bytes) |
|---|---|---|
| `msg_name` | pointer | pointer |
| `msg_namelen` | `int` (read signed) | `socklen_t` |
| `msg_iov` | pointer | pointer |
| `msg_iovlen` | `size_t` | `int` |
| `msg_control` | pointer | pointer |
| `msg_controllen` | `size_t` | `socklen_t` |
| `msg_flags` | `int` | `int` |

Each `struct iovec` is a pointer and a `size_t`, 16 bytes on both.

`sendmsg` reads the header, the iovec array, the name, the control buffer and
the bytes of each iovec. `recvmsg` reads the header and the iovec array, and
writes the bytes into the iovecs, the source into the name, and
`msg_namelen`, `msg_controllen` and `msg_flags` back into the header.

Kernel source suggests the two flavours read in different orders (to be
measured, section 3):

- **Linux**: the header; the name (in `__copy_msghdr`); the check of
  `msg_iovlen` against `UIO_MAXIOV`, 1024 (`EMSGSIZE`); the iovec array; the
  control buffer; then `udp_sendmsg`'s checks, and the bytes.
- **Darwin**: the header; the check of `msg_iovlen` (`EMSGSIZE` for 0, which
  2.12 measured, and above 1024); the iovec array; then, in `sendit`, the name
  and the control buffer.

## 3. To measure first

A probe, `udp-msg.c`, crossing each argument as `udp-sendto.c` crossed
`sendto`'s (2.15):

- **Y1, `sendmsg`**: a header that faults; `msg_iovlen` of 0, 1, 1024, 1025
  and one with the top bit set (negative to Darwin's `int`); an iovec array
  that faults; an iovec whose base faults, first or second; an iovec length
  with the top bit set, and two that overflow together; a name that is NULL,
  faults, or is 0, 8, 16, 129 and 0x80000000 long; a control buffer that is
  NULL, faults, or is 8 or 16 zero bytes or 0x80000000 long; over the sender
  states and flags of Z1.
- **Y2, `recvmsg`**: the same header, count and array cases; an iovec base
  that faults, in the first or the second iovec the datagram reaches; a name
  that is NULL or faults, with `msg_namelen` 0, 8, 16, 0x7fffffff and
  0xffffffff; a control buffer that is NULL, faults, or is 8 or 64 bytes; over
  the queue states and flags of Z2.
- **Y3**: what each call writes back to the header (`msg_namelen`,
  `msg_controllen`, `msg_flags`) on every rung, with sentinels in each field,
  as Z6 did for `recvfrom`'s length cell.

## 4. Options

### 4.1 Who decodes the header and the iovec array

- **(A) The client.** The header pause is resumed with a typed header,
  `MessageHeader`, whose pointers the client has classified as `UserBuffer`s,
  and whose integers are the raw bits of the flavour's field, zero-extended to
  `uint64` where the field is narrower, for the kernel to read signed or not
  as its flavour does. The iovec array is resumed with a list of
  `IoVector = { Base : UserBuffer ; Length : uint64 }`. Later copies (the
  name, the control buffer, the bytes) are `CopyRange`s into those
  arguments, as today.
  - Keeps the rule that the kernel never learns an address, so a symbolic
    pointer (`Addressless`) in a header works as it does in a `recvfrom`.
  - The client decodes the C structure, which it already knows from its own
    headers. A client that decodes it wrong is wrong invisibly: the kernel
    cannot tell a misread field from a real one.
- **(B) The kernel.** The header pause is resumed with the header's bytes,
  which the kernel decodes by its flavour's layout. Each later copy names the
  address the header held, which the client answers as a `CopiedArgument`
  (`Readable`, `Unmapped`, `Opaque`, `Addressless`).
  - The layout is in one place, held to the probe.
  - It is a new kind of pause, one that names an address rather than an
    argument. The platform gains a pointer width and a byte order it does not
    hold today, and a pointer the client holds symbolically cannot be put in
    bytes at all.

**Recommend (A).** It changes no rule the library already keeps, and the
layout it leaves to the client is the platform's C ABI, which the client
compiled against.

### 4.2 How the call stops for each copy

The copy-in law gives each copy its own paused type. The orders in section 2
differ by flavour after the header, so the next copy is not fixed.

- **(a) One paused type per copy, in each flavour's order.** The header's
  resume answers a union of the paused types that can come next (under Linux
  the name, under Darwin the iovec array), or the answer. Every copy is
  exactly where the kernel makes it. The client handles a union at the point
  where the orders part.
- **(b) One paused type for the call, `PausedSendMsg`, whose `next` accessor
  says what to copy**, and one resume, `sendmsgWithCopy`. One type for the
  client, but it is the copy-request union the copy-in law rules out: the
  value could disagree with what the resume expects.
- **(c) One pause for every argument copy after the header** (name, iovec
  array, control), then one for the bytes. Two paused types, in a fixed order.
  But the client is asked to read memory a kernel would not have: under
  Linux, an iovec array the `EMSGSIZE` check would have stopped short of;
  under Darwin, a name the iovec array's fault would have.

**Recommend (a)**, if the probe confirms the orders differ; if they agree, it
is a plain chain, as `clonefile`'s is.

### 4.3 Control messages

No socket option that makes a kernel attach control data (`IP_PKTINFO`,
`IP_RECVTOS`, `SO_TIMESTAMP` and the rest) is settable, so a `recvmsg` always
writes `msg_controllen` 0, as 2.12 measured. What `sendmsg` does with control
data is the question:

- **(i) Refuse any `msg_controllen` but 0.** No control buffer is read. A
  client that sends control data, even an empty `cmsghdr`, is refused.
- **(ii) Parse the `cmsghdr` chain** as each flavour does, answering what is
  measured for a malformed one (Linux's `EINVAL` for a `cmsg_len` of 0,
  2.12; Darwin sends), and refuse every well-formed message, whose meaning is
  unmodelled.

**Recommend (i)** for U5: a client following the documentation passes control
data only to set something, and none of it is modelled. (ii) can come when a
client needs it.

### 4.4 What a `recvmsg` answers of the bytes

- **(α) Per iovec.** The answer holds the bytes each iovec received, in
  order: `ImmutableArray<ImmutableArray<byte>>`, one entry per iovec, empty
  past the datagram's end. A Linux receive that faults partway (it takes the
  datagram, fills the iovecs before the one that faults, and answers
  `EFAULT`) says exactly what each iovec holds.
- **(β) One array**, which the client scatters across its iovecs in order, as
  `recvfrom`'s `Received` does for its one buffer. Simpler, but the client
  repeats the kernel's filling rule, and a partway fault needs the count the
  kernel reached as well.

**Recommend (α).**

## 5. Staging

Two PRs, each after the probe's rows it replays:

- **U5a, `sendmsg`**: `Syscall.SendMsg`'s arguments, the pauses, the ladder,
  delivery through `sendto`'s path.
- **U5b, `recvmsg`**: `Syscall.RecvMsg`'s arguments, the answer, the ladder,
  the blocking receive (`ParkedDatagramReceiveCall` gains the call,
  `FinishedDatagramReceive` gains `RecvMsg`), and Darwin's echo of the flags
  into `msg_flags`.

Both refuse any socket but an IPv4 UDP one, and every flag `sendto` or
`recvfrom` refuses, as those calls do.

## Decisions

Patrick, 2026-10-22: the recommendations, (A), (a), (i) and (α). The client
decodes the header and the iovec array into typed values; each copy is its own
pause, in each flavour's order, with a union of paused types where the orders
part; `sendmsg` refuses any `msg_controllen` but 0; and `recvmsg` answers the
bytes each iovec received.
