# zoxy style — adopted from TigerStyle

zoxy adopts [TigerBeetle's TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md).
That document is the source of truth; this file records **the rules we enforce**
and the **proxy-specific deltas**. When in doubt, read the original.

> Another word for style is design. Design goals, in priority order:
> **safety, performance, developer experience.** All three matter; simplicity
> serves all three and is "not the first attempt but the hardest revision."

---

## Non-negotiables (CI-enforceable)

- **Static allocation only.** All memory is allocated at startup. **No dynamic
  allocation (or free-and-reallocate) after `init`.** Hot-path code runs under a
  `FailingAllocator` in tests to prove it.
- **Put a limit on everything.** Every loop and every queue has a fixed upper
  bound. An event loop that cannot terminate must *assert* that it cannot.
- **No recursion.** All bounded executions stay bounded; no unbounded stack.
- **Assertion density ≥ 2 per function** on average. Assert all arguments,
  return values, pre/postconditions, and invariants — positive space (what you
  expect) **and** negative space (what you don't). Split `assert(a and b)` into
  `assert(a); assert(b);`. Use `if (a) assert(b);` for implications. Assert
  relationships between comptime constants.
- **All errors handled.** No `catch unreachable` on a reachable error; no
  swallowed errors. (92% of catastrophic failures come from mishandled non-fatal
  errors — OSDI'14.)
- **Explicitly-sized integers** (`u32`, `u63`, …). Avoid `usize` except for real
  machine-word/index quantities.
- **Functions ≤ 70 lines.** Hard limit.
- **Lines ≤ 100 columns.** Hard limit, no exceptions.
- **4-space indentation.** `zig fmt` clean; trailing comma on wrapped signatures.
- **Braces on every `if`** unless it fits on one line (defense against
  `goto fail;`-class bugs).

## Control flow

- Simple, explicit control flow only. Centralize it: **push `if`s up and `for`s
  down** — branch in the parent, keep leaf functions straight-line and pure.
- Split compound conditions into nested `if/else`; split `else if` chains into
  `else { if { } }` trees. Consider whether each `if` needs an `else` (negative
  space).
- State invariants **positively**: `if (index < length) { holds } else { … }`.
  Negations are error-prone.
- **Functions run to completion without suspending** — this is why our I/O is
  callback-based (see DESIGN.md §I/O), so precondition assertions hold for the
  whole function body.
- Prefer simpler return types: `void > bool > u64 > ?u64 > !u64`.
- Pass options explicitly at the call site; don't rely on library defaults.

## Naming

- **Follow the [Zig reference naming conventions](https://ziglang.org/documentation/master/#Names)**
  — case encodes what a name *is*:
  - `TitleCase` for types and for any function that returns a type
    (`IpAddress`, `HttpReader`, `Pool(T)`, `Padded(T)`).
  - `camelCase` for every other function (`readHead`, `beginDrain`).
  - `snake_case` for variables, non-type constants, and struct fields
    (`latency_ms_max`, `header_bytes_max`, `connections_max`).
  - A field-less struct used purely as a namespace is `snake_case`.
  - **File names follow the same type/namespace split:** a file whose
    top-level struct has fields is a type → `TitleCase.zig`; a file that is
    just a namespace of declarations → `snake_case.zig`. Directories are
    `snake_case`.
  - Acronyms and initialisms are ordinary words under these rules, even
    two-letter ones: `IpAddress`/`HttpReader` (not `IPAddress`/`HTTPReader`),
    `Tcp`, `Io`.
- **No abbreviations** (except primitive indices in tight math). `source`/`target`
  over `src`/`dest` so `source_offset`/`target_offset` align.
- **Units/qualifiers last, most-significant word first:** `latency_ms_max`,
  `header_bytes_max`, `connections_max` — so related names column-align.
- Give allocators meaning: `gpa: Allocator` vs `arena: Allocator` signals whether
  `deinit` is needed.
- **Callbacks are the last parameter.** Helper naming shows call history:
  `readHead()` + `readHeadCallback()`.
- File order top-down, important first; `main` first. Struct order:
  **fields, then types (decls), then methods.** When unsure, sort alphabetically.
- Comments are complete sentences (capital, full stop) — say **why** and **how**,
  not just what. Write descriptive commit messages (they outlive PR text).

## Off-by-one & correctness hygiene (DX)

- Treat `index` (0-based), `count` (1-based), `size` (count × unit) as distinct;
  cast explicitly. Show division intent: `@divExact` / `@divFloor` / `divCeil`.
- Pass args > 16 bytes as `*const` to catch accidental stack copies.
- In-place init via out-pointer (`fn init(target: *T) !void`) for pointer
  stability and no intermediate copies.
- Declare variables at the smallest scope, close to use (avoid place-of-check to
  place-of-use gaps). Don't alias/duplicate state.
- Group `alloc` with its `defer` dealloc, separated by blank lines, to spot leaks.

## Performance

- **Back-of-the-envelope first.** Sketch every hot path against the four
  resources (network, disk, memory, CPU) × two characteristics (bandwidth,
  latency). Aim to be within ~90% of the global max. The big 1000× wins are won
  in *design*, before you can profile.
- Optimize the **slowest resource first, weighted by frequency** (a frequent
  cache miss can cost as much as an fsync). For a proxy the slow resource is the
  **network**, then syscalls/memory bandwidth.
- **Batch** to amortize syscall/network/memory costs (read many CQEs at once,
  coalesce writes). Let the CPU sprint in straight lines — give it big chunks,
  don't zig-zag on every event; run at our own pace, not one context-switch per
  event.
- Extract hot loops into standalone functions with primitive args (no `self`) so
  the compiler can keep values in registers and humans can see redundant work.

## Project policy

- **Zero technical debt** — solve it in design, right the first time.
- **Zero dependencies beyond the Zig toolchain**, wherever feasible. Each C-FFI
  dependency (e.g. an OpenSSL TLS terminator) must be a deliberate, justified
  exception, not a convenience.
- Tooling in Zig (`scripts/*.zig`, not `*.sh`) where practical.
- Assertions are always on (dev **and** release); they downgrade correctness bugs
  into liveness bugs. They are a safety net, not a substitute for understanding —
  build the mental model, encode it as assertions, and (later) let a
  deterministic simulator be the last line of defense.
