#import "../../Sherlock/template.typ": *

#show: report.with(
  title: "exfatprogs",
  subtitle: "Fuzzing & Upstream Fix",
  meta: (
    ("Target", "exfatprogs 1.4.4, Linux exFAT filesystem utilities (C)"),
    ("Method", "Coverage-guided fuzzing (libFuzzer), ASan + UBSan"),
    ("Finding", "Undefined behaviour: out-of-range shifts on boot sector fields"),
    ("Outcome", [Fix accepted upstream, shipped in exfatprogs 1.4.5]),
    ("References", [#link("https://github.com/exfatprogs/exfatprogs/pull/403")[PR \#403], #link("https://github.com/exfatprogs/exfatprogs/commit/f976d4d0b033e72518fb67f1d805fd49f2aebd95")[commit f976d4d]]),
    ("Harnesses", [#link("https://github.com/M3RICK/exfatprogs-fuzzer")[github.com/M3RICK/exfatprogs-fuzzer]]),
    ("Author", "M3RICK"),
  ),
  tldr: [
    - *Found* undefined behaviour in the exFAT boot sector parser by fuzzing it with libFuzzer and UBSan.
    - *Fixed* it in the shared library used by every exfatprogs tool, extended after the maintainer's review.
    - *Shipped* upstream in exfatprogs 1.4.5, six days after the pull request was opened.
  ],
)


// Figure helpers: boxes joined by arrows, in the template colors.
#let node(body, hl: false) = box(
  fill: if hl { accent.lighten(88%) } else { paper },
  stroke: 0.8pt + if hl { accent } else { navy },
  inset: (x: 7pt, y: 6pt), radius: 3pt,
  align(center, text(size: 8pt, body)))

#let flow(..nodes) = {
  let cells = ()
  for (i, n) in nodes.pos().enumerate() {
    if i > 0 { cells.push(text(fill: muted, size: 11pt, sym.arrow.r)) }
    cells.push(n)
  }
  align(center, grid(columns: cells.len(), column-gutter: 4pt, align: horizon, ..cells))
}

// One hexdump row; bytes listed in `hl` get the accent.
#let hexrow(offset, bytes, hl: ()) = {
  let cell(b, i) = {
    let on = i in hl
    box(fill: if on { accent } else { none }, inset: (x: 2pt, y: 2pt), radius: 2pt,
      text(font: mono, size: 8.5pt, fill: if on { white } else { ink }, b))
  }
  let head = range(16).map(i => text(font: mono, size: 7.5pt, fill: muted, str(i, base: 16)))
  align(center, grid(columns: 17, column-gutter: 5pt, row-gutter: 6pt, align: center,
    [], ..head,
    text(font: mono, size: 8.5pt, fill: muted, offset), ..bytes.enumerate().map(((i, b)) => cell(b, i))))
}

= Summary

exfatprogs is the set of user-space tools that create, check, repair and inspect exFAT filesystems on Linux. These tools read images that anyone can craft: a USB stick or an SD card is enough to hand them malicious bytes.

I wrote libFuzzer harnesses against the shared library used by every tool. After *two harnesses plateaued without a crash*, I moved to a surface they did not exercise on its own, the boot sector, and added UBSan. This found *undefined behaviour in `read_boot_sect()`*: two boot sector fields were used as shift counts before any range check.

I sent a fix upstream. During review the maintainer pointed out one more function with the same pattern; I extended the fix, and it was applied and released in exfatprogs 1.4.5.

= Target and attack surface

An exFAT volume starts with a boot sector that describes its geometry: sector size, cluster size, where the FAT and the cluster heap begin. Two of these fields are stored as powers of two:

#table(
  columns: (auto, auto, 1fr),
  [Field], [Type], [Meaning],
  [`sect_size_bits`], [`u8`], [log2 of the sector size (9 to 12 for 512 B to 4 KiB)],
  [`sect_per_clus_bits`], [`u8`], [log2 of the sectors per cluster (cluster at most 32 MiB)],
)

Every tool that opens a volume (`fsck`, `dump`, `label`, `tune` and the others) goes through the shared library in `lib/`. *A bug there is reachable from all of them*, which makes the library the natural fuzzing target.

= Harness design

libFuzzer calls one function per input. The library expects a device path, not a buffer, so each input takes the path below and is freed at the end.

#figure(kind: image,
  flow(
    node[input bytes],
    node[`memfd` \ `/proc/self/fd/N`],
    node[open as \ a device],
    node(hl: true)[parse boot sector \ `read_boot_sect()`],
    node[target \ work],
  ),
  caption: [Path of one fuzzer input. The highlighted step is where the bug was.],
)

This setup is shared by all targets in a small module, `image.c`, so each harness only contains what it exercises. Every input gets a fresh context: a crash can never come from state left by a previous input.

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct image img;

	if (image_open(&img, data, size) == 0)
		lookup_in_root(img.exfat);
	image_close(&img);
	return 0;
}
```

Two settings mattered in practice. The library logs every anomaly it sees, which slows fuzzing down and buries sanitizer reports, so `print_level` is set to 0. And libFuzzer truncates inputs to 1 MiB by default, which is below a valid exFAT geometry: without `-max_len=4194304` the seed is silently cut and coverage caps early.

= The plateau

The first harness iterated the root directory entry by entry. Coverage flattened quickly, at 111 edges: the iterator was hit, but the code that interprets a complete file (a file entry `0x85` followed by its stream `0xC0` and name `0xC1` entries) was not. Switching to `exfat_lookup_file()` with a name that never matches made the library check every file entry set in the directory (entry types, name length, entry count and name), and coverage moved again.

A second harness walked subdirectories recursively, following each directory's start cluster, with a depth cap and an entry cap to keep every input fast. Both harnesses then saturated, at 193 and 147 edges, after roughly 17 million executions, with no crash.

*They had run out of code to reach.* The lookup only checks a few fields of each set. Once those branches were covered, more executions could not find anything new on this path.

#note("A wrong first explanation")[
  I first blamed the 16-bit checksum carried by each file entry set, assuming the library rejected mutated sets before parsing them. Reading the code proved this wrong: the library only computes that checksum when it writes a set. It is verified in `fsck` and `dump`, which these harnesses do not link. The plateau was not a rejection, the path was exhausted.
]

#figure(kind: image,
  flow(
    node[*raw dentry iterator* \ plateau at 111 edges],
    node[*`exfat_lookup_file()`* \ plateau at 193 edges],
    node[*path exhausted* \ no new edges],
    node(hl: true)[*boot sector + UBSan* \ bug found],
  ),
  caption: [The investigation in four steps, with coverage edges reported by libFuzzer.],
)

= Changing surface: the boot sector

The third target, `fuzz_exfat_boot`, stops right after the boot sector parse. The boot sector had not been fuzzed on its own, and no directory is read here: every mutation goes straight to the geometry arithmetic.

*AddressSanitizer reported nothing there*, and that was expected: the suspicious code computes sizes with shifts, and a bad shift is not a memory error. It is undefined behaviour in C, which UndefinedBehaviorSanitizer detects.

I added a targeted set of UBSan checks (`shift`, `signed-integer-overflow`, `integer-divide-by-zero`, `bounds`) rather than the whole `undefined` group, which is noisy on this code base, and `-fno-sanitize-recover=all` so that a report becomes an abort and libFuzzer saves the input.

The fuzzer then stopped on reproducers like this one:

```
lib/libexfat.c:2035:16: runtime error: shift exponent 123 is too large for 32-bit type 'int'
```

= Root cause

The two fields sit next to each other in the boot sector:

#figure(kind: image,
  [
    #hexrow("0x60", ("05","00","00","00","12","34","56","78","00","01","00","00","7b","00","01","80"), hl: (12, 13))
    #v(0.6em)
    #text(size: 8.5pt)[`0x6C` `sect_size_bits` = `0x7b` (123), valid range 9 to 12 #h(1.5em) `0x6D` `sect_per_clus_bits` = 0]
  ],
  caption: [Bytes 0x60 to 0x6F of a crafted boot sector (constructed example, not the fuzzer's input).],
)

In `read_boot_sect()` both come straight from the image and are used immediately:

```c
sect_size = 1 << pbr->bsx.sect_size_bits;
clu_size = 1 << (pbr->bsx.sect_size_bits +
		 pbr->bsx.sect_per_clus_bits);
```

Both are `u8`, so an attacker controls values from 0 to 255. *Shifting a 32-bit `int` by 32 or more is undefined behaviour*: the C standard gives no result, and the compiler may assume it never happens. In practice the computed sizes become meaningless, and every later offset that depends on them is wrong.

`fsck` was not affected: it validates these fields in its own `read_boot_region()` before calling this code. The other tools reach `read_boot_sect()` through `exfat_alloc_exfat()` without that check. Reading the rest of the library, I found the same unchecked shifts in `exfat_set_volume_serial()`.

= Fix and review

The format itself bounds both values: sectors are 512 B to 4 KiB (9 to 12 bits) and a cluster is at most 32 MiB (25 bits in total). The fix adds one helper and calls it before every shift:

```c
static bool valid_boot_size_bits(unsigned char sect_size_bits,
		unsigned char sect_per_clus_bits)
{
	return sect_size_bits >= 9 && sect_size_bits <= 12 &&
		sect_per_clus_bits <= 25 - sect_size_bits;
}
```

Valid images are unaffected, and a crafted one is now rejected with an error message instead of undefined behaviour.

The maintainer reviewed the patch and asked whether `exfat_get_root_entry_offset()` needed the same check. It did: it reads the raw boot sector and performs the same shifts. I added the check there, verified that the reproducers no longer trigger UBSan, and reviewed every remaining shift on these fields: they all run after validation.

exfatprogs does not merge pull requests through GitHub. The maintainer applies patches to the `exfat-next` branch and closes the pull request, then merges that branch at release time. *The fix kept my authorship and was released in 1.4.5.*

#table(
  columns: (auto, 1fr),
  [Date], [Event],
  [2026-11-13], [Pull request \#403 opened],
  [2026-11-17], [Review: extend the check to `exfat_get_root_entry_offset()`, patch updated],
  [2026-11-18], [Applied to `exfat-next` as commit `f976d4d`],
  [2026-11-19], [Released in exfatprogs 1.4.5],
)

= Takeaways

- *A plateau is information.* Flat coverage means either that inputs are rejected somewhere or that the path is exhausted. Checking which one in the code, rather than assuming it, decided the next step: here the path was exhausted, so the answer was a new surface.
- *The sanitizer defines what can be found.* With ASan alone this bug was invisible. Choosing UBSan checks that match the code under test (size arithmetic) is what exposed it.
- *Read around the bug.* The fuzzer found one function; reading the library found a second, and the maintainer's review a third. A fix that covers the whole pattern is worth more than one that silences the reproducer.
