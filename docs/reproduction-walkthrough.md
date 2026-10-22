# San2Patch Reproduction: Benchmark Walkthroughs

We ran San2Patch (USENIX Security 2025) on four real vulnerabilities, using the
authors' Docker image and the same settings as the paper (GPT-4o, Tree-of-Thought
prompting). This document explains each bug, what the AI proposed,
how the patch was tested, and whether it really worked.

## Results at a glance

| Bug | Dataset | Program | Kind of bug | Result | Matches paper? |
|---|---|---|---|---|---|
| CVE-2016-1839 | VulnLoc | libxml2 (HTML reader) | Reads past the end of a buffer | Not fixed | Yes |
| CVE-2017-5969 | VulnLoc | libxml2 (XML reader) | Uses a missing (NULL) pointer | **Fixed** (on rerun) | Yes |
| CVE-2017-7595 | VulnLoc | libtiff (image tool) | Divides by zero | **Fixed** | Yes |
| NOFIX-2024-009 | San2Vuln | Bento4 (MP4 video tool) | Uses a missing (NULL) pointer | **Fixed** | Yes |

The first CVE-2017-5969 run reported a "success" that turned out to be false. The
cause was our machine's setup, not San2Patch or the AI. See
[Environment issue: random hangs](#environment-issue-random-hangs) below.

## Background

### The two datasets

- **VulnLoc**: 39 older bugs (2012–2018) from well-known open-source C programs.
  It is a standard academic benchmark that earlier repair tools were also tested on.
- **San2Vuln**: 27 newer bugs (mostly 2022–2024) collected by the paper's authors.
  Many appeared after the AI model's training data was collected, so the AI cannot
  just "remember" the fix. Bugs named `NOFIX-...` had no official fix at the time.

### Words used below

- **Crash input (PoC)**: a file that makes the program crash. It is the "attack" we replay.
- **Sanitizer**: a checker built into the program at compile time. When the program
  does something unsafe with memory or arithmetic, the sanitizer stops it and prints a
  report saying what went wrong and where. That report is what San2Patch gives the AI.
- **Buffer**: a block of memory holding data, like the text of a file being read.
  Reading past its end means reading memory that belongs to something else.
- **NULL pointer**: a pointer is an address of a piece of data. NULL means "points
  to nothing". Trying to read through it crashes the program.
- **Patch**: a small code change, shown as lines removed (`-`) and added (`+`).

### How every bug is tested

San2Patch gives the AI only the sanitizer report and the program's source code. The
AI then reasons in four steps: understand the bug → choose where to fix it → choose
how to fix it → write candidate patches. One attempt produces several candidates.
Each candidate goes through the same checks, stopping at the first failure:

1. **Apply** the patch to a clean copy of the source code.
2. **Rebuild** the program. If it doesn't compile, the compiler error is sent back to
   the AI to correct, and if it still doesn't compile, the candidate fails.
3. **Replay the attack**: run the crash input again. If the sanitizer still reports
   a problem, the candidate fails.
4. **Functionality test**: run the program's own test suite, to check the patch
   didn't break normal behaviour. These tests are **not** written by the AI. They come
   with the dataset and are usually the original project's own tests. Some projects
   in the dataset have no tests at all, and then this step always passes.

A candidate that passes all four is reported as **success**.

## Environment issue: random hangs

**What we saw.** Our first CVE-2017-5969 run reported success, but when we replayed the
attack by hand against the "fixed" program, it still crashed. Replaying it many times
showed the real behaviour: the program usually crashed, but sometimes it **froze**
until the test script killed it after 10 seconds. This happened even with **no patch
at all** (2 out of 10 runs). libtiff's attack showed the same random freezes, so the
problem was not specific to one bug.

**Why that produced a false success.** When the program freezes, it never prints a
crash report. San2Patch's attack replay only looks for a crash report, so the silence
was taken to mean "the crash is gone".

**The cause.** The benchmark programs are built with a 2018 version of the sanitizer
(from GCC 7.5). Newer Linux kernels, including the one WSL2 uses, place program memory
at much more random addresses (a setting called `vm.mmap_rnd_bits`, which defaults to
32 here). The old sanitizer doesn't expect that much randomness. Every so often memory
lands somewhere it can't handle, and it freezes instead of reporting the crash. The
paper's authors used Ubuntu 22.04, whose kernel used less randomness, so they would not
have seen this.

**The fix.** Lower the randomness on the host machine to the value the old sanitizer
expects, before running anything:

```bash
sudo sysctl vm.mmap_rnd_bits=28
```

This applies to Docker and all containers right away, but it resets whenever WSL
restarts, so run it again after a reboot or `wsl --shutdown`. After the fix, the
attacks crashed every time, and the later runs below were checked for this: each
"attack replay passed" result finished in under a second with real program output,
not after a 10-second freeze.

**Which results this affects.** Only results that say the attack **stopped crashing**
can be fooled by a freeze. A freeze can't make a crash appear, so the CVE-2016-1839
failure, which was run before the fix, is still valid.

---

## 1. CVE-2016-1839: libxml2 HTML reader (VulnLoc)

**Background.** libxml2 is a widely used library for reading XML and HTML files. This
bug is the paper's main motivating example (Figures 1–5).

**The vulnerability.** In HTML, `&name;` is an "entity", a short code for a special
character (for example `&amp;` for `&`). When the reader meets an entity name, it reads
the name character by character. If the name is very long, the reader has to load more
of the file partway through. Afterwards it works out where the name started by
counting backwards from where it is now. But after the reload, the true starting point
is no longer where it expects, so it counts back past the start of its buffer and
copies a large chunk of memory that isn't part of the file.

**The attack input.** A 73,666-byte text file that starts with `&:&::&:::::` and is
followed by tens of thousands of the letter `j`, which makes one enormous entity name.
The sanitizer report: "heap-buffer-overflow, READ of size 73661".

**The real fix (by the libxml2 developers).** Two checks in the HTML reader
(`HTMLparser.c`): stop if the reader has reached the end of the input, and give up if
the computed start of the name falls before the beginning of the buffer.

**What the AI proposed.** Nine candidates, in three groups:

- **3 candidates**: a size limit in the dictionary lookup (`dict.c`), using made-up
  maximum lengths such as 1024 or 65552.
- **3 candidates**: guard the *destination* of the copy in `dict.c`, checking there is
  room to write. The problem is the *source* being read, so this is the wrong buffer.
  The paper shows this exact mistake in Figure 3b.
- **3 candidates**: add an end-of-input check in the HTML reader's simple name function
  (`htmlParseName`). This is close to the developer's first check, and one candidate
  even used the correct "end of input" value. But this attack goes through a
  *different* function (`htmlParseNameComplex`), which none of them changed.

**Testing.** All nine compiled. After rebuilding, replaying the attack still crashed
for every candidate, so none reached the functionality test (libxml2's own test suite,
`make check`).

**Result: not fixed.** Every candidate fixed the wrong place or only part of the problem.

**Compared with the paper.** This matches the paper's own description of this bug. The
paper also reports GPT-4o failing on it in Table 3 and rates its patch "incorrect" on
manual review in Table 1. It names the same failure types: guarding the wrong buffer,
and fixing only one of the places that need fixing.

---

## 2. CVE-2017-5969: libxml2 XML reader (VulnLoc)

**Background.** Same library, different feature. XML files can contain a DTD, a set of
rules such as "a `<book>` must contain a `<title>` followed by an `<author>`". The command-line
tool `xmllint` can read a file and print it back out, rules included.

**The vulnerability.** A rule like `(a, b)` is stored as a pair with two halves, "a"
and "b". In "recovery mode", where the tool keeps going after errors, a *broken* rule
can be stored with one half missing (NULL). Later, when the tool prints the rules
back out, the printing code assumes both halves always exist and reads the missing
one, which crashes.

**The attack input.** A small XML file whose rules include broken ones, for example
`<!ELEMENT child4 (a, (b|cp+, (a|d)?, (e|f)* )?>`, which is missing a closing
bracket. It is run with `xmllint --recover`.

**The real fix (by the libxml2 developers).** In the printing function
(`xmlDumpElementContent` in `valid.c`), check that each half exists before using it.

### First run (before the environment fix): false success

The first nine candidates failed to compile: the AI rewrote a whole block of code and
damaged its structure, removing an `#endif` line and sticking another one onto a line
of code. The tenth candidate compiled, but it added checks in the wrong place, one level
up (`xmlDumpElementDecl`), where nothing is missing. The attack replay happened to hit a
random freeze (see [Environment issue](#environment-issue-random-hangs)), so it was
wrongly recorded as fixed. Replaying the attack by hand against that patch still
crashed at the same spot. We count this run as **not fixed**.

### Rerun (after the environment fix): fixed

**What the AI proposed.** It put NULL checks exactly where the developer did. In both
places where the printing code handles a pair, it now only uses each half if that half
exists:

```c
if (content->c1 != NULL) { ...print the first half and the separator... }
if (content->c2 != NULL) { ...print the second half... }
```

**Why this fixes it.** The crash came from reading a half that wasn't there. Now a
missing half is skipped, and the rest of the rule is printed normally. One small
difference from the developer's version: when the first half is missing, the AI's
version also leaves out the separator (`,` or `|`) next to it. That only changes how a
broken rule is printed back out, not whether the program is safe.

**Testing.**

- **Rebuild:** passed.
- **Replay the attack:** passed, for real. The program finished in under a second. It
  printed libxml2's normal warning about the broken rule, then printed the document
  back out, with no crash report.
- **Functionality test:** libxml2's own test suite (`make check`) passed.

**Result: fixed.** The patch is in the same place as the developer's fix and does the
same thing.

**Compared with the paper.** Matches. The paper reports this bug as fixed, with a patch
matching the developer's.

---

## 3. CVE-2017-7595: libtiff image tool (VulnLoc)

**Background.** libtiff is a widely used library for TIFF image files. `tiffcp` is its
command-line tool for copying and converting TIFF images. In the paper this bug was
fixed by every configuration and by all six AI models tested, so it was a good
"should succeed" check.

**The vulnerability.** Some images store colour at lower detail than brightness, to
save space. Two numbers in the file, the "sampling factors", say by how much (for
example 2 means "one colour value per 2 pixels"). When the image uses JPEG compression,
libtiff checks that the image's tile size divides evenly by these numbers. If the file
sets a sampling factor to **0**, that check divides by zero and the program crashes
(`tif_jpeg.c:1687`).

**The attack input.** A small, deliberately malformed TIFF file (`1.tif`) whose
sampling factor is 0, copied with `tiffcp -i 1.tif out`. The sanitizer report:
"FPE" (arithmetic error) in `JPEGSetupEncode`.

**The real fix (by the libtiff developers).** Right after reading the sampling factors,
reject the file with an error if either one is 0.

**What the AI proposed.** Right before the division, reject the file if either
sampling factor is not greater than 0:

```c
if (sp->v_sampling <= 0 || sp->h_sampling <= 0) {
    TIFFErrorExt(..., "Invalid sampling factors: must be greater than zero.");
    return (0);
}
```

It also re-indented the code block below, which changes the patch's appearance but not
what the code does.

**Why this fixes it.** The division can no longer happen with a zero. A bad file is
rejected with a clear error message instead of crashing the program. It is the same
idea as the developer's fix, placed a few lines later in the same function.

**Testing.**

- **Rebuild:** passed.
- **Replay the attack:** passed, for real. The program finished instantly, printing
  libtiff's normal warnings about the malformed file and no crash report.
- **Functionality test:** libtiff's own test suite ran against the patched code, and
  **all 81 tests passed**.

**Result: fixed.** The first candidate passed everything.

**Compared with the paper.** Matches. The paper reports this bug as fixed with a patch
matching the developer's.

---

## 4. NOFIX-2024-009: Bento4 MP4 tool (San2Vuln)

**Background.** Bento4 is a toolkit for MP4 video files, and `mp4edit` is one of its
command-line tools. This bug comes from the authors' new dataset and had no official
fix when the paper was written, so there is no "correct answer" to compare against.

**The vulnerability.** An MP4 file is a sequence of labelled boxes. One label, `sidx`,
marks an index box. The tool can only handle one index, so if it counts more than one
it tries to remove the index it saved. But it only saves a box if the box really is
a valid index. If the boxes are labelled `sidx` but aren't valid, the count says "2"
while the saved index is still empty (NULL). The tool then tries to remove "nothing"
and crashes (`Ap4Atom.cpp:567`, called from `Ap4Processor.cpp:490`).

**The attack input.** A 13,897-byte MP4 file with two boxes falsely labelled `sidx`.
One is really the file's header box with its label changed, and the other is too small
to be a real index.

**What the AI proposed.** One line at the start of the remove function: if asked to
remove nothing (NULL), return the existing "invalid parameter" error instead of
continuing:

```cpp
if (child == NULL) return AP4_ERROR_INVALID_PARAMETERS;
```

**Why this fixes it.** The crash happened because the function used a NULL pointer
without checking. Now it refuses politely, and the calling code carries on. This also
protects any other code that might call it with NULL. A more targeted alternative would
be to check in the caller before trying to remove the index. Either is reasonable.

**Testing.**

- **Rebuild:** passed.
- **Replay the attack:** passed for real. The program finished in under a second with
  normal output and no crash report. (This run was before the environment fix, but a
  freeze would have taken 10 seconds and printed nothing, so this was not one.)
- **Functionality test:** Bento4 has **no tests** in this dataset (the test script just
  reports success), so this step proves nothing either way.

**Result: fixed.** Judged by replaying the attack and reading the code, since there are
no functionality tests.

**Compared with the paper.** Matches. The paper reports this bug as fixed on the first
attempt (about $0.21, about 3 minutes), with a correct alternative patch. Ours was also
fixed on the first attempt, in about 1 minute.

---

## Takeaways

- **Reproduction:** all four results match the paper. Three real successes, one from
  San2Vuln (NOFIX-2024-009) and two from VulnLoc (CVE-2017-5969, CVE-2017-7595), plus one
  failure the paper also reports (CVE-2016-1839).
- **Check the environment first.** On newer kernels, run
  `sudo sysctl vm.mmap_rnd_bits=28` before any experiment. Otherwise attacks can
  freeze at random and be counted as "fixed".
- **The automated checks are weaker than they look:**
  - **The attack replay** counts a freeze as "fixed", because it only looks for a
    crash report. A safer check would treat timeouts and empty output as failures and
    replay the attack several times.
  - **The functionality tests** are missing for 16 of the 66 bugs (all of Bento4, plus
    zziplib, jasper, libarchive and one coreutils bug). For the rest, they are only as
    good as each project's existing tests.
- **Results vary between runs.** The same bug can fail on one attempt and succeed on
  the next. The paper allowed up to 5 attempts per bug.
- **The AI's typical mistakes match the paper's failure analysis (Section 5.2):**
  - guarding the wrong buffer
  - using made-up size limits
  - fixing only one of several places that need fixing
  - damaging code structure so it no longer compiles
