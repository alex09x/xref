# Social preview card

The 1280×640 image GitHub, X, LinkedIn and chat apps show for xrefcode.com and the
repository (`docs/og-vX.Y.Z.png`, copied to `docs/og.png`). It is rendered from HTML, never
drawn by an image model: every character on it must be true and readable.

## What the card says

Left side: the logo, the version, at most two "new" pills, a headline that starts with `$`, one
subline, the site and the one-line installer. Right side: a terminal with **real recorded
output** of the release's most interesting command.

The terminal is never typed by hand. `scripts/social_card/render.py` reads it from the
command reference: the first `$ xref …` command of the named example in
`docs/cli/<page>.md` and the output recorded under it, cut to 20 rows of 64 columns with an
explicit "… N more lines". Those pages are re-recorded at every release (step 2 below), so the
card always shows the newest log of the newest build.

## Brief for whoever writes the spec

Give this to the person or agent choosing the content:

> Pick the one change in this release a reverse engineer would want to try first. Find, or
> record, an example of it in `docs/cli/*.md` whose first 15–20 output lines are understandable
> on their own (an ordered trace, a ranked writer, a field layout; not a wall of hex). Write a
> headline of at most 48 characters that says what the user gets, in the user's words, not the
> feature name ("See what a thread calls, in order", not "Live trace v1"). Write one subline of
> at most 120 characters that states the scope honestly (platform, stripped or not, what is
> heuristic). Use at most two "new" pills, named after commands or options that exist in this
> version. Do not claim speed, accuracy or adoption the release notes do not support.
> If no recorded example shows the change well, add one to the reference page and record it
> first; never paste output into the spec.

## Spec

`scripts/social_card/specs/<version>.json`:

```json
{
  "version": "0.5.0",
  "new": ["live trace", "per-command reference"],
  "headline": "See what a thread calls, in order",
  "subline": "Ordered per-thread call windows from a running stripped binary, with static addresses.",
  "page": "live-trace",
  "example": "What one call of a hot function does",
  "keep": "optional regex: show only matching output lines"
}
```

## Release steps

1. Write the spec (brief above).
2. Re-record the reference with the release build from the neutral input directory, so the log
   is current and has no private paths:
   `python3 scripts/cli_reference/record.py --xref <release xref> --inputs /srv/xref-docs --pid <live target>`.
3. Render: `python3 scripts/social_card/render.py scripts/social_card/specs/<version>.json --out docs/og-v<version>.png`
   (macOS Chrome path by default; `--chrome` or `CHROME=` elsewhere). Copy it to `docs/og.png`.
4. Point `og:image` / `twitter:image` in `docs/index.html` at the new file. Keep older
   `og-v*.png` files: posts already shared reference them.
5. Look at the PNG at full size and at 600×300 (how X shows it). Check:
   - every line is legible and nothing is clipped except the marked cut;
   - the command and output appear verbatim in `docs/cli/<page>.md`;
   - the version pill equals `Cargo.toml`;
   - no home paths, hostnames or private binaries (the renderer refuses `/home/`, `/Users/`, `/root/`).
6. `bash scripts/check-public-hygiene.sh`; it runs `scripts/check_versions.py`, which fails while
   `og:image` names an older version or the referenced PNG is missing.

The renderer refuses a spec with a headline over 48 characters, a subline over 120, more than
two pills, an unknown example, or a recorded example containing a private path.
