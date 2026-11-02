# Maintaining the README translations

[The English README](../README.md) is the canonical source. The localized READMEs
translate its explanations and navigation. Code, commands, recorded CLI output,
Mermaid diagrams and BibTeX remain identical to the English fenced blocks.

The first set covers Russian (`ru`), Simplified Chinese (`zh-CN`), Spanish (`es`),
Brazilian Portuguese (`pt-BR`), Japanese (`ja`), German (`de`), French (`fr`),
Korean (`ko`) and Arabic (`ar`), alongside English.

When changing the English README:

1. Update the corresponding explanations in every translation. Preserve the
   distinction between measured facts, inferred types and limitations.
2. Copy changed fenced blocks directly from English. Keep addresses, command
   flags, versions, real stdout, benchmark values and citation metadata intact.
3. Update the `translation-source` comment to the English commit reviewed and
   update the localized source link. A source marker records a review snapshot;
   it does not mean later English edits were automatically translated.
4. Keep the language selector links absolute so they work from both GitHub and
   crates.io. Keep explicit navigation anchors stable; relative file and image
   links resolve from this directory, one level below the repository root.
5. Run the focused documentation checks:

   ```sh
   python3 scripts/check-readme-translations.py
   bash scripts/check-public-hygiene.sh
   ```

The checker catches changed examples, missing sections, missing language links
and broken local links. It does not judge translation quality. Review the prose
for natural phrasing and technical accuracy before opening a pull request.

For Arabic, preserve readable right-to-left prose and left-to-right code, paths
and identifiers. Use HTML direction attributes when needed, without changing
the contents of fenced blocks.

New languages are welcome. Add a complete `README.<locale>.md`, include it in
the selector in English and every translation, and update `LOCALES` in
[the checker](../scripts/check-readme-translations.py).
