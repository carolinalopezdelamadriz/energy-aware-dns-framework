# Archived / local experiment runs

This folder is for local-only experiment outputs that should not be committed to git.

New batch runs are written to `results/<YYYYMMDD_HHMMSS>/` by default. The reference
sample run tracked in version control is:

- `results/run_20260626/` — 5-site validation (DNS, DoH, DoQ + web profiling)

PCAP files are ignored globally (see root `.gitignore`) because they are large.
CSV summaries, JSON profiles and analysis figures from the sample run are kept
in the repository for reproducibility and thesis figures.
