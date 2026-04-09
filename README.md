# edf

Go module for read-only exploration of eDiary/IrisDB `.edf` files.

Status:
- container/schema parsing
- raw row iteration
- read-only `database/sql` driver
- stable attachment payload naming/content-type helpers
- stable `Sync` semantic parsing helper

This repository intentionally excludes private EDF files, passwords, and local machine paths.
