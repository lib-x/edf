# edf

Go module for read-only exploration of eDiary/IrisDB `.edf` files.

Status:
- container/schema parsing
- raw row iteration
- password-assisted decoded row iteration for encrypted eDiary payloads
- read-only `database/sql` driver
- stable attachment payload naming/content-type helpers
- stable `Sync` semantic parsing helper
- field-aware UTF-8/UTF-16 external text decoding
- article keyword and tag-ID-list metadata

Client artifact observations, verified format details, and remaining parsing
limits are documented in [docs/reverse-engineering.md](docs/reverse-engineering.md).

This repository intentionally excludes private EDF files, passwords, and local machine paths.

```go
db, err := edf.OpenWithPassword("notes.edf", []byte(password))
if err != nil {
	return err
}
if !db.PasswordVerified() {
	// The file still opens for structural exploration, but this password did
	// not match the known EDF header validation block.
	// Decrypted row/content recovery should not be considered reliable.
}
_ = db.PasswordSupplied()
rows, err := db.ReadDecodedRows("Document", 0, 0)

articles, err := db.ReadArticles()
attachments, err := db.ReadAttachments(0, 0)
tags, err := db.ReadTags()
summaries, err := db.DecodeSummaries()
```

`ArticleRecord.Keywords` and `ArticleRecord.TagIDList` expose the decoded
`Keywords` and `TagIdList` fields without guessing a multi-tag separator.
`ReadTags` provides available tag definitions; a tag ID can be dangling. Raw decoded content
bytes remain available alongside best-effort text. Markdown text extraction
recognizes the observed SDP v1 single-`Text` layout and respects its declared
byte length; unsupported layouts retain their bytes without speculative text.

Passwords can also be read from a local text file:

```go
db, err := edf.OpenWithPasswordFile("notes.edf", "/path/to/password")
```

The `database/sql` driver accepts explicit password options in the data source
name:

```go
db, err := sql.Open("edfsql", "notes.edf?password_file=/path/to/password")
db, err := sql.Open("edfsql", "notes.edf?password_env=EDF_PASSWORD")
```

SQL metadata tables include `__database`, `__tables`, `__columns`,
`__indexes`, and `__layouts`. For example:

```sql
select password_supplied, password_verified from __database;
```
