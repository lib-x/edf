# eDiary client artifact investigation

Investigation date: 2026-10-12. This is a bounded static-format investigation,
not a claim of complete client decompilation or full EDF format support.

## Targets and provenance

Targets came from the official eDiary download page:

- `https://ediary.haoxg.net/download.php`
- Windows: `ediary-4.4.3-win32-portable.zip`
- Linux: `ediary_1.0~beta2-2_amd64.deb`

The artifacts were downloaded from the download URLs on that page. Format
findings use the official public samples. Neither application was executed. Client executables,
sample databases, and complete resource dumps are not included in this repository.

REA 6.4.0 supplied these canonical static observations:

| Operation | Evidence ID |
| --- | --- |
| Windows archive inventory | `ev_ca378c6dca874063afa0c44b2e5fd8c349418f9d226c46b0cd66b68cd5905dfa` |
| Windows archive extraction | `ev_91a9b5b761e5e981f3ba75cbed4ea59ad9cd384156a8c05a4210300b857ea02b` |
| Windows PE resource inventory | `ev_8520f160b5acbeb4d77447c9769bc78c99578d8e890db808e1f4971a344da442` |

These IDs identify REA output records, not online lookup endpoints. REA inventoried
431 PE resources with complete resource-table coverage. Resource payloads other
than icon groups remain opaque to that operation: interpretations below come
from separate byte inspection and the EDF parser, not REA decompiler output.

SHA-256 identities:

| Artifact | SHA-256 |
| --- | --- |
| Windows portable ZIP | `09d68dffa627bdd9373040febe4afe589ed14cab0f5b9f71df48e4ba6b06727f` |
| Windows `eDiary.exe` | `9e058138bbe309e05f7ef3c9dc069fbd4615ba2f3552ea6171309230c5379b01` |
| Windows `DATA/SAMPLEFILE` | `a04bc16a1602cec1058521f7707883e6a09a9e527d3d38afe933b38b94a65849` |
| Linux executable | `00d79b0714cc8db28a2d7c048bf222f512819e10be89ef4a73637c8916557574` |
| Linux `resources/res/sample.edf` | `6899671c89987516c55c10cb0ff0e2fe4b0ede52a5fed8b08df86f81eae69686` |

The Windows resource inventory identifies `DATA/SAMPLEFILE` at executable file
offset 16,355,060 with length 245,500 bytes. That resource begins directly with
the IrisDB signature; no additional resource-container decompression is needed.
The Linux sample is a separate packaged file. These offsets apply only to the
exact Windows executable hash above.

## Observations and implemented corrections

Both public samples begin with `IrisDB\0` and declare IrisDB 1.4 / eDiary 4.2 in
their file headers. Both contain 19 tables. The Windows sample has four Diary
rows, one Document row, three DiaryTag rows, four DoubleChain rows, three Config
rows, two Registry rows, and four Sync rows. The Linux sample has the same row
counts in those tables except Sync, which is empty. These are sample contents,
not proof that every database uses the same counts, tables, or row layout.

### External text encoding

The samples distinguish UTF-16LE wide-memo fields (`0x0027`, including Title and
Registry.Value) from memo/blob payloads containing readable ASCII or UTF-8.
Windows `TagIdList` (`0x0010`) contains ASCII tag IDs. Config.Data (`0x000f`)
includes the literal ASCII payload `DiaryFirstLocation=3`.

Previously the generic decoder tried a permissive UTF-16 interpretation before
ASCII. Even-length IDs and configuration text became unrelated CJK characters.
The decoder now uses the wide-memo field type explicitly and prefers readable,
NUL-free UTF-8 for generic text before applying UTF-16 heuristics. Short Chinese
wide-memo values no longer depend on a minimum human-text score. Odd-length
wide-memo payloads retain their bytes without claiming decoded text.

`ArticleRecord` now exposes Keywords and TagIDList. The original tag-ID-list
string is preserved because a multi-tag delimiter was not established by these
samples; no unsupported splitting rule is introduced.

The Windows sample's article tag IDs do not match its three DiaryTag definitions,
and its DocumentTag table is empty. This is an observed dangling-reference
condition, not permission to rewrite or infer tag identities. The parser retains
both the article strings and the available tag-definition rows unchanged.

### Markdown SDP text

The Windows sample's Markdown article inflates to 8,192 bytes. Its observed
32-byte header is:

```text
53445000 00000001 00000001 00000004 54657874 00000000 00000291 00000291
```

It contains the signature `SDP\0`, version 1, one entry, a four-byte `Text`
name, a zero-valued type word, and two matching big-endian length words of 657.
Exactly 657 UTF-8 text bytes follow; the rest of the inflated allocation is zero
padding. The meanings of unequal length words and other entry types remain
unestablished.

Text extraction now supports this observed single-Text layout explicitly and
uses its declared length rather than treating all bytes after offset 32 as text.
Truncated data, mismatched lengths, unsupported versions/types, and multiple
entries produce no speculative text; the decoded binary payload stays available.

## Verification

Regression tests use generated compressed payloads rather than copied diary
files. They cover ASCII tag IDs, ASCII configuration, UTF-8 memo text, short
Chinese wide memos, UTF-16 bytes that resemble ASCII, odd-length wide memos,
SDP length boundaries, unsupported SDP headers, and article metadata mapping.

```sh
go test ./...
go test -race ./...
go vet ./...
EDF_SAMPLE_DIR=/path/to/official-sample-directory go test -run '^TestLocalEDFSamples$' -v .
```

The opt-in local-sample test was run separately against the extracted Windows
sample and the packaged Linux sample. All populated tables listed above were
read successfully by raw and decoded row iteration. No database password was
supplied for these public samples.

## Remaining limits

- Native decompilation was unavailable because no Ghidra or IDA provider was
  configured. The client registration and MCP initialization/tool listing were
  verified independently; this does not establish an active connection in an
  already-running coding-agent session.
- RVF text extraction remains heuristic and does not reconstruct full rich-text
  layout, embedded objects, or every control record.
- Only the observed SDP v1 single-Text variant is recognized; other versions,
  multiple entries, and compressed entry variants remain unsupported.
- Multi-tag serialization, record-page traversal beyond existing layout
  heuristics, unpopulated schemas, and arbitrary fixed-field widths need further
  evidence. The official samples do not prove those paths correct.
- Existing encrypted-record support was exercised by the synthetic regression
  suite. Opt-in tests against local private inputs did not authenticate a header,
  so real encrypted-content recovery remains unverified; skipped password tests
  are not counted as successful verification. Private input names, paths,
  passwords, contents, and diagnostic output are not included in this repository.
