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

### Native encryption investigation

REA 6.4.0 with Ghidra 12.1.4 completed native analysis of the Windows executable
identified above. Focused decompilation established these additional observations:

| Address / operation | Evidence ID |
| --- | --- |
| `0xa2954c`, encryption configuration | `ev_78c329d87d1ab85ffde12bf2047a1406d5f1cbc346488e00223426d5bee64d21` |
| `0x9f14b0`, tail decoding | `ev_c43effbd17cc8069ad859af031d59bc80bdd87ecf79562ca7de2c856202a6678` |
| `0xa29244`, password comparison | `ev_61588bdbcdf967e316d46c208e2f9357bf78c7233d667db06d9052839d56ec7f` |
| `0xa27fb4`, file-info decoding | `ev_2ae71c467c3f166692f796e9e0d26286630e8691710ca9596d55b2a8c7191f8a` |
| `0x9eacc0`, password-lock layout | `ev_728f038ade14214ebec103981dd3d987c697acf32f617a1dd096c38b4e1b3d46` |
| `0x9ed858`, digest formatting | `ev_2fb0225dfb8a7b6f32b2fa1ae7bc3075406a851fec1d9041d669ff42d952a4a1` |
| `0x9ef1e0`, SHA compression | `ev_94a71a56ec631aa81a03ff70bed736105a09767369c452eecb9f227000791743` |

Function-entry/name seeds were supplied before auto-analysis; those names are
investigator assertions. The cited code bodies, not the seed names, support the
format conclusions. Delphi exception handling and register calling conventions
limit pseudocode accuracy; focused byte inspection corroborated field offsets.

- File info starts at `0x907`, with 109 serialized bytes. Password lock starts at
  `0x974`, with 360 serialized bytes. Both use independent empty-key Blowfish
  EMCTS transforms. An all-zero eight-byte Blowfish key produces the same key
  schedule. Both contain a little-endian IEEE CRC-32 of the remaining bytes;
  metadata is used only after that checksum matches.
- File info byte 38 enables encryption, its ShortString at byte 39 names the
  algorithm, and byte 72 selects safe encryption. Standard mode uses the literal
  `!@#$%^&*()` as its data key; safe mode uses the database password. The same
  resolved key must reach both fixed-row and external-blob decoding.
- Password authentication compares a formatted hash, not a zero-filled region
  at `0x80c`. That region can store an original-password ShortString and is not
  a reliable all-zero password validator. The supported password-lock digest is
  a 28-byte Base64 SHA-0 value at bytes 6 through 33. The official public sample's
  digest matches SHA-0 of the empty string; known-answer vectors independently
  distinguish SHA-0 from SHA-1. This is legacy format compatibility, not a
  recommendation to use SHA-0 for new authentication.
- EMCTS initializes feedback with `E_K(ff...ff)`. Full-block plaintext is
  `D_K(ciphertext) XOR feedback`, followed by `feedback XOR ciphertext`.
  Each remaining byte requires a new block encryption of feedback, consumes
  stream byte zero, shifts feedback by one byte, and XORs the ciphertext byte
  into the retained final feedback byte. Reusing a single stream block for all
  tail bytes was incorrect.

Standard-mode decoding does not authenticate a supplied password. Safe-mode
decoding is withheld unless authentication succeeds. Unsupported or corrupt
metadata does not enable speculative raw-password decryption. Automatic Windows
ANSI code-page conversion for non-ASCII passwords remains unsupported.

## Linux native follow-up (2026-10-12)

REA 6.4.0 and Ghidra 12.1.4 also completed focused static analysis of the Linux
executable identified above. The supplied Debian package matches the previously
examined artifact. No client process was launched for this analysis.

| Address / operation | Evidence ID |
| --- | --- |
| `0xd419d0`, whole-record payload decryption | `ev_d64eb2057623e3c95fdb508562d4216a9ae4f21594a255b07246fdcb0d3cc120` |
| `0xd3bcf0`, cipher decode dispatch | `ev_b9b29f549c651e739cb9c761c4f711ada1d4a486cb3e1679a034ac4c388d19ef` |
| `0xd04f90`, typed fields copied from the record buffer | `ev_445e722748900594649acd9cf32329d0b332d79fccf89d4c15184a7a24ba55a2` |
| `0xcff7c0`, database password comparison | `ev_a5d44efad89016e9deb929fff586cfaae045beff683beffa0fe3e9b5a718292d` |
| `0xcee610`, password byte conversion and hash dispatch | `ev_c4245f854bc5a98e9b34e012f29f30c6302b534c5c6a09976efff02159174c64` |
| `0xe71da0`, SDP header reader | `ev_b4dc4a1608cd28ca09c2435e017e5dd926d8703d239f75e2ac1468ed8e43efb6` |
| `0xe6f530`, SDP item-count iteration | `ev_06f10a2abdc694898d1700403a2b41bc8de290b699d829184455ac144fed7a94` |
| `0xe71ef0`, SDP item reader | `ev_f73ea959fd58e0f7458e6ee14c51e7143f649e63b6f72d2f81cd79de4a675ca8` |

The native record reader decrypts the entire field payload after the record
prefix and null bitmap. It does not limit decryption to strings or blob
references, or restart cipher feedback at each field. The parser previously
applied decrypted bytes only to those textual/reference types, leaving integer,
boolean, date, time, and datetime values to be decoded from ciphertext. Every
field now uses its slice of the same decrypted payload. Zero dates/datetimes and
unknown field types retain their decrypted raw bytes rather than falling back
to ciphertext or a speculative per-field transform.

The SDP header's big-endian integer at byte 4 is version 1; the integer at
byte 8 is the item count, not a second version marker. Each item stores a
length-prefixed type string, a length-prefixed name, a declared payload size,
and a length-prefixed payload. The parser now walks every declared item and
extracts the unnamed `Text` body regardless of its position, skipping unrelated
items. It rejects excessive counts, truncated items, inconsistent sizes, and
duplicate bodies instead of returning text from a partially validated package.

The traced Linux database password path still uses Base64 SHA-0. Its separate
application-level SHA-1 helper has not been established as a database-password
derivation step. Bounded offline execution of the native SHA-0 routines matched
synthetic known answers; an anonymous local comparison also found no lock-digest
matches for the supplied password bytes. This does not establish why an official
client can open the same inputs. No heuristic password derivation or authentication
bypass is included in the library.

## Verification

Regression tests use generated compressed payloads rather than copied diary
files. They cover ASCII tag IDs, ASCII configuration, UTF-8 memo text, short
Chinese wide memos, UTF-16 bytes that resemble ASCII, odd-length wide memos,
SDP length boundaries, unsupported SDP headers, and article metadata mapping.
Encryption tests additionally cover independent PyCryptodome ECB-based reference
vectors for every tail size, SHA-0 known answers, CRC rejection, truncated headers,
standard/safe key selection, wrong passwords, and encrypted row/blob recovery.
Whole-row decryption regressions additionally cover both data-key modes and
integer, boolean, date, time, datetime, zero-valued, and unknown fields at a
non-block-aligned field offset.
SDP regressions cover body ordering among multiple items, named metadata,
duplicate bodies, incomplete subsequent items, and oversized length/count fields.

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

- Native decompilation now works through REA and Ghidra. This remains a focused
  investigation of the identified Windows and Linux builds, not complete reverse
  engineering or proof of every client version's encryption behavior.
- RVF text extraction remains heuristic and does not reconstruct full rich-text
  layout, embedded objects, or every control record.
- SDP version 1 packages support an unnamed Text body among multiple entries.
  Other versions and compressed entry variants remain unsupported; non-text
  entries are skipped, not reconstructed.
- Multi-tag serialization, record-page traversal beyond existing layout
  heuristics, unpopulated schemas, and arbitrary fixed-field widths need further
  evidence. The official samples do not prove those paths correct.
- Anonymous local checks recognize 11 encrypted Blowfish databases: eight in
  standard mode and three in safe mode. Standard-mode text/payload decoding
  recovers article content in eight files: 1,044 articles have content bytes,
  867 have extracted content text, and 488 attachments have recovered payloads.
  These counts describe recovery signals, not exhaustive fidelity checks.
  The supplied password did not match any of
  the CRC-checked password-lock digests, so safe-mode content recovery remains
  unverified. Successful structural opening or readable signals are not proof
  that every article or attachment is complete. Opt-in password tests now fail,
  rather than skip, when no sample authenticates. Private input names, paths,
  passwords, hashes, contents, and diagnostic output remain outside the repository.
