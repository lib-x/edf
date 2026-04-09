package edf

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lib-x/edf/internal/irisdb"
)

var (
	ErrNotEDF                  = irisdb.ErrNotEDF
	ErrTableNotFound           = irisdb.ErrTableNotFound
	ErrRecordLayoutUnavailable = irisdb.ErrRecordLayoutUnavailable
)

type Database struct {
	file *irisdb.File
}

type Table struct {
	Name         string
	HeaderOffset int64
	RecordCount  int
	RecordRoot   int64
	PageRoot     int64
	Queryable    bool
	Decodable    bool
	Layout       *Layout
	Fields       []Field
	Indexes      []Index
}

type Field struct {
	Name       string
	TypeCode   uint16
	RawWidth   int
	SlotOffset int
}

type Index struct {
	Name string
}

type Layout struct {
	RecordCount int
	RecordRoot  int64
	Stride      int
	BitmapSize  int
	FieldCount  int
}

type RawRow struct {
	Sequence int
	Bitmap   []byte
	Values   [][]byte
}

type DecodedRow struct {
	Sequence int
	Bitmap   []byte
	Values   map[string]DecodedValue
}

type AttachmentSchema struct {
	MetaTable    Table
	ContentTable Table
}

type AttachmentPayloadInfo struct {
	Filename    string
	ContentType string
	Extension   string
}

type SyncRecord struct {
	ItemID      string
	UpdateCount int32
	Modified    bool
	Deleted     bool
}

type DecodedKind = irisdb.DecodedKind

const (
	DecodedRaw      = irisdb.DecodedRaw
	DecodedString   = irisdb.DecodedString
	DecodedBool     = irisdb.DecodedBool
	DecodedInt32    = irisdb.DecodedInt32
	DecodedDate     = irisdb.DecodedDate
	DecodedTime     = irisdb.DecodedTime
	DecodedDateTime = irisdb.DecodedDateTime
	DecodedExternal = irisdb.DecodedExternal
)

type BlobRef = irisdb.BlobRef

type DecodedValue = irisdb.DecodedValue

// Open opens an `.edf` file as a read-only eDiary database.
func Open(path string) (*Database, error) {
	file, err := irisdb.Open(path)
	if err != nil {
		return nil, err
	}

	return &Database{file: file}, nil
}

// Path returns the underlying file path.
func (db *Database) Path() string {
	return db.file.Path()
}

// Tables returns the parsed table metadata.
func (db *Database) Tables() []Table {
	source := db.file.Tables()
	out := make([]Table, 0, len(source))
	for _, table := range source {
		out = append(out, convertTable(table))
	}
	return out
}

// Table returns metadata for a table by name.
func (db *Database) Table(name string) (Table, bool) {
	table, ok := db.file.Table(name)
	if !ok {
		return Table{}, false
	}
	return convertTable(table), true
}

// AttachmentSchema returns the attachment-related table metadata when available.
func (db *Database) AttachmentSchema() (AttachmentSchema, bool) {
	meta, ok := db.Table("AttachMeta")
	if !ok {
		return AttachmentSchema{}, false
	}
	content, ok := db.Table("AttachContent")
	if !ok {
		return AttachmentSchema{}, false
	}
	return AttachmentSchema{
		MetaTable:    meta,
		ContentTable: content,
	}, true
}

// ReadRawRows reads raw record slots for a queryable table.
func (db *Database) ReadRawRows(tableName string, limit, offset int) ([]RawRow, error) {
	rows, err := db.file.ReadRawRows(tableName, limit, offset)
	if err != nil {
		if errors.Is(err, irisdb.ErrTableNotFound) || errors.Is(err, irisdb.ErrRecordLayoutUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("read raw rows for %s: %w", tableName, err)
	}

	out := make([]RawRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, RawRow{
			Sequence: row.Sequence,
			Bitmap:   row.Bitmap,
			Values:   row.Values,
		})
	}
	return out, nil
}

// ReadDecodedRows reads rows and decodes any fields that are currently understood.
func (db *Database) ReadDecodedRows(tableName string, limit, offset int) ([]DecodedRow, error) {
	table, ok := db.Table(tableName)
	if !ok {
		return nil, ErrTableNotFound
	}

	rawRows, err := db.ReadRawRows(tableName, limit, offset)
	if err != nil {
		return nil, err
	}

	out := make([]DecodedRow, 0, len(rawRows))
	for _, raw := range rawRows {
		values := make(map[string]DecodedValue, len(table.Fields))
		for idx, field := range table.Fields {
			decoded, err := db.DecodeValue(tableName, field.Name, raw.Values[idx])
			if err != nil {
				return nil, fmt.Errorf("decode %s.%s: %w", tableName, field.Name, err)
			}
			values[field.Name] = decoded
		}
		out = append(out, DecodedRow{
			Sequence: raw.Sequence,
			Bitmap:   raw.Bitmap,
			Values:   values,
		})
	}

	return out, nil
}

// ReadRawAttachmentMetaRows reads raw attachment metadata rows.
func (db *Database) ReadRawAttachmentMetaRows(limit, offset int) ([]RawRow, error) {
	return db.ReadRawRows("AttachMeta", limit, offset)
}

// ReadRawAttachmentContentRows reads raw attachment content rows.
func (db *Database) ReadRawAttachmentContentRows(limit, offset int) ([]RawRow, error) {
	return db.ReadRawRows("AttachContent", limit, offset)
}

// DecodeValue decodes one raw field value when a decoder is currently known.
func (db *Database) DecodeValue(tableName, fieldName string, raw []byte) (DecodedValue, error) {
	return db.file.DecodeValue(tableName, fieldName, raw)
}

// InferAttachmentFilename normalizes an attachment filename using the current
// name, payload magic, and a fallback identifier.
func InferAttachmentFilename(currentName string, payload []byte, fallback string) string {
	base := normalizeAttachmentFilename(currentName, fallback)
	if len(payload) == 0 {
		return base
	}

	kind := classifyAttachmentPayload(payload)
	if kind.extension != "" {
		lower := strings.ToLower(base)
		switch kind.extension {
		case ".gz":
			if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".gz") {
				return base
			}
		case ".docx", ".xlsx", ".pptx", ".jar", ".apk":
			if strings.HasSuffix(lower, kind.extension) {
				return base
			}
		default:
			if strings.HasSuffix(lower, kind.extension) {
				return base
			}
		}
		return replaceAttachmentExt(base, kind.extension)
	}

	return base
}

// InferAttachmentContentType classifies the payload bytes into a stable content
// type that can be reused by higher-level SDK code.
func InferAttachmentContentType(payload []byte) string {
	return classifyAttachmentPayload(payload).contentType
}

// InspectAttachmentPayload returns the stable filename/content-type inference for
// an attachment payload based on the current recovered name and payload bytes.
func InspectAttachmentPayload(currentName string, payload []byte, fallback string) AttachmentPayloadInfo {
	kind := classifyAttachmentPayload(payload)
	return AttachmentPayloadInfo{
		Filename:    InferAttachmentFilename(currentName, payload, fallback),
		ContentType: kind.contentType,
		Extension:   kind.extension,
	}
}

// ParseSyncRecord converts a decoded Sync table row into a stable semantic record.
func ParseSyncRecord(values map[string]DecodedValue) (SyncRecord, error) {
	var record SyncRecord

	itemID, ok := values["ItemId"]
	if !ok {
		return SyncRecord{}, fmt.Errorf("missing Sync.ItemId")
	}
	if itemID.Kind != DecodedString || itemID.String == "" {
		return SyncRecord{}, fmt.Errorf("unexpected Sync.ItemId kind=%s", itemID.Kind)
	}
	record.ItemID = itemID.String

	updateCount, ok := values["UpdateCount"]
	if !ok {
		return SyncRecord{}, fmt.Errorf("missing Sync.UpdateCount")
	}
	if updateCount.Kind != DecodedInt32 {
		return SyncRecord{}, fmt.Errorf("unexpected Sync.UpdateCount kind=%s", updateCount.Kind)
	}
	record.UpdateCount = updateCount.Int32

	modified, ok := values["Modified"]
	if !ok {
		return SyncRecord{}, fmt.Errorf("missing Sync.Modified")
	}
	if modified.Kind != DecodedBool {
		return SyncRecord{}, fmt.Errorf("unexpected Sync.Modified kind=%s", modified.Kind)
	}
	record.Modified = modified.Bool

	deleted, ok := values["Deleted"]
	if !ok {
		return SyncRecord{}, fmt.Errorf("missing Sync.Deleted")
	}
	if deleted.Kind != DecodedBool {
		return SyncRecord{}, fmt.Errorf("unexpected Sync.Deleted kind=%s", deleted.Kind)
	}
	record.Deleted = deleted.Bool

	return record, nil
}

func convertTable(table *irisdb.Table) Table {
	fields := make([]Field, 0, len(table.Fields))
	for _, field := range table.Fields {
		fields = append(fields, Field{
			Name:       field.Name,
			TypeCode:   field.TypeCode,
			RawWidth:   field.RawWidth,
			SlotOffset: field.SlotOffset,
		})
	}

	indexes := make([]Index, 0, len(table.Indexes))
	for _, index := range table.Indexes {
		indexes = append(indexes, Index{Name: index.Name})
	}

	var layout *Layout
	if table.Layout != nil {
		layout = &Layout{
			RecordCount: table.Layout.RecordCount,
			RecordRoot:  table.Layout.RecordRoot,
			Stride:      table.Layout.Stride,
			BitmapSize:  table.Layout.BitmapSize,
			FieldCount:  table.Layout.FieldCount,
		}
	}

	return Table{
		Name:         table.Name,
		HeaderOffset: table.HeaderOffset,
		RecordCount:  table.RecordCount,
		RecordRoot:   table.RecordRoot,
		PageRoot:     table.PageRoot,
		Queryable:    table.Layout != nil,
		Decodable:    table.Decodable,
		Layout:       layout,
		Fields:       fields,
		Indexes:      indexes,
	}
}

func normalizeAttachmentFilename(currentName string, fallback string) string {
	source := strings.TrimSpace(currentName)
	if source == "" {
		source = fallback
	}
	if strings.TrimSpace(source) == "" {
		source = "attachment.bin"
	}

	source = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', 0:
			return -1
		default:
			if r < 32 {
				return -1
			}
			return r
		}
	}, source)
	source = strings.TrimSpace(source)
	source = strings.Trim(source, ".")
	if source == "" {
		source = fallback
	}
	if strings.TrimSpace(source) == "" {
		source = "attachment.bin"
	}
	return source
}

func replaceAttachmentExt(name string, ext string) string {
	base := name
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		base = name[:dot]
	}
	if base == "" {
		base = "attachment"
	}
	return base + ext
}

func attachmentZipMemberBlob(payload []byte) []byte {
	reader, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return payload[:min(len(payload), 4096)]
	}

	var buf bytes.Buffer
	for _, file := range reader.File {
		name := filepath.ToSlash(file.Name)
		if name == "" {
			continue
		}
		if buf.Len() > 0 {
			_, _ = buf.WriteString("\n")
		}
		_, _ = buf.WriteString(name)
		if buf.Len() >= 4096 {
			break
		}
	}
	return buf.Bytes()
}

type attachmentPayloadKind struct {
	extension   string
	contentType string
}

func classifyAttachmentPayload(payload []byte) attachmentPayloadKind {
	if bytes.HasPrefix(payload, []byte("7z\xbc\xaf\x27\x1c")) {
		return attachmentPayloadKind{extension: ".7z", contentType: "application/x-7z-compressed"}
	}
	if bytes.HasPrefix(payload, []byte("Rar!")) {
		return attachmentPayloadKind{extension: ".rar", contentType: "application/vnd.rar"}
	}
	if bytes.HasPrefix(payload, []byte{0x1f, 0x8b}) {
		return attachmentPayloadKind{extension: ".gz", contentType: "application/gzip"}
	}
	if bytes.HasPrefix(payload, []byte("%PDF-")) {
		return attachmentPayloadKind{extension: ".pdf", contentType: "application/pdf"}
	}
	if bytes.HasPrefix(payload, []byte("PK\x03\x04")) {
		memberBlob := attachmentZipMemberBlob(payload)
		if bytes.Contains(memberBlob, []byte("word/")) {
			return attachmentPayloadKind{
				extension:   ".docx",
				contentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			}
		}
		if bytes.Contains(memberBlob, []byte("xl/")) {
			return attachmentPayloadKind{
				extension:   ".xlsx",
				contentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
			}
		}
		if bytes.Contains(memberBlob, []byte("ppt/")) {
			return attachmentPayloadKind{
				extension:   ".pptx",
				contentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
			}
		}
		return attachmentPayloadKind{extension: ".zip", contentType: "application/zip"}
	}

	printable := 0
	limit := min(len(payload), 256)
	for _, b := range payload[:limit] {
		if b == 9 || b == 10 || b == 13 || (32 <= b && b < 127) {
			printable++
		}
	}
	if limit > 0 && printable*100/max(1, limit) >= 85 {
		return attachmentPayloadKind{extension: ".txt", contentType: "text/plain"}
	}
	return attachmentPayloadKind{}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
