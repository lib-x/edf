package edf

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
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

type ArticleRecord struct {
	TableName      string
	Sequence       int
	ID             string
	ParentID       string
	IsFolder       bool
	ArticleFormat  int32
	IconID         int32
	Title          string
	Keywords       string
	TagIDList      string
	Content        []byte
	ContentText    string
	Date           string
	Time           string
	WeatherIconID  string
	WeatherText    string
	ModifyDateTime string
	CreateDateTime string
	WordCount      int32
	SortCode       int32
	Deleted        bool
	Values         map[string]DecodedValue
}

type AttachmentRecord struct {
	Sequence      int
	ID            string
	ContentID     string
	OwnerID       string
	Name          string
	Comment       string
	Payload       []byte
	PayloadText   string
	Info          AttachmentPayloadInfo
	MetaValues    map[string]DecodedValue
	ContentValues map[string]DecodedValue
}

type TagRecord struct {
	TableName    string
	Sequence     int
	ID           string
	Name         string
	SortCode     int32
	IsPreCreated bool
	Values       map[string]DecodedValue
}

type FieldDecodeSummary struct {
	Name           string
	TypeCode       uint16
	Values         int
	Raw            int
	String         int
	Bool           int
	Int32          int
	Int64          int
	Date           int
	Time           int
	DateTime       int
	External       int
	NonEmptyString int
	NonEmptyBytes  int
}

type TableDecodeSummary struct {
	Name           string
	Rows           int
	Fields         []FieldDecodeSummary
	Values         int
	Raw            int
	Decoded        int
	NonEmptyString int
	NonEmptyBytes  int
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
	DecodedInt64    = irisdb.DecodedInt64
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

// OpenWithPassword opens an `.edf` file and enables password-based decoding for
// encrypted row payloads. The password is used exactly as supplied.
func OpenWithPassword(path string, password []byte) (*Database, error) {
	file, err := irisdb.OpenWithPassword(path, password)
	if err != nil {
		return nil, err
	}

	return &Database{file: file}, nil
}

// OpenWithPasswordFile opens an `.edf` file using a password read from a local
// text file. Surrounding whitespace in the password file is ignored.
func OpenWithPasswordFile(path string, passwordPath string) (*Database, error) {
	data, err := os.ReadFile(passwordPath)
	if err != nil {
		return nil, fmt.Errorf("read password file: %w", err)
	}
	password := strings.TrimSpace(string(data))
	if password == "" {
		return nil, fmt.Errorf("password file is empty")
	}
	return OpenWithPassword(path, []byte(password))
}

// Path returns the underlying file path.
func (db *Database) Path() string {
	return db.file.Path()
}

// PasswordVerified reports whether the supplied password matches the known EDF
// header validation block. A false result means either no password was supplied,
// the password did not match, or the file uses an unsupported validation variant.
func (db *Database) PasswordVerified() bool {
	return db.file.PasswordVerified()
}

// PasswordSupplied reports whether this database was opened with a non-empty
// password.
func (db *Database) PasswordSupplied() bool {
	return db.file.PasswordSupplied()
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
	source, err := db.file.ReadDecodedRows(tableName, limit, offset)
	if err != nil {
		if errors.Is(err, irisdb.ErrTableNotFound) || errors.Is(err, irisdb.ErrRecordLayoutUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("read decoded rows for %s: %w", tableName, err)
	}

	out := make([]DecodedRow, 0, len(source))
	for _, row := range source {
		out = append(out, DecodedRow{
			Sequence: row.Sequence,
			Bitmap:   row.Bitmap,
			Values:   row.Values,
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

// DecodeSummaries reports per-table and per-field decoding coverage. It is
// useful for inspecting partially understood EDF files without reading raw rows
// manually.
func (db *Database) DecodeSummaries() ([]TableDecodeSummary, error) {
	tables := db.Tables()
	out := make([]TableDecodeSummary, 0, len(tables))
	for _, table := range tables {
		if !table.Queryable {
			continue
		}
		rows, err := db.ReadDecodedRows(table.Name, 0, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, SummarizeDecodedRows(table, rows))
	}
	return out, nil
}

// SummarizeDecodedRows reports decoding coverage for one table.
func SummarizeDecodedRows(table Table, rows []DecodedRow) TableDecodeSummary {
	summary := TableDecodeSummary{
		Name:   table.Name,
		Rows:   len(rows),
		Fields: make([]FieldDecodeSummary, 0, len(table.Fields)),
	}

	for _, field := range table.Fields {
		fieldSummary := FieldDecodeSummary{
			Name:     field.Name,
			TypeCode: field.TypeCode,
		}
		for _, row := range rows {
			value, ok := row.Values[field.Name]
			if !ok {
				continue
			}
			accumulateFieldDecodeSummary(&fieldSummary, value)
		}
		summary.Values += fieldSummary.Values
		summary.Raw += fieldSummary.Raw
		summary.NonEmptyString += fieldSummary.NonEmptyString
		summary.NonEmptyBytes += fieldSummary.NonEmptyBytes
		summary.Fields = append(summary.Fields, fieldSummary)
	}
	summary.Decoded = summary.Values - summary.Raw
	return summary
}

func accumulateFieldDecodeSummary(summary *FieldDecodeSummary, value DecodedValue) {
	summary.Values++
	if value.String != "" {
		summary.NonEmptyString++
	}
	if len(value.Bytes) > 0 {
		summary.NonEmptyBytes++
	}

	switch value.Kind {
	case DecodedRaw:
		summary.Raw++
	case DecodedString:
		summary.String++
	case DecodedBool:
		summary.Bool++
	case DecodedInt32:
		summary.Int32++
	case DecodedInt64:
		summary.Int64++
	case DecodedDate:
		summary.Date++
	case DecodedTime:
		summary.Time++
	case DecodedDateTime:
		summary.DateTime++
	case DecodedExternal:
		summary.External++
	}
}

// InferAttachmentFilename normalizes an attachment filename using the current
// name, payload magic, and a fallback identifier.
func preserveTextualAttachmentExtension(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".txt") ||
		strings.HasSuffix(strings.ToLower(name), ".csv") ||
		strings.HasSuffix(strings.ToLower(name), ".md") ||
		strings.HasSuffix(strings.ToLower(name), ".json") ||
		strings.HasSuffix(strings.ToLower(name), ".xml") ||
		strings.HasSuffix(strings.ToLower(name), ".ini") ||
		strings.HasSuffix(strings.ToLower(name), ".conf") ||
		strings.HasSuffix(strings.ToLower(name), ".yaml") ||
		strings.HasSuffix(strings.ToLower(name), ".yml") ||
		strings.HasSuffix(strings.ToLower(name), ".log") ||
		strings.HasSuffix(strings.ToLower(name), ".cs") ||
		strings.HasSuffix(strings.ToLower(name), ".go") ||
		strings.HasSuffix(strings.ToLower(name), ".py") ||
		strings.HasSuffix(strings.ToLower(name), ".js") ||
		strings.HasSuffix(strings.ToLower(name), ".ts") ||
		strings.HasSuffix(strings.ToLower(name), ".java") ||
		strings.HasSuffix(strings.ToLower(name), ".kt") ||
		strings.HasSuffix(strings.ToLower(name), ".cpp") ||
		strings.HasSuffix(strings.ToLower(name), ".c") ||
		strings.HasSuffix(strings.ToLower(name), ".h") ||
		strings.HasSuffix(strings.ToLower(name), ".hpp") ||
		strings.HasSuffix(strings.ToLower(name), ".sh") ||
		strings.HasSuffix(strings.ToLower(name), ".bat") ||
		strings.HasSuffix(strings.ToLower(name), ".ps1") ||
		strings.HasSuffix(strings.ToLower(name), ".au3") ||
		strings.HasSuffix(strings.ToLower(name), ".nsi")
}

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
		if kind.extension == ".txt" && preserveTextualAttachmentExtension(base) {
			return base
		}
		return replaceAttachmentExt(base, kind.extension)
	}

	if InferAttachmentContentType(payload) == "text/plain" && preserveTextualAttachmentExtension(base) {
		return base
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

// ParseSyncRows converts decoded Sync rows into stable semantic records.
func ParseSyncRows(rows []DecodedRow) ([]SyncRecord, error) {
	out := make([]SyncRecord, 0, len(rows))
	for _, row := range rows {
		record, err := ParseSyncRecord(row.Values)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

// AttachmentPayloadSummary captures the public, sample-free metadata that can be inferred
// from a recovered attachment name and payload bytes.
type AttachmentPayloadSummary struct {
	CurrentName  string
	FallbackName string
	Info         AttachmentPayloadInfo
}

// SummarizeAttachmentPayload combines attachment naming and content-type inference
// into one stable public helper.
func SummarizeAttachmentPayload(currentName string, payload []byte, fallback string) AttachmentPayloadSummary {
	return AttachmentPayloadSummary{
		CurrentName:  currentName,
		FallbackName: fallback,
		Info:         InspectAttachmentPayload(currentName, payload, fallback),
	}
}

// ReadDocuments decodes rows from the Document table into stable semantic
// article records.
func (db *Database) ReadDocuments(limit, offset int) ([]ArticleRecord, error) {
	rows, err := db.ReadDecodedRows("Document", limit, offset)
	if err != nil {
		return nil, err
	}
	return ParseArticleRows("Document", rows), nil
}

// ReadDiaries decodes rows from the Diary table into stable semantic article
// records.
func (db *Database) ReadDiaries(limit, offset int) ([]ArticleRecord, error) {
	rows, err := db.ReadDecodedRows("Diary", limit, offset)
	if err != nil {
		return nil, err
	}
	return ParseArticleRows("Diary", rows), nil
}

// ReadArticles decodes Diary and Document rows into one article list.
func (db *Database) ReadArticles() ([]ArticleRecord, error) {
	out := make([]ArticleRecord, 0, 128)
	if rows, err := db.ReadDiaries(0, 0); err == nil {
		out = append(out, rows...)
	} else if !errors.Is(err, ErrTableNotFound) && !errors.Is(err, ErrRecordLayoutUnavailable) {
		return nil, err
	}
	if rows, err := db.ReadDocuments(0, 0); err == nil {
		out = append(out, rows...)
	} else if !errors.Is(err, ErrTableNotFound) && !errors.Is(err, ErrRecordLayoutUnavailable) {
		return nil, err
	}
	return out, nil
}

// ParseArticleRows converts decoded Document or Diary rows into semantic
// article records while keeping the original decoded values available.
func ParseArticleRows(tableName string, rows []DecodedRow) []ArticleRecord {
	out := make([]ArticleRecord, 0, len(rows))
	for _, row := range rows {
		values := row.Values
		record := ArticleRecord{
			TableName:      tableName,
			Sequence:       row.Sequence,
			ID:             decodedString(values, "Id"),
			ParentID:       decodedString(values, "ParentId"),
			IsFolder:       decodedBool(values, "IsFolder"),
			ArticleFormat:  decodedInt32(values, "ArticleFormat"),
			IconID:         decodedInt32(values, "IconId"),
			Title:          decodedString(values, "Title"),
			Keywords:       decodedString(values, "Keywords"),
			TagIDList:      decodedString(values, "TagIdList"),
			Content:        decodedBytes(values, "Content"),
			ContentText:    decodedString(values, "Content"),
			Date:           decodedString(values, "Date"),
			Time:           decodedString(values, "Time"),
			WeatherIconID:  decodedString(values, "WeatherIconId"),
			WeatherText:    decodedString(values, "WeatherText"),
			ModifyDateTime: decodedString(values, "ModifyDateTime"),
			CreateDateTime: decodedString(values, "CreateDateTime"),
			WordCount:      decodedInt32(values, "WordCount"),
			SortCode:       decodedInt32(values, "SortCode"),
			Deleted:        decodedBool(values, "Deleted"),
			Values:         values,
		}
		out = append(out, record)
	}
	return out
}

// ReadAttachments joins AttachMeta and AttachContent rows into attachment
// records with decoded payload bytes and filename/content-type inference.
func (db *Database) ReadAttachments(limit, offset int) ([]AttachmentRecord, error) {
	metaRows, err := db.ReadDecodedRows("AttachMeta", limit, offset)
	if err != nil {
		return nil, err
	}
	contentRows, err := db.ReadDecodedRows("AttachContent", 0, 0)
	if err != nil {
		return nil, err
	}
	return ParseAttachmentRows(metaRows, contentRows), nil
}

// ParseAttachmentRows joins decoded AttachMeta and AttachContent rows into
// semantic attachment records.
func ParseAttachmentRows(metaRows, contentRows []DecodedRow) []AttachmentRecord {
	contentByID := make(map[string]DecodedRow, len(contentRows))
	for _, row := range contentRows {
		if id := decodedString(row.Values, "Id"); id != "" {
			contentByID[id] = row
		}
	}

	out := make([]AttachmentRecord, 0, len(metaRows))
	for _, row := range metaRows {
		metaValues := row.Values
		record := AttachmentRecord{
			Sequence:   row.Sequence,
			ID:         decodedString(metaValues, "Id"),
			ContentID:  decodedString(metaValues, "ContentId"),
			OwnerID:    decodedString(metaValues, "OwnerId"),
			Name:       decodedString(metaValues, "Name"),
			Comment:    decodedString(metaValues, "Comment"),
			MetaValues: metaValues,
		}

		if contentRow, ok := contentByID[record.ContentID]; ok {
			record.ContentValues = contentRow.Values
			record.Payload = decodedBytes(contentRow.Values, "Content")
			record.PayloadText = decodedString(contentRow.Values, "Content")
		}

		fallback := record.ContentID
		if fallback == "" {
			fallback = record.ID
		}
		if fallback == "" {
			fallback = fmt.Sprintf("attachment-%d.bin", record.Sequence)
		} else if !strings.Contains(filepath.Base(fallback), ".") {
			fallback += ".bin"
		}
		record.Info = InspectAttachmentPayload(record.Name, record.Payload, fallback)
		out = append(out, record)
	}
	return out
}

// ReadDiaryTags decodes rows from the DiaryTag table into semantic tag records.
func (db *Database) ReadDiaryTags(limit, offset int) ([]TagRecord, error) {
	rows, err := db.ReadDecodedRows("DiaryTag", limit, offset)
	if err != nil {
		return nil, err
	}
	return ParseTagRows("DiaryTag", rows), nil
}

// ReadDocumentTags decodes rows from the DocumentTag table into semantic tag
// records.
func (db *Database) ReadDocumentTags(limit, offset int) ([]TagRecord, error) {
	rows, err := db.ReadDecodedRows("DocumentTag", limit, offset)
	if err != nil {
		return nil, err
	}
	return ParseTagRows("DocumentTag", rows), nil
}

// ReadTags decodes DiaryTag and DocumentTag rows into one tag list.
func (db *Database) ReadTags() ([]TagRecord, error) {
	out := make([]TagRecord, 0, 16)
	if rows, err := db.ReadDiaryTags(0, 0); err == nil {
		out = append(out, rows...)
	} else if !errors.Is(err, ErrTableNotFound) && !errors.Is(err, ErrRecordLayoutUnavailable) {
		return nil, err
	}
	if rows, err := db.ReadDocumentTags(0, 0); err == nil {
		out = append(out, rows...)
	} else if !errors.Is(err, ErrTableNotFound) && !errors.Is(err, ErrRecordLayoutUnavailable) {
		return nil, err
	}
	return out, nil
}

// ParseTagRows converts decoded DiaryTag or DocumentTag rows into semantic tag
// records.
func ParseTagRows(tableName string, rows []DecodedRow) []TagRecord {
	out := make([]TagRecord, 0, len(rows))
	for _, row := range rows {
		values := row.Values
		out = append(out, TagRecord{
			TableName:    tableName,
			Sequence:     row.Sequence,
			ID:           decodedString(values, "Id"),
			Name:         decodedString(values, "TagName"),
			SortCode:     decodedInt32(values, "SortCode"),
			IsPreCreated: decodedBool(values, "IsPreCreated"),
			Values:       values,
		})
	}
	return out
}

// ReadSyncRecords decodes rows from the Sync table into stable semantic records.
func (db *Database) ReadSyncRecords(limit, offset int) ([]SyncRecord, error) {
	rows, err := db.ReadDecodedRows("Sync", limit, offset)
	if err != nil {
		return nil, err
	}
	return ParseSyncRows(rows)
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

func decodedString(values map[string]DecodedValue, name string) string {
	value, ok := values[name]
	if !ok {
		return ""
	}
	if value.String != "" {
		return value.String
	}
	if value.Kind == DecodedString && len(value.Bytes) > 0 {
		return string(value.Bytes)
	}
	return ""
}

func decodedBytes(values map[string]DecodedValue, name string) []byte {
	value, ok := values[name]
	if !ok || len(value.Bytes) == 0 {
		return nil
	}
	out := make([]byte, len(value.Bytes))
	copy(out, value.Bytes)
	return out
}

func decodedBool(values map[string]DecodedValue, name string) bool {
	value, ok := values[name]
	return ok && value.Kind == DecodedBool && value.Bool
}

func decodedInt32(values map[string]DecodedValue, name string) int32 {
	value, ok := values[name]
	if !ok || value.Kind != DecodedInt32 {
		return 0
	}
	return value.Int32
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

	sniff := http.DetectContentType(payload[:min(len(payload), 512)])
	switch sniff {
	case "application/pdf":
		return attachmentPayloadKind{extension: ".pdf", contentType: sniff}
	case "application/zip":
		return attachmentPayloadKind{extension: ".zip", contentType: sniff}
	case "application/gzip", "application/x-gzip":
		return attachmentPayloadKind{extension: ".gz", contentType: "application/gzip"}
	case "text/plain; charset=utf-8":
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
