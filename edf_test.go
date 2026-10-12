package edf_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	edf "github.com/lib-x/edf"
)

func TestLocalEDFSamples(t *testing.T) {
	sampleDir := os.Getenv("EDF_SAMPLE_DIR")
	if sampleDir == "" {
		t.Skip("set EDF_SAMPLE_DIR to scan local EDF samples")
	}
	verboseSchema := os.Getenv("EDF_SAMPLE_VERBOSE_SCHEMA") != ""

	matches, err := filepath.Glob(filepath.Join(sampleDir, "*.edf"))
	if err != nil {
		t.Fatalf("glob EDF_SAMPLE_DIR: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no .edf files found in %s", sampleDir)
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			db, err := edf.Open(path)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			tables := db.Tables()
			if len(tables) == 0 {
				t.Fatalf("no tables parsed")
			}
			t.Logf("tables=%d", len(tables))

			for _, table := range tables {
				if !table.Queryable || table.RecordCount == 0 {
					continue
				}
				t.Logf("table=%s records=%d fields=%d decodable=%t", table.Name, table.RecordCount, len(table.Fields), table.Decodable)
				if !table.Decodable {
					t.Fatalf("queryable table %s is not decodable", table.Name)
				}
				if verboseSchema {
					for _, field := range table.Fields {
						t.Logf("field=%s.%s type=0x%04x width=%d offset=%d", table.Name, field.Name, field.TypeCode, field.RawWidth, field.SlotOffset)
					}
				}
				rawRows, err := db.ReadRawRows(table.Name, 0, 0)
				if err != nil {
					t.Fatalf("ReadRawRows(%s) error = %v", table.Name, err)
				}
				if len(rawRows) != table.RecordCount {
					t.Fatalf("ReadRawRows(%s) returned %d rows, want %d", table.Name, len(rawRows), table.RecordCount)
				}
				decodedRows, err := db.ReadDecodedRows(table.Name, 0, 0)
				if err != nil {
					t.Fatalf("ReadDecodedRows(%s) error = %v", table.Name, err)
				}
				if len(decodedRows) != table.RecordCount {
					t.Fatalf("ReadDecodedRows(%s) returned %d rows, want %d", table.Name, len(decodedRows), table.RecordCount)
				}
				if verboseSchema {
					logDecodedKindSummary(t, table.Name, decodedRows)
				}
			}
		})
	}
}

func TestLocalEDFSamplesWithPasswordDoNotRegressDecodedSignals(t *testing.T) {
	sampleDir := os.Getenv("EDF_SAMPLE_DIR")
	if sampleDir == "" {
		t.Skip("set EDF_SAMPLE_DIR to scan local EDF samples")
	}
	password := localEDFPassword(t)
	if len(password) == 0 {
		t.Skip("set EDF_PASSWORD or EDF_PASSWORD_FILE to verify encrypted EDF decoding")
	}

	matches, err := filepath.Glob(filepath.Join(sampleDir, "*.edf"))
	if err != nil {
		t.Fatalf("glob EDF_SAMPLE_DIR: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no .edf files found in %s", sampleDir)
	}

	withoutPassword := 0
	withPassword := 0
	verifiedFiles := 0
	verbose := os.Getenv("EDF_SAMPLE_VERBOSE_SCHEMA") != ""
	for _, path := range matches {
		plain, err := edf.Open(path)
		if err != nil {
			t.Fatalf("Open(%s) error = %v", filepath.Base(path), err)
		}
		encrypted, err := edf.OpenWithPassword(path, password)
		if err != nil {
			t.Fatalf("OpenWithPassword(%s) error = %v", filepath.Base(path), err)
		}
		if !encrypted.PasswordSupplied() {
			t.Fatalf("PasswordSupplied(%s) = false, want true", filepath.Base(path))
		}
		if summaries, err := encrypted.DecodeSummaries(); err != nil {
			t.Fatalf("DecodeSummaries(%s) error = %v", filepath.Base(path), err)
		} else if len(summaries) == 0 {
			t.Fatalf("DecodeSummaries(%s) returned no queryable table summaries", filepath.Base(path))
		}
		if encrypted.PasswordVerified() {
			verifiedFiles++
		}
		plainSignals := countStrongDecodedSignals(t, plain)
		encryptedSignals := countStrongDecodedSignals(t, encrypted)
		if verbose {
			t.Logf("decoded-signal-summary file=%s without_password=%d with_password=%d password_verified=%t", filepath.Base(path), plainSignals, encryptedSignals, encrypted.PasswordVerified())
			t.Logf("decoded-signal-by-table file=%s without_password=%v with_password=%v", filepath.Base(path), strongDecodedSignalsByTable(t, plain), strongDecodedSignalsByTable(t, encrypted))
		}
		withoutPassword += plainSignals
		withPassword += encryptedSignals
	}

	if verifiedFiles == 0 {
		t.Skip("supplied password did not verify any local EDF sample; decoded recovery assertions skipped")
	}
	if withPassword < withoutPassword {
		t.Fatalf("decoded signal count with password = %d, without password = %d; want no regression", withPassword, withoutPassword)
	}
}

func TestOpenWithPasswordFileRejectsEmptyPasswordFile(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte(" \n\t"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	_, err := edf.OpenWithPasswordFile("missing.edf", passwordPath)
	if err == nil {
		t.Fatalf("expected empty password file error")
	}
	if !strings.Contains(err.Error(), "password file is empty") {
		t.Fatalf("error = %v, want empty password file", err)
	}
}

func localEDFPassword(t *testing.T) []byte {
	t.Helper()

	if password := strings.TrimSpace(os.Getenv("EDF_PASSWORD")); password != "" {
		return []byte(password)
	}
	path := os.Getenv("EDF_PASSWORD_FILE")
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read EDF_PASSWORD_FILE: %v", err)
	}
	password := strings.TrimSpace(string(data))
	if password == "" {
		t.Fatalf("EDF_PASSWORD_FILE is empty")
	}
	return []byte(password)
}

func countStrongDecodedSignals(t *testing.T, db *edf.Database) int {
	t.Helper()

	count := 0
	for _, value := range strongDecodedSignalsByTable(t, db) {
		count += value
	}
	return count
}

func strongDecodedSignalsByTable(t *testing.T, db *edf.Database) map[string]int {
	t.Helper()

	counts := make(map[string]int)
	for _, table := range db.Tables() {
		if !table.Queryable || table.RecordCount == 0 {
			continue
		}
		rows, err := db.ReadDecodedRows(table.Name, 0, 0)
		if err != nil {
			t.Fatalf("ReadDecodedRows(%s) error = %v", table.Name, err)
		}
		for _, row := range rows {
			for _, field := range table.Fields {
				value := row.Values[field.Name]
				if value.Kind == edf.DecodedExternal && len(value.Bytes) > 0 {
					counts[table.Name]++
					continue
				}
				if value.Kind == edf.DecodedString && value.String != "" && isStrongStringField(field.TypeCode) {
					counts[table.Name]++
				}
			}
		}
	}
	return counts
}

func isStrongStringField(typeCode uint16) bool {
	switch typeCode {
	case 0x000f, 0x0010, 0x0027, 0x1e18, 0x2001, 0x2201, 0x4018, 0x8018:
		return true
	default:
		return false
	}
}

func logDecodedKindSummary(t *testing.T, tableName string, rows []edf.DecodedRow) {
	t.Helper()

	counts := make(map[edf.DecodedKind]int)
	nonEmptyStrings := 0
	nonEmptyBytes := 0
	for _, row := range rows {
		for _, value := range row.Values {
			counts[value.Kind]++
			if value.String != "" {
				nonEmptyStrings++
			}
			if len(value.Bytes) > 0 {
				nonEmptyBytes++
			}
		}
	}
	t.Logf("decoded-summary table=%s kinds=%v non_empty_strings=%d non_empty_bytes=%d", tableName, counts, nonEmptyStrings, nonEmptyBytes)
}

func TestInferAttachmentFilename(t *testing.T) {
	tests := []struct {
		name        string
		currentName string
		fallback    string
		payload     []byte
		want        string
	}{
		{name: "pdf payload wins over txt fallback", currentName: "manual.txt", fallback: "manual.bin", payload: []byte("%PDF-1.7\n%"), want: "manual.pdf"},
		{name: "docx inferred from OOXML members", currentName: "report.zip", fallback: "report.bin", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "word/document.xml": "x"}), want: "report.docx"},
		{name: "xlsx inferred from OOXML members", currentName: "sheet.bin", fallback: "sheet.bin", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "xl/workbook.xml": "x"}), want: "sheet.xlsx"},
		{name: "pptx inferred from OOXML members", currentName: "slides.dat", fallback: "slides.dat", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "ppt/presentation.xml": "x"}), want: "slides.pptx"},
		{name: "7z keeps archive extension", currentName: "bundle.bin", fallback: "bundle.bin", payload: append([]byte("7z\xbc\xaf\x27\x1c"), []byte("rest")...), want: "bundle.7z"},
		{name: "rar keeps archive extension", currentName: "archive.bin", fallback: "archive.bin", payload: append([]byte("Rar!"), []byte("rest")...), want: "archive.rar"},
		{name: "gzip keeps gzip extension", currentName: "dump.bin", fallback: "dump.bin", payload: append([]byte{0x1f, 0x8b, 0x08}, []byte("rest")...), want: "dump.gz"},
		{name: "printable text falls back to txt", currentName: "notes.bin", fallback: "notes.bin", payload: []byte("hello world\nsecond line\n"), want: "notes.txt"},
		{name: "text keeps source code extension", currentName: "BoundReceiver.cs", fallback: "BoundReceiver.bin", payload: []byte("using System;\nclass X {}\n"), want: "BoundReceiver.cs"},
		{name: "text keeps installer script extension", currentName: "install.nsi", fallback: "install.bin", payload: []byte("!define PRODUCT_NAME \"demo\"\n"), want: "install.nsi"},
		{name: "already good extension is preserved", currentName: "spec.docx", fallback: "spec.bin", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "word/document.xml": "x"}), want: "spec.docx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := edf.InferAttachmentFilename(tt.currentName, tt.payload, tt.fallback)
			if got != tt.want {
				t.Fatalf("InferAttachmentFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInferAttachmentContentType(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{name: "pdf", payload: []byte("%PDF-1.7\n%"), want: "application/pdf"},
		{name: "docx", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "word/document.xml": "x"}), want: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
		{name: "xlsx", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "xl/workbook.xml": "x"}), want: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
		{name: "pptx", payload: mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "ppt/presentation.xml": "x"}), want: "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
		{name: "zip", payload: mustZipPayload(t, map[string]string{"plain.txt": "x"}), want: "application/zip"},
		{name: "7z", payload: append([]byte("7z\xbc\xaf\x27\x1c"), []byte("rest")...), want: "application/x-7z-compressed"},
		{name: "rar", payload: append([]byte("Rar!"), []byte("rest")...), want: "application/vnd.rar"},
		{name: "gzip", payload: append([]byte{0x1f, 0x8b, 0x08}, []byte("rest")...), want: "application/gzip"},
		{name: "text", payload: []byte("hello world\nsecond line\n"), want: "text/plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := edf.InferAttachmentContentType(tt.payload)
			if got != tt.want {
				t.Fatalf("InferAttachmentContentType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInspectAttachmentPayload(t *testing.T) {
	payload := mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "word/document.xml": "x"})
	info := edf.InspectAttachmentPayload("proposal.bin", payload, "proposal.bin")
	if info.Filename != "proposal.docx" {
		t.Fatalf("Filename = %q, want %q", info.Filename, "proposal.docx")
	}
	if info.ContentType != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("ContentType = %q", info.ContentType)
	}
	if info.Extension != ".docx" {
		t.Fatalf("Extension = %q, want .docx", info.Extension)
	}
}

func TestParseArticleRows(t *testing.T) {
	rows := []edf.DecodedRow{
		{
			Sequence: 3,
			Values: map[string]edf.DecodedValue{
				"Id":             {Kind: edf.DecodedString, String: "aaed9485e7514a4c81730acee0005420"},
				"ParentId":       {Kind: edf.DecodedString, String: "0"},
				"IsFolder":       {Kind: edf.DecodedBool, Bool: false},
				"ArticleFormat":  {Kind: edf.DecodedInt32, Int32: 2},
				"IconId":         {Kind: edf.DecodedInt32, Int32: 9},
				"Title":          {Kind: edf.DecodedString, String: "title"},
				"Keywords":       {Kind: edf.DecodedExternal, String: "work,notes"},
				"TagIdList":      {Kind: edf.DecodedExternal, String: "17fe007e5dcb427d982701aa6b03d652"},
				"Content":        {Kind: edf.DecodedExternal, String: "body", Bytes: []byte("body")},
				"Date":           {Kind: edf.DecodedDate, String: "2026-06-29"},
				"Time":           {Kind: edf.DecodedTime, String: "12:00:00"},
				"WeatherIconId":  {Kind: edf.DecodedString, String: "sunny"},
				"WeatherText":    {Kind: edf.DecodedString, String: "晴"},
				"ModifyDateTime": {Kind: edf.DecodedDateTime, String: "2026-06-29 12:00:00.000"},
				"WordCount":      {Kind: edf.DecodedInt32, Int32: 4},
				"SortCode":       {Kind: edf.DecodedInt32, Int32: 8},
				"Deleted":        {Kind: edf.DecodedBool, Bool: true},
			},
		},
	}

	articles := edf.ParseArticleRows("Document", rows)
	if len(articles) != 1 {
		t.Fatalf("article count = %d, want 1", len(articles))
	}
	article := articles[0]
	if article.TableName != "Document" || article.Sequence != 3 || article.ID != "aaed9485e7514a4c81730acee0005420" {
		t.Fatalf("unexpected article identity: %+v", article)
	}
	if article.Title != "title" || article.ContentText != "body" || string(article.Content) != "body" {
		t.Fatalf("unexpected article content: %+v", article)
	}
	if article.Keywords != "work,notes" || article.TagIDList != "17fe007e5dcb427d982701aa6b03d652" {
		t.Fatalf("unexpected article keyword/tag metadata: %+v", article)
	}
	if article.ArticleFormat != 2 || article.IconID != 9 || article.WordCount != 4 || article.SortCode != 8 {
		t.Fatalf("unexpected article numeric metadata: %+v", article)
	}
	if article.Date != "2026-06-29" || article.Time != "12:00:00" || article.WeatherIconID != "sunny" || article.WeatherText != "晴" {
		t.Fatalf("unexpected article calendar metadata: %+v", article)
	}
	if !article.Deleted || article.ModifyDateTime == "" {
		t.Fatalf("expected deleted flag and modify time: %+v", article)
	}
}

func TestParseAttachmentRows(t *testing.T) {
	metaRows := []edf.DecodedRow{
		{
			Sequence: 4,
			Values: map[string]edf.DecodedValue{
				"Id":        {Kind: edf.DecodedString, String: "meta-id"},
				"ContentId": {Kind: edf.DecodedString, String: "content-id"},
				"OwnerId":   {Kind: edf.DecodedString, String: "owner-id"},
				"Name":      {Kind: edf.DecodedString, String: "notes.bin"},
				"Comment":   {Kind: edf.DecodedString, String: "comment"},
			},
		},
	}
	contentRows := []edf.DecodedRow{
		{
			Sequence: 8,
			Values: map[string]edf.DecodedValue{
				"Id":      {Kind: edf.DecodedString, String: "content-id"},
				"Content": {Kind: edf.DecodedExternal, String: "hello\n", Bytes: []byte("hello\n")},
			},
		},
	}

	attachments := edf.ParseAttachmentRows(metaRows, contentRows)
	if len(attachments) != 1 {
		t.Fatalf("attachment count = %d, want 1", len(attachments))
	}
	attachment := attachments[0]
	if attachment.ID != "meta-id" || attachment.ContentID != "content-id" || attachment.OwnerID != "owner-id" {
		t.Fatalf("unexpected attachment identity: %+v", attachment)
	}
	if attachment.Name != "notes.bin" || attachment.Comment != "comment" || string(attachment.Payload) != "hello\n" {
		t.Fatalf("unexpected attachment content: %+v", attachment)
	}
	if attachment.PayloadText != "hello\n" || attachment.Info.Filename != "notes.txt" || attachment.Info.ContentType != "text/plain" {
		t.Fatalf("unexpected attachment info: %+v", attachment)
	}
}

func TestParseTagRows(t *testing.T) {
	rows := []edf.DecodedRow{
		{
			Sequence: 2,
			Values: map[string]edf.DecodedValue{
				"Id":           {Kind: edf.DecodedString, String: "tag-id"},
				"TagName":      {Kind: edf.DecodedString, String: "工作"},
				"SortCode":     {Kind: edf.DecodedInt32, Int32: 7},
				"IsPreCreated": {Kind: edf.DecodedBool, Bool: true},
			},
		},
	}

	tags := edf.ParseTagRows("DiaryTag", rows)
	if len(tags) != 1 {
		t.Fatalf("tag count = %d, want 1", len(tags))
	}
	tag := tags[0]
	if tag.TableName != "DiaryTag" || tag.Sequence != 2 || tag.ID != "tag-id" || tag.Name != "工作" {
		t.Fatalf("unexpected tag identity: %+v", tag)
	}
	if tag.SortCode != 7 || !tag.IsPreCreated {
		t.Fatalf("unexpected tag metadata: %+v", tag)
	}
}

func TestSummarizeDecodedRows(t *testing.T) {
	table := edf.Table{
		Name: "Document",
		Fields: []edf.Field{
			{Name: "Id", TypeCode: 0x2001},
			{Name: "Content", TypeCode: 0x000f},
		},
	}
	rows := []edf.DecodedRow{
		{Values: map[string]edf.DecodedValue{
			"Id":      {Kind: edf.DecodedString, String: "aaed9485e7514a4c81730acee0005420"},
			"Content": {Kind: edf.DecodedRaw},
		}},
		{Values: map[string]edf.DecodedValue{
			"Id":      {Kind: edf.DecodedRaw},
			"Content": {Kind: edf.DecodedExternal, String: "body", Bytes: []byte("body")},
		}},
	}

	summary := edf.SummarizeDecodedRows(table, rows)
	if summary.Name != "Document" || summary.Rows != 2 || summary.Values != 4 || summary.Raw != 2 || summary.Decoded != 2 {
		t.Fatalf("unexpected table summary: %+v", summary)
	}
	if len(summary.Fields) != 2 {
		t.Fatalf("field summary count = %d, want 2", len(summary.Fields))
	}
	if summary.Fields[0].String != 1 || summary.Fields[0].Raw != 1 {
		t.Fatalf("unexpected Id summary: %+v", summary.Fields[0])
	}
	if summary.Fields[1].External != 1 || summary.Fields[1].Raw != 1 || summary.Fields[1].NonEmptyBytes != 1 {
		t.Fatalf("unexpected Content summary: %+v", summary.Fields[1])
	}
}

func TestParseSyncRecord(t *testing.T) {
	record, err := edf.ParseSyncRecord(map[string]edf.DecodedValue{
		"ItemId":      {Kind: edf.DecodedString, String: "aaed9485e7514a4c81730acee0005420"},
		"UpdateCount": {Kind: edf.DecodedInt32, Int32: 2},
		"Modified":    {Kind: edf.DecodedBool, Bool: true},
		"Deleted":     {Kind: edf.DecodedBool, Bool: false},
	})
	if err != nil {
		t.Fatalf("ParseSyncRecord() error = %v", err)
	}
	if record.ItemID != "aaed9485e7514a4c81730acee0005420" || record.UpdateCount != 2 || !record.Modified || record.Deleted {
		t.Fatalf("unexpected SyncRecord: %+v", record)
	}
}

func TestSummarizeAttachmentPayload(t *testing.T) {
	payload := mustZipPayload(t, map[string]string{"[Content_Types].xml": "x", "xl/workbook.xml": "x"})
	summary := edf.SummarizeAttachmentPayload("sheet.bin", payload, "sheet.bin")
	if summary.CurrentName != "sheet.bin" {
		t.Fatalf("CurrentName = %q", summary.CurrentName)
	}
	if summary.FallbackName != "sheet.bin" {
		t.Fatalf("FallbackName = %q", summary.FallbackName)
	}
	if summary.Info.Filename != "sheet.xlsx" {
		t.Fatalf("Filename = %q", summary.Info.Filename)
	}
	if summary.Info.ContentType != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Fatalf("ContentType = %q", summary.Info.ContentType)
	}
	if summary.Info.Extension != ".xlsx" {
		t.Fatalf("Extension = %q", summary.Info.Extension)
	}
}

func TestParseSyncRows(t *testing.T) {
	rows := []edf.DecodedRow{
		{Values: map[string]edf.DecodedValue{
			"ItemId":      {Kind: edf.DecodedString, String: "aaed9485e7514a4c81730acee0005420"},
			"UpdateCount": {Kind: edf.DecodedInt32, Int32: 2},
			"Modified":    {Kind: edf.DecodedBool, Bool: true},
			"Deleted":     {Kind: edf.DecodedBool, Bool: false},
		}},
		{Values: map[string]edf.DecodedValue{
			"ItemId":      {Kind: edf.DecodedString, String: "95ca9323b18347abb435b75b6f223ea0"},
			"UpdateCount": {Kind: edf.DecodedInt32, Int32: 1},
			"Modified":    {Kind: edf.DecodedBool, Bool: true},
			"Deleted":     {Kind: edf.DecodedBool, Bool: false},
		}},
	}
	records, err := edf.ParseSyncRows(rows)
	if err != nil {
		t.Fatalf("ParseSyncRows() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("record count = %d, want 2", len(records))
	}
	if records[1].ItemID != "95ca9323b18347abb435b75b6f223ea0" || records[1].UpdateCount != 1 {
		t.Fatalf("unexpected second record: %+v", records[1])
	}
}

func TestParseSyncRecordRejectsWrongKinds(t *testing.T) {
	_, err := edf.ParseSyncRecord(map[string]edf.DecodedValue{
		"ItemId":      {Kind: edf.DecodedRaw},
		"UpdateCount": {Kind: edf.DecodedInt32, Int32: 1},
		"Modified":    {Kind: edf.DecodedBool, Bool: true},
		"Deleted":     {Kind: edf.DecodedBool, Bool: false},
	})
	if err == nil {
		t.Fatalf("expected ParseSyncRecord to reject invalid kinds")
	}
}

func TestLocalSemanticReadersWithPasswordDoNotRegressSignals(t *testing.T) {
	sampleDir := os.Getenv("EDF_SAMPLE_DIR")
	if sampleDir == "" {
		t.Skip("set EDF_SAMPLE_DIR to scan local EDF samples")
	}
	password := localEDFPassword(t)
	if len(password) == 0 {
		t.Skip("set EDF_PASSWORD or EDF_PASSWORD_FILE to verify encrypted EDF semantic readers")
	}

	matches, err := filepath.Glob(filepath.Join(sampleDir, "*.edf"))
	if err != nil {
		t.Fatalf("glob EDF_SAMPLE_DIR: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no .edf files found in %s", sampleDir)
	}

	withoutPassword := 0
	withPassword := 0
	verifiedFiles := 0
	for _, path := range matches {
		plain, err := edf.Open(path)
		if err != nil {
			t.Fatalf("Open(%s) error = %v", filepath.Base(path), err)
		}
		encrypted, err := edf.OpenWithPassword(path, password)
		if err != nil {
			t.Fatalf("OpenWithPassword(%s) error = %v", filepath.Base(path), err)
		}
		if !encrypted.PasswordSupplied() {
			t.Fatalf("PasswordSupplied(%s) = false, want true", filepath.Base(path))
		}
		if encrypted.PasswordVerified() {
			verifiedFiles++
		}
		withoutPassword += countSemanticSignals(t, plain)
		withPassword += countSemanticSignals(t, encrypted)
	}

	if verifiedFiles == 0 {
		t.Skip("supplied password did not verify any local EDF sample; semantic recovery assertions skipped")
	}
	if withPassword < withoutPassword {
		t.Fatalf("semantic signal count with password = %d, without password = %d; want no regression", withPassword, withoutPassword)
	}
}

func countSemanticSignals(t *testing.T, db *edf.Database) int {
	t.Helper()

	count := 0
	if articles, err := db.ReadArticles(); err == nil {
		for _, article := range articles {
			if article.ID != "" {
				count++
			}
			if article.Title != "" {
				count++
			}
			if article.Date != "" {
				count++
			}
		}
	} else {
		t.Fatalf("ReadArticles() error = %v", err)
	}
	if documents, err := db.ReadDocuments(0, 0); err == nil {
		for _, document := range documents {
			if document.ID != "" {
				count++
			}
			if document.ParentID != "" {
				count++
			}
			if document.Title != "" {
				count++
			}
			if document.ContentText != "" {
				count++
			}
			if len(document.Content) > 0 {
				count++
			}
		}
	}
	if diaries, err := db.ReadDiaries(0, 0); err == nil {
		for _, diary := range diaries {
			if diary.ID != "" {
				count++
			}
			if diary.Title != "" {
				count++
			}
			if diary.ContentText != "" {
				count++
			}
		}
	}
	attachments, err := db.ReadAttachments(0, 0)
	if err != nil {
		t.Fatalf("ReadAttachments() error = %v", err)
	}
	for _, attachment := range attachments {
		if attachment.ID != "" {
			count++
		}
		if attachment.ContentID != "" {
			count++
		}
		if attachment.OwnerID != "" {
			count++
		}
		if attachment.Name != "" {
			count++
		}
		if len(attachment.Payload) > 0 {
			count++
		}
		if attachment.Info.Filename != "" {
			count++
		}
	}
	if tags, err := db.ReadDiaryTags(0, 0); err == nil {
		for _, tag := range tags {
			if tag.ID != "" {
				count++
			}
			if tag.Name != "" {
				count++
			}
		}
	}
	if tags, err := db.ReadDocumentTags(0, 0); err == nil {
		for _, tag := range tags {
			if tag.ID != "" {
				count++
			}
			if tag.Name != "" {
				count++
			}
		}
	}
	if tags, err := db.ReadTags(); err == nil {
		for _, tag := range tags {
			if tag.ID != "" {
				count++
			}
			if tag.Name != "" {
				count++
			}
		}
	} else {
		t.Fatalf("ReadTags() error = %v", err)
	}
	return count
}

func mustZipPayload(t *testing.T, files map[string]string) []byte {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "payload.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp zip: %v", err)
	}
	zw := zip.NewWriter(file)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp zip: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp zip: %v", err)
	}
	return payload
}
