package edf_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	edf "github.com/lib-x/edf"
)

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
