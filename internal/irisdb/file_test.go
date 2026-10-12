package irisdb

import "testing"

func TestDetectDecodableUsesKnownFieldTypes(t *testing.T) {
	table := &Table{
		RecordCount: 1,
		Fields: []Field{
			{Name: "Title", TypeCode: 0x0027, RawWidth: 24},
		},
		Layout: &RecordLayout{RecordCount: 1, RecordRoot: 128, Stride: 32},
	}

	if !detectDecodable(table) {
		t.Fatalf("detectDecodable() = false, want true")
	}
}

func TestDetectDecodableRejectsUnknownFieldTypes(t *testing.T) {
	table := &Table{
		RecordCount: 1,
		Fields: []Field{
			{Name: "Unknown", TypeCode: 0xffff, RawWidth: 8},
		},
		Layout: &RecordLayout{RecordCount: 1, RecordRoot: 128, Stride: 16},
	}

	if detectDecodable(table) {
		t.Fatalf("detectDecodable() = true, want false")
	}
}
