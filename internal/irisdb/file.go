package irisdb

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
)

const (
	tableMagic    = "IRISDBTABLEHEADER\x00"
	fieldDescBase = 0x7f
	fieldDescSize = 164
	indexDescSize = 78
)

var (
	dirOffsets  = []int{0x4960, 0x68ac}
	aaMagic     = []byte{0xaa, 0x00}
	fieldWidths = map[uint16]int{
		0x0003: 4,
		0x0005: 2,
		0x0009: 4,
		0x000a: 4,
		0x000b: 8,
		0x000f: 24,
		0x0010: 24,
		0x0019: 8,
		0x0027: 24,
		0x1e18: 62,
		0x2001: 33,
		0x2201: 35,
		0x4018: 130,
		0x8018: 130,
	}
)

type File struct {
	path   string
	data   []byte
	tables []*Table
	byName map[string]*Table
}

type Table struct {
	Name         string
	HeaderOffset int64
	RecordCount  int
	RecordRoot   int64
	PageRoot     int64
	Decodable    bool
	Fields       []Field
	Indexes      []Index
	Layout       *RecordLayout
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

type RecordLayout struct {
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

func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	file, err := openBytes(path, data)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	return file, nil
}

func openBytes(path string, data []byte) (*File, error) {
	if len(data) < 8 {
		return nil, ErrShortRead
	}
	if !bytes.HasPrefix(data, []byte("IrisDB\x00")) {
		return nil, ErrNotEDF
	}

	tableOffsets, err := parsePrimaryDirectory(data)
	if err != nil {
		return nil, err
	}

	file := &File{
		path:   path,
		data:   data,
		byName: make(map[string]*Table, len(tableOffsets)),
	}

	for _, tableOffset := range tableOffsets {
		table, err := parseTable(data, tableOffset)
		if err != nil {
			return nil, fmt.Errorf("parse table at 0x%x: %w", tableOffset, err)
		}
		file.tables = append(file.tables, table)
		file.byName[strings.ToLower(table.Name)] = table
	}

	return file, nil
}

func (f *File) Path() string {
	return f.path
}

func (f *File) Tables() []*Table {
	return slices.Clone(f.tables)
}

func (f *File) Table(name string) (*Table, bool) {
	table, ok := f.byName[strings.ToLower(name)]
	return table, ok
}

func (f *File) ReadRawRows(tableName string, limit, offset int) ([]RawRow, error) {
	table, ok := f.Table(tableName)
	if !ok {
		return nil, ErrTableNotFound
	}
	if table.Layout == nil {
		return nil, ErrRecordLayoutUnavailable
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}
	if offset >= table.Layout.RecordCount {
		return []RawRow{}, nil
	}

	fields := table.Fields
	end := table.Layout.RecordCount
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}

	rows := make([]RawRow, 0, end-offset)
	for idx := offset; idx < end; idx++ {
		recordOffset := int(table.Layout.RecordRoot) + idx*table.Layout.Stride
		recordEnd := recordOffset + table.Layout.Stride
		if recordEnd > len(f.data) {
			return nil, ErrShortRead
		}

		record := f.data[recordOffset:recordEnd]
		row, err := decodeRawRow(record, fields, table.Layout.BitmapSize)
		if err != nil {
			return nil, fmt.Errorf("decode row %d in %s: %w", idx, table.Name, err)
		}
		rows = append(rows, row)
	}

	return rows, nil
}

func decodeRawRow(record []byte, fields []Field, bitmapSize int) (RawRow, error) {
	if len(record) < 6+bitmapSize {
		return RawRow{}, ErrShortRead
	}

	row := RawRow{
		Sequence: int(readU16(record, 2)),
		Bitmap:   slices.Clone(record[6 : 6+bitmapSize]),
		Values:   make([][]byte, 0, len(fields)),
	}

	pos := 6 + bitmapSize
	for _, field := range fields {
		if field.RawWidth == 0 {
			return RawRow{}, fmt.Errorf("%w: %s (0x%x)", ErrUnsupportedFieldType, field.Name, field.TypeCode)
		}
		end := pos + field.RawWidth
		if end > len(record) {
			return RawRow{}, ErrShortRead
		}
		row.Values = append(row.Values, slices.Clone(record[pos:end]))
		pos = end
	}

	return row, nil
}

func parsePrimaryDirectory(data []byte) ([]int64, error) {
	for _, dirOffset := range dirOffsets {
		offsets, err := parseDirectory(data, dirOffset)
		if err == nil && len(offsets) > 0 {
			return offsets, nil
		}
	}
	return nil, fmt.Errorf("parse primary directory: %w", ErrNotEDF)
}

func parseDirectory(data []byte, offset int) ([]int64, error) {
	if offset+8 > len(data) {
		return nil, ErrShortRead
	}

	count := int(readU32(data, offset+4))
	pos := offset + 8
	out := make([]int64, 0, count)
	for range count {
		if pos+8 > len(data) {
			return nil, ErrShortRead
		}
		tableOffset := int64(readU32(data, pos))
		if tableOffset != 0 {
			out = append(out, tableOffset)
		}
		pos += 8
	}
	return out, nil
}

func parseTable(data []byte, tableOffset int64) (*Table, error) {
	off := int(tableOffset)
	if off+len(tableMagic) > len(data) {
		return nil, ErrShortRead
	}
	if string(data[off:off+len(tableMagic)]) != tableMagic {
		return nil, ErrNotEDF
	}

	name := readPascalString(data, off+len(tableMagic))
	fieldCount := int(readU32(data, off+0x63))
	indexCount := int(readU32(data, off+0x67))
	recordCount := int(readU32(data, off+0x47))
	recordRoot := int64(readU32(data, off+0x3f))
	pageRoot := int64(readU32(data, off+0x6b))

	fields, err := parseFields(data, off, fieldCount)
	if err != nil {
		return nil, err
	}
	indexes, err := parseIndexes(data, off, fieldCount, indexCount)
	if err != nil {
		return nil, err
	}

	table := &Table{
		Name:         name,
		HeaderOffset: tableOffset,
		RecordCount:  recordCount,
		RecordRoot:   recordRoot,
		PageRoot:     pageRoot,
		Fields:       fields,
		Indexes:      indexes,
	}
	table.Layout = detectLayout(data, table)
	table.Decodable = detectDecodable(data, table)

	return table, nil
}

func parseFields(data []byte, tableOffset, fieldCount int) ([]Field, error) {
	fields := make([]Field, 0, fieldCount)
	base := tableOffset + fieldDescBase
	slotOffset := 6 + bitmapSize(fieldCount)
	for idx := range fieldCount {
		off := base + idx*fieldDescSize
		if off+fieldDescSize > len(data) {
			return nil, ErrShortRead
		}

		typeCode := readU16(data, off+0x21)
		rawWidth := fieldWidths[typeCode]
		fields = append(fields, Field{
			Name:       readPascalString(data, off),
			TypeCode:   typeCode,
			RawWidth:   rawWidth,
			SlotOffset: slotOffset,
		})
		slotOffset += rawWidth
	}
	return fields, nil
}

func parseIndexes(data []byte, tableOffset, fieldCount, indexCount int) ([]Index, error) {
	indexes := make([]Index, 0, indexCount)
	base := tableOffset + fieldDescBase + fieldCount*fieldDescSize
	for idx := range indexCount {
		off := base + idx*indexDescSize
		if off+indexDescSize > len(data) {
			return nil, ErrShortRead
		}
		indexes = append(indexes, Index{Name: readPascalString(data, off)})
	}
	return indexes, nil
}

func detectLayout(data []byte, table *Table) *RecordLayout {
	if table.RecordRoot == 0 || table.RecordCount == 0 || table.RecordRoot >= int64(len(data)) {
		return nil
	}

	recordRoot := int(table.RecordRoot)
	scanEnd := min(len(data), recordRoot+max(0x4000, table.RecordCount*512))
	blob := data[recordRoot:scanEnd]
	if len(blob) < 6 || !bytes.HasPrefix(blob, aaMagic) {
		return nil
	}

	candidates := candidateStrides(blob)
	for _, stride := range candidates {
		if verifyStride(blob, stride, table.RecordCount) {
			return &RecordLayout{
				RecordCount: table.RecordCount,
				RecordRoot:  table.RecordRoot,
				Stride:      stride,
				BitmapSize:  bitmapSize(len(table.Fields)),
				FieldCount:  len(table.Fields),
			}
		}
	}

	expected, ok := expectedStride(table.Fields)
	if ok && len(blob) >= expected && readU16(blob, 2) == 1 {
		return &RecordLayout{
			RecordCount: table.RecordCount,
			RecordRoot:  table.RecordRoot,
			Stride:      expected,
			BitmapSize:  bitmapSize(len(table.Fields)),
			FieldCount:  len(table.Fields),
		}
	}

	return nil
}

func detectDecodable(data []byte, table *Table) bool {
	if table.Layout == nil || table.RecordCount == 0 {
		return false
	}

	recordOffset := int(table.Layout.RecordRoot)
	recordEnd := recordOffset + table.Layout.Stride
	if recordEnd > len(data) {
		return false
	}

	row, err := decodeRawRow(data[recordOffset:recordEnd], table.Fields, table.Layout.BitmapSize)
	if err != nil {
		return false
	}

	decodedStrong := 0
	for idx, field := range table.Fields {
		decoded, err := decodeRawValue(data, field, row.Values[idx])
		if err != nil {
			continue
		}
		switch decoded.Kind {
		case DecodedString:
			if decoded.String != "" {
				decodedStrong++
			}
		case DecodedExternal:
			if decoded.String != "" || len(decoded.Bytes) > 0 {
				decodedStrong++
			}
		}
	}

	return decodedStrong >= 2
}

func candidateStrides(blob []byte) []int {
	hits := make([]int, 0, 16)
	for pos := 0; pos < min(len(blob), 0x400); pos++ {
		if pos+2 <= len(blob) && bytes.Equal(blob[pos:pos+2], aaMagic) {
			hits = append(hits, pos)
		}
	}
	if len(hits) < 2 {
		return nil
	}

	out := make([]int, 0, len(hits)-1)
	for _, hit := range hits[1:] {
		if hit > 0 && !slices.Contains(out, hit) {
			out = append(out, hit)
		}
	}
	return out
}

func verifyStride(blob []byte, stride, recordCount int) bool {
	for idx := range recordCount {
		off := idx * stride
		if off+6 > len(blob) {
			return false
		}
		if !bytes.Equal(blob[off:off+2], aaMagic) {
			return false
		}
		if int(readU16(blob, off+2)) != idx+1 {
			return false
		}
	}
	return true
}

func expectedStride(fields []Field) (int, bool) {
	total := 6 + bitmapSize(len(fields))
	for _, field := range fields {
		if field.RawWidth == 0 {
			return 0, false
		}
		total += field.RawWidth
	}
	return total, true
}

func bitmapSize(fieldCount int) int {
	return int(math.Ceil(float64(fieldCount) / 8.0))
}

func readPascalString(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	length := int(data[offset])
	start := offset + 1
	end := min(len(data), start+length)
	return string(data[start:end])
}

func readU16(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return uint16(data[offset]) | uint16(data[offset+1])<<8
}

func readU32(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24
}
