package irisdb

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type DecodedKind string

const (
	DecodedRaw      DecodedKind = "raw"
	DecodedString   DecodedKind = "string"
	DecodedBool     DecodedKind = "bool"
	DecodedInt32    DecodedKind = "int32"
	DecodedDate     DecodedKind = "date"
	DecodedTime     DecodedKind = "time"
	DecodedDateTime DecodedKind = "datetime"
	DecodedExternal DecodedKind = "external"
)

var (
	asciiIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	asciiTypedIDPattern = regexp.MustCompile(`^[0-9]-[0-9a-f]{32}$`)
)

type BlobRef struct {
	DataOffset   uint32
	Reserved0    uint32
	PlainSize    uint32
	StoredSize   uint32
	AreaSize     uint32
	Reserved1    uint32
	DecodedBytes []byte
	DecodedText  string
}

type DecodedValue struct {
	Kind     DecodedKind
	TypeCode uint16
	Raw      []byte
	String   string
	Bool     bool
	Int32    int32
	Time     time.Time
	Bytes    []byte
	External *BlobRef
}

func (f *File) DecodeValue(tableName, fieldName string, raw []byte) (DecodedValue, error) {
	table, ok := f.Table(tableName)
	if !ok {
		return DecodedValue{}, ErrTableNotFound
	}

	var field *Field
	for idx := range table.Fields {
		if strings.EqualFold(table.Fields[idx].Name, fieldName) {
			field = &table.Fields[idx]
			break
		}
	}
	if field == nil {
		return DecodedValue{}, fmt.Errorf("field %q in table %q: %w", fieldName, tableName, ErrTableNotFound)
	}

	return decodeRawValue(f.data, *field, raw)
}

func decodeRawValue(data []byte, field Field, raw []byte) (DecodedValue, error) {
	value := DecodedValue{
		Kind:     DecodedRaw,
		TypeCode: field.TypeCode,
		Raw:      slicesCloneBytes(raw),
	}

	switch field.TypeCode {
	case 0x0005:
		if len(raw) < 2 {
			return DecodedValue{}, ErrShortRead
		}
		value.Kind = DecodedBool
		value.Bool = binary.LittleEndian.Uint16(raw[:2]) != 0
		return value, nil
	case 0x0003:
		if len(raw) < 4 {
			return DecodedValue{}, ErrShortRead
		}
		value.Kind = DecodedInt32
		value.Int32 = int32(binary.LittleEndian.Uint32(raw[:4]))
		return value, nil
	case 0x0009:
		if len(raw) < 4 {
			return DecodedValue{}, ErrShortRead
		}
		days := int(binary.LittleEndian.Uint32(raw[:4]))
		if days <= 0 {
			return value, nil
		}
		value.Kind = DecodedDate
		value.Time = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days-1)
		value.String = value.Time.Format("2006-01-02")
		return value, nil
	case 0x000a:
		if len(raw) < 4 {
			return DecodedValue{}, ErrShortRead
		}
		millis := int(binary.LittleEndian.Uint32(raw[:4]))
		base := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		value.Kind = DecodedTime
		value.Time = base.Add(time.Duration(millis) * time.Millisecond)
		value.String = value.Time.Format("15:04:05")
		return value, nil
	case 0x000b:
		if len(raw) < 8 {
			return DecodedValue{}, ErrShortRead
		}
		totalMillis := binary.LittleEndian.Uint64(raw[:8])
		if totalMillis == 0 {
			return value, nil
		}
		total := math.Float64frombits(totalMillis)
		if total <= 0 {
			return value, nil
		}
		value.Kind = DecodedDateTime
		value.Time = decodeFloatMillisSinceYearOne(total)
		value.String = value.Time.Format("2006-01-02 15:04:05.000")
		return value, nil
	case 0x2001, 0x2201:
		text := trimCString(raw)
		if isLikelyIDText(field.TypeCode, text, raw) {
			value.Kind = DecodedString
			value.String = text
			value.Bytes = []byte(text)
			return value, nil
		}
		return value, nil
	case 0x4018, 0x8018:
		if looksLikeUTF16LE(raw) {
			text := decodeUTF16CString(raw)
			value.Kind = DecodedString
			value.String = text
			value.Bytes = []byte(text)
			return value, nil
		}
		return value, nil
	case 0x000f, 0x0010, 0x0027:
		ref, ok, err := decodeBlobRef(data, raw)
		if err != nil {
			return DecodedValue{}, err
		}
		if ok {
			value.Kind = DecodedExternal
			value.Bytes = ref.DecodedBytes
			value.String = ref.DecodedText
			value.External = ref
			return value, nil
		}
		return value, nil
	default:
		return value, nil
	}
}

func decodeFloatMillisSinceYearOne(totalMillis float64) time.Time {
	const dayMillis = float64(24 * time.Hour / time.Millisecond)

	ordinalDay := int(totalMillis / dayMillis)
	msOfDay := totalMillis - float64(ordinalDay)*dayMillis

	baseDate := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	date := baseDate.AddDate(0, 0, ordinalDay-1)
	return date.Add(time.Duration(msOfDay * float64(time.Millisecond)))
}

func decodeBlobRef(data []byte, raw []byte) (*BlobRef, bool, error) {
	if len(raw) < 24 {
		return nil, false, nil
	}

	ref := &BlobRef{
		DataOffset: binary.LittleEndian.Uint32(raw[0:4]),
		Reserved0:  binary.LittleEndian.Uint32(raw[4:8]),
		PlainSize:  binary.LittleEndian.Uint32(raw[8:12]),
		StoredSize: binary.LittleEndian.Uint32(raw[12:16]),
		AreaSize:   binary.LittleEndian.Uint32(raw[16:20]),
		Reserved1:  binary.LittleEndian.Uint32(raw[20:24]),
	}

	if ref.DataOffset == 0 || int(ref.DataOffset) >= len(data) {
		return nil, false, nil
	}

	size := ref.StoredSize
	if size == 0 {
		size = ref.AreaSize
	}
	if size == 0 {
		return ref, true, nil
	}

	end := int(ref.DataOffset + size)
	if end > len(data) {
		return nil, false, ErrShortRead
	}

	decoded, err := tryZlib(data[ref.DataOffset:end])
	if err != nil {
		return nil, false, nil
	}

	ref.DecodedBytes = decoded
	ref.DecodedText = decodeExternalText(decoded)
	return ref, true, nil
}

func tryZlib(blob []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func trimCString(raw []byte) string {
	end := bytes.IndexByte(raw, 0)
	if end == -1 {
		end = len(raw)
	}
	return string(raw[:end])
}

func decodeUTF16CString(raw []byte) string {
	u16s := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		v := binary.LittleEndian.Uint16(raw[i : i+2])
		if v == 0 {
			break
		}
		u16s = append(u16s, v)
	}
	return string(utf16.Decode(u16s))
}

func decodeExternalText(blob []byte) string {
	if text := decodeSDPText(blob); text != "" {
		return text
	}
	if text := decodeRVFText(blob); text != "" {
		return text
	}
	if text := decodeUTF16BlobText(blob); text != "" {
		return text
	}
	return bestEffortText(blob)
}

func decodeUTF16BlobText(blob []byte) string {
	if len(blob) < 4 || len(blob)%2 != 0 {
		return ""
	}

	if looksLikeUTF16LE(blob) {
		text := decodeUTF16CString(blob)
		if strings.TrimSpace(text) != "" {
			return text
		}
	}

	u16s := make([]uint16, 0, len(blob)/2)
	for i := 0; i+1 < len(blob); i += 2 {
		u16s = append(u16s, binary.LittleEndian.Uint16(blob[i:i+2]))
	}
	text := strings.TrimRight(string(utf16.Decode(u16s)), "\x00")
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if !looksLikeHumanText(text) {
		return ""
	}
	return text
}

func decodeSDPText(blob []byte) string {
	if len(blob) < 32 || !bytes.HasPrefix(blob, []byte("SDP\x00")) {
		return ""
	}
	if !bytes.Contains(blob[:32], []byte("Text")) {
		return ""
	}
	body := blob[32:]
	body = bytes.TrimRight(body, "\x00")
	if len(body) == 0 {
		return ""
	}
	if !utf8MostlyReadable(body) {
		return ""
	}
	return string(body)
}

func decodeRVFText(blob []byte) string {
	if !bytes.HasPrefix(blob, []byte("-8 1 3 2\r\n")) {
		return ""
	}
	out := make([]string, 0, 32)

	// RVF mixes control records and textual payload. Be conservative: avoid
	// treating arbitrary ASCII control lines as正文文本.

	for _, text := range scanUTF16Runs(blob) {
		for _, segment := range splitRVFSegments(text) {
			if isLikelyRVFControlLine(segment) {
				continue
			}
			if hasUnexpectedScriptNoise(segment) {
				continue
			}
			if !looksLikeRVFHumanText(segment) {
				continue
			}
			if !slices.Contains(out, segment) {
				out = append(out, segment)
			}
		}
	}

	return strings.Join(out, "\n")
}

func splitRVFSegments(text string) []string {
	parts := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case '\r', '\n', '\u2028', '\u2029':
			return true
		default:
			return false
		}
	})

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func bestEffortText(blob []byte) string {
	if len(blob) == 0 {
		return ""
	}
	if looksLikeUTF16LE(blob) {
		if utf16Text := decodeUTF16CString(blob); utf16Text != "" {
			return utf16Text
		}
	}
	if isMostlyPrintable(blob) {
		return string(blob)
	}
	return ""
}

func utf8MostlyReadable(blob []byte) bool {
	if len(blob) == 0 || !utf8.Valid(blob) {
		return false
	}

	runes := []rune(string(blob))
	if len(runes) == 0 {
		return false
	}

	readable := 0
	for _, r := range runes {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r), unicode.IsSpace(r), unicode.IsPunct(r):
			readable++
		case unicode.Is(unicode.Han, r):
			readable++
		}
	}

	return readable*100/len(runes) >= 80
}

func isLikelyRVFControlLine(line string) bool {
	if strings.HasPrefix(line, "-8 ") || strings.HasPrefix(line, "-9 ") || strings.HasPrefix(line, "-7 ") {
		return true
	}
	if regexp.MustCompile(`^[0-9 \-]+$`).MatchString(line) {
		return true
	}
	controlTokens := []string{
		"StyleName",
		"Normal text",
		"SizeDouble",
		"FontName",
		"Unicode",
		"Standard",
		"Border.Width",
		"Border.InternalWidth",
		"Tabs",
		"LineSpacing",
		"Alignment",
		"rvaCenter",
		"CodeBlock",
		"TRVTable",
		"TBitmap",
		"Hyperlink",
		"Color",
		"clBlue",
		"clBlack",
		"fsUnderline",
		"微软雅黑",
		"宋体",
		"Consolas",
		"Courier New",
		"Symbol",
	}
	for _, token := range controlTokens {
		if strings.Contains(line, token) {
			return true
		}
	}
	return false
}

func looksLikeHumanText(text string) bool {
	if text == "" {
		return false
	}

	runes := []rune(text)
	if len(runes) < 4 {
		return false
	}

	hasASCIIWord := false
	hasHan := false
	hasSpaceOrPunct := false
	for _, r := range runes {
		if unicode.Is(unicode.Han, r) {
			hasHan = true
		}
		if unicode.IsLetter(r) && r <= unicode.MaxASCII {
			hasASCIIWord = true
		}
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			hasSpaceOrPunct = true
		}
	}

	switch {
	case hasASCIIWord && (hasHan || hasSpaceOrPunct):
		return true
	case hasHan && hasSpaceOrPunct:
		return true
	case hasHan && len(runes) >= 4:
		return true
	default:
		return false
	}
}

func looksLikeRVFHumanText(text string) bool {
	if !looksLikeHumanText(text) {
		return false
	}

	runes := []rune(text)
	hasHan := false
	hasASCIIWord := false
	hasSentenceSignal := false
	for _, r := range runes {
		if unicode.Is(unicode.Han, r) {
			hasHan = true
		}
		if unicode.IsLetter(r) && r <= unicode.MaxASCII {
			hasASCIIWord = true
		}
		if hasStrongRVFSentenceSignal(r) {
			hasSentenceSignal = true
		}
	}

	switch {
	case hasHan && hasSentenceSignal:
		return true
	case hasHan && hasASCIIWord && hasSentenceSignal:
		return true
	default:
		return false
	}
}

func hasStrongRVFSentenceSignal(r rune) bool {
	return strings.ContainsRune("。；：！？“”‘’（）《》【】…;:!?\"", r)
}

func hasUnexpectedScriptNoise(text string) bool {
	for _, r := range text {
		switch {
		case unicode.IsSpace(r), unicode.IsPunct(r), unicode.IsDigit(r):
			continue
		case unicode.Is(unicode.Han, r), unicode.IsLetter(r) && r <= unicode.MaxASCII:
			continue
		case unicode.In(r, unicode.Hiragana, unicode.Katakana):
			continue
		default:
			return true
		}
	}

	return false
}

type textRun struct {
	start int
	end   int
	text  string
}

func scanUTF16Runs(blob []byte) []string {
	runs := make([]textRun, 0, 16)

	for start := 0; start+8 < len(blob); start += 2 {
		pos := start
		runes := make([]rune, 0, 64)
		for pos+1 < len(blob) {
			v := binary.LittleEndian.Uint16(blob[pos : pos+2])
			r := rune(v)
			if !isLikelyTextRune(r) {
				break
			}
			runes = append(runes, r)
			pos += 2
		}
		if len(runes) < 4 {
			continue
		}

		text := strings.TrimSpace(string(runes))
		if len([]rune(text)) < 4 {
			continue
		}
		if textReadability(text) < 85 {
			continue
		}

		runs = append(runs, textRun{
			start: start,
			end:   pos,
			text:  text,
		})
	}

	// Keep only maximal non-noisy runs first.
	filtered := make([]textRun, 0, len(runs))
	for _, candidate := range runs {
		contained := false
		for _, other := range runs {
			if candidate.start == other.start && candidate.end == other.end {
				continue
			}
			if candidate.start >= other.start && candidate.end <= other.end && len([]rune(candidate.text)) <= len([]rune(other.text)) {
				contained = true
				break
			}
		}
		if !contained {
			filtered = append(filtered, candidate)
		}
	}

	out := make([]string, 0, len(filtered))
	seen := make(map[string]struct{})
	for _, run := range filtered {
		if _, ok := seen[run.text]; ok {
			continue
		}
		seen[run.text] = struct{}{}
		out = append(out, run.text)
	}
	return out
}

func isLikelyTextRune(r rune) bool {
	switch {
	case r == 0:
		return false
	case unicode.Is(unicode.Han, r):
		return true
	case unicode.IsLetter(r), unicode.IsDigit(r), unicode.IsSpace(r), unicode.IsPunct(r):
		return true
	default:
		return false
	}
}

func textReadability(text string) int {
	if text == "" {
		return 0
	}
	readable := 0
	runes := []rune(text)
	for _, r := range runes {
		if isLikelyTextRune(r) {
			readable++
		}
	}
	return readable * 100 / len(runes)
}

func isLikelyIDText(typeCode uint16, text string, raw []byte) bool {
	if text == "" {
		return false
	}

	switch typeCode {
	case 0x2001:
		if asciiIDPattern.MatchString(text) {
			return true
		}
		if text == "0" {
			return true
		}
	case 0x2201:
		if asciiTypedIDPattern.MatchString(text) {
			return true
		}
	}

	return isMostlyPrintable(raw[:min(len(raw), len(text)+1)])
}

func looksLikeUTF16LE(blob []byte) bool {
	if len(blob) < 4 || len(blob)%2 != 0 {
		return false
	}

	zeroHigh := 0
	pairs := 0
	for i := 0; i+1 < len(blob); i += 2 {
		lo := blob[i]
		hi := blob[i+1]
		if lo == 0 && hi == 0 {
			break
		}
		pairs++
		if hi == 0 && (lo == 0x09 || lo == 0x0a || lo == 0x0d || (lo >= 0x20 && lo < 0x7f)) {
			zeroHigh++
		}
	}

	if pairs == 0 {
		return false
	}
	return zeroHigh*100/pairs >= 70
}

func isMostlyPrintable(blob []byte) bool {
	if len(blob) == 0 {
		return false
	}
	printable := 0
	for _, b := range blob {
		if b == 0x09 || b == 0x0a || b == 0x0d || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return printable*100/len(blob) >= 85
}

func slicesCloneBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
