package irisdb

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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
	DecodedInt64    DecodedKind = "int64"
	DecodedDate     DecodedKind = "date"
	DecodedTime     DecodedKind = "time"
	DecodedDateTime DecodedKind = "datetime"
	DecodedExternal DecodedKind = "external"
)

var (
	asciiIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	asciiTypedIDPattern = regexp.MustCompile(`^[0-9]-[0-9a-f]{32}$`)
	asciiIDSearch       = regexp.MustCompile(`[0-9a-f]{32}`)
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

const maxBlobDecodeInputSize = 32 << 20

type DecodedValue struct {
	Kind     DecodedKind
	TypeCode uint16
	Raw      []byte
	String   string
	Bool     bool
	Int32    int32
	Int64    int64
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

	return decodeRawValueWithPassword(f.data, *field, raw, f.password)
}

func decodeRawValue(data []byte, field Field, raw []byte) (DecodedValue, error) {
	return decodeRawValueWithPassword(data, field, raw, nil)
}

func decodeRawValueWithPassword(data []byte, field Field, raw []byte, password []byte) (DecodedValue, error) {
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
	case 0x0019:
		if len(raw) < 8 {
			return DecodedValue{}, ErrShortRead
		}
		value.Kind = DecodedInt64
		value.Int64 = int64(binary.LittleEndian.Uint64(raw[:8]))
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
		if text = extractIDText(raw, field.TypeCode); text != "" {
			value.Kind = DecodedString
			value.String = text
			value.Bytes = []byte(text)
			return value, nil
		}
		return value, nil
	case 0x1e18, 0x4018, 0x8018:
		if text, ok := decodeFixedUTF16Text(raw); ok {
			value.Kind = DecodedString
			value.String = text
			value.Bytes = []byte(text)
			return value, nil
		}
		return value, nil
	case 0x000f, 0x0010, 0x0027:
		ref, ok, err := decodeBlobRef(data, raw, password, allowNonZeroBlobReserved(field))
		if err != nil {
			return DecodedValue{}, err
		}
		if ok {
			ref.DecodedText = decodeExternalFieldText(ref.DecodedBytes, field.TypeCode)
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

func allowNonZeroBlobReserved(field Field) bool {
	return strings.EqualFold(field.Name, "Content")
}

func canDecodeFieldType(typeCode uint16) bool {
	switch typeCode {
	case 0x0003, 0x0005, 0x0009, 0x000a, 0x000b, 0x000f, 0x0010,
		0x0019, 0x0027, 0x1e18, 0x2001, 0x2201, 0x4018, 0x8018:
		return true
	default:
		return false
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

func shouldTryDecryptedField(typeCode uint16) bool {
	switch typeCode {
	case 0x000f, 0x0010, 0x0027, 0x1e18, 0x2001, 0x2201, 0x4018, 0x8018:
		return true
	default:
		return false
	}
}

func decodeBlobRef(data []byte, raw []byte, password []byte, allowNonZeroReserved bool) (*BlobRef, bool, error) {
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
	nonZeroReserved := ref.Reserved0 != 0 || ref.Reserved1 != 0
	if nonZeroReserved && !allowNonZeroReserved {
		return nil, false, nil
	}

	size := ref.StoredSize
	if size == 0 {
		size = ref.AreaSize
	}
	if size == 0 {
		return ref, true, nil
	}

	if ref.DataOffset > uint32(len(data)) || size > uint32(len(data))-ref.DataOffset {
		return nil, false, nil
	}
	if size > maxBlobDecodeInputSize {
		if nonZeroReserved {
			return nil, false, nil
		}
		return ref, true, nil
	}
	end := int(ref.DataOffset + size)

	decoded, ok := decodeBlobPayload(data[ref.DataOffset:end], password)
	if !ok {
		if nonZeroReserved {
			return nil, false, nil
		}
		return ref, true, nil
	}

	ref.DecodedBytes = decoded
	return ref, true, nil
}

func decodeBlobPayload(blob []byte, password []byte) ([]byte, bool) {
	candidates := make([]blobPayloadCandidate, 0, 8)
	addBlobPayloadCandidates(&candidates, blob)
	if len(password) > 0 {
		decrypted, err := decryptTinyDBEMCTS(blob, password)
		if err == nil {
			addBlobPayloadCandidates(&candidates, decrypted)
		}
	}
	if len(candidates) == 0 {
		return nil, false
	}

	slices.SortFunc(candidates, func(left, right blobPayloadCandidate) int {
		if left.score != right.score {
			return right.score - left.score
		}
		return len(left.bytes) - len(right.bytes)
	})
	return candidates[0].bytes, true
}

type blobPayloadCandidate struct {
	score int
	bytes []byte
}

func addBlobPayloadCandidates(candidates *[]blobPayloadCandidate, blob []byte) {
	for skip := 0; skip < min(8, len(blob)); skip++ {
		sliced := blob[skip:]
		if looksLikeDirectPayload(sliced) {
			*candidates = append(*candidates, blobPayloadCandidate{
				score: 220 + payloadReadableScore(sliced[:min(len(sliced), 256)]),
				bytes: slicesCloneBytes(sliced),
			})
		}
	}

	for skip := 0; skip < min(5, len(blob)); skip++ {
		sliced := blob[skip:]
		if decoded, err := tryZlib(sliced); err == nil {
			*candidates = append(*candidates, blobPayloadCandidate{
				score: scoreDecodedPayload(decoded),
				bytes: decoded,
			})
		}
		if decoded, err := tryRawDeflate(sliced); err == nil {
			score := scoreDecodedPayload(decoded)
			if score >= 32 {
				*candidates = append(*candidates, blobPayloadCandidate{
					score: score,
					bytes: decoded,
				})
			}
		}
		if decoded, err := tryGzip(sliced); err == nil {
			*candidates = append(*candidates, blobPayloadCandidate{
				score: scoreDecodedPayload(decoded),
				bytes: decoded,
			})
		}
	}
}

func looksLikeDirectPayload(blob []byte) bool {
	switch {
	case bytes.HasPrefix(blob, []byte("PK\x03\x04")):
		return true
	case bytes.HasPrefix(blob, []byte("%PDF-")):
		return true
	case bytes.HasPrefix(blob, []byte("7z\xbc\xaf\x27\x1c")):
		return true
	case bytes.HasPrefix(blob, []byte("Rar!")):
		return true
	case bytes.HasPrefix(blob, []byte{0x1f, 0x8b}):
		return true
	default:
		return false
	}
}

func scoreDecodedPayload(blob []byte) int {
	score := payloadReadableScore(blob[:min(len(blob), 256)])
	if bytes.HasPrefix(blob, []byte("SDP")) || bytes.HasPrefix(blob, []byte("-8 ")) || bytes.HasPrefix(blob, []byte("PK")) {
		score += 100
	}
	if bytes.HasPrefix(blob, []byte("7z\xbc\xaf\x27\x1c")) || bytes.HasPrefix(blob, []byte("%PDF-")) || bytes.HasPrefix(blob, []byte("Rar!")) {
		score += 100
	}
	return score
}

func payloadReadableScore(blob []byte) int {
	if len(blob) == 0 {
		return 0
	}
	printable := 0
	for _, b := range blob {
		if b == 9 || b == 10 || b == 13 || (32 <= b && b < 127) {
			printable++
		}
	}
	return printable
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

func tryGzip(blob []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(blob))
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

func tryRawDeflate(blob []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(blob))
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

func extractIDText(raw []byte, typeCode uint16) string {
	text := make([]byte, 0, len(raw))
	for _, b := range raw {
		if b >= 0x20 && b < 0x7f {
			text = append(text, b)
		}
	}
	if len(text) == 0 {
		return ""
	}
	if typeCode == 0x2201 && len(text) >= 34 {
		for idx := 0; idx+34 <= len(text); idx++ {
			candidate := string(text[idx : idx+34])
			if asciiTypedIDPattern.MatchString(candidate) {
				return candidate
			}
		}
	}
	match := asciiIDSearch.Find(text)
	if match == nil {
		return ""
	}
	return string(match)
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

func decodeFixedUTF16Text(raw []byte) (string, bool) {
	if len(raw) < 2 || len(raw)%2 != 0 {
		return "", false
	}
	text := strings.TrimSpace(decodeUTF16CString(raw))
	if text == "" {
		return "", false
	}
	if hasUnexpectedScriptNoise(text) {
		return "", false
	}
	if textReadability(text) < 85 {
		return "", false
	}
	return text, true
}

func decodeExternalFieldText(blob []byte, typeCode uint16) string {
	if typeCode == 0x0027 {
		if len(blob)%2 != 0 {
			return ""
		}
		return decodeUTF16CString(blob)
	}
	return decodeExternalText(blob)
}

func decodeExternalText(blob []byte) string {
	if bytes.HasPrefix(blob, []byte("SDP\x00")) {
		return decodeSDPText(blob)
	}
	if text := decodeRVFText(blob); text != "" {
		return text
	}
	if !bytes.ContainsRune(blob, '\x00') && utf8MostlyReadable(blob) {
		return string(blob)
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
	if binary.BigEndian.Uint32(blob[4:8]) != 1 || binary.BigEndian.Uint32(blob[8:12]) != 1 {
		return ""
	}
	if binary.BigEndian.Uint32(blob[12:16]) != 4 || string(blob[16:20]) != "Text" || binary.BigEndian.Uint32(blob[20:24]) != 0 {
		return ""
	}
	textSize := binary.BigEndian.Uint32(blob[28:32])
	if binary.BigEndian.Uint32(blob[24:28]) != textSize || uint64(textSize) > uint64(len(blob)-32) {
		return ""
	}
	body := blob[32 : 32+int(textSize)]
	if !utf8MostlyReadable(body) {
		return ""
	}
	return string(body)
}

func decodeRVFText(blob []byte) string {
	if !bytes.HasPrefix(blob, []byte("-8 1 3 2\r\n")) && !bytes.HasPrefix(blob, []byte("-8 1 3 1\r\n")) {
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
	out := make([]string, 0, 16)
	seen := make(map[string]struct{})

	for start := 0; start+8 < len(blob); {
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
			start += 2
			continue
		}

		text := strings.TrimSpace(string(runes))
		if len([]rune(text)) < 4 {
			start = max(start+2, pos)
			continue
		}
		if textReadability(text) < 85 {
			start = max(start+2, pos)
			continue
		}

		if _, ok := seen[text]; !ok {
			seen[text] = struct{}{}
			out = append(out, text)
		}
		start = max(start+2, pos)
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
