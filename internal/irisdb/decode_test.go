package irisdb

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestDecodeRawValueKeepsMalformedBlobReferenceRaw(t *testing.T) {
	raw := makeBlobRefRaw(8, 64, 64, 64)

	decoded, err := decodeRawValue(make([]byte, 16), Field{Name: "Content", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedRaw {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedRaw)
	}
	if !bytes.Equal(decoded.Raw, raw) {
		t.Fatalf("Raw was not preserved")
	}
}

func TestDecodeRawValueDecodesValidBlobReference(t *testing.T) {
	payload := zlibPayload(t, []byte("hello"))
	data := append(make([]byte, 32), payload...)
	raw := makeBlobRefRaw(32, uint32(len(payload)), uint32(len(payload)), uint32(len(payload)))

	decoded, err := decodeRawValue(data, Field{Name: "Content", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedExternal {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedExternal)
	}
	if string(decoded.Bytes) != "hello" {
		t.Fatalf("Bytes = %q, want hello", decoded.Bytes)
	}
}

func TestDecodeRawValueUsesBlobFieldEncoding(t *testing.T) {
	tests := []struct {
		name     string
		typeCode uint16
		payload  []byte
		want     string
	}{
		{name: "memo tag ID", typeCode: 0x0010, payload: []byte("17fe007e5dcb427d982701aa6b03d652"), want: "17fe007e5dcb427d982701aa6b03d652"},
		{name: "blob configuration", typeCode: 0x000f, payload: []byte("DiaryFirstLocation=3"), want: "DiaryFirstLocation=3"},
		{name: "memo UTF-8", typeCode: 0x0010, payload: []byte("标签：工作"), want: "标签：工作"},
		{name: "wide memo short Chinese", typeCode: 0x0027, payload: fixedUTF16Raw("工作"), want: "工作"},
		{name: "wide memo ASCII-looking bytes", typeCode: 0x0027, payload: fixedUTF16Raw("慢慢"), want: "慢慢"},
		{name: "wide memo ASCII", typeCode: 0x0027, payload: fixedUTF16Raw("Markdown 示例"), want: "Markdown 示例"},
		{name: "wide memo odd length", typeCode: 0x0027, payload: []byte("abc"), want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := zlibPayload(t, test.payload)
			data := append(make([]byte, 32), payload...)
			raw := makeBlobRefRaw(32, uint32(len(test.payload)), uint32(len(payload)), uint32(len(payload)))
			decoded, err := decodeRawValue(data, Field{Name: "Value", TypeCode: test.typeCode}, raw)
			if err != nil {
				t.Fatalf("decodeRawValue() error = %v", err)
			}
			if decoded.Kind != DecodedExternal || decoded.String != test.want {
				t.Fatalf("decoded = %+v, want external text %q", decoded, test.want)
			}
			if decoded.External.DecodedText != test.want || !bytes.Equal(decoded.Bytes, test.payload) {
				t.Fatalf("blob metadata or original bytes changed: %+v", decoded.External)
			}
		})
	}
}

func TestDecodeSDPTextUsesDeclaredLength(t *testing.T) {
	text := "**Markdown 示例**\r\n"
	pack := make([]byte, 32)
	copy(pack, "SDP\x00")
	binary.BigEndian.PutUint32(pack[4:8], 1)
	binary.BigEndian.PutUint32(pack[8:12], 1)
	binary.BigEndian.PutUint32(pack[12:16], 4)
	copy(pack[16:20], "Text")
	binary.BigEndian.PutUint32(pack[24:28], uint32(len(text)))
	binary.BigEndian.PutUint32(pack[28:32], uint32(len(text)))
	pack = append(pack, []byte(text)...)
	pack = append(pack, []byte("not part of Text")...)

	if got := decodeSDPText(pack); got != text {
		t.Fatalf("decodeSDPText() = %q, want %q", got, text)
	}
	if got := decodeExternalText(pack); got != text {
		t.Fatalf("decodeExternalText() = %q, want %q", got, text)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "unsupported version", mutate: func(blob []byte) { binary.BigEndian.PutUint32(blob[4:8], 2) }},
		{name: "multiple entries", mutate: func(blob []byte) { binary.BigEndian.PutUint32(blob[8:12], 2) }},
		{name: "wrong name length", mutate: func(blob []byte) { binary.BigEndian.PutUint32(blob[12:16], 3) }},
		{name: "wrong entry name", mutate: func(blob []byte) { copy(blob[16:20], "Data") }},
		{name: "unsupported entry type", mutate: func(blob []byte) { binary.BigEndian.PutUint32(blob[20:24], 1) }},
		{name: "mismatched lengths", mutate: func(blob []byte) { binary.BigEndian.PutUint32(blob[24:28], 1) }},
		{name: "truncated data", mutate: func(blob []byte) {
			binary.BigEndian.PutUint32(blob[24:28], uint32(len(blob)))
			binary.BigEndian.PutUint32(blob[28:32], uint32(len(blob)))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malformed := bytes.Clone(pack)
			test.mutate(malformed)
			if got := decodeExternalText(malformed); got != "" {
				t.Fatalf("decodeExternalText() = %q, want no speculative text", got)
			}
		})
	}
}

func TestDecodeRawValueKeepsValidUnknownBlobReferenceMetadata(t *testing.T) {
	payload := []byte("not a compressed payload")
	data := append(make([]byte, 32), payload...)
	raw := makeBlobRefRaw(32, uint32(len(payload)), uint32(len(payload)), uint32(len(payload)))

	decoded, err := decodeRawValue(data, Field{Name: "Content", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedExternal {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedExternal)
	}
	if decoded.External == nil {
		t.Fatalf("External is nil")
	}
	if decoded.External.DataOffset != 32 || decoded.External.StoredSize != uint32(len(payload)) {
		t.Fatalf("unexpected external metadata: %+v", decoded.External)
	}
	if len(decoded.Bytes) != 0 || decoded.String != "" {
		t.Fatalf("unexpected decoded payload: bytes=%q string=%q", decoded.Bytes, decoded.String)
	}
}

func TestDecodeRawValueRejectsBlobReferenceWithNonZeroReservedFields(t *testing.T) {
	payload := zlibPayload(t, []byte("hello"))
	data := append(make([]byte, 32), payload...)
	raw := makeBlobRefRaw(32, uint32(len(payload)), uint32(len(payload)), uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[4:8], 99)

	decoded, err := decodeRawValue(data, Field{Name: "Title", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedRaw {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedRaw)
	}
}

func TestDecodeRawValueDecodesContentBlobReferenceWithNonZeroReservedFields(t *testing.T) {
	payload := zlibPayload(t, []byte("hello content"))
	data := append(make([]byte, 32), payload...)
	raw := makeBlobRefRaw(32, uint32(len(payload)), uint32(len(payload)), uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[4:8], 99)

	decoded, err := decodeRawValue(data, Field{Name: "Content", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedExternal {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedExternal)
	}
	if string(decoded.Bytes) != "hello content" {
		t.Fatalf("Bytes = %q, want hello content", decoded.Bytes)
	}
}

func TestDecodeRawValueRejectsUndecodableContentBlobReferenceWithNonZeroReservedFields(t *testing.T) {
	payload := []byte("not compressed")
	data := append(make([]byte, 32), payload...)
	raw := makeBlobRefRaw(32, uint32(len(payload)), uint32(len(payload)), uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[4:8], 99)

	decoded, err := decodeRawValue(data, Field{Name: "Content", TypeCode: 0x000f}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedRaw {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedRaw)
	}
}

func TestDecodeRawValueDecodesInt64(t *testing.T) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, 9876543210)

	decoded, err := decodeRawValue(nil, Field{Name: "Size", TypeCode: 0x0019}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedInt64 {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedInt64)
	}
	if decoded.Int64 != 9876543210 {
		t.Fatalf("Int64 = %d, want 9876543210", decoded.Int64)
	}
}

func TestDecodeRawValueDecodesFixedUTF16Text(t *testing.T) {
	raw := fixedUTF16Raw("工作")

	decoded, err := decodeRawValue(nil, Field{Name: "TagName", TypeCode: 0x1e18}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedString {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedString)
	}
	if decoded.String != "工作" {
		t.Fatalf("String = %q, want 工作", decoded.String)
	}
}

func TestDecodeRawValueRejectsNoisyFixedUTF16Text(t *testing.T) {
	raw := fixedUTF16Raw("工作\uE000")

	decoded, err := decodeRawValue(nil, Field{Name: "TagName", TypeCode: 0x1e18}, raw)
	if err != nil {
		t.Fatalf("decodeRawValue() error = %v", err)
	}
	if decoded.Kind != DecodedRaw {
		t.Fatalf("Kind = %s, want %s", decoded.Kind, DecodedRaw)
	}
}

func TestReadDecodedRowsUsesEncryptedPayload(t *testing.T) {
	password := []byte("secret")
	wantID := "aaed9485e7514a4c81730acee0005420"
	wantBlob := []byte("hello encrypted blob")

	db := encryptedTestFile(t, password, wantID, wantBlob)
	if !db.PasswordSupplied() {
		t.Fatalf("PasswordSupplied() = false, want true")
	}
	rows, err := db.ReadDecodedRows("Document", 0, 0)
	if err != nil {
		t.Fatalf("ReadDecodedRows() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("row count = %d, want 1", len(rows))
	}
	if got := rows[0].Values["Id"]; got.Kind != DecodedString || got.String != wantID {
		t.Fatalf("Id = kind %s string %q, want %q", got.Kind, got.String, wantID)
	}
	if got := rows[0].Values["Content"]; got.Kind != DecodedExternal || string(got.Bytes) != string(wantBlob) {
		t.Fatalf("Content = kind %s bytes %q, want %q", got.Kind, got.Bytes, wantBlob)
	}
}

func TestReadDecodedRowsKeepsEncryptedPayloadRawWithoutPassword(t *testing.T) {
	db := encryptedTestFile(t, []byte("secret"), "aaed9485e7514a4c81730acee0005420", []byte("hello encrypted blob"))
	db.password = nil
	db.cipher = nil
	db.hasPassword = false

	rows, err := db.ReadDecodedRows("Document", 0, 0)
	if err != nil {
		t.Fatalf("ReadDecodedRows() error = %v", err)
	}
	if got := rows[0].Values["Id"]; got.Kind != DecodedRaw {
		t.Fatalf("Id kind = %s, want raw", got.Kind)
	}
	if got := rows[0].Values["Content"]; got.Kind != DecodedRaw {
		t.Fatalf("Content kind = %s, want raw", got.Kind)
	}
}

func TestReadDecodedRowsKeepsEncryptedPayloadRawWithWrongPassword(t *testing.T) {
	db := encryptedTestFile(t, []byte("secret"), "aaed9485e7514a4c81730acee0005420", []byte("hello encrypted blob"))
	wrongPassword := []byte("wrong-secret")
	block, err := newBlowfishCipher(wrongPassword)
	if err != nil {
		t.Fatalf("newBlowfishCipher() error = %v", err)
	}
	db.password = wrongPassword
	db.cipher = block

	rows, err := db.ReadDecodedRows("Document", 0, 0)
	if err != nil {
		t.Fatalf("ReadDecodedRows() error = %v", err)
	}
	if got := rows[0].Values["Id"]; got.Kind != DecodedRaw {
		t.Fatalf("Id kind = %s, want raw", got.Kind)
	}
	if got := rows[0].Values["Content"]; got.Kind != DecodedRaw {
		t.Fatalf("Content kind = %s, want raw", got.Kind)
	}
}

func TestVerifyPasswordBlock(t *testing.T) {
	password := []byte("secret")
	data := make([]byte, passwordValidationOffset+passwordValidationLength)
	encrypted := encryptTinyDBEMCTSForTest(t, make([]byte, passwordValidationLength), password)
	copy(data[passwordValidationOffset:], encrypted)

	block, err := newBlowfishCipher(password)
	if err != nil {
		t.Fatalf("newBlowfishCipher() error = %v", err)
	}
	if !verifyPasswordBlock(data, block) {
		t.Fatalf("verifyPasswordBlock() = false, want true")
	}

	wrongBlock, err := newBlowfishCipher([]byte("wrong-secret"))
	if err != nil {
		t.Fatalf("newBlowfishCipher(wrong) error = %v", err)
	}
	if verifyPasswordBlock(data, wrongBlock) {
		t.Fatalf("verifyPasswordBlock() with wrong password = true, want false")
	}
}

func makeBlobRefRaw(dataOffset, plainSize, storedSize, areaSize uint32) []byte {
	raw := make([]byte, 24)
	binary.LittleEndian.PutUint32(raw[0:4], dataOffset)
	binary.LittleEndian.PutUint32(raw[8:12], plainSize)
	binary.LittleEndian.PutUint32(raw[12:16], storedSize)
	binary.LittleEndian.PutUint32(raw[16:20], areaSize)
	return raw
}

func encryptedTestFile(t *testing.T, password []byte, id string, blobPlain []byte) *File {
	t.Helper()

	blobOffset := 160
	blobStored := encryptTinyDBEMCTSForTest(t, zlibPayload(t, blobPlain), password)
	data := make([]byte, blobOffset+len(blobStored))
	copy(data[blobOffset:], blobStored)

	fields := []Field{
		{Name: "Id", TypeCode: 0x2001, RawWidth: 33, SlotOffset: 7},
		{Name: "Content", TypeCode: 0x000f, RawWidth: 24, SlotOffset: 40},
	}

	plainPayload := make([]byte, 33+24)
	copy(plainPayload[:33], append([]byte(id), 0))
	copy(plainPayload[33:], makeBlobRefRaw(uint32(blobOffset), uint32(len(blobPlain)), uint32(len(blobStored)), uint32(len(blobStored))))
	encryptedPayload := encryptTinyDBEMCTSForTest(t, plainPayload, password)

	record := make([]byte, 7+len(encryptedPayload))
	copy(record[:2], aaMagic)
	binary.LittleEndian.PutUint16(record[2:4], 1)
	copy(record[7:], encryptedPayload)
	copy(data[:len(record)], record)

	block, err := newBlowfishCipher(password)
	if err != nil {
		t.Fatalf("newBlowfishCipher() error = %v", err)
	}
	table := &Table{
		Name:        "Document",
		RecordCount: 1,
		Fields:      fields,
		Layout: &RecordLayout{
			RecordCount: 1,
			RecordRoot:  0,
			Stride:      len(record),
			BitmapSize:  1,
			FieldCount:  len(fields),
		},
	}
	return &File{
		data:        data,
		password:    slicesCloneBytes(password),
		cipher:      block,
		hasPassword: len(password) > 0,
		tables:      []*Table{table},
		byName:      map[string]*Table{"document": table},
	}
}

func encryptTinyDBEMCTSForTest(t *testing.T, data []byte, key []byte) []byte {
	t.Helper()

	block, err := newBlowfishCipher(key)
	if err != nil {
		t.Fatalf("newBlowfishCipher() error = %v", err)
	}

	feedback := make([]byte, cipherBlockSize)
	for idx := range feedback {
		feedback[idx] = 0xff
	}
	block.Encrypt(feedback, feedback)

	out := slicesCloneBytes(data)
	pos := 0
	remain := len(out)
	f := feedback

	for remain >= cipherBlockSize {
		plain := slicesCloneBytes(out[pos : pos+cipherBlockSize])
		xored := make([]byte, cipherBlockSize)
		for idx := range cipherBlockSize {
			xored[idx] = plain[idx] ^ f[idx]
		}

		ciphertext := make([]byte, cipherBlockSize)
		block.Encrypt(ciphertext, xored)
		copy(out[pos:pos+cipherBlockSize], ciphertext)

		nextFeedback := make([]byte, cipherBlockSize)
		for idx := range cipherBlockSize {
			nextFeedback[idx] = ciphertext[idx] ^ f[idx]
		}
		f = nextFeedback
		pos += cipherBlockSize
		remain -= cipherBlockSize
	}

	if remain > 0 {
		stream := make([]byte, cipherBlockSize)
		block.Encrypt(stream, f)
		for idx := range remain {
			out[pos+idx] ^= stream[idx]
		}
	}

	return out
}

func zlibPayload(t *testing.T, payload []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(payload); err != nil {
		t.Fatalf("write zlib payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zlib payload: %v", err)
	}
	return buf.Bytes()
}

func fixedUTF16Raw(text string) []byte {
	u16s := utf16.Encode([]rune(text))
	raw := make([]byte, 62)
	for idx, v := range u16s {
		binary.LittleEndian.PutUint16(raw[idx*2:idx*2+2], v)
	}
	return raw
}
