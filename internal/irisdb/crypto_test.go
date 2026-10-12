package irisdb

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"testing"
)

func TestDecryptEMCTSReferenceVectors(t *testing.T) {
	vectors := []string{
		"", "71", "71d3", "71d382", "71d38226", "71d382266c", "71d382266c2e", "71d382266c2e17",
		"57480f593e06472c", "57480f593e06472c90", "57480f593e06472c90a2", "57480f593e06472c90a2a1",
		"57480f593e06472c90a2a13d", "57480f593e06472c90a2a13d46", "57480f593e06472c90a2a13d4623",
		"57480f593e06472c90a2a13d46233e", "57480f593e06472cfde5ca6f758a83d6",
		"57480f593e06472cfde5ca6f758a83d6ca96c8e693a5f1",
	}
	for _, encoded := range vectors {
		t.Run(encoded, func(t *testing.T) {
			ciphertext, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(ciphertext)
			plain, err := decryptTinyDBEMCTS(ciphertext, []byte("synthetic-key"))
			if err != nil {
				t.Fatal(err)
			}
			for index, value := range plain {
				if value != byte(index) {
					t.Fatalf("byte %d = %02x, want %02x", index, value, index)
				}
			}
			if !bytes.Equal(ciphertext, original) {
				t.Fatal("decryption modified the input")
			}
		})
	}
}

func TestSHA0KnownAnswers(t *testing.T) {
	for _, test := range []struct{ input, digest string }{
		{"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"},
		{"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8"},
	} {
		digest := sha0Sum([]byte(test.input))
		if hex.EncodeToString(digest[:]) != test.digest {
			t.Fatalf("SHA-0(%q) = %x, want %s", test.input, digest, test.digest)
		}
	}
}

func TestResolveEncryption(t *testing.T) {
	password := []byte("synthetic-password")
	for _, safe := range []bool{false, true} {
		for _, supplied := range [][]byte{nil, []byte("wrong-password"), password} {
			data := encryptedHeaderForTest(t, password, safe)
			key, verified, err := resolveEncryption(data, supplied)
			if err != nil {
				t.Fatal(err)
			}
			wantVerified := bytes.Equal(supplied, password)
			if verified != wantVerified {
				t.Fatalf("safe=%t: verified=%t, want %t", safe, verified, wantVerified)
			}
			var wantKey []byte
			if !safe {
				wantKey = []byte(standardEncryptionKey)
			} else if wantVerified {
				wantKey = password
			}
			if !bytes.Equal(key, wantKey) {
				t.Fatalf("safe=%t: incorrect data key", safe)
			}
		}
	}
}

func TestResolveEncryptionRejectsInvalidMetadata(t *testing.T) {
	password := []byte("synthetic-password")
	for _, offset := range []int{fileInfoOffset, passwordLockOffset} {
		data := encryptedHeaderForTest(t, password, true)
		data[offset] ^= 1
		key, verified, err := resolveEncryption(data, password)
		if err != nil || key != nil || verified {
			t.Fatalf("corrupt header: key=%v verified=%t err=%v", key != nil, verified, err)
		}
	}
	data := encryptedHeaderForTest(t, password, true)
	for size := range len(data) {
		key, verified, err := resolveEncryption(data[:size], password)
		if err != nil || key != nil || verified {
			t.Fatalf("truncated header size %d accepted", size)
		}
	}
}

func TestResolveEncryptionUnencryptedAndUnsupported(t *testing.T) {
	password := []byte("synthetic-password")
	for _, encrypted := range []bool{false, true} {
		data := encryptedHeaderForTest(t, password, true)
		info := decodeHeaderBlock(data, fileInfoOffset, fileInfoLength)
		if !encrypted {
			info[38] = 0
		} else {
			info[40] = 'X'
		}
		binary.LittleEndian.PutUint32(info, crc32.ChecksumIEEE(info[4:]))
		copy(data[fileInfoOffset:], encryptTinyDBEMCTSForTest(t, info, make([]byte, cipherBlockSize)))
		key, verified, err := resolveEncryption(data, password)
		if key != nil || verified || (err != nil) != encrypted {
			t.Fatalf("encrypted=%t: key=%v verified=%t err=%v", encrypted, key != nil, verified, err)
		}
	}
}

func TestResolvedKeyDecodesRowsAndBlobs(t *testing.T) {
	password := []byte("synthetic-password")
	for _, safe := range []bool{false, true} {
		data := encryptedDatabaseForTest(t, password, safe)
		database, err := openBytes("synthetic.edf", data, password)
		if err != nil || !database.PasswordVerified() {
			t.Fatalf("open encrypted database: err=%v", err)
		}
		rows, err := database.ReadDecodedRows("Document", 0, 0)
		if err != nil || len(rows) != 1 || string(rows[0].Values["Content"].Bytes) != "synthetic blob" || rows[0].Values["Id"].String != "aaed9485e7514a4c81730acee0005420" {
			t.Fatalf("safe=%t: row/blob recovery failed", safe)
		}
		wrong, err := openBytes("synthetic.edf", data, []byte("wrong-password"))
		if err != nil || wrong.PasswordVerified() || safe && wrong.cipher != nil {
			t.Fatalf("safe=%t: wrong password accepted", safe)
		}
	}
}

func encryptedDatabaseForTest(t *testing.T, password []byte, safe bool) []byte {
	t.Helper()
	key := []byte(standardEncryptionKey)
	if safe {
		key = password
	}
	fixture := encryptedTestFile(t, key, "aaed9485e7514a4c81730acee0005420", []byte("synthetic blob"))
	const tableOffset, recordOffset, blobOffset = 0x7000, 0x8000, 0x9000
	data := make([]byte, blobOffset+len(fixture.data)-160)
	copy(data, encryptedHeaderForTest(t, password, safe))
	copy(data, "IrisDB\x00")
	binary.LittleEndian.PutUint32(data[dirOffsets[0]+4:], 1)
	binary.LittleEndian.PutUint32(data[dirOffsets[0]+8:], tableOffset)
	copy(data[tableOffset:], tableMagic)
	data[tableOffset+len(tableMagic)] = byte(len("Document"))
	copy(data[tableOffset+len(tableMagic)+1:], "Document")
	binary.LittleEndian.PutUint32(data[tableOffset+0x63:], 2)
	binary.LittleEndian.PutUint32(data[tableOffset+0x47:], 1)
	binary.LittleEndian.PutUint32(data[tableOffset+0x3f:], recordOffset)
	for index, field := range fixture.tables[0].Fields {
		offset := tableOffset + fieldDescBase + index*fieldDescSize
		data[offset] = byte(len(field.Name))
		copy(data[offset+1:], field.Name)
		binary.LittleEndian.PutUint16(data[offset+0x21:], field.TypeCode)
	}
	copy(data[recordOffset:], fixture.data[:64])
	plain, err := decryptTinyDBEMCTS(fixture.data[7:64], key)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(plain[33:], blobOffset)
	copy(data[recordOffset+7:], encryptTinyDBEMCTSForTest(t, plain, key))
	copy(data[blobOffset:], fixture.data[160:])
	return data
}

func encryptedHeaderForTest(t *testing.T, password []byte, safe bool) []byte {
	t.Helper()
	info := make([]byte, fileInfoLength)
	info[38] = 1
	info[39] = 8
	copy(info[40:], "Blowfish")
	if safe {
		info[72] = 1
	}
	lock := make([]byte, passwordLockLength)
	digest := sha0Sum(password)
	encoded := base64.StdEncoding.EncodeToString(digest[:])
	lock[5] = byte(len(encoded))
	copy(lock[6:], encoded)
	data := make([]byte, passwordLockOffset+passwordLockLength)
	for _, region := range []struct {
		offset int
		plain  []byte
	}{{fileInfoOffset, info}, {passwordLockOffset, lock}} {
		binary.LittleEndian.PutUint32(region.plain, crc32.ChecksumIEEE(region.plain[4:]))
		copy(data[region.offset:], encryptTinyDBEMCTSForTest(t, region.plain, make([]byte, cipherBlockSize)))
	}
	return data
}
