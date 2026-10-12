package irisdb

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math/bits"

	"golang.org/x/crypto/blowfish"
)

const cipherBlockSize = blowfish.BlockSize

const (
	fileInfoOffset        = 0x907
	fileInfoLength        = 109
	passwordLockOffset    = fileInfoOffset + fileInfoLength
	passwordLockLength    = 360
	standardEncryptionKey = "!@#$%^&*()"
)

func newBlowfishCipher(key []byte) (cipher.Block, error) {
	if len(key) == 0 {
		return nil, nil
	}
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init blowfish cipher: %w", err)
	}
	return block, nil
}

func decryptTinyDBEMCTS(data []byte, key []byte) ([]byte, error) {
	block, err := newBlowfishCipher(key)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return slicesCloneBytes(data), nil
	}
	return decryptTinyDBEMCTSWithBlock(data, block), nil
}

func decryptTinyDBEMCTSWithBlock(data []byte, block cipher.Block) []byte {
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
		chunk := slicesCloneBytes(out[pos : pos+cipherBlockSize])
		nextFeedback := xorBytes(chunk, f)

		decrypted := make([]byte, cipherBlockSize)
		block.Decrypt(decrypted, chunk)
		for idx := range decrypted {
			decrypted[idx] ^= f[idx]
		}
		copy(out[pos:pos+cipherBlockSize], decrypted)

		f = nextFeedback
		pos += cipherBlockSize
		remain -= cipherBlockSize
	}

	if remain > 0 {
		stream := make([]byte, cipherBlockSize)
		for idx := range remain {
			block.Encrypt(stream, f)
			ciphertext := out[pos+idx]
			copy(f, f[1:])
			f[cipherBlockSize-1] ^= ciphertext
			out[pos+idx] ^= stream[0]
		}
	}

	return out
}

func resolveEncryption(data, password []byte) ([]byte, bool, error) {
	info := decodeHeaderBlock(data, fileInfoOffset, fileInfoLength)
	if info == nil || info[38] != 1 {
		return nil, false, nil
	}
	if info[39] != 8 || string(info[40:48]) != "Blowfish" || info[72] > 1 {
		return nil, false, fmt.Errorf("unsupported EDF encryption configuration")
	}
	lock := decodeHeaderBlock(data, passwordLockOffset, passwordLockLength)
	verified := false
	if len(password) > 0 && lock != nil && lock[5] == 28 {
		digest := sha0Sum(password)
		expected := base64.StdEncoding.EncodeToString(digest[:])
		verified = subtle.ConstantTimeCompare(lock[6:34], []byte(expected)) == 1
	}
	if info[72] == 0 {
		return []byte(standardEncryptionKey), verified, nil
	}
	if !verified {
		return nil, false, nil
	}
	return slicesCloneBytes(password), true, nil
}

func decodeHeaderBlock(data []byte, offset, length int) []byte {
	if offset < 0 || length < 4 || offset > len(data) || length > len(data)-offset {
		return nil
	}
	block, err := blowfish.NewCipher(make([]byte, cipherBlockSize))
	if err != nil {
		return nil
	}
	decoded := decryptTinyDBEMCTSWithBlock(data[offset:offset+length], block)
	if binary.LittleEndian.Uint32(decoded) != crc32.ChecksumIEEE(decoded[4:]) {
		return nil
	}
	return decoded
}

func sha0Sum(input []byte) [20]byte {
	data := slicesCloneBytes(input)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0)
	}
	data = binary.BigEndian.AppendUint64(data, uint64(len(input))*8)
	state := [5]uint32{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}
	for offset := 0; offset < len(data); offset += 64 {
		var words [80]uint32
		for index := range 16 {
			words[index] = binary.BigEndian.Uint32(data[offset+index*4:])
		}
		for index := 16; index < len(words); index++ {
			words[index] = words[index-3] ^ words[index-8] ^ words[index-14] ^ words[index-16]
		}
		first, second, third, fourth, fifth := state[0], state[1], state[2], state[3], state[4]
		for index, word := range words {
			var function, constant uint32
			switch {
			case index < 20:
				function, constant = (second&third)|(^second&fourth), 0x5a827999
			case index < 40:
				function, constant = second^third^fourth, 0x6ed9eba1
			case index < 60:
				function, constant = (second&third)|(second&fourth)|(third&fourth), 0x8f1bbcdc
			default:
				function, constant = second^third^fourth, 0xca62c1d6
			}
			first, second, third, fourth, fifth = bits.RotateLeft32(first, 5)+function+fifth+constant+word, first, bits.RotateLeft32(second, 30), third, fourth
		}
		state[0] += first
		state[1] += second
		state[2] += third
		state[3] += fourth
		state[4] += fifth
	}
	var result [20]byte
	for index, word := range state {
		binary.BigEndian.PutUint32(result[index*4:], word)
	}
	return result
}

func xorBytes(left []byte, right []byte) []byte {
	n := min(len(left), len(right))
	out := make([]byte, n)
	for idx := range n {
		out[idx] = left[idx] ^ right[idx]
	}
	return out
}
