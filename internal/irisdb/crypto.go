package irisdb

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/blowfish"
)

const cipherBlockSize = blowfish.BlockSize

const (
	passwordValidationOffset = 0x80c
	passwordValidationLength = 0x90d - 0x80c - cipherBlockSize
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
		block.Encrypt(stream, f)
		for idx := range remain {
			out[pos+idx] ^= stream[idx]
		}
	}

	return out
}

func verifyPasswordBlock(data []byte, block cipher.Block) bool {
	if block == nil || len(data) < passwordValidationOffset+passwordValidationLength {
		return false
	}
	decrypted := decryptTinyDBEMCTSWithBlock(
		data[passwordValidationOffset:passwordValidationOffset+passwordValidationLength],
		block,
	)
	for _, b := range decrypted {
		if b != 0 {
			return false
		}
	}
	return true
}

func xorBytes(left []byte, right []byte) []byte {
	n := min(len(left), len(right))
	out := make([]byte, n)
	for idx := range n {
		out[idx] = left[idx] ^ right[idx]
	}
	return out
}
