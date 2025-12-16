package cryptohash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"runtime"
	"strings"

	"github.com/oarkflow/hash/utils"
	"golang.org/x/crypto/blake2b"
)

// Config holds hashing parameters
type Config struct {
	MemoryKB    uint32
	Iterations  uint32
	Parallelism uint32
	OutputLen   uint32
}

// LightweightConfig provides fast, memory-efficient defaults
func LightweightConfig() Config {
	return Config{
		MemoryKB:    4096,
		Iterations:  1,
		Parallelism: 1,
		OutputLen:   32,
	}
}

// FastConfig for maximum throughput
func FastConfig() Config {
	return Config{
		MemoryKB:    2048,
		Iterations:  1,
		Parallelism: 1,
		OutputLen:   32,
	}
}

// SecureConfig for higher security
func SecureConfig() Config {
	return Config{
		MemoryKB:    16384,
		Iterations:  1,
		Parallelism: uint32(runtime.NumCPU()),
		OutputLen:   32,
	}
}

// DefaultConfig provides the default configuration for password hashing
func DefaultConfig() Config {
	return FastConfig()
}

// Hash performs optimized password hashing
func Hash(password, salt []byte, cfg Config) []byte {
	if cfg.Parallelism == 0 {
		cfg.Parallelism = 1
	}
	if cfg.OutputLen == 0 {
		cfg.OutputLen = 32
	}

	// Use 512-byte blocks for L1 cache optimization
	const blockSize = 512
	blocks := (cfg.MemoryKB * 1024) / blockSize
	if blocks < 16 {
		blocks = 16
	}

	memory := make([]byte, blocks*blockSize)

	// Initialize with combined hash
	h, _ := blake2b.New256(nil)
	h.Write(password)
	h.Write(salt)

	var params [12]byte
	binary.LittleEndian.PutUint32(params[0:], cfg.MemoryKB)
	binary.LittleEndian.PutUint32(params[4:], cfg.Iterations)
	binary.LittleEndian.PutUint32(params[8:], cfg.Parallelism)
	h.Write(params[:])

	seed := h.Sum(nil)

	// Fast seed expansion - write seed directly as uint64
	seedU64 := make([]uint64, 4)
	for i := 0; i < 4; i++ {
		seedU64[i] = binary.LittleEndian.Uint64(seed[i*8:])
	}

	// Initialize first block
	for i := 0; i < blockSize; i += 32 {
		binary.LittleEndian.PutUint64(memory[i:], seedU64[0]^uint64(i))
		binary.LittleEndian.PutUint64(memory[i+8:], seedU64[1]^uint64(i+8))
		binary.LittleEndian.PutUint64(memory[i+16:], seedU64[2]^uint64(i+16))
		binary.LittleEndian.PutUint64(memory[i+24:], seedU64[3]^uint64(i+24))
	}

	// Ultra-fast block filling with minimal operations
	state0 := seedU64[0]
	state1 := seedU64[1]
	var i, j uint32
	for i = uint32(1); i < blocks; i++ {
		prevOff := (i - 1) * blockSize
		currOff := i * blockSize

		for j = 0; j < blockSize; j += 16 {
			v0 := binary.LittleEndian.Uint64(memory[prevOff+j:])
			v1 := binary.LittleEndian.Uint64(memory[prevOff+j+8:])

			v0 ^= state0
			v1 ^= state1

			v0 += 0x9E3779B97F4A7C15
			v1 += 0x517CC1B727220A95

			binary.LittleEndian.PutUint64(memory[currOff+j:], v0)
			binary.LittleEndian.PutUint64(memory[currOff+j+8:], v1)

			state0 = v0
			state1 = v1
		}
	}

	// Optimized mixing passes
	for pass := uint32(0); pass < cfg.Iterations; pass++ {
		mixPass(memory, blocks, blockSize, pass)
	}

	// Final hash
	h.Reset()
	lastBlock := (blocks - 1) * blockSize
	h.Write(memory[lastBlock : lastBlock+blockSize])

	finalHash := h.Sum(nil)
	output := make([]byte, cfg.OutputLen)
	copy(output, finalHash)

	return output
}

// mixPass performs a single mixing pass with maximum efficiency
func mixPass(memory []byte, blocks uint32, blockSize uint32, pass uint32) {
	state := uint64(pass)*0x9E3779B97F4A7C15 + uint64(blocks)

	for i := uint32(1); i < blocks; i++ {
		offset := i * blockSize

		// Simple data-dependent indexing
		idx0 := binary.LittleEndian.Uint64(memory[offset:])
		refBlock := uint32(idx0 % uint64(i))
		refOffset := refBlock * blockSize

		// Process 64 bytes at a time (8x uint64)
		for j := uint32(0); j < blockSize; j += 64 {
			p := offset + j
			r := refOffset + j

			// Load 8 uint64 values
			c0 := binary.LittleEndian.Uint64(memory[p:])
			c1 := binary.LittleEndian.Uint64(memory[p+8:])
			c2 := binary.LittleEndian.Uint64(memory[p+16:])
			c3 := binary.LittleEndian.Uint64(memory[p+24:])
			c4 := binary.LittleEndian.Uint64(memory[p+32:])
			c5 := binary.LittleEndian.Uint64(memory[p+40:])
			c6 := binary.LittleEndian.Uint64(memory[p+48:])
			c7 := binary.LittleEndian.Uint64(memory[p+56:])

			r0 := binary.LittleEndian.Uint64(memory[r:])
			r1 := binary.LittleEndian.Uint64(memory[r+8:])
			r2 := binary.LittleEndian.Uint64(memory[r+16:])
			r3 := binary.LittleEndian.Uint64(memory[r+24:])
			r4 := binary.LittleEndian.Uint64(memory[r+32:])
			r5 := binary.LittleEndian.Uint64(memory[r+40:])
			r6 := binary.LittleEndian.Uint64(memory[r+48:])
			r7 := binary.LittleEndian.Uint64(memory[r+56:])

			// Enhanced mixing for better diffusion
			c0 = c0 ^ r0 + state
			c1 = c1 ^ r1 + state
			c2 = c2 ^ r2 + state
			c3 = c3 ^ r3 + state
			c4 = c4 ^ r4 + state
			c5 = c5 ^ r5 + state
			c6 = c6 ^ r6 + state
			c7 = c7 ^ r7 + state

			// Additional diffusion rounds
			c0 = (c0 << 13) | (c0 >> 51)
			c1 = (c1 << 17) | (c1 >> 47)
			c2 = (c2 << 21) | (c2 >> 43)
			c3 = (c3 << 25) | (c3 >> 39)
			c4 = (c4 << 13) | (c4 >> 51)
			c5 = (c5 << 17) | (c5 >> 47)
			c6 = (c6 << 21) | (c6 >> 43)
			c7 = (c7 << 25) | (c7 >> 39)

			c0 ^= state
			c1 ^= state
			c2 ^= state
			c3 ^= state
			c4 ^= state
			c5 ^= state
			c6 ^= state
			c7 ^= state

			// Write back
			binary.LittleEndian.PutUint64(memory[p:], c0)
			binary.LittleEndian.PutUint64(memory[p+8:], c1)
			binary.LittleEndian.PutUint64(memory[p+16:], c2)
			binary.LittleEndian.PutUint64(memory[p+24:], c3)
			binary.LittleEndian.PutUint64(memory[p+32:], c4)
			binary.LittleEndian.PutUint64(memory[p+40:], c5)
			binary.LittleEndian.PutUint64(memory[p+48:], c6)
			binary.LittleEndian.PutUint64(memory[p+56:], c7)

			state = c0 ^ c1 ^ c2 ^ c3
		}
	}
}

// CreateHash generates a hash from the password using default configuration
func CreateHash(password string) (string, error) {
	// Generate random 16-byte salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Hash with default config
	hash := Hash(utils.ToByte(password), salt, DefaultConfig())

	// Encode as base64(salt)$base64(hash)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	return saltB64 + "$" + hashB64, nil
}

// ComparePasswordAndHash compares a password with a hash
func ComparePasswordAndHash(password, encodedHash string) (bool, error) {
	// Split the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 2 {
		return false, errors.New("invalid hash format")
	}

	// Decode salt and hash
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}

	expectedHash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	// Verify
	if !Verify(utils.ToByte(password), salt, expectedHash, DefaultConfig()) {
		return false, errors.New("password does not match")
	}

	return true, nil
}

// Verify checks if a password matches a hash in constant time
func Verify(password, salt []byte, hash []byte, cfg Config) bool {
	computed := Hash(password, salt, cfg)
	return subtle.ConstantTimeCompare(computed, hash) == 1
}
