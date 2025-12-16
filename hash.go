package hash

import (
	"github.com/oarkflow/hash/argon2id"
	"github.com/oarkflow/hash/bcrypt"
	"github.com/oarkflow/hash/cryptohash"
	"github.com/oarkflow/hash/md5"
	"github.com/oarkflow/hash/sha1"
	"github.com/oarkflow/hash/sha256"
	"github.com/oarkflow/hash/sha512"
)

func Make(password string, algo ...string) (hash string, err error) {
	algorithm := "cryptohash"
	if len(algo) > 0 {
		algorithm = algo[0]
	}
	switch algorithm {
	case "bcrypt":
		return bcrypt.CreateHash(password)
	case "md5":
		return md5.CreateHash(password), nil
	case "sha1":
		return sha1.CreateHash(password), nil
	case "sha256":
		return sha256.CreateHash(password), nil
	case "sha512":
		return sha512.CreateHash(password), nil
	case "argon2id":
		return argon2id.CreateHash(password)
	default:
		return cryptohash.CreateHash(password)
	}
}

func Match(password string, hash string, algo ...string) (match bool, err error) {
	algorithm := "cryptohash"
	if len(algo) > 0 {
		algorithm = algo[0]
	}
	switch algorithm {
	case "bcrypt":
		return true, bcrypt.ComparePasswordAndHash(password, hash)
	case "md5":
		return md5.ComparePasswordAndHash(password, hash), nil
	case "sha1":
		return sha1.ComparePasswordAndHash(password, hash), nil
	case "sha256":
		return sha256.ComparePasswordAndHash(password, hash), nil
	case "sha512":
		return sha512.ComparePasswordAndHash(password, hash), nil
	case "argon2id":
		return argon2id.ComparePasswordAndHash(password, hash)
	default:
		return cryptohash.ComparePasswordAndHash(password, hash)
	}
}
