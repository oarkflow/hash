package sha512

import (
	md "crypto/sha512"
	"encoding/hex"
	
	"github.com/oarkflow/hash/utils"
)

func CreateHash(password string) string {
	hash := md.Sum512(utils.ToByte(password))
	return hex.EncodeToString(hash[:])
}

func ComparePasswordAndHash(password, hash string) bool {
	pHash := CreateHash(password)
	return utils.EqualFold(utils.ToUpper(pHash), utils.ToUpper(hash))
}
