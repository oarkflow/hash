package sha256

import (
	md "crypto/sha256"
	"encoding/hex"
	
	"github.com/oarkflow/hash/utils"
)

func CreateHash(password string) string {
	hash := md.Sum256(utils.ToByte(password))
	return hex.EncodeToString(hash[:])
}

func ComparePasswordAndHash(password, hash string) bool {
	pHash := CreateHash(password)
	return utils.EqualFold(utils.ToUpper(pHash), utils.ToUpper(hash))
}
