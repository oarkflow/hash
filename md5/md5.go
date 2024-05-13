package md5

import (
	md "crypto/md5"
	"encoding/hex"
	
	"github.com/oarkflow/hash/utils"
)

func CreateHash(password string) string {
	hash := md.Sum([]byte(password))
	return hex.EncodeToString(hash[:])
}

func ComparePasswordAndHash(password, hash string) bool {
	pHash := CreateHash(password)
	return utils.EqualFold(utils.ToUpper(pHash), utils.ToUpper(hash))
}
