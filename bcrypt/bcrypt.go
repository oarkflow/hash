package bcrypt

import (
	crypt "golang.org/x/crypto/bcrypt"
	
	"github.com/oarkflow/hash/utils"
)

func CreateHash(password string) (string, error) {
	hash, err := crypt.GenerateFromPassword(utils.ToByte(password), 8)
	return utils.FromByte(hash), err
}

func ComparePasswordAndHash(password, hash string) error {
	return crypt.CompareHashAndPassword(utils.ToByte(hash), utils.ToByte(password))
}
