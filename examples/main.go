package main

import (
	"fmt"
	
	"github.com/oarkflow/hash"
)

func main() {
	h, err := hash.Make("test", "bcrypt")
	if err != nil {
		panic(err)
	}
	fmt.Println(hash.Match("test", h, "bcrypt"))
}
