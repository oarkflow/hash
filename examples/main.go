package main

import (
	"fmt"

	"github.com/oarkflow/hash"
)

func main() {
	h, err := hash.Make("test")
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
	fmt.Println(hash.Match("test", h))
}
