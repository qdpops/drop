package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"dropt/internal/wire"
)

func main() {
	priv, err := wire.GenerateStatic()
	if err != nil {
		panic(err)
	}
	psk := make([]byte, 16)
	if _, err := rand.Read(psk); err != nil {
		panic(err)
	}
	fmt.Println("# DROP credentials — keep the private key and PSK secret")
	fmt.Println("server_static_priv =", hex.EncodeToString(priv.Bytes()), "  (server only)")
	fmt.Println("server_static_pub  =", hex.EncodeToString(priv.PublicKey().Bytes()), "  (ship to client)")
	fmt.Println("psk                =", hex.EncodeToString(psk), "  (both sides)")
}
