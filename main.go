package main

import "fmt"

func main() {
	teamID := "XXXXXXXXXX"

	clientID := "XXXX"

	keyID := "XXXXXXXXXX"

	secret := `-----BEGIN PRIVATE KEY-----
XXXX
-----END PRIVATE KEY-----`

	secret, err := generateClientSecret(secret, teamID, clientID, keyID)
	if err != nil {
		panic(err)
	}
	fmt.Println(secret)
}
