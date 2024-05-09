package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

const (
	data    = "Hello Tatu!"
	privKey = "<PRIVATE_KEY>"
)

type Response struct {
	Data []struct {
		Index string `json:"index"`
		Blob  string `json:"blob"`
	} `json:"data"`
}

func main() {

	blockId, err := sendBlobTX("<RPC_URL>", data, privKey) // This was just added.
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := http.Get("<BEACON_RPC_URL>" + blockId.BeaconRoot.String())
	if err != nil {
		log.Fatalln(err)
		return
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Fatalln(err)
		return
	}

	decodedBody := Response{}
	err = json.Unmarshal(body, &decodedBody)
	if err != nil {
		log.Fatalln(err)
	}

	for _, blob := range decodedBody.Data {
		log.Println(blob.Index, blob.Blob[:50])
	}

}
