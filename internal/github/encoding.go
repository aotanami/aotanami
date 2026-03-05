/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
*/

package github

import "encoding/base64"

// base64StdEncoding encodes data to standard base64 string.
func base64StdEncoding(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64StdDecoding decodes base64 data.
func base64StdDecoding(dst, src []byte) (int, error) {
	return base64.StdEncoding.Decode(dst, src)
}
