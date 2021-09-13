package encryption_data

import (
	"encoding/base64"
	"fmt"
)

// AesEncode is 加密
func AesEncode(data string, AESKey string) (encryptedStr string) {
	AesKey := []byte(AESKey)

	fmt.Printf("明文: %s\n秘钥: %s\n", data, string(AesKey))
	encrypted, err := AesEncryptCBC([]byte(data), AesKey)
	if err != nil {
		fmt.Printf("失败: %s\n", err)
		return  ""
	}
	encryptedStr = base64.StdEncoding.EncodeToString(encrypted)

	fmt.Printf("加密后: %s\n", encryptedStr)
	return
}

// AesDEncode is 解密
func AesDEncode(encryptedStr string, AESKey string) (originStr string) {
	AesKey := []byte(AESKey)

	encrypted, err := base64.StdEncoding.DecodeString(encryptedStr)

	if err != nil {
		fmt.Printf("DecodeString: %s\n", err)
		return ""
	}

	fmt.Printf("encryptedStr: %s\n", encryptedStr)
	origin, err := AesDecryptCBC(encrypted, AesKey)
	if err != nil {
		return ""
	}
	fmt.Printf("解密后明文: %s\n", string(origin))
	originStr = string(origin)
	return
}