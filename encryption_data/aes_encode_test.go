package encryption_data

import "testing"

const AESKeyTest = "wHDB0Ml9yPbGCM9RCoHERhpVu3IIPXu8" // 对称秘钥长度必须是16的倍数

func TestEnCode(t *testing.T) {

	var text = "123456"

	str := AesEncode(text, AESKeyTest)

	t.Log(str)

	text2 := AesDEncode(str, AESKeyTest)

	t.Log(text2)
}

