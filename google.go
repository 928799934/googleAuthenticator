/*******************************************************
	File Name: google.go
	Author: An
	Mail:lijian@cmcm.com
	Created Time: 14/11/26 - 10:25:26
	Modify Time: 14/11/26 - 10:25:26
 *******************************************************/
package googleAuthenticator

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type GoogleAuthenticator struct {
	codeLength   float64
	tableFlipped map[string]int
}

func NewGoogleAuthenticator() *GoogleAuthenticator {
	return &GoogleAuthenticator{
		codeLength:   6,
		tableFlipped: arrayFlip(Table),
	}
}

// SetCodeLength Set the code length, should be >=6
func (this *GoogleAuthenticator) SetCodeLength(length float64) error {
	if length < 6 {
		return SecretLengthLssErr
	}
	this.codeLength = length
	return nil
}

// CreateSecret create new secret
// 16 characters, randomly chosen from the allowed base32 characters.
func (this *GoogleAuthenticator) CreateSecret(lens ...int) (string, error) {
	var (
		length int
		secret []string
	)
	// init length
	switch len(lens) {
	case 0:
		length = 16
	case 1:
		length = lens[0]
	default:
		return "", ParamErr
	}
	for i := 0; i < length; i++ {
		secret = append(secret, Table[rand.Intn(len(Table))])
	}
	return strings.Join(secret, ""), nil
}

// VerifyCode Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
func (this *GoogleAuthenticator) VerifyCode(secret, code string, discrepancy int64) (bool, error) {
	// now time
	curTimeSlice := time.Now().Unix() / 30
	for i := -discrepancy; i <= discrepancy; i++ {
		calculatedCode, err := this.GetCode(secret, curTimeSlice+i)
		if err != nil {
			return false, err
		}
		if calculatedCode == code {
			return true, nil
		}
	}
	return false, nil
}

// GetCode Calculate the code, with given secret and point in time
func (this *GoogleAuthenticator) GetCode(secret string, timeSlices ...int64) (string, error) {
	var timeSlice int64
	switch len(timeSlices) {
	case 0:
		timeSlice = time.Now().Unix() / 30
	case 1:
		timeSlice = timeSlices[0]
	default:
		return "", ParamErr
	}
	secretKey, err := this.base32Decode(secret)

	if err != nil {
		return "", err
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", timeSlice))
	if err != nil {
		return "", err
	}
	hm := HmacSha1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashpart := hm[offset : offset+4]
	fmt.Println(hashpart)
	value, err := strconv.ParseInt(hex.EncodeToString(hashpart), 16, 0)
	if err != nil {
		return "", err
	}
	fmt.Println(hex.EncodeToString(hashpart), value)
	value = value & 0x7FFFFFFF
	modulo := int64(math.Pow(10, this.codeLength))
	format := fmt.Sprintf("%%0%dd", int(this.codeLength))
	fmt.Println(format)
	return fmt.Sprintf(format, value%modulo), nil
}

// base32Decode Helper class to decode base32
func (this *GoogleAuthenticator) base32Decode(secret string) ([]byte, error) {
	var binaryString []byte
	if l := len(secret); l < 8 || l%8 != 0 {
		return binaryString, SecretLengthLssErr
	}
	paddingCharCount := strings.Count(secret, Table[32])
	paddingString, ok := allowedValues[paddingCharCount]
	if !ok {
		return binaryString, PaddingCharCountErr
	}
	secretArr := strings.Split(secret, "")
	paddingCharArr := secretArr[len(secretArr)-paddingCharCount:]
	if paddingString != strings.Join(paddingCharArr, "") {
		return binaryString, PaddingCharLocationErr
	}
	secretArr = secretArr[:len(secretArr)-paddingCharCount]
	for i, max := 0, len(secretArr); i < max; i += 8 {
		x := ""
		if n, _ := strconv.Atoi(secretArr[i]); "" == Table[n] {
			return binaryString, PaddingCharLocationErr
		}
		for j := 0; j < 8; j++ {
			x += fmt.Sprintf("%05b", this.tableFlipped[secretArr[i+j]])
		}
		eightBitsTmp := strings.Split(x, "")
		for x, max := 0, len(eightBitsTmp); x < max; x += 8 {
			num, _ := strconv.ParseInt(strings.Join(eightBitsTmp[x:x+8], ""), 2, 0)
			y := byte(num)
			if len(string(y)) > 0 || num == 48 {
				binaryString = append(binaryString, y)
			}
		}
	}
	return binaryString, nil
}
