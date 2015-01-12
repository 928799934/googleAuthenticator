/*******************************************************
	File Name: error.go
	Author: An
	Mail:lijian@cmcm.com
	Created Time: 14/11/26 - 10:23:52
	Modify Time: 14/11/26 - 10:23:52
 *******************************************************/
package googleAuthenticator

import "errors"

var (
	SecretLengthLssErr     = errors.New("secret length lss 6 error")
	SecretLengthErr        = errors.New("secret length error")
	PaddingCharCountErr    = errors.New("padding char count error")
	PaddingCharLocationErr = errors.New("padding char Location error")
	ParamErr               = errors.New("param error")
)
