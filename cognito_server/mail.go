package main

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
	"net/http"
	"time"
)

var (
	userPool = "ap-northeast-1_BPeYRhoZV"
	accessToken = "eyJraWQiOiJaTHBHTXRxZHU2UHcwUFBITytvbGxPQ3dpYjZkcUJVb1Z6dER2Y1lLYVRVPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJlOTBkOTk3Mi1kMzdjLTQ0YzAtYWQ3ZC0xNTlkOWI4MTBiZDciLCJldmVudF9pZCI6IjFhYjJkMTMyLWJiOTctNDUwNS05ODBkLWQwMGIxZGY3NWFhZiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1OTc5MjY1NzUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1ub3J0aGVhc3QtMS5hbWF6b25hd3MuY29tXC9hcC1ub3J0aGVhc3QtMV9CUGVZUmhvWlYiLCJleHAiOjE1OTc5MzAxNzUsImlhdCI6MTU5NzkyNjU3NSwianRpIjoiOGEyYWM1NTItMDZmMC00NmRkLTg0MGItMzFhYzZjODJjOTA4IiwiY2xpZW50X2lkIjoiMWdpaWk1dmw0YzRha2NuaTg0a2puODA5YjIiLCJ1c2VybmFtZSI6Im1peWF1Y2hpIn0.PfBwmxpD684VSyxMs-8mxKKdvFUgc8XUTu06MAVXucMxTQs9BZJYrul9IxecqfMRxe13E_O-P0K7x4JEYh9uDm-vlhJBXI_iF8dkz2zVwy_6mGOA8HhcRg9J4Ll281Mw2dmkGXPQmgxVD9jxM7XLAlL2cuwYXsTJUMuIgZREs5tFNDk4hJptHnbabyCJKquKRmUIJfXNGHmEVNQDQ-WeNyOGYy9NE5Qmb9oYo3IN9JvchbQvvvJJCTk_NQa3owEQB-fyOjeTZkY8TTRhTyI1VhfIuyMSOjK7gR0_Evpf6xX08sRf8N6S1AurL98hNOY1RFYW1DFqugKe7qQVGnCNNQ"
)

func main() {
	DecodeAPIToken()
}

func DecodeAPIToken() {

	_, err := TokenValidator(accessToken)
	if err != nil {
		print("認証しません")
		return
	}

	print("認証します")

	return
}

func getJSONWebKeys() (*jose.JSONWebKeySet, error) {

	jwks := &jose.JSONWebKeySet{}

	url := "https://cognito-idp.ap-northeast-1.amazonaws.com/" + userPool + "/.well-known/jwks.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(jwks); err != nil {
		return nil, err
	}

	return jwks, nil
}

// TokenValidator middleware implementation
func TokenValidator(tokenString string) (bool, error) {

	type Claims struct {
		Username string `json:"username"`
		ClientID string `json:"client_id"`
		TokenUse string `json:"token_use"`
		jwt.StandardClaims
	}
	var claims Claims

	_, err := jwt.ParseWithClaims(tokenString, &claims, lookupKey)
	if err != nil {
		return false, err
	}

	//時間切れの場合
	if claims.ExpiresAt < time.Now().Unix() {
		return false, err
	}

	//発行者が違う場合
	expectedIssuer := "https://cognito-idp.ap-northeast-1.amazonaws.com/" + userPool
	if claims.Issuer != expectedIssuer {
		return false, err
	}

	//トークンの種類が違う場合
	if claims.TokenUse != "access" {
		return false, err
	}

	_, err = usernameToAuthorization(claims.Username)
	if err != nil {
		return false, err
	}

	return true, nil
}

//ユーザーネームで識別して認可を与える場合。
func usernameToAuthorization(username string) (string, error) {
	switch username {
	case "miyauchi":
		return "君には管理者権限を与える", nil
	case "other":
		return "君には閲覧権限を与える", nil
	default:
		return "なんの権限もあげない", nil
	}
}

func lookupKey(token *jwt.Token) (interface{}, error) {
	jwks, err := getJSONWebKeys()
	if err != nil {
		return nil, err
	}

	kid := token.Header["kid"]

	var jwk jose.JSONWebKey
	for _, k := range jwks.Keys {
		if k.KeyID == kid {
			jwk = k
		}
	}

	return jwk.Key, nil
}
