package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

var (
	username = ""
	password = ""
	clientId = "1giii5vl4c4akcni84kjn809b2"

)

func main() {
	GetSystemAPIToken()
}

func GetSystemAPIToken() {
	input := cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(username),
			"PASSWORD": aws.String(password),
		},
		ClientId: aws.String(clientId),
	}
	svc := cognitoidentityprovider.New(session.New(&aws.Config{
		Credentials: credentials.AnonymousCredentials,
	}), aws.NewConfig().WithRegion("ap-northeast-1").WithMaxRetries(0))
	output, err := svc.InitiateAuth(&input)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(*output.AuthenticationResult)

	return
}