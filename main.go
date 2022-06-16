package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"os"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/joho/godotenv"

	cognito "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// This is not the password, it is the flow of the authentication only
// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow.html
const flowUsernamePassword = "USER_PASSWORD_AUTH"
const flowRefreshToken = "REFRESH_TOKEN_AUTH"

// Secret hash is not a client secret itself, but a base64 encoded hmac-sha256 hash.
func computeSecretHash(clientSecret string, username string, clientId string) string {
    mac := hmac.New(sha256.New, []byte(clientSecret))
    mac.Write([]byte(username + clientId))

    return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Login handles login scenario.
func main() {

    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    AppClientID := os.Getenv("APP_CLIENT_ID")
    AppClientSecret := os.Getenv("APP_CLIENT_SECRET")

    username := os.Getenv("USERNAME")
    password := os.Getenv("PASSWORD")
    refresh := os.Getenv("REFRESH")
    refreshToken := os.Getenv("REFRESH_TOKEN")

    flow := aws.String(flowUsernamePassword)
    params := map[string]*string{
        "USERNAME": aws.String(username),
        "PASSWORD": aws.String(password),
    }

    // Compute secret hash based on client secret.
    if AppClientSecret != "" {
        secretHash := computeSecretHash(AppClientSecret, username, AppClientID)
        params["SECRET_HASH"] = aws.String(secretHash)
    }

    if refresh != "" {
        flow = aws.String(flowRefreshToken)
        params = map[string]*string{
            "REFRESH_TOKEN": aws.String(refreshToken),
        }
    }

    authTry := &cognito.InitiateAuthInput{
        AuthFlow:       flow,
        AuthParameters: params,
		ClientId:       aws.String(AppClientID),
    }

    conf := &aws.Config{Region: aws.String("eu-west-1")}
    sess, err := session.NewSession(conf)

    if err != nil {
        panic(err)
    }

    CognitoClient := cognito.New(sess)

    res, err := CognitoClient.InitiateAuth(authTry)
    log.Println(res.AuthenticationResult.AccessToken)
    if err != nil {
        fmt.Println(err)
        return
    }
}
