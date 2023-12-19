package authorize

import (
	// "fmt"
	//jwt "github.com/dhf0820/golangJWT"
	jwToken "github.com/dhf0820/jwToken"
	//log "github.com/dhf0820/vslog"
	"os"
	// "strconv"
	// "time"
)

func CreateToken(ip string, userName string, userId, fullName, role, sessionId string) (string, *jwToken.UcPayload, error) {
	var err error
	sessionLengthStr := os.Getenv("SESSION_LENGTH")
	os.Setenv("TOKEN_DURATION", sessionLengthStr)
	// sessionLength, err := strconv.Atoi(sessionLengthStr)
	// if err != nil {
	// 	return "", nil, log.Errorf(fmt.Sprintf("Can not convert SESSION_LENGTH: [%s] to integer minutes", sessionLengthStr))
	// }
	//durationMinutes := time.Duration(sessionLength) * time.Minute
	jwtKey := "I am so blessed Debbie loves me!"
	//refreshKey := os.Getenv("REFRESH_SECRET")
	// maker, err := jw_token.NewJWTMaker(jwtKey, "", "")
	// if err != nil {
	// 	log.Error("NewJWToken failed: " + err.Error())
	// 	return "", nil, err
	// }
	os.Setenv("ACCESS_SECRET", jwtKey)
	token, payload, err := CreateToken(ip, userName, userId, fullName, role, sessionId)
	return token, payload, err
}

func VerifyToken(token string) (*jwToken.UcPayload, error) {
	jwtKey := os.Getenv("ACCESS_SECRET")
	os.Setenv("ACCESS_SECRET", jwtKey)

	// maker, err := jw_token.NewJWTMaker(jwtKey, "", "")
	// if err != nil {
	// 	log.Error("NewJWToken failed: " + err.Error())
	// 	return nil, err
	// }
	payload, err := VerifyToken(token)
	return payload, err
}
