package authorize

import (
	// "fmt"
	jwt "github.com/dhf0820/golangJWT"
	//jwToken "github.com/dhf0820/jwToken"
	common "github.com/dhf0820/uc_core/common"
	log "github.com/dhf0820/vslog"
	"os"
	// "strconv"
	// "time"
)

func CreateToken(ip string, userName string, userId, fullName, role, sessionId string) (string, *jwt.UcPayload, error) {
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

	token, payload, err := jwt.CreateToken(ip, userName, userId, fullName, role, sessionId)
	return token, payload, err
}

func CreateTokenForUser(usr *common.User, ip string, sessionId string) (string, *jwt.UcPayload, error) {
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

	token, payload, err := jwt.CreateToken(ip, usr.UserName, usr.ID.Hex(), usr.FullName, usr.Role, sessionId)
	return token, payload, err
}

func VerifyToken(token string) (*jwt.UcPayload, error) {
	jwtKey := os.Getenv("ACCESS_SECRET")
	log.Debug3("ACCESS_SECRET: " + jwtKey)
	payload, err := jwt.VerifyToken(token)
	return payload, err
}
