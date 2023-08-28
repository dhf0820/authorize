package authorize

import (
	"fmt"
	jw_token "github.com/dhf0820/jwToken"
	log "github.com/dhf0820/vslog"
	"os"
	"strconv"
	"time"
)

func CreateToken(ip string, userName string, duration string, userId, fullName, role, sessionId string) (string, *jw_token.Payload, error) {
	var err error
	sessionLengthStr := os.Getenv("SESSION_LENGTH")
	sessionLength, err := strconv.Atoi(sessionLengthStr)
	if err != nil {
		return "", nil, log.Errorf(fmt.Sprintf("Can not convert SESSION_LENGTH: [%s] to integer minutes", sessionLengthStr))
	}
	durationMinutes := time.Duration(sessionLength) * time.Minute
	jwtKey := "I am so blessed Debbie loves me!"
	//refreshKey := os.Getenv("REFRESH_SECRET")
	maker, err := jw_token.NewJWTMaker(jwtKey)
	if err != nil {
		log.Error("NewJWToken failed: " + err.Error())
		return "", nil, err
	}
	token, payload, err := maker.CreateToken(ip, userName, durationMinutes, userId, fullName, role, sessionId)
	return token, payload, err
}

func VerifyToken(token string) (*jw_token.Payload, error) {
	jwtKey := os.Getenv("ACCESS_SECRET")
	maker, err := jw_token.NewJWTMaker(jwtKey)
	if err != nil {
		log.Error("NewJWToken failed: " + err.Error())
		return nil, err
	}
	payload, err := maker.VerifyToken(token)
	return payload, err
}
