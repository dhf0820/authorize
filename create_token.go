package authorize

import (
	//"fmt"
	jw_token "github.com/dhf0820/jwToken"
	log "github.com/dhf0820/vslog"
	"os"
	"time"
)

func CreateToken(ip string, userName string, duration time.Duration, userId, fullName, role string) (string, *jw_token.Payload, error) {
	var err error
	jwtKey := "I am so blessed Debbie loves me!"
	//refreshKey := os.Getenv("REFRESH_SECRET")
	maker, err := jw_token.NewJWTMaker(jwtKey)
	if err != nil {
		log.Error("NewJWToken failed: " + err.Error())
		return "", nil, err
	}
	token, payload, err := maker.CreateToken(ip, userName, duration, userId, fullName, role)
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
