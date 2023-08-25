package token

import (
	//"fmt"
	//log "github.com/sirupsen/logrus"
	jw_token "github.com/dhf0820/jwToken"
	//"os"
	"time"
)

func CreateToken(ip, userName string, duration time.Duration, userId, fullName, role, sessionId string) (string, error) {
	var err error
	jwtKey := "I am so blessed Debbie loves me!"
	//refreshKey := os.Getenv("REFRESH_SECRET")
	maker, err := jw_token.NewJWTMaker(jwtKey)
	if err != nil {
		log.Printf("NewJWToken err: %s\n", err.Error())
		return "", err
	}
	token, _, err := maker.CreateToken(ip, userName, duration, userId, fullName, role, sessionId)
	return token, err
}
