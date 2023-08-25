package authorize

import (
	"errors"
	"fmt"
	jw_token "github.com/dhf0820/jwToken"
	"testing"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/joho/godotenv"
	. "github.com/smartystreets/goconvey/convey"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// func TestDeleteAuthSession(t *testing.T) {
// 	as := setupTest("")
// 	Convey("Delete AuthSession", t, func() {
// 		So(as.ID, ShouldNotEqual, primitive.NilObjectID)
// 		session := as
// 		session, err := ValidateAuth("test")
// 		fmt.Printf("validated session: %s\n", session.SessionID)
// 		fmt.Printf("ooriginal session: %s\n", as.SessionID)
// 		So(err, ShouldBeNil)
// 		So(session, ShouldNotBeNil)
// 		err = session.Delete()
// 		So(err, ShouldBeNil)
// 		fmt.Printf("Validating a deleted session\n")
// 		session, err = ValidateAuth("test")
// 		So(err, ShouldNotBeNil)
// 		So(err, ShouldEqual, "Not Authorized")
// 	})
// }

// func TestGetAuthSession(t *testing.T) {
// 	as := setupTest("")
// 	Convey("GetAuthSession", t, func() {
// 		So(as.ID, ShouldNotEqual, primitive.NilObjectID)

// 		session, err := GetSessionForUserID(as.UserID)
// 		So(err, ShouldBeNil)
// 		So(session, ShouldNotBeNil)
// 		So(as.PatSessionId, ShouldEqual, session.PatSessionId)
// 		updAS, err := as.UpdatePatSessionId()
// 		So(updAS.PatSessionId, ShouldNotEqual, session.PatSessionId)
// 	})
// }

func TestCreateSession(t *testing.T) {
	Convey("Delete AuthSession", t, func() {
		as, err := setUpTest()
		So(err, ShouldBeNil)
		So(as.ID, ShouldNotEqual, primitive.NilObjectID)
		err = as.Create()
		So(err, ShouldBeNil)
		s, err := ValidateAuth(string(as.ID.Hex()))
		So(err, ShouldBeNil)
		So(s, ShouldNotBeNil)
	})
}

func setUpTest() (*AuthSession, error) {
	as := AuthSession{}
	jwt, payload, err := jw_token.CreateTestJWToken("30s")
	if err != nil {
		return nil, err
	}
	payload.ID.ID()
	as.FullName = payload.FullName
	as.JWToken = jwt
	as.UserName = payload.Username
	as.UserID, err = primitive.ObjectIDFromHex(payload.UserId)
	if err != nil {
		return nil, errors.New(VLogErr(fmt.Sprintf("Invalid UserId: [%s] - err: %s", payload.UserId, err.Error())))
	}
	return &as, nil

}
