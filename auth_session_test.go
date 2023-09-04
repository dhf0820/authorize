package authorize

import (
	"context"
	//"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dhf0820/VsMongo"
	jw_token "github.com/dhf0820/jwToken"
	common "github.com/dhf0820/uc_core/common"
	log "github.com/dhf0820/vslog"
	"os"
	"testing"
	//"github.com/joho/godotenv"
	. "github.com/smartystreets/goconvey/convey"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestCreateSessionForUser(t *testing.T) {
	Convey("CreateSessionForUser", t, func() {
		jwt, payload, err := jw_token.CreateTestJWToken("30s")
		So(err, ShouldBeNil)
		So(jwt, ShouldNotBeNil)
		So(payload, ShouldNotBeNil)
		id, err := primitive.ObjectIDFromHex("62d0af5dec383ade03a96b7e")
		So(err, ShouldBeNil)
		So(id, ShouldNotEqual, primitive.NilObjectID)
		filter := primitive.M{"_id": id}
		collection, err := VsMongo.GetCollection("user")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)
		var usr *common.User
		log.Info(fmt.Sprintf("Calling FindOne:%v", filter))
		err = collection.FindOne(context.TODO(), filter).Decode(&usr)
		So(err, ShouldBeNil)
		//TODO: Fix this test Get the test user.
		as, err := CreateSessionForUser(usr, "192.168.1.99")
		So(err, ShouldBeNil)
		So(as, ShouldNotBeNil)
		payloadNew, err := VerifyToken(as.JWToken)
		So(err, ShouldBeNil)
		So(payloadNew, ShouldNotBeNil)
		log.Info("payloadNew: " + spew.Sdump(payloadNew))
	})
}

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
	Convey("Create AuthSession", t, func() {
		os.Setenv("SESSION_LENGTH", "60")
		os.Setenv("CORE_DB", "mongodb+srv://dhfadmin:Sacj0nhati@cluster1.24b12.mongodb.net/test?retryWrites=true&w=majority")
		os.Setenv("COMPANY", "test")

		vsMongo := VsMongo.OpenDB("")
		So(vsMongo, ShouldNotBeNil)
		as, err := setUpTest()
		So(err, ShouldBeNil)
		So(as.ID, ShouldEqual, primitive.NilObjectID)
		payload, err := VerifyToken(as.JWToken)
		So(err, ShouldBeNil)
		So(payload, ShouldNotBeNil)
		log.Info("payload: " + spew.Sdump(payload))
		err = as.Delete()
		if err == nil {
			log.Info("Deleted existing test AuthSession for UseId " + as.UserID.Hex())
		}
		id, err := primitive.ObjectIDFromHex("62d0af5dec383ade03a96b7e")
		So(err, ShouldBeNil)
		So(id, ShouldNotEqual, primitive.NilObjectID)
		filter := primitive.M{"_id": id}
		collection, err := VsMongo.GetCollection("user")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)
		var usr *common.User
		log.Info(fmt.Sprintf("Calling FindOne:%v", filter))
		err = collection.FindOne(context.TODO(), filter).Decode(&usr)
		So(err, ShouldBeNil)
		err = as.Create(usr)
		So(err, ShouldBeNil)
		s, err := ValidateAuth(string(as.ID.Hex()))
		So(err, ShouldBeNil)
		So(s, ShouldNotBeNil)
		log.Info("Success session: " + spew.Sdump(s))
	})
	log.Info("TestCreateSession complete")
}

func TestValidateSessionForUserId(t *testing.T) {
	Convey("ValidateSessionForuserId", t, func() {
		os.Setenv("SESSION_LENGTH", "60")
		os.Setenv("CORE_DB", "mongodb+srv://dhfadmin:Sacj0nhati@cluster1.24b12.mongodb.net/test?retryWrites=true&w=majority")
		os.Setenv("COMPANY", "test")
		vsMongo := VsMongo.OpenDB("")
		So(vsMongo, ShouldNotBeNil)
		// id, err := primitive.ObjectIDFromHex("62d0af5dec383ade03a96b7e")
		// So(err, ShouldBeNil)
		// So(id, ShouldNotEqual, primitive.NilObjectID)
		userId, err := primitive.ObjectIDFromHex("62f18efcba5395278cd530d5")
		So(err, ShouldBeNil)
		So(userId, ShouldNotEqual, primitive.NilObjectID)
		as, err := ValidateSessionForUserID(&userId)
		So(err, ShouldBeNil)
		So(as, ShouldNotBeNil)
	})
}

func setUpTest() (*AuthSession, error) {
	as := AuthSession{}
	jwt, payload, err := jw_token.CreateTestJWToken("30s")
	if err != nil {
		return nil, err
	}
	log.Info("jwt: " + jwt)
	log.Info("payload: " + spew.Sdump(payload))
	//as.ID = primitive.NewObjectID()
	as.FullName = payload.FullName
	as.JWToken = jwt
	as.UserName = payload.Username
	as.UserID, err = primitive.ObjectIDFromHex(payload.UserId)
	if err != nil {
		return nil, log.Errorf(fmt.Sprintf("Invalid UserId: [%s] - err: %s", payload.UserId, err.Error()))
	}
	return &as, nil

}
