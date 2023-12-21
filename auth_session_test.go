package authorize

import (
	"context"
	//"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/dhf0820/VsMongo"
	jwt "github.com/dhf0820/golangJWT"

	//jw_token "github.com/dhf0820/jwToken"
	"os"
	"testing"

	common "github.com/dhf0820/uc_core/common"
	log "github.com/dhf0820/vslog"
	"github.com/joho/godotenv"
	. "github.com/smartystreets/goconvey/convey"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func CreateTestToken(duration string) (string, *jwt.UcPayload, error) {
	fmt.Printf("\n\n\n\n")
	log.SetDebuglevel("DEBUG3")
	log.Debug3("CreateTestToken")
	//key := util.RandomString(32)
	key := "Debbie Harman the love of my life" //"Debbie Harman my love of my life"
	log.Debug3("Key: " + key)
	os.Setenv("ACCESS_SECRET", key)
	username := "dharman0127"
	os.Setenv("TOKEN_DURATION:", duration)
	userId := "62f18efcba5395278cd530d5" //Debra Harman
	role := "Provider"
	ip := "192.168.1.99"
	fullName := "Debra Harman MD"
	//comment := "Debbie is my Lover"
	log.Info("FullUserName: " + fullName)
	log.Info("Calling CreateToken")
	token, payload, err := jwt.CreateToken(ip, username, userId, fullName, role, "")
	if err != nil {
		log.Error(err.Error())
		return "", nil, err
	}
	if token == "" {
		err = log.Errorf("Token is blank")
		log.Error(err.Error())
		return "", nil, err
	}
	if payload == nil {
		err = log.Errorf("Payload is nil")
		log.Error(err.Error())
		return "", nil, err
	}

	log.Debug3("Token: " + token)
	log.Debug3("Payload: " + spew.Sdump(payload))
	pl, err := VerifyToken(token)
	So(err, ShouldBeNil)
	So(pl, ShouldNotBeNil)
	log.Debug3("pl: " + spew.Sdump(pl))
	return token, payload, nil
}
func TestCreateSessionForUser(t *testing.T) {
	log.SetDebuglevel("DEBUG3")
	log.Debug3("TestCreateSessionForUser")
	godotenv.Load("./.env.authorize_test")
	Convey("CreateSessionForUser", t, func() {
		jwt, payload, err := CreateTestToken("10s")
		So(err, ShouldBeNil)
		So(jwt, ShouldNotBeNil)
		So(payload, ShouldNotBeNil)
		log.Info("jwt: " + jwt)

		log.Info("payload: " + spew.Sdump(payload))
		id, err := primitive.ObjectIDFromHex("62f18efcba5395278cd530d5") //Find User Dr Harman
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
		log.Debug3("User: " + spew.Sdump(usr))
		//TODO: Fix this test Get the test user.
		log.Info("auth.CreateSessionForUser: " + payload.Username + " ID: " + payload.UserId + " IP: " + payload.IP)

		collection, err = VsMongo.GetCollection("AuthSession")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)

		as := &AuthSession{}
		filter = primitive.M{"user_id": payload.UserId}
		log.Debug3("created AuthSession Filter: " + spew.Sdump(filter))
		// singleResult := collection.FindOne(context.Background(), filter).Decode(as)
		// log.Debug3("singleResult: " + spew.Sdump(singleResult))
		// log.Debug3("as: " + spew.Sdump(as))

		log.Debug3("Delete the existing AuthSession for this user")
		collection.FindOneAndDelete(context.Background(), filter)

		//So(err, ShouldBeNil)
		//log.Debug3("result.DeletedCount: " + spew.Sdump(result.DeletedCount))
		log.Debug3("User: " + spew.Sdump(usr))
		as, err = CreateSessionForUser(usr, "192.168.1.99")
		So(err, ShouldBeNil)
		So(as, ShouldNotBeNil)
		log.Debug3("as: " + spew.Sdump(as))
		payloadNew, err := VerifyToken(as.JWToken)
		So(err, ShouldBeNil)
		So(payloadNew, ShouldNotBeNil)
		log.Info("payloadNew: " + spew.Sdump(payloadNew))

	})
}

func TestCreateSessionForUserID(t *testing.T) {
	log.SetDebuglevel("DEBUG3")
	log.Debug3("TestCreateSessionForUserID")
	godotenv.Load("./.env.authorize_test")
	Convey("CreateSessionForUserID", t, func() {
		id, err := primitive.ObjectIDFromHex("65833bd42fefe64f96ac3b2a") //Find User Dr Harman
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
		log.Debug3("User: " + spew.Sdump(usr))

		jwt, payload, err := CreateTokenForUser(usr, "192.168.1.99", "10s")
		So(err, ShouldBeNil)
		So(jwt, ShouldNotBeNil)
		So(payload, ShouldNotBeNil)
		log.Info("jwt: " + jwt)
		log.Info("payload: " + spew.Sdump(payload))
		//TODO: Fix this test Get the test user.
		log.Info("auth.CreateSessionForUser: " + payload.Username + " ID: " + payload.UserId + " IP: " + payload.IP)

		collection, err = VsMongo.GetCollection("AuthSession")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)

		as := &AuthSession{}
		filter = primitive.M{"user_id": payload.UserId}
		log.Debug3("created AuthSession Filter: " + spew.Sdump(filter))
		// singleResult := collection.FindOne(context.Background(), filter).Decode(as)
		// log.Debug3("singleResult: " + spew.Sdump(singleResult))
		// log.Debug3("as: " + spew.Sdump(as))

		log.Debug3("Delete the existing AuthSession for this user")
		collection.FindOneAndDelete(context.Background(), filter)

		//So(err, ShouldBeNil)
		//log.Debug3("result.DeletedCount: " + spew.Sdump(result.DeletedCount))
		log.Debug3("User: " + spew.Sdump(usr))
		as, err = CreateSessionForUser(usr, "192.168.1.99")
		So(err, ShouldBeNil)
		So(as, ShouldNotBeNil)
		log.Debug3("as: " + spew.Sdump(as))
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
	log.SetDebuglevel("DEBUG3")
	godotenv.Load("./.env.authorize_test")
	Convey("Create AuthSession", t, func() {
		os.Setenv("SESSION_LENGTH", "60m")
		os.Setenv("CORE_DB", "mongodb+srv://dhfadmin:Sacj0nhati@cluster1.24b12.mongodb.net/test?retryWrites=true&w=majority")
		os.Setenv("COMPANY", "test")

		vsMongo := VsMongo.OpenDB("")
		So(vsMongo, ShouldNotBeNil)
		as, err := setUpTest()
		So(err, ShouldBeNil)
		So(as.ID, ShouldEqual, primitive.NilObjectID)
		log.Debug3("as: " + spew.Sdump(as))
		payload, err := VerifyToken(as.JWToken)
		So(err, ShouldBeNil)
		So(payload, ShouldNotBeNil)
		log.Info("payload: " + spew.Sdump(payload))
		log.Debug3("as: " + spew.Sdump(as))
		err = as.Delete()
		if err == nil {
			log.Info("Deleted existing test AuthSession for Debra Harman UserId " + as.UserID.Hex())
		}
		id, err := primitive.ObjectIDFromHex("630bc578415105069d24386e") //ouerfellir
		So(err, ShouldBeNil)
		So(id, ShouldNotEqual, primitive.NilObjectID)
		filter := primitive.M{"_id": id}
		collection, err := VsMongo.GetCollection("user")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)
		var usr *common.User
		log.Info(fmt.Sprintf("Calling FindOne: %v", filter))
		err = collection.FindOne(context.TODO(), filter).Decode(&usr)
		So(err, ShouldBeNil)
		err = as.Create(usr)
		So(err, ShouldBeNil)
		s, err := ValidateAuth(string(as.ID.Hex()))
		So(err, ShouldBeNil)
		So(s, ShouldNotBeNil)
		log.Info("Success session: " + spew.Sdump(s))
		collection, err = VsMongo.GetCollection("AuthSession")
		So(err, ShouldBeNil)
		So(collection, ShouldNotBeNil)

		//log.Debug3("Deleting test user")
		// deleteResults, err := collection.DeleteOne(context.Background(), filter)
		// So(err, ShouldBeNil)
		// So(deleteResults.DeletedCount, ShouldEqual, 1)
	})
	log.Info("TestCreateSession complete")
}

func TestValidateSessionForUserId(t *testing.T) {
	log.SetDebuglevel("DEBUG3")
	log.Debug3("TestValidateSessionForUserId")
	godotenv.Load("./.env.authorize_test")
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
	jwt, payload, err := CreateTestToken("30s")
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
