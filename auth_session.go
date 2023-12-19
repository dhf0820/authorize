package authorize

import (
	"context"
	"errors"
	"fmt"
	"os"

	"strconv"
	"strings"

	"time"

	//"github.com/dgrijalva/jwt-go"
	//uuid "github.com/aidarkhanov/nanoid/v2"
	//"github.com/davecgh/go-spew/spew"
	jwToken "github.com/dhf0820/jwToken"
	"github.com/dhf0820/uc_core/common"
	log "github.com/dhf0820/vslog"

	//"github.com/google/uuid"
	"github.com/davecgh/go-spew/spew"
	"github.com/dhf0820/VsMongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

//	type Session struct {
//		Token     string `json:"token"`
//		CacheName string `json:"cacheName"`
//	}
//
// A limited information of the patient.
type PatientSummary struct {
	ID         primitive.ObjectID `json:"id" bson:"id"`
	FullName   string             `json:"fullName" bson:"fullName"`
	LastAccess time.Time          `json:"lastAccess" bson:"lastAccess"`
}

// type SessionHistory struct {
// 	FacilityId		primitive.ObjectID	`json:"facilityId" bson:"facilityId"`
// 	SystemId		primitive.ObjectID	`json:"systemId" bson:"systemId"`
// 	//Last X patients the user has selected
// 	PatientHistory	[]PatientSummary	`json:"patientHistory" bson:"patientHistory"`
// 	Token 			string				`json:"token" bson:"token"`
// }

// SessionConnection is a remote EMR The User has connected to in this AuthSession
// Would need to include the Facility/System Name
type SessionConnection struct {
	UserId     primitive.ObjectID `json:"userId" bson:"userId"`
	FacilityId primitive.ObjectID `json:"facilityId" bson:"facilityId"`
	SystemId   primitive.ObjectID `json:"systemId" bson:"systemId"`
	UserName   string             `json:"userName" bson:"userName"`
	Fields     []*common.KVData   `json:"fields" bson:"fields"`
	//Last X patients the user has selected
	PatientHistory []PatientSummary `json:"patientHistory" bson:"patientHistory"`
	Token          string           `json:"token" bson:"token"` //for this connection to Remote EMR from the connector

}

// A user logged into UC receives an AuthSession
type AuthSession struct {
	ID             primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Status         int                `json:"status" bson:"status"`
	UserID         primitive.ObjectID `json:"user_id" bson:"user_id"`
	UserName       string             `json:"userName" bson:"user_name"`
	FullName       string             `json:"fullName" bson:"fullName"`
	JWToken        string             `json:"jwToken" bson:"jwToken"`
	CurrentPatId   string             `json:"currentPatId" bson:"current_pat_id"` //Keeps the current patient. If changes, start a new session, Delete old
	ExpiresAt      *time.Time         `json:"expiresAt" bson:"expiresAt"`
	CreatedAt      *time.Time         `json:"createdAt" bson:"createdAt"`
	LastAccessedAt *time.Time         `json:"lastAccessedAt" bson:"lastAccessedAt"`
	// May not want to include this in what gets returned to the user on login
	Connections []SessionConnection `json:"connections" bson:"connections"`
	IP          string              `json:"ip" bson:"ip"`
	//SessionID   string              `json:"sessionID" bson:"sessionID"`
}

// type Status struct {
// 	Diagnostic string `json:"diag" bson:"diag"`
// 	Reference  string `json:"ref" bson:"ref"`
// 	Patient    string `json:"pat" bson:"pat"`
// 	Encounter  string `json:"enc" bson:"enc"`
// }

func ValidateSession(id string) (*AuthSession, error) {
	id = strings.Trim(id, " ")
	if id == "" {
		log.Error("session is blank")
		return nil, fmt.Errorf("401|Unauthorized")
	}
	log.Error("Validate Id: " + id)
	ID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, errors.New(log.ErrMsg("ID " + id + " FromHex Error: " + err.Error()))
	}
	// Session ID is valid formay, Retrieve it, Update it and return it.
	filter := bson.M{"_id": ID}
	collection, _ := VsMongo.GetCollection("AuthSession")
	as := &AuthSession{}
	err = collection.FindOne(context.TODO(), filter).Decode(as)
	if err != nil {
		return nil, log.Errorf(fmt.Sprintf("Session for ID [%s] returned ERROR: %s", id, err.Error()))
	}
	//Sessions is valid update it including new token
	// payload, err := VerifyToken(as.JWToken)
	// if err != nil {
	// 	return nil, log.Errorf("VerifyToken: " + err.Error())
	// }
	filter = bson.M{"_id": as.UserID}

	collection, err = VsMongo.GetCollection("user")
	if err != nil {
		return nil, log.Errorf("GetCollection(user): " + err.Error())
	}
	var user common.User
	err = collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, log.Errorf(fmt.Sprintf("Not Authorized for UserID: %s returned ERROR: %s", as.UserID.Hex(), err.Error()))
	}
	err = as.UpdateSession(&user)
	if err != nil {
		return nil, err
	}
	return as, err
}

func (as *AuthSession) UpdateTimes() error {
	tnow := time.Now().UTC()

	//log.Infof("ValidateSession:70 - Time now: %d  expireTime: %d", tnow, as.ExpireAt)
	if tnow.Unix() > as.ExpiresAt.Unix() {
		return log.Errorf("Session Expired")
	}
	sessionLengthStr := os.Getenv("SESSION_LENGTH")
	sessionLength, err := strconv.Atoi(sessionLengthStr)
	if err != nil {
		return log.Errorf(fmt.Sprintf("Can not convert SESSION_LENGTH: [%s] to integer minutes", sessionLengthStr))
	}
	expires := tnow.Add(time.Duration(sessionLength) * time.Minute)
	as.ExpiresAt = &expires
	return nil
}

//func (as *AuthSession) NewSessionID() error {
// 	id, err := uuid.New()
// 	if err!= nil {
// 		return fmt.Errorf("Cound not generate uuid: %s\n", err.Error())
// 	}
// 	err = DeleteAllCasheForSession(as.SessionID)
// 	as.SessionID = id
// 	filter := bson.M{"_id": as.ID}

// 	update := bson.M{"$set": bson.M{"session_id": as.SessionID}}
// 	collection, _ := storage.GetCollection("AuthSession")
// 	_, err = collection.UpdateOne(context.TODO(), filter, update)
// 	if err != nil {
// 		msg := fmt.Sprintf("Update SessionID failed: %s", err.Error)
// 		log.Error(msg)
// 		return errors.New(msg)
// 	}

// }

func (as *AuthSession) Delete() error {
	filter := bson.M{"user_id": as.UserID}
	collection, _ := VsMongo.GetCollection("AuthSession")
	_, err := collection.DeleteOne(context.Background(), filter)
	if err != nil {
		return log.Errorf("DeleteOne failed: " + err.Error())
	}
	return nil
}

func (as *AuthSession) Create(user *common.User) error { // SessionID is provided
	if !as.ID.IsZero() {
		return log.Errorf("AuthSession with ID: " + as.ID.Hex() + " exists")
	}
	as.ID = primitive.NewObjectID()

	//as.JWToken = jwt
	//as.SessionID = as.ID.Hex()
	// id, err := uuid.New()
	// if err != nil {
	// 	return fmt.Errorf("auth_session:95 -- Could not generate uuid: %s\n", err.Error())
	// }
	//fmt.Printf("CreateSession:100 -- cheking if session exists: %s\n", spew.Sdump(as))
	// as, err = ValidateAuth(as.Token)
	// if err == nil {
	// 	log.Infof("Session already exists for %s\n", as.Token)

	// 	as.UpdateSessionID()
	// 	return nil //errors.New("Session already exsts")
	// } else {
	// 	msg := fmt.Sprintf("auth_session:77 -- err: %s", err.Error())
	// 	log.Error(msg)
	// 	return errors.New(msg)
	// }
	// if as == nil {
	// 	log.Errorf("auth_session:76 -- as is nil returned from")
	// }
	// sessionLengthStr := os.Getenv("SESSION_LENGTH")
	// sessionLength, err := strconv.Atoi(sessionLengthStr)
	// if err != nil {
	// 	return log.Errorf("Can not convert SESSION_LENGTH: [" + sessionLengthStr + "] to integer minutes")
	// }
	//as.UserID = userId
	now := time.Now()
	expires := now //.Add(time.Duration(sessionLength) * time.Minute)

	as.CreatedAt = &now
	as.ExpiresAt = &expires

	//as.SessionID = id
	//log.Infof("Creating Session: %s\n", spew.Sdump(as))
	err := as.Insert(user)
	if err != nil {
		return log.Errorf("Insert Failed err: " + err.Error())
	}
	// filter := bson.D{{"token", as.Token}}
	// collection, _ := storage.GetCollection("AuthSession")

	// err = collection.FindOne(context.TODO(), filter).Decode(&as)
	// if err != nil {
	// 	fmt.Printf("Create:82 - FindFilter: %s - Err:%s\n", as.Token, err.Error())
	// }
	//fmt.Printf("Right after Insert: %s\n", spew.Sdump(as))
	return nil
}

// func (as *AuthSession) Delete() error {
// 	//startTime := time.Now()
// 	collection, _ := GetCollection("AuthSession")
// 	filter := bson.D{{"sessionid", as.SessionID}}
// 	//log.Debugf("    bson filter delete: %v\n", filter)
// 	_, err := collection.DeleteMany(context.Background(), filter)
// 	if err != nil {
// 		log.Errorf("!     137 -- DeleteSession for Dession %s failed: %v", as.SessionID, err)
// 		return err
// 	}
// 	//log.Infof("@@@!!!   140 -- Deleted %d Sessions for session: %v in %s", deleteResult.DeletedCount, as.SessionID, time.Since(startTime))
// 	return nil
// }

////////////////////////////////////CreateSessiopnForUser/////////////////////////////////////////////////////
// CreateSessionForUser creates a new AuthSession for the user. It is called on every login to create a new //
// session.  If the user already has a session, it is extended.                                             //

func CreateSessionForUser(user *common.User, ip string) (*AuthSession, error) {
	log.Info("auth.CreateSessionForUser: " + user.UserName + " ID: " + user.ID.Hex() + " IP: " + ip)
	collection, err := VsMongo.GetCollection("AuthSession")
	if err != nil {
		return nil, log.Errorf("GetCollection(AuthSession): " + err.Error())
	}
	as := &AuthSession{}
	filter := bson.M{"user_id": user.ID}
	log.Info("INFO: created AuthSession Filter: " + spew.Sdump(filter))

	err = collection.FindOne(context.TODO(), filter).Decode(as) // See if the user already has a session
	if err == nil {
		log.Info("AuthSession  exist, update it") // The user has a session, keep using it
		as.UpdateSession(user)                    // Extend the current session
		return as, nil
	}
	log.Info("Create New Auth.AuthSession: " + spew.Sdump(as))

	// as.UserName = payload.Username
	// as.FullName = payload.FullName
	as.IP = ip
	// as.JWToken = jwToken
	//as.UserID, err = primitive.ObjectIDFromHex(payload.UserId)
	log.Info("INFO: Inserting AuthSession")
	err = as.Insert(user)
	if err != nil {
		msg := fmt.Sprintf("insert Session error: %s", err.Error())

		return nil, log.Errorf(msg)
	}
	log.Info("Created new Session: " + spew.Sdump(as))
	return as, nil
}

func ValidateSessionForUserID(userID *primitive.ObjectID) (*AuthSession, error) {
	filter := bson.M{"user_id": userID}
	collection, _ := VsMongo.GetCollection("AuthSession")
	as := &AuthSession{}
	err := collection.FindOne(context.TODO(), filter).Decode(as) // See if the user already has a session
	return as, err
}

func ValidateAuth(authId string) (*AuthSession, error) {
	//TODO: Actually validate the session as a valid JWT. Right now just using
	log.Info(fmt.Sprintf("ID: [%s]", authId))
	if strings.Trim(authId, " ") == "" {
		return nil, log.Errorf("401|Unauthorized ID is Blank")
	}
	oId, err := primitive.ObjectIDFromHex(authId)
	if err != nil {
		return nil, log.Errorf("Invalid SessionID: " + err.Error())
	}
	filter := bson.M{"_id": oId}

	collection, _ := VsMongo.GetCollection("AuthSession")
	var as AuthSession
	err = collection.FindOne(context.TODO(), filter).Decode(&as)
	if err != nil {
		return nil, log.Errorf(fmt.Sprintf("Not Authorized for ID: %s returned ERROR: %s", authId, err.Error()))
	}
	tnow := time.Now().UTC().Unix()
	if tnow > as.ExpiresAt.Unix() {
		//TODO: Should we delete the current Session since timed out?
		return nil, log.Errorf("notLoggedIn")
	}
	_, err = VerifyToken(as.JWToken)
	if err != nil {
		//TODO: Should we delete the current Session since JWToken is invalid?
		return nil, log.Errorf("Token error: " + err.Error())
	}
	filter = bson.M{"_id": as.UserID}

	collection, err = VsMongo.GetCollection("user")
	if err != nil {
		return nil, log.Errorf("GetCollection(user): " + err.Error())
	}
	var user common.User
	err = collection.FindOne(context.TODO(), filter).Decode(&user)
	if err != nil {
		return nil, log.Errorf(fmt.Sprintf("Not Authorized for ID: %s returned ERROR: %s", authId, err.Error()))
	}
	as.UpdateSession(&user)
	return &as, nil
}

// //////////////////////////////Insert AuthSession///////////////////////////////////////////////////////////
// Insert AuthSession inserts a new AuthSession into the AuthSession collection, with initial jwt and      //
// expire time. It is called on every login to create a new session.  See CreateSessionForUser             //
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////
func (as *AuthSession) Insert(user *common.User) error {
	// duration := os.Getenv("SESSION_LENGTH") + "m"
	// if as.ID.IsZero() {
	// 	log.Info("as.ID is Zero")
	// 	as.ID = primitive.NewObjectID()
	// }
	log.Info("inserting AuthSession: " + spew.Sdump(as))
	// jwt, payload, err := CreateToken(as.IP, user.UserName, duration, user.ID.Hex(), user.FullName, user.Role, as.ID.Hex())
	// if err != nil {
	// 	return log.Errorf("Call to CreateJWToken failed: " + err.Error())
	// }
	// log.Info("Inserted jwt: " + jwt)
	// log.Info("Inserted payload: " + spew.Sdump(payload))
	//as.JWToken = jwt
	// as.ExpiresAt = &payload.ExpiresAt
	//as.CreatedAt = &payload.IssuedAt
	as.UserID = user.ID
	//as.ExpiresAt = &payload.ExpiresAt
	as.UserName = user.UserName
	as.FullName = user.FullName

	tn := time.Now().UTC()
	as.CreatedAt = &tn
	as.LastAccessedAt = &tn
	collection, _ := VsMongo.GetCollection("AuthSession")
	log.Info("Inserting AuthSession: " + spew.Sdump(as))
	insertResult, err := collection.InsertOne(context.TODO(), as)
	if err != nil {
		return log.Errorf("InsertOne error: " + err.Error())
	}
	as.ID = insertResult.InsertedID.(primitive.ObjectID)
	log.Info("New ID: " + as.ID.Hex())
	return nil
}

////////////////////////UpdateSession/////////////////////////////////////////////
// UpdateSession updates the AuthSession with the new token and new expire time //
// It is called on every call to Core to keep the session and token alive       //
// It is also called when a new session is created or a Session is validated    //
//////////////////////////////////////////////////////////////////////////////////

func (as *AuthSession) UpdateSession(user *common.User) error {
	duration := os.Getenv("SESSION_LENGTH")
	saveAs := *as
	filter := bson.M{"_id": as.ID}
	//as.ExpiresAt = as.CalculateExpireTime()
	tn := time.Now().UTC()
	as.LastAccessedAt = &tn
	os.Setenv("TOKEN_DURATION", duration)
	jwToken, payload, err := jwToken.CreateJWToken(as.IP, as.UserName, as.UserID.Hex(), as.FullName, user.Role, as.ID.Hex())
	if err != nil {
		return log.Errorf("Call to CreateJWToken failed: " + err.Error())
	}
	as.JWToken = jwToken
	log.Info("UpdateSession payload: " + spew.Sdump(payload))

	//TODO: Make the JwToke can update expire time
	//as.ExpiresAt = &payload.ExpiresAt
	// update := bson.M{"$set": bson.M{"expiresAt": as.ExpiresAt, "lastAccessedAt": as.LastAccessedAt,
	// 	"jwToken": as.JWToken}}

	collection, err := VsMongo.GetCollection("AuthSession")
	if err != nil {
		return log.Errorf("GetCollection(AuthSession): " + err.Error())
	}
	updResults, err := collection.UpdateOne(context.TODO(), filter, update)
	log.Info("updResult: " + spew.Sdump(updResults))
	if err != nil {
		*as = saveAs
		return log.Errorf("UpdateSession failed: " + err.Error())
	}

	//log.Info("Updated AuthSession: " + spew.Sdump(as))
	return nil
}

// func (as *AuthSession) Update(update bson.M) (error) {
// 	saveAS := *as
// 	//fmt.Printf("AuthSession.Update: 274 -- as: %s\n", spew.Sdump(as))
// 	collection, _ := GetCollection("AuthSession")
// 	//fmt.Printf("LIne 258\n")
// 	filter := bson.M{"_id": as.ID}
// 	//fmt.Printf("Filter: %v\n", filter)
// 	_, err := collection.UpdateOne(context.TODO(), filter, update)
// 	if err != nil {
// 		log.Errorf("AuthSession.Update:272 error %s", err)
// 		return errors.New(VLogErr("Update error: "+ err.Error()))
// 	}
// 	//log.Debugf("AuthSession.Update:275 -- Matched: %d  -- modified: %d for ID: %s", res.MatchedCount, res.ModifiedCount, as.ID.String())

// 	asUpd, err := GetSessionForUserID(as.UserID)
// 	as = asUpd
// 	return asUpd, err
// }

// func (as *AuthSession) UpdateDiagStatus(status string) (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpdateDiagStatus:292\n")
// 	as.Status.Diagnostic = status
// 	update := bson.M{"$set": bson.M{"status": as.Status}}
// 	asUpd, err := as.Update(update)
// 	if err != nil {
// 		err = fmt.Errorf("UpdateStatus:294 -- error: %s", err.Error())
// 		log.Error(err.Error())
// 		return nil, err
// 	}
// 	return asUpd, nil
// }

// func (as *AuthSession) UpdatePatStatus(status string) (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpdatePatStatus:302")
// 	as.Status.Patient = status
// 	update := bson.M{"$set": bson.M{"status": as.Status}}
// 	asUpd, err := as.Update(update)
// 	if err != nil {
// 		err = fmt.Errorf("UpdateStatus:294 -- error: %s", err.Error())
// 		log.Error(err.Error())
// 		return nil, err
// 	}
// 	return asUpd, nil
// }

// func (as *AuthSession) UpdateRefStatus(status string) (*AuthSession, error) {
// 	//fmt.Printf("AuthSession.UpdateStatus:316")
// 	as.Status.Reference = status
// 	update := bson.M{"$set": bson.M{"status": as.Status}}
// 	asUpd, err := as.Update(update)
// 	if err != nil {
// 		err = fmt.Errorf("UpdateStatus:322 -- error: %s", err.Error())
// 		log.Error(err.Error())
// 		return nil, err
// 	}
// 	return asUpd, nil
// }

// func (as *AuthSession) UpdateEncStatus(status string) (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpdateEncStatus:329")

// 	as.Status.Encounter = status
// 	update := bson.M{"$set": bson.M{"status": as.Status}}
// 	asUpd, err := as.Update(update)
// 	if err != nil {
// 		err = fmt.Errorf("UpdateStatus:335 -- error: %s", err.Error())
// 		log.Error(err.Error())
// 		return nil, err
// 	}
// 	return asUpd, nil
// }

// func (as *AuthSession) UpdateEncSessionId() (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpEncSessionId:348 --Entry: %s\n", spew.Sdump(as))

// 	id, err := uuid.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdateEncSessionId:352 -- Could not generate Enc uuid: %s", err.Error())
// 	}
// 	update := bson.M{"$set": bson.M{"enc_session_id": id}}
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdatEncSessionId:291 -- Cound not set EncSessionID uuid: %s", err.Error())
// 	}
// 	fmt.Printf("AuthSession.UpdatEncSessionId:293 -- %s\n", spew.Sdump(as))
// 	asUpd, err := as.Update(update)
// 	as = asUpd
// 	return asUpd, err
// }

// func (as *AuthSession) UpdatePatSessionId() (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpdatePatSessionId:366 --Entry: %s\n", spew.Sdump(as))

// 	id, err := uuid.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdatePatSessionId:287 -- Cound not generate Pat uuid: %s", err.Error())
// 	}
// 	update := bson.M{"$set": bson.M{"pat_session_id": id}}
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdatePatSessionId:291 -- Cound not set PatSessionID uuid: %s", err.Error())
// 	}
// 	fmt.Printf("AuthSession.UpdatePatSessionId:293 -- %s\n", spew.Sdump(as))
// 	asUpd, err := as.Update(update)
// 	as = asUpd
// 	return asUpd, err
// }

// func (as *AuthSession) UpdateDocSessionId() (*AuthSession, error) {
// 	fmt.Printf("AuthSession.UpdateDocSessionId:383 --Entry: %s\n", spew.Sdump(as))
// 	id, err := uuid.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("auth_session.UpdateDocId:302 -- Cound not generate Doc uuid: %s", err.Error())
// 	}
// 	update := bson.M{"$set": bson.M{"doc_session_id": id}}
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdateDocSessionId:306 -- Cound not set DocSessionID uuid: %s", err.Error())
// 	}
// 	return as.Update(update)
// }

// func (as *AuthSession) UpdateSessionID() (*AuthSession, error) {
// 	id, err := uuid.New()
// 	if err != nil {
// 		return nil, fmt.Errorf("AuthSession.UpdateSessionId:314 -- Cound not generate uuid: %s", err.Error())
// 	}
// 	update := bson.M{"$set": bson.M{"session_id": id}}
// 	return as.Update(update)

// 	// collection, _ := storage.GetCollection("AuthSession")
// 	// res, err := collection.UpdateOne(context.TODO(), filter, update)
// 	// if err != nil {
// 	// 	log.Errorf(" Update error %s", err)
// 	// 	return err
// 	// }
// 	// log.Debugf("auth_session:265 -- Matched: %d  -- modified: %d for ID: %s", res.MatchedCount, res.ModifiedCount, as.ID.String())
// 	//return nil
// }

// func (as *AuthSession) CalculateExpireTime() *time.Time {
// 	loc, _ := time.LoadLocation("UTC")
// 	addlTime := time.Hour * 2
// 	ExpireAt := time.Now().In(loc).Add(addlTime)
// 	return &ExpireAt
// }

// func (as *AuthSession) GetDocumentStatus() string {
// 	latest, _ := GetSessionForUserID(as.UserID)
// 	if latest.Status.Diagnostic == "filling" || latest.Status.Reference == "filling" {
// 		return "filling"
// 	}
// 	return "done"
// }

// func (as *AuthSession) GetDiagReptStatus() string {
// 	latest, _ := GetSessionForUserID(as.UserID)
// 	return latest.Status.Diagnostic
// }

// func (as *AuthSession) GeReptRefStatus() string {
// 	latest, _ := GetSessionForUserID(as.UserID)
// 	return latest.Status.Reference
// }
// func (as *AuthSession) GetPatientStatus() string {
// 	latest, _ := GetSessionForUserID(as.UserID)
// 	return latest.Status.Patient
// }

// func (as *AuthSession) GetEncounterStatus() string {
// 	latest, _ := GetSessionForUserID(as.UserID)
// 	return latest.Status.Encounter
// }
