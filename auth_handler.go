package authorize

import (
	//"bytes"
	"encoding/json"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/dhf0820/uc_core/common"
	log "github.com/sirupsen/logrus"

	"net/http"
	"os"
	"strconv"
	"time"

	fhir "github.com/dhf0820/fhir4"
	"go.mongodb.org/mongo-driver/bson/primitive"

	//"log"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	//"github.com/dgrijalva/jwt-go"
)

// type LoginFilter struct {
// 	UserName string `schema:"userName"`
// 	Password string `schema:"password"`
// 	//PracticeId string `schema:"practiceId"`
// }

// type AuthLogin struct {
// 	UserName string `json:"userName"`
// 	Password string `json:"password"`
// }

// type LoginResponse struct {
// 	ID       primitive.ObjectID `json:"id"`
// 	Token    string             `json:"token"`
// 	Status   int                `json:"status"`
// 	Message  string             `json:"message"`
// 	UserName string             `json:"userName"`
// 	FullName string             `json:"fullName"`
// 	Role     string             `json:"role"`
// 	//Practices  []*Practice        `json:"practices"`
// 	Facilities []*Facility `json:"facilities"` // Facilities have Classification of HOSP or PRAC
// }

var userName string
var password string
var StartTotalTime time.Time

func WriteLoginResponse(w http.ResponseWriter, resp *common.LoginResponse) error {
	log.Println("WriteLoginResponse:52")
	w.Header().Set("Content-Type", "application/json")
	//TODO: Put JWT in Header
	w.WriteHeader(resp.Status)
	err := json.NewEncoder(w).Encode(resp)
	if err != nil {

		log.Printf("Error marshaling JSON: %s", err.Error())
		return err
	}
	return nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var err error
	//enableCors(&w)
	//fmt.Printf("\n\nLogin:67 - Request: %s\n\n", spew.Sdump(r))
	StartTotalTime = time.Now()
	ip := GetIP(r)
	//fmt.Printf("Login:70 - ip = %s\n", ip)
	auth := &common.AuthLogin{}
	resp := common.LoginResponse{}
	if r.Method == "GET" {
		//fmt.Printf("Handling GET Login\n\n")
		var decoder = schema.NewDecoder()
		decoder.IgnoreUnknownKeys(true)
		var params common.LoginFilter
		err := decoder.Decode(&params, r.URL.Query())
		if err != nil {
			errMsg := VLogErr("Decode error:" + err.Error())
			WriteFhirOperationOutcome(w, 400, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		} else {
			userName = params.UserName
			password = params.Password
		}
	} else {
		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		err = dec.Decode(&auth)
		if err != nil {
			resp.Status = 401
			resp.Message = err.Error()
			WriteLoginResponse(w, &resp)
			return
		}
		userName = auth.UserName
		password = auth.Password
		// practiceId = auth.PracticeId
	}

	// From here down is the same for both POST and GET
	//fmt.Printf("\nlogin:107 Calling login: userName: %s, password: %s\n\n", userName, password)

	startTime := time.Now()
	user, token, err := Login(userName, password, ip)
	VLog("INFO", fmt.Sprintf("Actual Login took: %s", time.Since(startTime)))
	//fmt.Printf("\nUser:112 - %s\n", spew.Sdump(user))
	VLog("INFO", "JWToken: "+token)
	if err != nil {
		resp.Status = 400
		resp.Message = err.Error()
	} else {
		resp.Status = 200
		resp.Message = "Ok"
		resp.Token = "Bearer " + token
		//resp.Url = user
		resp.Role = user.Role
		//resp.Practices = user.Practices
		resp.Facilities = user.Facilities
		//log.Debugf("Login:121 -- %s", spew.Sdump(user.Facilities))

	}
	//fmt.Printf("Setting Cookie:93 - %s\n", token)
	expMinutes, err := strconv.Atoi(os.Getenv("TOKENDURATION"))
	if err != nil {
		VLog("WARN", "environment TOKENDURATION is invalid, defaulting to 15 Minutes")
		expMinutes = 15
		err = nil
	}
	expirationTime := time.Now().Add(time.Duration(expMinutes) * time.Minute)
	http.SetCookie(w, &http.Cookie{
		Name:    "uc_token",
		Value:   token,
		Expires: expirationTime,
	})
	//fmt.Printf("Response: %s\n", spew.Sdump(resp))
	WriteLoginResponse(w, &resp)
	VLog("INFO", fmt.Sprintf("Login Elapsed time: %s\n", time.Since(StartTotalTime)))
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	var err error
	//spew.Dump(r.Body)
	//fmt.Printf("\n\n:PostLogin:225 - r = %s\n\n", spew.Sdump(r))
	//ip := GetIP(r)
	//fmt.Printf("PostLogin:2237 - ip = %s\n", ip)
	resp := common.LoginResponse{}
	ip := GetIP(r)
	auth := &common.AuthLogin{}
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	err = dec.Decode(&auth)
	if err != nil {
		resp.Status = 401
		resp.Message = VLogErr("Body is invalid: " + err.Error())
		WriteLoginResponse(w, &resp)
		return
	}
	userName = auth.UserName
	password = auth.Password
	user, token, err := Login(userName, password, ip)
	if err != nil {
		log.Printf("Login failed for user: [%s][%s]  err : %s\n", userName, password, err.Error())
		resp.Status = 400
		resp.Message = VLogErr(fmt.Sprintf("Login failed for user: [%s][%s]  err : %s\n", userName, password, err.Error()))
		WriteLoginResponse(w, &resp)
		return
	} else {
		resp.Status = 200
		resp.Message = "Ok"
		resp.Token = "Bearer " + token
		resp.UserName = user.UserName
		resp.FullName = user.FullName
		resp.ID = user.ID
		resp.Role = user.Role
		//resp.Practices = user.Practices
		resp.Facilities = user.Facilities
		//log.Debugf("Login:259 -- %s", spew.Sdump(user.Facilities))

	}
	//fmt.Printf("Setting Cookie:266 - %s\n", token)
	expMinutes, err := strconv.Atoi(os.Getenv("TOKENDURATION"))
	if err != nil {
		//log.Warn("TOKENDURATION is invalid default to 15 Minutes")
		expMinutes = 15
		err = nil
	}
	expirationTime := time.Now().Add(time.Duration(expMinutes) * time.Minute)
	http.SetCookie(w, &http.Cookie{
		Name:    "uc_token",
		Value:   token,
		Expires: expirationTime,
	})
	//fmt.Printf("Response: %s\n", spew.Sdump(resp))
	WriteLoginResponse(w, &resp)
}

func validateConnectorSession(w http.ResponseWriter, r *http.Request) {
	ip := GetIP(r)
	VLog("INFO", "IP of caller: "+ip)

	vars := mux.Vars(r)
	VLog("INFO", fmt.Sprintf("FindResource:182  --  %v\n", vars))
	systemId := vars["SystemId"] // The id of the fhirSystem to use
	if systemId == "" {
		VLog("INFO", "SystemId not found in params, checking header")
		systemId = r.Header.Get("SystemId")
	}
	systemOid, err := primitive.ObjectIDFromHex(systemId)
	if err != nil {
		errMsg := VLogErr("SystemId: " + err.Error())
		WriteFhirOperationOutcome(w, 400, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		return
	}
	systemConfig, err := GetSystemConfigById(systemOid)
	if err != nil {
		errMsg := VLogErr(fmt.Sprintf("SystemId - %s  error: %s", systemId, err.Error()))
		WriteFhirOperationOutcome(w, 400, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		return
	}
	VLog("INFO", "SystemId: "+systemId)
	jwt := r.Header.Get("Authorization")
	TokenPayload, status, err := ValidateToken(jwt, "")
	if err != nil {
		errMsg := err.Error()
		WriteFhirOperationOutcome(w, status, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		return
	}
	VLog("INFO", "Payload = %s"+spew.Sdump(TokenPayload))
	//jwt is valid get the authSession from it.
	conPayload, err := BuildConnectorPayload(systemConfig, "", nil)
	if err != nil {
		status = 400
		errMsg := VLogErr("CallConnector error: " + err.Error())
		WriteFhirOperationOutcome(w, status, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		return
	}
	//fmt.Printf("findPatients:163  --  conPayload(): %s \n", spew.Sdump(conPayload))
	baseUrl := conPayload.ConnectorConfig.URL
	query := "?" + r.URL.RawQuery
	VLog("INFO", fmt.Sprintf("conPayload(): %s \n", spew.Sdump(conPayload)))
	con := New(baseUrl, jwt)
	//log.Printf("findPatients:177  --  Calling con.CallConnector(): %s   with resource: %s  query: %s\n", baseUrl, resource, query)
	resp, err := con.CallConnector("Patient", query, conPayload)
	if err != nil {
		status = 400
		errMsg := VLogErr("CallConnector error: " + err.Error())
		WriteFhirOperationOutcome(w, status, CreateOperationOutcome(fhir.IssueTypeProcessing, fhir.IssueSeverityFatal, &errMsg))
		return
	}
	VLog("INFO", "response: "+spew.Sdump(resp))
}
func reDirect(w http.ResponseWriter, r *http.Request) {
	// fmt.Printf("Redirect: %s\n", spew.Sdump(r))
}
