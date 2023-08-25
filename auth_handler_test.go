package authorize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	//"time"
	"github.com/davecgh/go-spew/spew"
	"github.com/dhf0820/uc_core/common"
	"github.com/joho/godotenv"

	//log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

type LoginRequest struct {
	UserName string `json:"userName"`
	Password string `json:"password"`
}

func TestPostLogin(t *testing.T) {
	godotenv.Load("./.env.uc_core_test")
	_, err := InitCore("uc_core", "test", "test")
	if err != nil {
		t.Fatalf("InitCore failed: %s", err.Error())
	}
	Convey("Subject: GetPatient returns the user information", t, func() {
		pwReq := LoginRequest{}
		pwReq.UserName = "dhfrench@vertisoft.com"
		pwReq.Password = "password"
		body, err := json.Marshal(pwReq)
		So(err, ShouldBeNil)
		So(body, ShouldNotBeNil)
		Convey("Given a valid username and password", func() {
			fmt.Printf("\n\nGiven a valid user/password\n")

			req := httptest.NewRequest(http.MethodPost, "/api/rest/v1/authorize", bytes.NewReader(body))
			respData := common.LoginResponse{}
			resp := httptest.NewRecorder()

			NewRouter().ServeHTTP(resp, req)
			//So(resp.Code, ShouldEqual, 200)

			b, _ := io.ReadAll(resp.Body)
			fmt.Printf("Headers : %v\n", resp.Header())
			//log.Debugf("b: %s\n", string(b))
			//defer resp.Body.Close()

			err := json.Unmarshal(b, &respData)
			So(err, ShouldBeNil)
			So(respData, ShouldNotBeNil)
			So(respData.Status, ShouldEqual, 200)
			//So(respData.Message, ShouldEqual "Ok")
			//sessionId := respData.SessionId
			fmt.Printf("ResponseData: %s\n", spew.Sdump(respData))
			// So(sessionId, ShouldNotEqual, "")
			// session, err := m.ValidateSession(sessionId)
			// //token, err :=m.VerifyTokenString(tokenString)
			// So(err, ShouldBeNil)
			// So(session, ShouldNotBeNil)
			//log.Debugf("Token: %s", spew.Sdump(token))
			// ad, err := m.GetTokenMetaData(token)
			// So(err, ShouldBeNil)
			// So(ad.SessionId, ShouldNotBeEmpty)
			//log.Debugf("Session: %s", ad.SessionId)
			//log.Debugf("Token: %s", tokenString)

			//log.Debugf("SessionId: %s", session.SessionID)

		})
		// Convey("Given a invalid username and password", func() {
		// 	fmt.Printf("\n\nGiven a invalid user/password\n")
		// 	req := httptest.NewRequest("POST", "/api/rest/v1/login?user_name=dhf&password=passsword", nil)
		// 	respData := LoginResponse{}
		// 	resp := httptest.NewRecorder()

		// 	NewRouter().ServeHTTP(resp, req)
		// 	So(resp.Code, ShouldEqual, 400)

		// 	b, _ := ioutil.ReadAll(resp.Body)

		// 	//log.Debugf("b: %s\n", string(b))
		// 	//defer resp.Body.Close()

		// 	err := json.Unmarshal(b, &respData)
		// 	So(err, ShouldBeNil)
		// 	So(respData, ShouldNotBeNil)

		// 	fmt.Printf("messsage: %s\n", spew.Sdump(respData))
		// })
	})
}

func TestGetLogin(t *testing.T) {
	godotenv.Load("./.env.uc_core_test")
	_, err := InitCore("uc_core", "test", "test")
	if err != nil {
		t.Fatalf("InitCore failed: %s", err.Error())
	}
	// godotenv.Load("./.env.core_test")
	// _, err := InitCore("uc_core", "test", "test")
	// if err != nil {
	// 	t.Fatalf("InitCore failed: %s", err.Error())
	// }
	Convey("Subject: GetPatient returns the user information using GET", t, func() {
		Convey("Given a valid username and password", func() {
			fmt.Printf("\n\nGiven a valid user/password\n")

			req := httptest.NewRequest(http.MethodGet, "/api/rest/v1/login?userName=dhfrench@vertisoft.com&password=password", nil)
			respData := common.LoginResponse{}
			resp := httptest.NewRecorder()

			NewRouter().ServeHTTP(resp, req)

			b, _ := io.ReadAll(resp.Body)
			fmt.Printf("Headers : %v\n", resp.Header())
			//log.Debugf("b: %s\n", string(b))
			//defer resp.Body.Close()

			err := json.Unmarshal(b, &respData)
			So(err, ShouldBeNil)
			So(respData, ShouldNotBeNil)
			So(respData.Status, ShouldEqual, 200)
			//So(respData.Message, ShouldEqual "Ok")
			//sessionId := respData.SessionId
			fmt.Printf("ResponseData: %s\n", spew.Sdump(respData))
			// So(sessionId, ShouldNotEqual, "")
			// session, err := m.ValidateSession(sessionId)
			// //token, err :=m.VerifyTokenString(tokenString)
			// So(err, ShouldBeNil)
			// So(session, ShouldNotBeNil)
			//log.Debugf("Token: %s", spew.Sdump(token))
			// ad, err := m.GetTokenMetaData(token)
			// So(err, ShouldBeNil)
			// So(ad.SessionId, ShouldNotBeEmpty)
			//log.Debugf("Session: %s", ad.SessionId)
			//log.Debugf("Token: %s", tokenString)

			//log.Debugf("SessionId: %s", session.SessionID)

		})
	})
}
