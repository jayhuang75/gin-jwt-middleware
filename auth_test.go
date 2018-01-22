package auth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWTAuthMiddleware(t *testing.T) {
	JWTAuthMiddleware(false, "mySercet")

	// Switch to test mode so you don't get such noisy output
	gin.SetMode(gin.TestMode)

	// Setup your router, just like you did in your main function, and
	// register your routes
	r := gin.Default()
	r.Use(JWTAuthMiddleware(false, "mySecret"))
	r.GET("/api/v1")

	////////////////////////////////////
	// Test without Authorization header
	////////////////////////////////////
	req1, _ := http.NewRequest(http.MethodGet, "/api/v1", nil)

	// Create a response recorder so you can inspect the response
	resp1 := httptest.NewRecorder()

	// Perform the request
	r.ServeHTTP(resp1, req1)

	assert.Equal(t, resp1.Code, 401)
	bodyBytes1, _ := ioutil.ReadAll(resp1.Body)
	bodyString1 := string(bodyBytes1)
	expect := &APIError{401, "API token required"}
	expectString, _ := json.Marshal(expect)
	assert.Equal(t, bodyString1, string(expectString))

	////////////////////////////////////
	// Test with Authorization header but without Bearer
	////////////////////////////////////
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1", nil)
	req2.Header.Set("Authorization", "test")
	// Create a response recorder so you can inspect the response
	resp2 := httptest.NewRecorder()

	// Perform the request
	r.ServeHTTP(resp2, req2)

	assert.Equal(t, resp2.Code, 401)
	bodyBytes2, _ := ioutil.ReadAll(resp2.Body)
	bodyString2 := string(bodyBytes2)
	expect = &APIError{401, "Authorization header must start with Bearer"}
	expectString, _ = json.Marshal(expect)
	assert.Equal(t, bodyString2, string(expectString))

	////////////////////////////////////
	// Test with Authorization header with Bearer but without token
	////////////////////////////////////
	req3, _ := http.NewRequest(http.MethodGet, "/api/v1", nil)
	req3.Header.Set("Authorization", "Bearer ")
	// Create a response recorder so you can inspect the response
	resp3 := httptest.NewRecorder()

	// Perform the request
	r.ServeHTTP(resp3, req3)

	assert.Equal(t, resp3.Code, 401)
	bodyBytes3, _ := ioutil.ReadAll(resp3.Body)
	bodyString3 := string(bodyBytes3)
	expect = &APIError{401, "Token not found"}
	expectString, _ = json.Marshal(expect)
	assert.Equal(t, bodyString3, string(expectString))

	////////////////////////////////////
	// Test with Authorization header with Bearer and token but more than those
	////////////////////////////////////
	req4, _ := http.NewRequest(http.MethodGet, "/api/v1", nil)
	req4.Header.Set("Authorization", "Bearer tasfasdf test")
	// Create a response recorder so you can inspect the response
	resp4 := httptest.NewRecorder()

	// Perform the request
	r.ServeHTTP(resp4, req4)

	assert.Equal(t, resp3.Code, 401)
	bodyBytes4, _ := ioutil.ReadAll(resp4.Body)
	bodyString4 := string(bodyBytes4)
	expect = &APIError{401, "Authorization header must be Bearer and token"}
	expectString, _ = json.Marshal(expect)
	assert.Equal(t, bodyString4, string(expectString))

	////////////////////////////////////
	// Test with Authorization header with Bearer and token but sigature is invalid
	////////////////////////////////////
	req5, _ := http.NewRequest(http.MethodGet, "/api/v1", nil)
	req5.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiJXZWkuSHVhbmdAQ09SUC5BRC5DVEMiLCJzZXNzaW9uSUQiOiJuWjZlM3dKWFBaUndUOElvMHFncjF3akdqUFNsNzgtSCIsImlhdCI6MTUxNjUwMjM0MywiZXhwIjoxNTE2NTAyNDYzfQ.dRbEhMlhO1t1AuTLsvdYd-hva7K2tLbgQNNXJgb5GCw")
	// Create a response recorder so you can inspect the response
	resp5 := httptest.NewRecorder()

	// Perform the request
	r.ServeHTTP(resp5, req5)

	assert.Equal(t, resp5.Code, 401)
	bodyBytes5, _ := ioutil.ReadAll(resp5.Body)
	bodyString5 := string(bodyBytes5)
	expect = &APIError{401, "signature is invalid"}
	expectString, _ = json.Marshal(expect)
	assert.Equal(t, bodyString5, string(expectString))

}
