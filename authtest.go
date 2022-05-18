// Copyright 2021 J. Thomas Eck. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	//"flag"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

const CHARGES_URL = "http://gorouter-env.eba-feu6zuyy.us-east-2.elasticbeanstalk.com/ch/payments/v1/charges"
const INQUIRY_URL = "http://gorouter-env.eba-feu6zuyy.us-east-2.elasticbeanstalk.com/ch/payments/v1/transaction-inquiry"

// const CHARGES_URL = "https://cert.api.fiservapps.com/ch/payments/v1/charges"

// const CHARGES_URL = "http://localhost:5000/ch/payments/v1/charges"

// const CHARGES_URL = "http://dstest-349919.ue.r.appspot.com/ch/payments/v1/charges"

//const CHARGES_URL = "https://httpbin.org/post"

// JTE TODO - put these in Environment for security purposes
const key = "lq6sRHxltHk4PkB4myfSGalRzK9kvcir"
const secret = "vZ9UUZ5gtzUPlbia8BgC2G6qzDJGmli38G1osZjJPDz"

// Here are the bodies of the requests that we'll be sending
const gCancel_data = `{"amount":{"total":1,"currency":"USD"}, "merchantDetails": {"merchantId": "100009000000035", "terminalId": "10000002"}}`
const gCapture_data = `{"amount":{"total":1,"currency":"USD"}, "merchantDetails": {"merchantId": "100009000000035", "terminalId": "10000002"}}`
const gRefund_data = `{"amount":{"total":3,"currency":"USD"}, "merchantDetails": {"merchantId": "100009000000035", "terminalId": "10000002"}}`

const gInquiry_data = `{"transactionDetails":{"primaryTransactionId":"b5275cf57d7b43a8a448752372e8f4b1"}}`

const gCharge_data = `{
    "amount": {
        "total": 3,
        "currency": "USD"
    },
    "source": {
          "sourceType": "PaymentTrack",
        "encryptionData": {
            "encryptionType": "ON_GUARD",
            "encryptionTarget": "TRACK_2",
            "encryptionBlock": "2205243045158404=49883671338327",
            "keyId": "FFFF9999990217A000190114",
            "deviceType": "INGENICO"
        }
    },
    "transactionDetails": {
         "captureFlag": true
    },
    "transactionInteraction": {
         "origin": "POS",
        "posEntryMode": "MAG_STRIPE",
        "posConditionCode": "CARD_PRESENT", 
        "terminalTimestamp": "2022-03-11T09:21:46Z",
        "additionalPosInformation": {
            "dataEntrySource": "MOBILE_POS",
            "posFeatures": {
                "pinAuthenticationCapability": "UNSPECIFIED",
                "terminalEntryCapability": "MAG_STRIPE_ONLY"
            }
        }
    },
    "merchantDetails": {
        "merchantId": "100009000000035",
        "terminalId": "10000002"
    },
    "additionalDataCommon": {
        "directedRouting": {
            "processors": [
                {
                    "code": "NASHVILLE",
                    "platform": "NORTH",
                    "priority": "PRIMARY"
                }
            ]
        }
    }
}`

// Header value for the TestRun identifier
const TEST_RUN_ID = "88888888"

// Will be set in the charge request, and read in the cancel request
var gTransactionId = ""

func getSignature(key string, secret string, data string, time int64, clientRequestId int) string {

	rawSignature := key + fmt.Sprint(clientRequestId) + fmt.Sprint(time) + data

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(rawSignature))

	// Get result and encode as Base64 string
	sha := b64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))

	return sha
}

func cleanse(input string) string {
	return strings.Trim(input, "\"")
}

func sendAuthRequest() {

	// Create an http client
	client := &http.Client{
		CheckRedirect: nil,
	}

	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, gCharge_data, time, clientRequestId)

	// Setup http request
	req, err := http.NewRequest("POST", CHARGES_URL, bytes.NewBuffer([]byte(gCharge_data)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)
	req.Header.Add("X-TESTRUN-ID", TEST_RUN_ID)

	req.Header.Add("xOriginator", "thd")

	// Make http call
	log.Println("Sending Charge request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking charges endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))

		jsonResp := gjson.Parse(string(body))
		gTransactionId = cleanse(jsonResp.Get("gatewayResponse.transactionProcessingDetails.transactionId").Raw)
		log.Println("Charge request successful, transactionId is", gTransactionId)
	}
}

func sendCancelRequest() {

	// Create an http client
	client := &http.Client{
		CheckRedirect: nil,
	}

	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, gCancel_data, time, clientRequestId)

	// Setup http request
	cancel_url := CHARGES_URL + "/" + gTransactionId + "/cancel"
	log.Println("Cancel URL is", cancel_url)
	req, err := http.NewRequest("POST", cancel_url, bytes.NewBuffer([]byte(gCancel_data)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)
	req.Header.Add("X-TESTRUN-ID", TEST_RUN_ID)

	// Make http call
	log.Println("Sending Cancel request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking cancel endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		//log.Print(string(body))

		jsonResp := gjson.Parse(string(body))
		// Set the global transactionId so we can cancel it next
		gTransactionId = cleanse(jsonResp.Get("gatewayResponse.transactionProcessingDetails.transactionId").Raw)
		log.Println("Cancel request successful, transactionId is", gTransactionId)
	}
}

func sendCaptureRequest() {

	// Create an http client
	client := &http.Client{
		CheckRedirect: nil,
	}

	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, gCapture_data, time, clientRequestId)

	// Setup http request
	capture_url := CHARGES_URL + "/" + gTransactionId + "/capture"
	log.Println("Capture URL is", capture_url)
	req, err := http.NewRequest("POST", capture_url, bytes.NewBuffer([]byte(gCapture_data)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)
	req.Header.Add("X-TESTRUN-ID", TEST_RUN_ID)

	// Make http call
	log.Println("Sending Capture request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking capture endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		//log.Print(string(body))

		jsonResp := gjson.Parse(string(body))
		// Set the global transactionId so we can cancel it next
		gTransactionId = cleanse(jsonResp.Get("gatewayResponse.transactionProcessingDetails.transactionId").Raw)
		log.Println("Capture request successful, transactionId is", gTransactionId)
	}
}

func sendRefundRequest() {

	// Create an http client
	client := &http.Client{
		CheckRedirect: nil,
	}

	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, gRefund_data, time, clientRequestId)

	// Setup http request
	refund_url := CHARGES_URL + "/" + gTransactionId + "/refund"
	log.Println("Refund URL is", refund_url)
	req, err := http.NewRequest("POST", refund_url, bytes.NewBuffer([]byte(gRefund_data)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)
	req.Header.Add("X-TESTRUN-ID", TEST_RUN_ID)

	// Make http call
	log.Println("Sending Refund request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking refund endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		//log.Print(string(body))

		jsonResp := gjson.Parse(string(body))
		// Set the global transactionId so we can cancel it next
		gTransactionId = cleanse(jsonResp.Get("gatewayResponse.transactionProcessingDetails.transactionId").Raw)
		log.Println("Refund request successful, transactionId is", gTransactionId)
	}
}

func sendInquiryRequest() {

	// Create an http client
	client := &http.Client{
		CheckRedirect: nil,
	}

	time := time.Now().UnixNano() / int64(time.Millisecond)

	// Generate a nice random number (seeded w/current time) for idempotency check
	randSource := rand.NewSource(time)
	clientRequestId := rand.New(randSource).Intn(10000000) + 1

	signature := getSignature(key, secret, gInquiry_data, time, clientRequestId)

	// Setup http request
	inquiry_url := INQUIRY_URL
	log.Println("Inquiry URL is", inquiry_url)
	req, err := http.NewRequest("POST", inquiry_url, bytes.NewBuffer([]byte(gInquiry_data)))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept-language", "en")
	req.Header.Add("Auth-Token-Type", "HMAC")
	req.Header.Add("Timestamp", strconv.Itoa(int(time)))
	req.Header.Add("Api-Key", key)
	req.Header.Add("Client-Request-Id", strconv.Itoa(int(clientRequestId)))
	req.Header.Add("Authorization", signature)
	req.Header.Add("X-TESTRUN-ID", TEST_RUN_ID)

	// Make http call
	log.Println("Sending Inquiry request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking Inquiry endpoint:", resp.StatusCode)
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		log.Print(string(body))
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		// log.Print(string(body))

		jsonResp := gjson.Parse(string(body))
		log.Println("Inquiry request successful, response is\n", jsonResp)
	}
}

func main() {
	sendInquiryRequest()
	sendAuthRequest()
	sendRefundRequest()
	sendCaptureRequest()
	sendCancelRequest()
}
