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

//const CHARGES_URL = "https://cert.api.fiservapps.com/ch/payments/v1/charges"

const CHARGES_URL = "http://localhost:8080/ch/payments/v1/charges"

//const CHARGES_URL = "https://httpbin.org/post"

// JTE TODO - put these in Environment for security purposes
const key = "lq6sRHxltHk4PkB4myfSGalRzK9kvcir"
const secret = "vZ9UUZ5gtzUPlbia8BgC2G6qzDJGmli38G1osZjJPDz"

// Here are the bodies of the requests that we'll be sending
const gCharge_data = "{\"amount\":{\"total\":500,\"currency\":\"USD\"},\"source\":{\"sourceType\":\"PaymentTrack\",\"encryptionData\":{\"encryptionType\":\"ON_GUARD\",\"encryptionTarget\":\"TRACK_2\",\"encryptionBlock\":\"4614507291879694=078443325742854\",\"keyId\":\"FFFF109700000E4000340114\",\"deviceType\":\"INGENICO\"},\"pinBlock\":{\"encryptedPin\":\"0FF7A610CC84CE40\",\"keySerialNumber\":\"FFFF3D3D3D00232002C9\"}},\"transactionDetails\":{\"captureFlag\":true},\"transactionInteraction\":{\"origin\":\"POS\",\"posEntryMode\":\"MAG_STRIPE\",\"posConditionCode\":\"CARD_PRESENT\",\"terminalTimestamp\":\"2022-03-10T04:26:56Z\",\"additionalPosInformation\":{\"dataEntrySource\":\"MOBILE_TERMINAL\",\"posFeatures\":{\"pinAuthenticationCapability\":\"CAN_ACCEPT_PIN\",\"terminalEntryCapability\":\"MAG_STRIPE_MANUAL_CHIP\"}}},\"merchantDetails\":{\"merchantId\":\"100009000000035\",\"terminalId\":\"10000002\"},\"additionalDataCommon\":{\"directedRouting\":{\"processors\":[{\"code\":\"NASHVILLE\",\"platform\":\"NORTH\",\"priority\":\"PRIMARY\"}]}}}"
const gCancel_data = `{"amount":{"total":500,"currency":"USD"}, "merchantDetails": {"merchantId": "100009000000035", "terminalId": "10000002"}}`

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

func sendChargeRequest() {

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

	// Make http call
	log.Println("Sending Charge request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking charges endpoint:", resp.StatusCode)
	} else {
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		//log.Print(string(body))

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

	// Make http call
	log.Println("Sending Cancel request")

	resp, err := client.Do(req)
	if err != nil || (resp.StatusCode != 201 && resp.StatusCode != 200) {
		// handle error
		log.Println("Error invoking cancel endpoint:", resp.StatusCode)
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

func main() {
	sendChargeRequest()
	sendCancelRequest()
}
