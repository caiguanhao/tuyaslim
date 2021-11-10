package tuyaslim

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type (
	Client struct {
		ClientId     string
		ClientSecret string
		AccessToken  *AccessToken
		Host         string // defaults to "https://openapi.tuyacn.com"
	}

	AccessToken struct {
		AccessToken  string `json:"access_token"`
		ExpireTime   int    `json:"expire_time"`
		RefreshToken string `json:"refresh_token"`
		Uid          string `json:"uid"`
		expiredAt    time.Time
	}

	Device struct {
		Id        string   `json:"id"`
		Category  string   `json:"category"`
		IpAddress string   `json:"ip"`
		Name      string   `json:"name"`
		Online    bool     `json:"online"`
		Statuses  Statuses `json:"status"`
		CreatedAt Time     `json:"create_time"`
		UpdatedAt Time     `json:"update_time"`
	}

	Statuses map[string]interface{}

	Time time.Time

	tuyaRawStatus struct {
		Code  string      `json:"code"`
		Value interface{} `json:"value"`
	}

	response struct {
		Result  json.RawMessage `json:"result"`
		Success bool            `json:"success"`
		Code    int             `json:"code"`
		Message string          `json:"message"`
	}
)

func (t Time) MarshalJSON() ([]byte, error) {
	return time.Time(t).MarshalJSON()
}

func (t *Time) UnmarshalJSON(data []byte) error {
	u, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*t = Time(time.Unix(u, 0).UTC())
	return nil
}

func (t Time) String() string {
	return time.Time(t).Format(time.RFC3339)
}

func (s *Statuses) UnmarshalJSON(data []byte) error {
	var statuses []tuyaRawStatus
	err := json.Unmarshal(data, &statuses)
	if err != nil {
		return err
	}
	m := Statuses{}
	for _, status := range statuses {
		m[status.Code] = status.Value
	}
	*s = m
	return nil
}

// Create new client.
func NewClient(id, secret string) *Client {
	return &Client{
		ClientId:     id,
		ClientSecret: secret,
	}
}

// GetToken updates client.AccessToken.
func (client *Client) GetToken(ctx context.Context) error {
	defer func() {
		if client.AccessToken != nil {
			client.AccessToken.expiredAt = time.Now().Add(time.Duration(client.AccessToken.ExpireTime-5) * time.Second)
		}
	}()
	client.AccessToken = nil
	return client.Request(ctx, "GET", "/v1.0/token?grant_type=1", nil, &client.AccessToken)
}

// GetDevices returns all devices.
func (client *Client) GetDevices(ctx context.Context) (devices []Device, err error) {
	res := struct {
		Devices    []Device `json:"devices"`
		HasMore    bool     `json:"has_more"`
		LastRowKey string   `json:"last_row_key"`
	}{HasMore: true}
	for res.HasMore == true {
		url := "/v1.0/iot-01/associated-users/devices?size=50"
		if res.LastRowKey != "" {
			url += "&last_row_key=" + res.LastRowKey
		}
		err = client.Request(ctx, "GET", url, nil, &res)
		if err != nil {
			return
		}
		devices = append(devices, res.Devices...)
	}
	return
}

// Execute executes a command for a device given device ID.
func (client *Client) Execute(ctx context.Context, deviceId string, commands ...interface{}) error {
	req := struct {
		Commands []map[string]interface{} `json:"commands"`
	}{}
	var key *string = nil
	for _, value := range commands {
		if key == nil {
			if v, ok := value.(string); ok {
				key = &v
			}
		} else {
			req.Commands = append(req.Commands, map[string]interface{}{
				"code":  *key,
				"value": value,
			})
			key = nil
		}
	}
	return client.Request(ctx, "POST", "/v1.0/iot-03/devices/"+deviceId+"/commands", req, nil)
}

// Request makes a new request given a method, URL, and optional body, parses
// the JSON response and stores the result in the value pointed to by the
// optional targets. Error is returned if network has connectivity problem or
// server responded an error.
func (client *Client) Request(ctx context.Context, method, path string, body interface{}, targets ...interface{}) (err error) {
	host := client.Host
	if host == "" {
		host = "https://openapi.tuyacn.com"
	}
	url := host + path
	var bodyBytes []byte
	if body != nil {
		if bodyBytes, err = json.Marshal(body); err != nil {
			return
		}
	}
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return
	}

	if req.URL.Path != "/v1.0/token" && (client.AccessToken == nil || client.AccessToken.expiredAt.Before(time.Now())) {
		if err = client.GetToken(ctx); err != nil {
			return
		}
	}

	req.Header.Set("Signature-Headers", "access_token:client_id:content-type:sign_method:t")
	req.Header.Set("Content-Type", "application/json")
	client.signRequest(req, bodyBytes)

	var res *http.Response
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	var resp response
	if err = json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return
	}
	if resp.Success == false {
		if resp.Message != "" {
			err = fmt.Errorf("error: %s (code %d)", resp.Message, resp.Code)
			return
		}
		// https://developer.tuya.com/en/docs/iot/error-code?id=K989ruxx88swc
		err = fmt.Errorf("error code %d returned", resp.Code)
		return
	}
	for _, target := range targets {
		if target == nil {
			continue
		}
		if err = json.Unmarshal(resp.Result, target); err != nil {
			return
		}
	}
	return
}

func (client *Client) signRequest(req *http.Request, bodyBytes []byte) {
	t := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	req.Header.Set("client_id", client.ClientId)
	req.Header.Set("t", t)
	req.Header.Set("sign_method", "HMAC-SHA256")
	if client.AccessToken != nil {
		req.Header.Set("access_token", client.AccessToken.AccessToken)
	}

	var headers string
	if signHeaders := req.Header.Get("Signature-Headers"); signHeaders != "" {
		list := strings.Split(signHeaders, ":")
		for _, key := range list {
			headers += key + ":" + req.Header.Get(key) + "\n"
		}
	}
	contentSha256 := sha256sum(bodyBytes)
	stringToSign := req.Method + "\n" + contentSha256 + "\n" + headers + "\n" + canonicalPath(req)
	message := client.ClientId
	if client.AccessToken != nil {
		message += client.AccessToken.AccessToken
	}
	message += t + stringToSign
	sign := strings.ToUpper(hmacSha256(message, client.ClientSecret))

	req.Header.Set("sign", sign)
}

func canonicalPath(req *http.Request) string {
	path := req.URL.Path
	q, _ := url.ParseQuery(req.URL.RawQuery)
	var keys []string
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			path += "?"
		} else {
			path += "&"
		}
		path += k + "=" + q.Get(k)
	}
	return path
}

func sha256sum(data []byte) string {
	s := sha256.New()
	s.Write(data)
	return hex.EncodeToString(s.Sum(nil))
}

func hmacSha256(message, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
