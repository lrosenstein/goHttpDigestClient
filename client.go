package goHttpDigestClient

import (
	"io"
	"io/ioutil"
	"net/http"
)

// if option is set, get challenge at construct time
// if option not set, ever digest auth will send 2 request
type Client struct {
	is_init bool
	option  ClientOption
	http.Client
}

type ClientOption struct {
	username string
	password string
}

// create new Client instance
func NewClient(username, password string) *Client {
	opt := &ClientOption{username: username, password: password}
	// here need more attention
	return &Client{option: *opt, is_init: false}
}

func GetChallengeFromHeader(h *http.Header) Challenge {
	return NewChallenge(h.Get(KEY_WWW_Authenticate))
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	res, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		res.Body.Close()
		challenge := GetChallengeFromHeader(&res.Header)
		challenge.ComputeResponse(req.Method, req.URL.RequestURI(), getStrFromIO(req.Body), c.option.username, c.option.password)
		authorization := challenge.ToAuthorizationStr()
		req.Header.Set(KEY_AUTHORIZATION, authorization)
		return c.Client.Do(req)
	} else {
		return res, err
	}
}

// From ReadCloser to string
func getStrFromIO(r io.ReadCloser) string {
	if r == nil {
		return ""
	}
	if b, err := ioutil.ReadAll(r); err == nil {
		return string(b)
	} else {
		return ""
	}
}
