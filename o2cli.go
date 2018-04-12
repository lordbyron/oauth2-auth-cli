package o2cli

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/Sirupsen/logrus"
	rndm "github.com/nmrshll/rndm-go"
	"github.com/skratchdot/open-golang/open"
)

type Oauth2CLI struct {
	log  *logrus.Logger
	Conf *oauth2.Config
}

func (o *Oauth2CLI) init() {
	if o.log == nil {
		o.log = logrus.StandardLogger()
	}
}

func (o *Oauth2CLI) Authorize() (*oauth2.Token, error) {
	o.init()

	errorC := make(chan error, 1)
	successC := make(chan *oauth2.Token, 1)
	state := rndm.String(8)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := o.handle(w, r, state)
		if err != nil {
			errorC <- err
			http.Redirect(w, r, "failure", http.StatusOK)
			return
		}
		successC <- token
		http.Redirect(w, r, "success", http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	o.Conf.RedirectURL = fmt.Sprintf("%s%s", server.URL, "/callback")
	url := o.Conf.AuthCodeURL(state)

	fmt.Printf("If browser window does not open automatically, open it by clicking on the link:\n %s\n", url)
	open.Run(url)
	fmt.Printf("Waiting for response on: %s\n", server.URL)

	select {
	case err := <-errorC:
		o.log.Errorf("Error in callback: %v", err)
		return nil, err
	case token := <-successC:
		o.log.Info("Successfully exchanged for Access Token")
		return token, nil
	case <-time.After(60 * time.Second):
		o.log.Error("Timed out waiting for callback")
		return nil, errors.New("Timed out waiting for callback")
	}
}

func (o *Oauth2CLI) handle(w http.ResponseWriter, r *http.Request, expectedState string) (*oauth2.Token, error) {
	if r.URL.Path != "/callback" {
		return nil, errors.New("callback has incorrect path. should be `/callback`")
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		return nil, errors.New("callback missing required query param `state`")
	}
	if state != expectedState {
		return nil, errors.New("callback state invalid")
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("callback missing required query param `code`")
	}
	oauth2.RegisterBrokenAuthHeaderProvider(o.Conf.Endpoint.TokenURL)
	return o.Conf.Exchange(context.Background(), code)
}
