package jaccount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
	"github.com/dyweb/go-jaccount/jaccount"
)

type Config struct {
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	RedirectURI  string   `json:"redirectURI"`
	Scopes       []string `json:"scopes"`
}

func (c *Config) Open(id string, logger log.Logger) (conn connector.Connector, err error) {
	return &jaccountConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		logger:       logger,
	}, nil
}

type connectorData struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type jaccountConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	logger       log.Logger
}

var (
	_ connector.CallbackConnector = (*jaccountConnector)(nil)
	_ connector.RefreshConnector  = (*jaccountConnector)(nil)
)

func (c *jaccountConnector) Close() error {
	return nil
}

func (c *jaccountConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     jaccount.Endpoint,
		Scopes:       []string{jaccount.ScopeProfile},
		RedirectURL:  c.redirectURI,
	}
}

func (c *jaccountConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", c.redirectURI, callbackURL)
	}
	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

func (c *jaccountConnector) HandleCallback(scopes connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if err := q.Get("error"); err != "" {
		return identity, fmt.Errorf("jaccount: %v", err)
	}

	oauth2Config := c.oauth2Config(scopes)

	ctx := r.Context()
	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("jaccount: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	jaccountClient := jaccount.NewClient(client)

	profile, err := jaccountClient.Profile.Get(context.Background())
	if err != nil {
		return identity, fmt.Errorf("jaccount: get profile: %v", err)
	}

	identity = connector.Identity{
		UserID:            profile.ID,
		Username:          profile.Name,
		PreferredUsername: profile.Account,
		Email:             profile.Email,
		EmailVerified:     true,
	}

	if scopes.OfflineAccess {
		data := connectorData{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
		}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *jaccountConnector) Refresh(ctx context.Context, scopes connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	if len(identity.ConnectorData) == 0 {
		return identity, errors.New("no upstream refresh token found")
	}

	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("jaccount: unmarshal refresh token: %v", err)
	}

	client := c.oauth2Config(scopes).Client(ctx, &oauth2.Token{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
	})

	jaccountClient := jaccount.NewClient(client)

	profile, err := jaccountClient.Profile.Get(context.Background())
	if err != nil {
		return identity, fmt.Errorf("jaccount: get profile: %v", err)
	}

	identity.Username = profile.Name
	identity.PreferredUsername = profile.Account
	identity.Email = profile.Email

	return identity, nil
}
