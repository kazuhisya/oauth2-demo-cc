package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"encoding/json"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

// Client info from Json
type Client struct {
	Id     string `json:"id"`
	Secret string `json:"secret"`
}

func main() {
	// Read file
	bytes, err := ioutil.ReadFile("client.json")
	if err != nil {
		log.Fatal(err)
	}

	// Decode
	var clients []Client
	if err := json.Unmarshal(bytes, &clients); err != nil {
		log.Fatal(err)
	}

	// Token Store
	manager := manage.NewDefaultManager()

	// SetClientTokenCfg set the password grant token config
	cfg := &manage.Config{
		// access token expiration time (default: time.Hour * 2)
		AccessTokenExp: time.Minute * 2,
	}
	manager.SetClientTokenCfg(cfg)

	// TODO: imple RDBMS
	manager.MustTokenStorage(store.NewFileTokenStore("token.db"))

	// client memory store
	clientStore := store.NewClientStore()
	// form JSON
	for _, p := range clients {
		clientStore.Set(p.Id, &models.Client{ID: p.Id, Secret: p.Secret})
	}
	manager.MapClientStorage(clientStore)

	// http srv
	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetAllowedGrantType(oauth2.ClientCredentials)

	// client authentication from GET pram
	// e.g. &client_id=APP01&client_secret=APPSEC
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"scope":      token.GetScope(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}
