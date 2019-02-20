package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/comail/colog"
	"github.com/dgrijalva/jwt-go"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/errors"
	"gopkg.in/oauth2.v3/generates"
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
	//CoLog init
	colog.Register()

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

	// JWT
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("12345678"), jwt.SigningMethodHS256))

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
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")

		log.Printf("info: /token, ID: %s , Sec: %s", clientID, clientSecret)
		srv.HandleTokenRequest(w, r)
	})

	http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.FormValue("access_token")
		log.Printf("info: /test, Token: %s", accessToken)

		token, err := srv.ValidationBearerToken(r)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		if err != nil {

			log.Printf("warn: /test, Token: %s is invalid access token", accessToken)
			//http.Error(w, err.Error(), http.StatusBadRequest)
			w.WriteHeader(400)
			data := map[string]interface{}{
				"error":             "invalid_access_token",
				"error_description": "Invalid access token",
			}
			e := json.NewEncoder(w)
			e.SetIndent("", "  ")
			e.Encode(data)
			return
		}

		log.Printf("info: /test, Token: %s is verified", accessToken)

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"scope":      token.GetScope(),
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(data)
	})

	// wip
	http.HandleFunc("/jwt", func(w http.ResponseWriter, r *http.Request) {
		access := r.FormValue("access_token")
		fmt.Fprintf(w, "access: %s\n", access)

		token, err := jwt.ParseWithClaims(access, &generates.JWTAccessClaims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				log.Println("1")
				return nil, fmt.Errorf("parse error")
			}
			log.Println("2")
			return []byte("12345678"), nil
		})
		if err != nil {
			log.Println("3")
			fmt.Errorf("parse error2")
			return
		}
		log.Println("4")
		claims := token.Claims.(*generates.JWTAccessClaims)
		fmt.Println(claims.ClientID)
	})

	log.Println("Server is running at 9096 port.")
	log.Fatal(http.ListenAndServe(":9096", nil))
}
