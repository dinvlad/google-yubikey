package metadata

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"github.com/dinvlad/google-yubikey/v2/token"
	"github.com/go-piv/piv-go/v2/piv"
)

const (
	metaRoot          = "/computeMetadata/v1"
	metaRootSa        = metaRoot + "/instance/service-accounts"
	metaRootSaDefault = metaRootSa + "/" + metaDefaultAlias
	metaRootProject   = metaRoot + "/project"
	metaDefaultAlias  = "default"

	metaFlavorHeader = "Metadata-Flavor"
	metaFlavorValue  = "Google"
)

type server struct {
	email      *mail.Address
	projectID  string
	projectNum string
	scopes     []string
}

func Serve(serial uint, slot piv.Slot, email *mail.Address, projectNum uint64, scopes []string, addr string) error {
	if len(scopes) == 0 {
		scopes = []string{token.DefaultScope}
	}

	s := server{
		email:      email,
		projectID:  strings.Split(strings.Split(email.Address, "@")[1], ".")[0],
		projectNum: strconv.FormatUint(projectNum, 10),
		scopes:     scopes,
	}

	mux := http.NewServeMux()

	saMux := http.NewServeMux()
	saMux.HandleFunc("GET /{$}", s.saDefaultHandler)
	saMux.HandleFunc("GET /email", s.saEmailHandler)
	saMux.HandleFunc("GET /identity", saIdentityHandler)
	saMux.HandleFunc("GET /token", saTokenHandler)
	mux.HandleFunc(metaRootSa+"/", s.saHandler)
	mux.Handle(metaRootSaDefault+"/", http.StripPrefix(metaRootSaDefault, saMux))

	pMux := http.NewServeMux()
	pMux.HandleFunc("GET /project-id", s.projectIDHandler)
	pMux.HandleFunc("GET /numeric-project-id", s.projectNumHandler)
	mux.Handle(metaRootProject+"/", http.StripPrefix(metaRootProject, pMux))

	return http.ListenAndServe(addr, metaHeaders(mux))
}

func (s server) saHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s/\n%s/\n", metaDefaultAlias, s.email.Address)
}

type saDefault struct {
	Aliases []string `json:"aliases"`
	Email   string   `json:"email"`
	Scopes  []string `json:"scopes"`
}

func (s server) saDefaultHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("recursive") != "true" {
		handleNotImplemented(w)
		return
	}
	setContentTypeJSON(w)
	if err := json.MarshalWrite(w, &saDefault{
		Aliases: []string{metaDefaultAlias},
		Email:   s.email.Address,
		Scopes:  s.scopes,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s server) saEmailHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, s.email.Address)
}

func saTokenHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func saIdentityHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func (s server) projectIDHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, s.projectID)
}

func (s server) projectNumHandler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, s.projectNum)
}

func handleNotImplemented(w http.ResponseWriter) {
	http.Error(w, "501 Not Implemented", http.StatusNotImplemented)
}

func setContentTypeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

func metaHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(metaFlavorHeader) != metaFlavorValue {
			err := fmt.Errorf("Missing %s:%s header.", metaFlavorHeader, metaFlavorValue)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		h := w.Header()
		h.Set(metaFlavorHeader, metaFlavorValue)
		h.Set("Server", "Metadata Server for VM")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("X-XSS-Protection", "1")
		next.ServeHTTP(w, r)
	})
}
