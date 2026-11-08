package metadata

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"slices"
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

func Serve(serial uint, slot piv.Slot, email *mail.Address, projectNum uint64, scopes []string, addr string) (err error) {
	s, err := newServer(serial, slot, email, projectNum, scopes)
	if err != nil {
		return
	}
	defer s.m.Close()

	mux := http.NewServeMux()

	saMux := http.NewServeMux()
	saMux.HandleFunc("GET /{$}", s.saDefaultHandler)
	saMux.HandleFunc("GET /email", s.saEmailHandler)
	saMux.HandleFunc("GET /identity", s.saIdentityHandler)
	saMux.HandleFunc("GET /token", s.saTokenHandler)
	mux.HandleFunc(metaRootSa+"/", s.saHandler)
	mux.Handle(metaRootSaDefault+"/", http.StripPrefix(metaRootSaDefault, saMux))

	pMux := http.NewServeMux()
	pMux.HandleFunc("GET /project-id", s.projectIDHandler)
	pMux.HandleFunc("GET /numeric-project-id", s.projectNumHandler)
	mux.Handle(metaRootProject+"/", http.StripPrefix(metaRootProject, pMux))

	fmt.Printf("export GCE_METADATA_ROOT=%s\n", addr)
	fmt.Printf("export GCE_METADATA_HOST=%s\n", addr)
	return http.ListenAndServe(addr, metaHeaders(mux))
}

type server struct {
	email      *mail.Address
	projectID  string
	projectNum string
	scopes     []string
	m          *token.Minter
}

func newServer(serial uint, slot piv.Slot, email *mail.Address, projectNum uint64, scopes []string) (s server, err error) {
	if len(scopes) == 0 {
		scopes = []string{token.DefaultScope}
	}
	s = server{
		email:      email,
		projectID:  strings.Split(strings.Split(email.Address, "@")[1], ".")[0],
		projectNum: strconv.FormatUint(projectNum, 10),
		scopes:     scopes,
	}
	s.m, err = token.NewMinter(serial, slot, email)
	return
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

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (s server) saTokenHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scopes := s.scopes
	switch strings.ToLower(q.Get("enforce_scopes")) {
	case "":
	case "true", "1", "yes", "y":
		scopes = strings.Split(q.Get("scopes"), ",")
		for i, sc := range scopes {
			sc = strings.TrimSpace(sc)
			scopes[i] = sc
			if !slices.Contains(s.scopes, sc) {
				http.Error(w, "scopes must be a subset of instance scopes", http.StatusBadRequest)
				return
			}
		}
	case "false", "0", "no", "n":
		http.Error(w, "enforce_scopes=false is not supported", http.StatusBadRequest)
		return
	default:
		http.Error(w, "invalid enforce_scopes value", http.StatusBadRequest)
		return
	}

	tok, err := s.m.Generate(token.AccessToken, "", scopes)
	if errors.Is(err, token.ErrInvalidParams) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setContentTypeJSON(w)
	json.MarshalWrite(w, &accessTokenResponse{tok, token.DefaultLifetimeSec, "Bearer"})
}

func (s server) saIdentityHandler(w http.ResponseWriter, r *http.Request) {
	tok, err := s.m.Generate(token.IDToken, r.URL.Query().Get("audience"), nil)
	if errors.Is(err, token.ErrInvalidParams) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, tok)
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
