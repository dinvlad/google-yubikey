package metadata

import (
	"fmt"
	"net/http"

	"github.com/go-piv/piv-go/v2/piv"
)

const (
	metaRoot          = "/computeMetadata/v1"
	metaRootSa        = metaRoot + "/instance/service-accounts"
	metaRootSaDefault = metaRootSa + "/default"
	metaRootProject   = metaRoot + "/project"

	metaFlavorHeader = "Metadata-Flavor"
	metaFlavorValue  = "Google"
)

func Serve(serial uint, slot piv.Slot, account string, nProjectID uint64, addr string) error {
	mux := http.NewServeMux()

	saMux := http.NewServeMux()
	saMux.HandleFunc("GET /{$}", saDefaultHandler)
	saMux.HandleFunc("GET /email", saEmailHandler)
	saMux.HandleFunc("GET /identity", saIdentityHandler)
	saMux.HandleFunc("GET /token", saTokenHandler)
	mux.Handle(metaRootSaDefault+"/", http.StripPrefix(metaRootSaDefault, saMux))
	mux.HandleFunc(metaRootSa+"/", saHandler)

	pMux := http.NewServeMux()
	pMux.HandleFunc("GET /project-id", projectIDHandler)
	pMux.HandleFunc("GET /numeric-project-id", numericProjectIDHandler)
	mux.Handle(metaRootProject+"/", http.StripPrefix(metaRootProject, pMux))

	return http.ListenAndServe(addr, metaHeaders(mux))
}

func saHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func saDefaultHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func saEmailHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func saTokenHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func saIdentityHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func projectIDHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func numericProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	handleNotImplemented(w)
}

func handleNotImplemented(w http.ResponseWriter) {
	http.Error(w, "501 Not Implemented", http.StatusNotImplemented)
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
