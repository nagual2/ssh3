// Package pprofutil serves net/http/pprof on an opt-in address so bulk
// transfers can be profiled without a rebuild (SSH3_PPROF=127.0.0.1:6060).
package pprofutil

import (
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof handlers on http.DefaultServeMux

	"github.com/rs/zerolog/log"
)

// ServeIfEnabled starts a pprof HTTP server in the background when addr is
// non-empty; a no-op otherwise.
func ServeIfEnabled(addr string) {
	if addr == "" {
		return
	}
	go func() {
		log.Info().Msgf("pprof server listening on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Error().Msgf("pprof server: %s", err)
		}
	}()
}
