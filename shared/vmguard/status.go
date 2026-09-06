package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type statusResponse struct {
	Uptime  string       `json:"uptime"`
	Guest   string       `json:"guest"`
	Gateway string       `json:"gateway"`
	Egress  ruleSetView  `json:"egress"`
	Ingress ruleSetView  `json:"ingress"`
	Traffic trafficView  `json:"traffic"`
	Blocked []blockEntry `json:"blocked"`
}

type ruleSetView struct {
	Default string   `json:"default"`
	Rules   []string `json:"rules"`
}

type trafficView struct {
	FramesOut   uint64 `json:"frames_out"`
	FramesIn    uint64 `json:"frames_in"`
	BytesOut    uint64 `json:"bytes_out"`
	BytesIn     uint64 `json:"bytes_in"`
	DeniedOut   uint64 `json:"denied_out"`
	DeniedIn    uint64 `json:"denied_in"`
	RejectsTCP  uint64 `json:"rejects_tcp"`
	RejectsICMP uint64 `json:"rejects_icmp"`
	Flows       int    `json:"tracked_flows"`
}

func viewOf(rs *ruleSet) ruleSetView {
	v := ruleSetView{Default: rs.fallback.String()}
	for _, r := range rs.rules {
		v.Rules = append(v.Rules, r.String())
	}
	return v
}

// serveStatus exposes the live policy and counters. It is read-only: rules are
// changed through the environment or NET_RULES_FILE, never over HTTP, so an
// exposed port cannot be used to widen the guest's access.
func serveStatus(cfg *config, f *filter) {
	start := time.Now()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		out, in := f.rules()
		resp := statusResponse{
			Uptime:  time.Since(start).Round(time.Second).String(),
			Guest:   addrOrDash(cfg.Guest),
			Gateway: addrOrDash(cfg.Gateway),
			Egress:  viewOf(out),
			Ingress: viewOf(in),
			Traffic: trafficView{
				FramesOut:   f.stats.framesOut.Load(),
				FramesIn:    f.stats.framesIn.Load(),
				BytesOut:    f.stats.bytesOut.Load(),
				BytesIn:     f.stats.bytesIn.Load(),
				DeniedOut:   f.stats.deniedOut.Load(),
				DeniedIn:    f.stats.deniedIn.Load(),
				RejectsTCP:  f.stats.rejectsTCP.Load(),
				RejectsICMP: f.stats.rejectsICM.Load(),
				Flows:       f.trackedFlows(),
			},
			Blocked: f.blocks.snapshot(),
		}

		if strings.Contains(r.Header.Get("Accept"), "text/plain") || r.URL.Query().Has("text") {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writeText(w, &resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	})

	addr := cfg.HTTPAddr
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("status endpoint on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("status endpoint stopped: %v", err)
	}
}

func writeText(w interface{ Write([]byte) (int, error) }, r *statusResponse) {
	fmt.Fprintf(w, "uptime   %s\nguest    %s\ngateway  %s\n\n", r.Uptime, r.Guest, r.Gateway)
	fmt.Fprintf(w, "egress (default %s)\n", r.Egress.Default)
	for i, s := range r.Egress.Rules {
		fmt.Fprintf(w, "  %2d. %s\n", i+1, s)
	}
	fmt.Fprintf(w, "\ningress (default %s)\n", r.Ingress.Default)
	for i, s := range r.Ingress.Rules {
		fmt.Fprintf(w, "  %2d. %s\n", i+1, s)
	}
	t := r.Traffic
	fmt.Fprintf(w, "\nframes   out=%d in=%d\nbytes    out=%d in=%d\ndenied   out=%d in=%d\nrejects  tcp=%d icmp=%d\nflows    %d tracked\n",
		t.FramesOut, t.FramesIn, t.BytesOut, t.BytesIn, t.DeniedOut, t.DeniedIn,
		t.RejectsTCP, t.RejectsICMP, t.Flows)
	if len(r.Blocked) > 0 {
		fmt.Fprintf(w, "\nblocked flows\n")
		for _, b := range r.Blocked {
			fmt.Fprintf(w, "  %-3s %-4s %s -> %s:%d  x%d  (%s)\n",
				b.Direction, b.Proto, b.Src, b.Dst, b.Port, b.Count, b.Rule)
		}
	}
}
