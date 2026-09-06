package main

import (
	"log"
	"os"
	"time"
)

// watchRules reloads NET_RULES_FILE when it changes, so a policy can be edited
// on a mounted volume without restarting the VM.
//
// Two failure modes are deliberately treated as "keep what is running":
// a file that no longer parses, and a file that disappeared. Both would
// otherwise silently widen the guest's access, which is the one outcome a
// network policy must never produce by accident. A change is also required to
// stay put for a full interval before it is applied, so a half-written file
// caught mid-save is never mistaken for an empty policy.
func watchRules(cfg *config, f *filter, res *hostResolver, interval time.Duration) {
	if cfg.RulesFile == "" {
		return
	}

	applied := stamp(cfg.RulesFile) // version currently in force
	settling := applied             // version seen on the previous tick
	warnedMissing := false

	t := time.NewTicker(interval)
	defer t.Stop()

	for range t.C {
		cur := stamp(cfg.RulesFile)

		if cur == "" {
			if !warnedMissing {
				log.Printf("keeping previous rules, %s is gone", cfg.RulesFile)
				warnedMissing = true
			}
			continue
		}
		warnedMissing = false

		if cur != settling {
			// Still being written; wait for it to hold still.
			settling = cur
			continue
		}
		if cur == applied {
			continue
		}
		applied = cur

		out, in, err := buildRules(cfg, os.Getenv)
		if err != nil {
			log.Printf("keeping previous rules, %s is invalid: %v", cfg.RulesFile, err)
			continue
		}

		if res != nil {
			res.mu.Lock()
			res.targets = append(out.hostRules(), in.hostRules()...)
			res.mu.Unlock()
			res.refresh()
		}

		f.setRules(out, in)
		log.Printf("reloaded %s", cfg.RulesFile)
		for _, line := range describe(cfg, out, in) {
			log.Print(line)
		}
	}
}

// stamp identifies a file version cheaply; a missing file has an empty stamp.
func stamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return st.ModTime().UTC().Format(time.RFC3339Nano) + ":" + itoa(st.Size())
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
