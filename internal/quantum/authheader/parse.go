package authheader

import (
	"fmt"
	"strings"

	"github.com/quantumauth-io/quantum-auth/internal/quantum/constants"
)

func ParseQuantumAuthHeader(auth string) (map[string]string, error) {
	const prefix = constants.QAAuthHeaderPrefix
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("invalid scheme")
	}
	rest := strings.TrimSpace(auth[len(prefix):])
	parts := strings.Split(rest, ",")
	fields := make(map[string]string, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		fields[key] = val
	}
	return fields, nil
}
