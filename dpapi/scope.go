package DPAPI

import (
	"errors"
	"strings"
)

const (
	ScopeCurrentUser  = 0
	ScopeLocalMachine = 1
)

func ParseScope(s string) (uint32, error) {
	switch strings.ToLower(s) {
	case "currentuser":
		return ScopeCurrentUser, nil
	case "localmachine":
		return ScopeLocalMachine, nil
	default:
		return 0, errors.New("scope must be 'CurrentUser' or 'LocalMachine'")
	}
}
