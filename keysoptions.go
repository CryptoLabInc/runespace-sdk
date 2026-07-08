package runespace

import (
	"fmt"
	"strings"
)

// KeyPart names an encrypt/decrypt material a Keys bundle can load. Select via
// WithKeyParts to load only what a process needs:
//
//   - KeyPartEnc: encrypt items/queries locally (Insert / Search)
//   - KeyPartSec: decrypt Search results
//
// Omitting WithKeyParts loads both. KeyPartEval is retained for compatibility but
// loads nothing: the eval key is no longer held in memory — Client.RegisterKeys
// streams it straight from disk. The CKKS preset is fixed per bundle (rmp/flat =
// IP0, mm = IP1/MM).
type KeyPart int

const (
	KeyPartEnc  KeyPart = iota // EncKey → cgo Encryptor handle (local encrypt)
	KeyPartEval                // retained for compatibility; loads nothing (see above)
	KeyPartSec                 // SecKey  → cgo Decryptor handle (local decrypt)
)

type keysOptions struct {
	Path     string
	KeyID    string
	Dim      int
	Parts    []KeyPart
	FlatMode string // "rmp" (default) | "single"
}

// KeysOption configures KeysExist, GenerateKeys and OpenKeys. Apply via the
// With* helpers below. Only the dimension and which key parts to load are
// selectable.
type KeysOption func(*keysOptions)

// WithKeyPath sets the directory the key set lives in.
func WithKeyPath(p string) KeysOption { return func(o *keysOptions) { o.Path = p } }

// WithKeyID sets the identifier stamped into the JSON key envelopes.
func WithKeyID(id string) KeysOption { return func(o *keysOptions) { o.KeyID = id } }

// WithKeyDim sets the FHE slot dimension the key set is generated/opened for.
func WithKeyDim(d int) KeysOption { return func(o *keysOptions) { o.Dim = d } }

func WithFlatMode(mode string) KeysOption { return func(o *keysOptions) { o.FlatMode = mode } }

// WithKeyParts restricts OpenKeys to load only the listed key materials.
// Passing no parts (or omitting the option) loads all three. Duplicates are
// tolerated.
func WithKeyParts(parts ...KeyPart) KeysOption {
	return func(o *keysOptions) { o.Parts = parts }
}

func buildKeysOptions(opts []KeysOption) keysOptions {
	var o keysOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func (o keysOptions) validate() error {
	if o.Path == "" {
		return fmt.Errorf("runespace: WithKeyPath required")
	}
	if o.KeyID == "" {
		return fmt.Errorf("runespace: WithKeyID required")
	}
	if o.Dim <= 0 {
		return fmt.Errorf("runespace: WithKeyDim required (got %d)", o.Dim)
	}
	switch strings.ToLower(strings.TrimSpace(o.FlatMode)) {
	case "", "rmp", "single":
	default:
		return fmt.Errorf("runespace: WithFlatMode %q must be rmp|single", o.FlatMode)
	}
	return nil
}

// resolveKeyParts maps the parts list to per-material flags. Empty list (the
// default) means "load everything".
func resolveKeyParts(parts []KeyPart) (enc, eval, sec bool) {
	if len(parts) == 0 {
		return true, true, true
	}
	for _, p := range parts {
		switch p {
		case KeyPartEnc:
			enc = true
		case KeyPartEval:
			eval = true
		case KeyPartSec:
			sec = true
		}
	}
	return
}
