// Identity and role primitives: who is signed in, and which roles may call.

package semantics

import (
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/exchange"
)

// Scheme is how a gateway verifies a caller's token.
type Scheme string

const (
	IssuerKey    Scheme = "issuer_key"    // an issuer's public key verifies every caller's token
	KeySet       Scheme = "jwks"          // keys fetched from the issuer's key set
	CallerKey    Scheme = "caller_key"    // a key stored per consumer
	SharedSecret Scheme = "shared_secret" // a secret shared with the gateway (HMAC, API key, password)
	Absent       Scheme = "absent"        // sign-in is required, but nothing signs a caller in
)

// Identity is a sign-in setting and the token checks it makes.
type Identity struct {
	Scheme         Scheme
	ChecksAudience bool
	ChecksExpiry   bool
}

// Token is what a request presents, as reference tests vary it.
type Token string

const (
	NoToken       Token = "none"
	Malformed     Token = "malformed"
	Expired       Token = "expired"
	WrongIssuer   Token = "wrong_issuer"
	WrongAudience Token = "wrong_audience"
	ValidToken    Token = "valid"
)

// Authenticates is the decision rule: whether the token signs the caller in.
func (i Identity) Authenticates(token Token) bool {
	if i.Scheme == Absent {
		return false
	}
	switch token {
	case ValidToken:
		return true
	case Expired:
		return !i.ChecksExpiry
	case WrongAudience:
		return !i.ChecksAudience
	}
	return false
}

// Convert is the distance to the gateway, which verifies RS256 tokens of
// trusted issuers with configured public keys and always checks expiry and audience.
func (i Identity) Convert() Distance {
	var added []string
	if !i.ChecksExpiry {
		added = append(added, "expiry")
	}
	if !i.ChecksAudience {
		added = append(added, "audience")
	}
	switch {
	case i.Scheme == Absent:
		return equivalent("Nothing signs callers in, so every caller is refused.")
	case i.Scheme == CallerKey || i.Scheme == SharedSecret:
		return inexpressible("The gateway signs callers in only with tokens of a trusted issuer.")
	case i.Scheme == KeySet:
		return approximated(exchange.Stricter, "The issuer's public keys are copied into the gateway; a new key is refused until it is copied."+
			checked(added))
	case len(added) > 0:
		return approximated(exchange.Stricter, strings.TrimSpace(checked(added)))
	}
	return equivalent("The issuer's public key is configured as a trusted key.")
}

func checked(added []string) string {
	if len(added) == 0 {
		return ""
	}
	return " The gateway also checks " + strings.Join(added, " and ") + "."
}

// RoleSource is where the source reads a caller's roles from.
type RoleSource string

const (
	TokenClaim    RoleSource = "token_claim"    // a claim of the token, at Claim
	GatewayGroups RoleSource = "gateway_groups" // groups stored on consumers at the gateway
)

// RoleRule is how the listed roles decide.
type RoleRule string

const (
	AllowList RoleRule = "allow_list" // a caller holding any listed role may call
	DenyList  RoleRule = "deny_list"  // a caller holding no listed role may call
)

// Roles is one authorisation setting.
type Roles struct {
	Source RoleSource
	Claim  string
	Rule   RoleRule
	Values []string
}

// Allows is the decision rule for a signed-in caller holding roles.
func (r Roles) Allows(roles []string) bool {
	held := slices.ContainsFunc(roles, func(role string) bool { return slices.Contains(r.Values, role) })
	return held == (r.Rule == AllowList)
}

// Convert is the distance to the gateway's permits: roles from the token's
// roles claim, allow lists only.
func (r Roles) Convert() Distance {
	switch {
	case r.Rule == DenyList:
		return inexpressible("The gateway permits listed roles; it has no deny list.")
	case r.Source == GatewayGroups:
		// The source decides by the groups stored on the signed-in consumer,
		// the gateway by the token's roles: a token can carry a listed role
		// its consumer never held, and the reverse.
		return approximated(exchange.Both, "The source decided by groups stored on its consumers; the gateway reads the token's roles claim. "+
			"Callers the source refused are permitted when their token carries a listed role, and callers it admitted are refused until it does.")
	case r.Claim != "roles":
		return approximated(exchange.Stricter, "The gateway reads the roles claim; tokens must carry the roles there.")
	}
	return equivalent("Permits for the listed roles.")
}
