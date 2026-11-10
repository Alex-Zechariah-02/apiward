// Upstream forms, version gating and address classes.

package compile

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Alex-Zechariah-02/apiward/internal/policy"
)

// network is a fixed operator network for these tests.
type network struct {
	public   bool
	profiles map[string]bool
}

func (n network) Public() bool            { return n.public }
func (n network) Has(profile string) bool { return n.profiles[profile] }

func upstreams(version int, us ...policy.Upstream) policy.Policy {
	return policy.Policy{SchemaVersion: version, Profile: policy.ProfileCore, Upstreams: us}
}

func refusal(err error) string {
	if e, ok := err.(*policy.PolicyError); ok {
		return e.Code + "@" + e.Field
	}
	return "accepted"
}

// Version 4 keeps only the loopback dial form; version 5 adds URLs, and
// every malformed or ambiguous destination is refused at its member.
func TestUpstreamSchema5(t *testing.T) {
	v5 := policy.LatestSchemaVersion
	for name, tc := range map[string]struct {
		p    policy.Policy
		want string
	}{
		"v4 dial":                 {upstreams(4, policy.Upstream{ID: "a", Dial: "127.0.0.1:9501"}), "accepted"},
		"v5 dial":                 {upstreams(v5, policy.Upstream{ID: "a", Dial: "127.0.0.1:9501"}), "accepted"},
		"v4 url":                  {upstreams(4, policy.Upstream{ID: "a", URL: "http://10.0.0.5:9501"}), "INVALID_VALUE@upstreams[0].url"},
		"v4 host":                 {upstreams(4, policy.Upstream{ID: "a", Dial: "127.0.0.1:1", Host: "inbound"}), "INVALID_VALUE@upstreams[0].host"},
		"v5 private http":         {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5:9501/"}), "accepted"},
		"v5 https name":           {upstreams(v5, policy.Upstream{ID: "a", URL: "https://orders.internal:8443", TLS: "fetch"}), "accepted"},
		"both forms":              {upstreams(v5, policy.Upstream{ID: "a", Dial: "127.0.0.1:1", URL: "http://10.0.0.5"}), "INVALID_UPSTREAM@upstreams[0].dial"},
		"name over http":          {upstreams(v5, policy.Upstream{ID: "a", URL: "http://orders.internal"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"single-label name":       {upstreams(v5, policy.Upstream{ID: "a", URL: "https://orders"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"upper-case name":         {upstreams(v5, policy.Upstream{ID: "a", URL: "https://Orders.internal"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"path":                    {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5/api"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"query":                   {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5/?a"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"user info":               {upstreams(v5, policy.Upstream{ID: "a", URL: "http://u@10.0.0.5"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"port zero":               {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5:0"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"metadata literal":        {upstreams(v5, policy.Upstream{ID: "a", URL: "http://169.254.169.254"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"mapped metadata literal": {upstreams(v5, policy.Upstream{ID: "a", URL: "http://[::ffff:169.254.169.254]"}), "INVALID_UPSTREAM@upstreams[0].url"},
		"tls over http":           {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5", TLS: "fetch"}), "INVALID_VALUE@upstreams[0].tls"},
		"unknown host mode":       {upstreams(v5, policy.Upstream{ID: "a", URL: "http://10.0.0.5", Host: "client"}), "INVALID_VALUE@upstreams[0].host"},
		"dial equals url": {upstreams(v5, policy.Upstream{ID: "a", Dial: "127.0.0.1:80"},
			policy.Upstream{ID: "b", URL: "http://127.0.0.1"}), "INVALID_UPSTREAM@upstreams[1].url"},
	} {
		_, err := Compile(tc.p, 1, time.Time{}, policy.Limits{})
		if got := refusal(err); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}

	// The operator's settings decide profiles and public literals.
	g, err := Compile(upstreams(v5, policy.Upstream{ID: "a", URL: "https://10.0.0.5", TLS: "fetch"},
		policy.Upstream{ID: "b", URL: "http://192.0.2.10"}), 1, time.Time{}, policy.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		n    network
		want string
	}{
		{network{profiles: map[string]bool{}}, "UNKNOWN_TLS_PROFILE@upstreams[0].tls"},
		{network{profiles: map[string]bool{"fetch": true}}, "INVALID_UPSTREAM@upstreams[1].url"},
		{network{public: true, profiles: map[string]bool{"fetch": true}}, "accepted"},
	} {
		if got := refusal(g.CheckNetwork(tc.n)); got != tc.want {
			t.Errorf("network %+v: %s, want %s", tc.n, got, tc.want)
		}
	}
}

// No setting allows the refused classes; public addresses need the switch.
// Named metadata addresses, from each provider's documentation (checked
// 8 Nov 2026):
//   - AWS IMDS IPv6: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
//   - Google Cloud IPv6: https://docs.cloud.google.com/compute/docs/metadata/querying-metadata
//   - Alibaba Cloud: https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata/
//   - Azure: https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16
//
// AWS, Google Cloud and DigitalOcean also answer on 169.254.169.254
// (https://docs.digitalocean.com/products/droplets/how-to/access-metadata/),
// which the link-local class covers.
func TestUpstreamAddressClasses(t *testing.T) {
	refused := []string{"0.0.0.0", "0.1.2.3", "::", "169.254.169.254", "::ffff:169.254.169.254", "fe80::1",
		"224.0.0.1", "ff02::1", "255.255.255.255", "fd00:ec2::254", "fd20:ce::254", "100.100.100.200", "168.63.129.16"}
	private := []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "fc00::1", "100.64.0.1", "::ffff:10.1.2.3"}
	public := []string{"192.0.2.10", "8.8.8.8", "2001:db8::1"}
	for _, s := range refused {
		a := netip.MustParseAddr(s)
		if !Refused(a) || Allowed(a, true) {
			t.Errorf("%s is not refused", s)
		}
	}
	for _, s := range private {
		if a := netip.MustParseAddr(s); Refused(a) || !Allowed(a, false) {
			t.Errorf("%s is not allowed by default", s)
		}
	}
	for _, s := range public {
		if a := netip.MustParseAddr(s); Allowed(a, false) || !Allowed(a, true) {
			t.Errorf("%s does not follow the public switch", s)
		}
	}
}
