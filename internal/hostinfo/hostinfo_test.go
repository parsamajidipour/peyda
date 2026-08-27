package hostinfo

import "testing"

func TestParseWHOISFindsCommonFields(t *testing.T) {
	fields := parseWHOIS(`Domain Name: SOOQ-CARS.COM
Registrar: GoDaddy.com, LLC
Creation Date: 2022-02-20T12:54:57Z
Registry Expiry Date: 2027-02-20T12:54:57Z
Name Server: ADRIAN.NS.CLOUDFLARE.COM
Name Server: COREY.NS.CLOUDFLARE.COM
`)
	if fields["registrar"] != "GoDaddy.com, LLC" {
		t.Fatalf("registrar = %q", fields["registrar"])
	}
	if fields["name_servers"] != "ADRIAN.NS.CLOUDFLARE.COM,COREY.NS.CLOUDFLARE.COM" {
		t.Fatalf("name_servers = %q", fields["name_servers"])
	}
}

func TestParseWHOISIgnoresInvalidVerboseRipeResponse(t *testing.T) {
	fields := parseWHOIS(`% This is the RIPE Database query service.
%ERROR:103: unknown object type 'sooq-cars.com'
`)
	if len(fields) != 0 {
		t.Fatalf("fields = %+v", fields)
	}
}
