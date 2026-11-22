package transport

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUPnPRejectsUnsafeLocationsAndExternalIPs(t *testing.T) {
	for _, bad := range []string{
		"https://192.168.1.1/desc.xml",
		"http://127.0.0.1:8080/desc.xml",
		"http://169.254.169.254/latest/meta-data",
		"http://8.8.8.8/desc.xml",
		"http://router.local/desc.xml",
		"http://[::1]/desc.xml",
	} {
		if _, _, err := validateLANURL(bad, false); err == nil {
			t.Errorf("validateLANURL accepted unsafe URL %q", bad)
		}
	}
	if _, ip, err := validateLANURL("http://192.168.1.1:5000/rootDesc.xml", false); err != nil || ip != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("rejected private LAN URL: ip=%v err=%v", ip, err)
	}
	if got := parseSSDPLocation("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: http://192.168.1.1:49000/igd.xml\r\n\r\n"); got != "http://192.168.1.1:49000/igd.xml" {
		t.Fatalf("parseSSDPLocation = %q", got)
	}
}

func TestUPnPAddInjectAndDeleteMapping(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	var addedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rootDesc.xml":
			_, _ = io.WriteString(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceList><device><serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/ctl/IPConn</controlURL>
      </service>
    </serviceList></device></deviceList>
  </device>
</root>`)
		case "/ctl/IPConn":
			body, _ := io.ReadAll(r.Body)
			action := r.Header.Get("SOAPAction")
			mu.Lock()
			actions = append(actions, action)
			if strings.Contains(action, "AddPortMapping") {
				addedBody = string(body)
			}
			mu.Unlock()
			switch {
			case strings.Contains(action, "GetExternalIPAddress"):
				_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>198.51.100.42</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
			case strings.Contains(action, "AddPortMapping"), strings.Contains(action, "DeletePortMapping"):
				_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`)
			default:
				http.Error(w, "unknown action", http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	gw, err := fetchUPnPGatewayWithPolicy(t.Context(), srv.URL+"/rootDesc.xml", srv.Client(), true)
	if err != nil {
		t.Fatalf("fetchUPnPGateway: %v", err)
	}
	rawSDP := strings.Join([]string{
		"v=0",
		"o=- 1 2 IN IP4 0.0.0.0",
		"s=-",
		"t=0 0",
		"m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
		"c=IN IP4 0.0.0.0",
		"a=ice-ufrag:testufrag",
		"a=ice-pwd:testpasswordtestpassword",
		"a=candidate:1 1 udp 2130706431 192.168.1.50 51234 typ host ufrag testufrag generation 0",
		"a=end-of-candidates",
		"",
	}, "\r\n")
	updated, pm := mapAndInjectUPnPForLAN(t.Context(), gw, netip.MustParseAddr("192.168.1.50"), rawSDP, time.Hour)
	if pm == nil {
		t.Fatal("expected UPnP port mapping")
	}
	if !strings.Contains(updated, "198.51.100.42 51234 typ srflx raddr 192.168.1.50 rport 51234") {
		t.Fatalf("injected SDP missing UPnP srflx candidate:\n%s", updated)
	}
	if CountCandidates(updated).Mapped != 1 {
		t.Fatalf("CountCandidates = %+v, want Mapped=1", CountCandidates(updated))
	}
	pm.Close()

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(addedBody, "<NewInternalClient>192.168.1.50</NewInternalClient>") ||
		!strings.Contains(addedBody, "<NewExternalPort>51234</NewExternalPort>") {
		t.Fatalf("unexpected AddPortMapping body: %s", addedBody)
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"GetExternalIPAddress", "AddPortMapping", "DeletePortMapping"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing SOAP action %s in %v", want, actions)
		}
	}
}

func TestUPnPRejectsControlURLHostEscape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<?xml version="1.0"?><root><device><serviceList><service>
			<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
			<controlURL>http://10.0.0.99/evil</controlURL>
		</service></serviceList></device></root>`)
	}))
	defer srv.Close()
	if _, err := fetchUPnPGatewayWithPolicy(t.Context(), srv.URL+"/desc.xml", srv.Client(), true); err == nil {
		t.Fatal("accepted controlURL escaping gateway host")
	}
}

func TestUPnPEdgeCasesAndCandidateInjection(t *testing.T) {
	// fetchUPnPGateway (production policy) must always reject loopback URLs.
	if _, err := fetchUPnPGateway(t.Context(), "http://127.0.0.1:1234/desc.xml", nil); err == nil {
		t.Fatal("production fetchUPnPGateway accepted loopback URL")
	}
	if sdp, pm := mapAndInjectUPnP(t.Context(), nil, "v=0\r\n", time.Hour); sdp != "v=0\r\n" || pm != nil {
		t.Fatalf("nil gateway modified SDP: %q %v", sdp, pm)
	}
	if ip, ok := localIPForGateway(netip.MustParseAddr("127.0.0.1")); !ok || !ip.Is4() {
		t.Fatalf("localIPForGateway(127.0.0.1) = (%v, %v)", ip, ok)
	}
	// Injecting into an LF-only SDP without end-of-candidates appends cleanly.
	ext := netip.MustParseAddrPort("198.51.100.9:50000")
	rel := netip.MustParseAddrPort("192.168.1.9:50000")
	injected := injectSrflxCandidate("v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel", ext, rel, "")
	if !strings.Contains(injected, "198.51.100.9 50000 typ srflx raddr 192.168.1.9 rport 50000 generation 0\n") {
		t.Fatalf("unexpected injected SDP: %q", injected)
	}
	// Gateway returning a private WAN IP (double-NAT / CGNAT) must be rejected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/desc.xml":
			_, _ = io.WriteString(w, `<root><device><serviceList><service>
				<serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
				<controlURL>/ctl</controlURL>
			</service></serviceList></device></root>`)
		case "/ctl":
			_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1"><NewExternalIPAddress>10.0.0.5</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
		}
	}))
	defer srv.Close()
	gw, err := fetchUPnPGatewayWithPolicy(t.Context(), srv.URL+"/desc.xml", srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gw.addPortMapping(t.Context(), rel, 10*time.Second); err == nil {
		t.Fatal("accepted private CGNAT external IP from UPnP gateway")
	}
}
