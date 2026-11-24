package transport

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	upnpDiscoveryTimeout = 1200 * time.Millisecond
	upnpHTTPTimeout      = 1500 * time.Millisecond
	upnpCleanupTimeout   = 2 * time.Second
	upnpMaxResponseBytes = 64 * 1024
)

var upnpServiceTypes = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

type upnpGateway struct {
	controlURL  string
	serviceType string
	gatewayHost netip.Addr
	client      *http.Client
}

type portMapping struct {
	gateway  *upnpGateway
	external netip.AddrPort
	internal netip.AddrPort
}

func (m *portMapping) Close() {
	if m == nil || m.gateway == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), upnpCleanupTimeout)
	defer cancel()
	_ = m.gateway.deletePortMapping(ctx, m.external.Port())
}

// discoverUPnPGateway broadcasts an SSDP M-SEARCH for an Internet Gateway
// Device on the local LAN. Returns nil quietly if no IGD responds.
func discoverUPnPGateway(parent context.Context) *upnpGateway {
	return discoverUPnPGatewayWith(parent, func() (ssdpSocket, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{})
	}, fetchUPnPGateway)
}

type ssdpSocket interface {
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	SetReadDeadline(time.Time) error
	Close() error
}

func discoverUPnPGatewayWith(parent context.Context, listen func() (ssdpSocket, error), fetch func(context.Context, string, *http.Client) (*upnpGateway, error)) *upnpGateway {
	ctx, cancel := context.WithTimeout(parent, upnpDiscoveryTimeout)
	defer cancel()
	conn, err := listen()
	if err != nil {
		return nil
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	mcast := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, st := range []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	} {
		req := fmt.Sprintf("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: %s\r\n\r\n", st)
		_, _ = conn.WriteToUDP([]byte(req), mcast)
	}

	deadline, _ := ctx.Deadline()
	_ = conn.SetReadDeadline(deadline)
	return awaitUPnPGateway(ctx, conn.ReadFromUDP, fetch)
}

func awaitUPnPGateway(ctx context.Context, read func([]byte) (int, *net.UDPAddr, error), fetch func(context.Context, string, *http.Client) (*upnpGateway, error)) *upnpGateway {
	buf := make([]byte, 4096)
	seen := make(map[string]bool)
	for ctx.Err() == nil {
		n, _, err := read(buf)
		if err != nil {
			return nil
		}
		loc := parseSSDPLocation(string(buf[:n]))
		if loc == "" || seen[loc] {
			continue
		}
		seen[loc] = true
		if gw, err := fetch(ctx, loc, nil); err == nil {
			return gw
		}
	}
	return nil
}

func parseSSDPLocation(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "location") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// validateLANURL restricts UPnP HTTP requests strictly to private LAN IPv4
// literals so a crafted SSDP packet cannot trigger SSRF against loopback or public hosts.
func validateLANURL(raw string, allowLoopback bool) (*url.URL, netip.Addr, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return nil, netip.Addr{}, errors.New("invalid UPnP URL")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || !ip.Is4() {
		return nil, netip.Addr{}, errors.New("UPnP host must be an IPv4 address")
	}
	if !ip.IsPrivate() && !(allowLoopback && ip.IsLoopback()) {
		return nil, netip.Addr{}, errors.New("UPnP host is not on a private LAN")
	}
	return u, ip, nil
}

func fetchUPnPGateway(ctx context.Context, location string, client *http.Client) (*upnpGateway, error) {
	return fetchUPnPGatewayWithPolicy(ctx, location, client, false)
}

func fetchUPnPGatewayWithPolicy(ctx context.Context, location string, client *http.Client, allowLoopback bool) (*upnpGateway, error) {
	base, hostIP, err := validateLANURL(location, allowLoopback)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{
			Timeout: upnpHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UPnP description HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, upnpMaxResponseBytes+1))
	if err != nil || len(body) > upnpMaxResponseBytes {
		return nil, errors.New("UPnP description unreadable or too large")
	}
	serviceType, controlPath, err := parseUPnPServices(body)
	if err != nil {
		return nil, err
	}
	ref, err := url.Parse(controlPath)
	if err != nil {
		return nil, err
	}
	ctrl := base.ResolveReference(ref)
	ctrlIP, err := netip.ParseAddr(ctrl.Hostname())
	if err != nil || ctrl.Scheme != "http" || ctrlIP != hostIP {
		return nil, errors.New("UPnP control URL escapes gateway host")
	}
	return &upnpGateway{controlURL: ctrl.String(), serviceType: serviceType, gatewayHost: hostIP, client: client}, nil
}

func parseUPnPServices(data []byte) (serviceType, controlURL string, err error) {
	type upnpService struct {
		ServiceType string `xml:"serviceType"`
		ControlURL  string `xml:"controlURL"`
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	found := make(map[string]string)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "service" {
			continue
		}
		var svc upnpService
		if dec.DecodeElement(&svc, &se) != nil {
			continue
		}
		st := strings.TrimSpace(svc.ServiceType)
		cu := strings.TrimSpace(svc.ControlURL)
		if st != "" && cu != "" {
			found[st] = cu
		}
	}
	for _, want := range upnpServiceTypes {
		if cu, ok := found[want]; ok {
			return want, cu, nil
		}
	}
	return "", "", errors.New("no WANIPConnection/WANPPPConnection service found")
}

func (g *upnpGateway) soapAction(ctx context.Context, action, bodyXML string) ([]byte, error) {
	envelope := fmt.Sprintf(
		`<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>`,
		action, g.serviceType, bodyXML, action,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL, strings.NewReader(envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, g.serviceType, action))
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, upnpMaxResponseBytes+1))
	if err != nil || len(data) > upnpMaxResponseBytes {
		return nil, errors.New("UPnP SOAP response invalid")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UPnP %s HTTP %d", action, resp.StatusCode)
	}
	return data, nil
}

func (g *upnpGateway) externalIP(ctx context.Context) (netip.Addr, error) {
	data, err := g.soapAction(ctx, "GetExternalIPAddress", "")
	if err != nil {
		return netip.Addr{}, err
	}
	raw, err := xmlElementText(data, "NewExternalIPAddress")
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !publicIPv4(ip) {
		return netip.Addr{}, errors.New("gateway returned non-public external IP")
	}
	return ip, nil
}

// IsGlobalUnicast includes shared, documentation and reserved IPv4 space.
var specialIPv4 = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(ip netip.Addr) bool {
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	// The PCP and TURN anycast addresses are global exceptions in 192.0.0.0/24.
	if ip == netip.AddrFrom4([4]byte{192, 0, 0, 9}) || ip == netip.AddrFrom4([4]byte{192, 0, 0, 10}) {
		return true
	}
	for _, prefix := range specialIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func (g *upnpGateway) addPortMapping(ctx context.Context, internal netip.AddrPort, lease time.Duration) (*portMapping, error) {
	extIP, err := g.externalIP(ctx)
	if err != nil {
		return nil, err
	}
	seconds := int(lease.Seconds())
	if seconds < 60 {
		seconds = 60
	}
	if seconds > 86400 {
		seconds = 86400
	}
	port := internal.Port()
	args := fmt.Sprintf(
		`<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>PeerTTY</NewPortMappingDescription><NewLeaseDuration>%d</NewLeaseDuration>`,
		port, port, internal.Addr().String(), seconds,
	)
	if _, err := g.soapAction(ctx, "AddPortMapping", args); err != nil {
		return nil, err
	}
	return &portMapping{
		gateway:  g,
		external: netip.AddrPortFrom(extIP, port),
		internal: internal,
	}, nil
}

func (g *upnpGateway) deletePortMapping(ctx context.Context, externalPort uint16) error {
	args := fmt.Sprintf(`<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>UDP</NewProtocol>`, externalPort)
	_, err := g.soapAction(ctx, "DeletePortMapping", args)
	return err
}

func xmlElementText(data []byte, localName string) (string, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("missing XML element %s", localName)
		}
		if err != nil {
			return "", err
		}
		se, ok := tok.(xml.StartElement)
		if ok && se.Name.Local == localName {
			var value string
			if err := dec.DecodeElement(&value, &se); err != nil {
				return "", err
			}
			return value, nil
		}
	}
}

// sourceIPv4 finds the local IPv4 address selected for this destination.
func sourceIPv4(target netip.AddrPort) (netip.Addr, bool) {
	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		return netip.Addr{}, false
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip := local.AddrPort().Addr().Unmap()
	return ip, ip.Is4()
}

// mapAndInjectUPnP maps the gathered LAN host candidate facing the discovered
// gateway and appends the resulting server-reflexive candidate if not already present.
func mapAndInjectUPnP(ctx context.Context, gw *upnpGateway, rawSDP string, lease time.Duration) (string, *portMapping) {
	if gw == nil {
		return rawSDP, nil
	}
	lanIP, ok := sourceIPv4(netip.AddrPortFrom(gw.gatewayHost, 1900))
	if !ok {
		return rawSDP, nil
	}
	return mapAndInjectUPnPForLAN(ctx, gw, lanIP, rawSDP, lease)
}

func mapAndInjectUPnPForLAN(ctx context.Context, gw *upnpGateway, lanIP netip.Addr, rawSDP string, lease time.Duration) (string, *portMapping) {
	desc := webrtc.SessionDescription{SDP: rawSDP}
	parsed, err := desc.Unmarshal()
	if err != nil || len(parsed.MediaDescriptions) != 1 {
		return rawSDP, nil
	}
	var targetPort uint16
	var ufrag string
	var existingSrflx []netip.AddrPort
	for _, a := range parsed.MediaDescriptions[0].Attributes {
		if a.Key == "ice-ufrag" {
			ufrag = a.Value
		}
		if a.Key != "candidate" {
			continue
		}
		c, err := ice.UnmarshalCandidate(a.Value)
		if err != nil || c.Component() != 1 || !c.NetworkType().IsUDP() {
			continue
		}
		ip, err := netip.ParseAddr(c.Address())
		if err != nil || !ip.Is4() || c.Port() <= 0 || c.Port() > 65535 {
			continue
		}
		ap := netip.AddrPortFrom(ip.Unmap(), uint16(c.Port()))
		switch c.Type() {
		case ice.CandidateTypeHost:
			if targetPort == 0 && ap.Addr() == lanIP {
				targetPort = ap.Port()
			}
		case ice.CandidateTypeServerReflexive:
			existingSrflx = append(existingSrflx, ap)
		}
	}
	if targetPort == 0 {
		return rawSDP, nil
	}
	mapCtx, cancel := context.WithTimeout(ctx, upnpHTTPTimeout*2)
	defer cancel()
	mapping, err := gw.addPortMapping(mapCtx, netip.AddrPortFrom(lanIP, targetPort), lease)
	if err != nil {
		return rawSDP, nil
	}
	if slices.Contains(existingSrflx, mapping.external) {
		return rawSDP, mapping
	}
	return injectSrflxCandidate(rawSDP, mapping.external, mapping.internal, ufrag), mapping
}

func injectSrflxCandidate(rawSDP string, ext, rel netip.AddrPort, ufrag string) string {
	// Standard ICE srflx priority: (2^24)*100 + (2^8)*65535 + 255 = 1694498815
	candLine := fmt.Sprintf("a=candidate:upnp%d 1 udp 1694498815 %s %d typ srflx raddr %s rport %d",
		ext.Port(), ext.Addr().String(), ext.Port(), rel.Addr().String(), rel.Port())
	if ufrag != "" {
		candLine += " ufrag " + ufrag
	}
	candLine += " generation 0"
	sep := "\r\n"
	if !strings.Contains(rawSDP, "\r\n") {
		sep = "\n"
	}
	marker := "a=end-of-candidates"
	if idx := strings.Index(rawSDP, marker); idx >= 0 {
		return rawSDP[:idx] + candLine + sep + rawSDP[idx:]
	}
	if !strings.HasSuffix(rawSDP, "\n") {
		rawSDP += sep
	}
	return rawSDP + candLine + sep
}

// CheckUPnP probes whether a UPnP IGD router on the local LAN responds and reports its external IP.
func CheckUPnP(ctx context.Context) (string, bool) {
	return checkUPnPWith(ctx, discoverUPnPGateway)
}

func checkUPnPWith(ctx context.Context, discover func(context.Context) *upnpGateway) (string, bool) {
	gw := discover(ctx)
	if gw == nil {
		return "", false
	}
	ext, err := gw.externalIP(ctx)
	if err != nil {
		return gw.gatewayHost.String(), true
	}
	return gw.gatewayHost.String() + "（出口 " + ext.String() + "）", true
}
