package capture

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	client = net.IPv4(10, 0, 0, 1)
	server = net.IPv4(10, 0, 0, 2)
	remote = netip.MustParseAddrPort("10.0.0.2:443")
)

func pkt(t *testing.T, fromClient bool, tcp layers.TCP, payload []byte) []byte {
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: client, DstIP: server}
	tcp.SrcPort, tcp.DstPort = 50000, 443
	if !fromClient {
		ip.SrcIP, ip.DstIP = server, client
		tcp.SrcPort, tcp.DstPort = 443, 50000
	}
	tcp.Window = 1000
	tcp.SetNetworkLayerForChecksum(&ip)
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip, &tcp, gopacket.Payload(payload))
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestHandshakeAndRetransmission(t *testing.T) {
	var d decoder
	d.init()
	steps := []struct {
		fromClient bool
		tcp        layers.TCP
		payload    []byte
		want       string
	}{
		{true, layers.TCP{SYN: true, Seq: 4000000000}, nil, "TCP handshake: SYN"},
		{false, layers.TCP{SYN: true, ACK: true, Seq: 7, Ack: 4000000001}, nil, "TCP handshake: SYN-ACK"},
		{true, layers.TCP{ACK: true, Seq: 4000000001, Ack: 8}, nil, "TCP handshake: ACK"},
		{true, layers.TCP{ACK: true, PSH: true, Seq: 4000000001, Ack: 8}, []byte{22, 3, 1, 0, 1, 0}, "TCP data 6B (TLS Handshake)"},
		{true, layers.TCP{ACK: true, PSH: true, Seq: 4000000001, Ack: 8}, []byte{22, 3, 1, 0, 1, 0}, "TCP retransmission 6B"},
		{false, layers.TCP{ACK: true, Seq: 8, Ack: 4000000007}, nil, "TCP ACK"},
		{true, layers.TCP{FIN: true, ACK: true, Seq: 4000000007, Ack: 8}, nil, "TCP FIN (closing)"},
		{false, layers.TCP{RST: true, Seq: 8}, nil, "TCP RST (connection reset)"},
	}
	for i, s := range steps {
		ev, ok := d.decode(pkt(t, s.fromClient, s.tcp, s.payload), remote, 50000)
		if !ok {
			t.Fatalf("step %d: packet not matched", i)
		}
		if ev.Title != s.want {
			t.Errorf("step %d: got %q, want %q", i, ev.Title, s.want)
		}
	}
}

func TestOtherConnectionsAreIgnored(t *testing.T) {
	var d decoder
	d.init()
	if _, ok := d.decode(pkt(t, true, layers.TCP{SYN: true}, nil), remote, 50001); ok {
		t.Fatal("packet from another local port should be ignored")
	}
}
