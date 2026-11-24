package transport

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/pion/datachannel"
)

type channelAdmissionFixture struct {
	name      string
	ordered   bool
	retries   *uint16
	lifetime  *uint16
	opened    func()
	stream    datachannel.ReadWriteCloserDeadliner
	detachErr error
	closes    int
	detaches  int
}

func (c *channelAdmissionFixture) Label() string              { return c.name }
func (c *channelAdmissionFixture) Ordered() bool              { return c.ordered }
func (c *channelAdmissionFixture) MaxRetransmits() *uint16    { return c.retries }
func (c *channelAdmissionFixture) MaxPacketLifeTime() *uint16 { return c.lifetime }
func (c *channelAdmissionFixture) Close() error               { c.closes++; return nil }
func (c *channelAdmissionFixture) OnOpen(f func())            { c.opened = f }
func (c *channelAdmissionFixture) DetachWithDeadline() (datachannel.ReadWriteCloserDeadliner, error) {
	c.detaches++
	return c.stream, c.detachErr
}

type channelAdmissionFixtureStream struct {
	datachannel.ReadWriteCloserDeadliner
}

func TestControlChannelRequiresExpectedOrderedReliableStreamAndOnlyOnePerGrant(t *testing.T) {
	var accepted atomic.Bool
	calls := 0
	one := uint16(1)
	for _, invalid := range []*channelAdmissionFixture{
		{name: linkLabel, ordered: true},
		{name: label},
		{name: label, ordered: true, retries: &one},
		{name: label, ordered: true, lifetime: &one},
	} {
		admitControlChannel(invalid, &accepted, func() { calls++ })
		if invalid.closes != 1 || accepted.Load() || calls != 0 {
			t.Fatalf("invalid control channel was attached or consumed the slot: %+v", invalid)
		}
	}
	first := &channelAdmissionFixture{name: label, ordered: true}
	second := &channelAdmissionFixture{name: label, ordered: true}
	admitControlChannel(first, &accepted, func() { calls++ })
	admitControlChannel(second, &accepted, func() { calls++ })
	if first.closes != 0 || second.closes != 1 || !accepted.Load() || calls != 1 {
		t.Fatalf("control slot not exclusive: first closed=%d second closed=%d attachments=%d", first.closes, second.closes, calls)
	}
}

func TestTerminalChannelHandsOffOnlyOpenedReliableStreams(t *testing.T) {
	one := uint16(1)
	calls := 0
	want := &channelAdmissionFixtureStream{}
	handle := func(got datachannel.ReadWriteCloserDeadliner) {
		calls++
		if got != want {
			t.Fatal("wrong opened stream")
		}
	}
	for _, invalid := range []*channelAdmissionFixture{
		{name: label, ordered: true},
		{name: linkLabel},
		{name: linkLabel, ordered: true, retries: &one},
		{name: linkLabel, ordered: true, lifetime: &one},
	} {
		admitTerminalChannel(invalid, handle)
		if invalid.closes != 1 || invalid.opened != nil || invalid.detaches != 0 || calls != 0 {
			t.Fatalf("invalid terminal attempted handoff: %+v", invalid)
		}
	}
	failed := &channelAdmissionFixture{name: linkLabel, ordered: true, detachErr: errors.New("fixture channel closed before detach")}
	admitTerminalChannel(failed, handle)
	if failed.opened == nil || calls != 0 || failed.detaches != 0 {
		t.Fatal("terminal should only detach after it opens")
	}
	failed.opened()
	if failed.closes != 1 || failed.detaches != 1 || calls != 0 {
		t.Fatalf("failed terminal escaped cleanup: %+v", failed)
	}
	for range 2 {
		ok := &channelAdmissionFixture{name: linkLabel, ordered: true, stream: want}
		admitTerminalChannel(ok, handle)
		if ok.opened == nil {
			t.Fatal("ready terminal has no OnOpen handler")
		}
		ok.opened()
		if ok.closes != 0 || ok.detaches != 1 {
			t.Fatalf("valid opened terminal not detached exactly once: %+v", ok)
		}
	}
	if calls != 2 {
		t.Fatal("separate authorized terminal channels were not both accepted")
	}
}
