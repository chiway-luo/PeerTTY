package console

import (
	"context"
	"fmt"
	"time"

	"peertty/internal/active"
	"peertty/internal/grant"
)

// A single-use peer pairs in OpenSSH's ProxyCommand. Its stdin and stdout
// carry SSH bytes. Only the controlling keyboard and diagnostic output may
// be used for the receipt, and only until the SSH handshake starts.
func (t *Console) singleUseReceipt(parent context.Context, st active.State, text bool, run func(context.Context, func(grant.Ticket) error, func(string)) error) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	answers := make(chan grant.Ticket)
	routes := make(chan string)
	resume := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, func(answer grant.Ticket) error {
			if err := answer.WriteNew(st.Exchange); err != nil {
				return err
			}
			select {
			case answers <- answer:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, func(route string) {
			select {
			case routes <- route:
				<-resume
			case <-ctx.Done():
			}
		})
	}()
	closeScreen := t.openScreen()
	t.setActivity(waitLabel(st))
	stopPanel := func() {
		t.setActivity("")
		closeScreen()
	}
	tick := time.NewTicker(spinInterval)
	defer tick.Stop()
	var answer grant.Ticket
	var keys receiptKeys
	var err error
	for err == nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case result := <-done:
			stopPanel()
			return result
		case answer = <-answers:
			st.Phase = "waiting"
			t.setActivity(waitLabel(st))
			err = t.drawReceipt(ctx, st, answer, t.autoCopy, !t.autoCopy && (text || t.interactive))
			if err == nil && t.interactive {
				t.receiptPrompt(st)
			}
		case route := <-routes:
			stopPanel()
			fmt.Fprintln(t.out, "控制会话已连接 ·", route)
			close(resume)
			return <-done
		case <-tick.C:
			t.advanceActivity()
			if t.interactive && st.Phase == "waiting" {
				_, err = t.receiptAction(ctx, &keys, st, answer)
			}
		}
	}
	cancel()
	stopPanel()
	<-done
	return err
}
