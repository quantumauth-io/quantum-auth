package email

import "context"

type Message struct {
	FromName string
	FromAddr string
	To       string
	Subject  string
	TextBody string
	HTMLBody string // optional
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}
