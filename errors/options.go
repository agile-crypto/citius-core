package errors

import "fmt"

type Option func(*options)

type options struct {
	withMessage string
}

func getOpts(opts []Option) *options {
	o := getDefaultOptions()
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func getDefaultOptions() *options {
	return &options{
		withMessage: "",
	}
}

func WithMessage(msg string, msgArgs ...any) Option {
	return func(opts *options) {
		if len(msgArgs) > 0 {
			opts.withMessage = fmt.Sprintf(msg, msgArgs...)
		} else {
			opts.withMessage = msg
		}
	}
}
