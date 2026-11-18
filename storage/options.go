package storage

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withMaxValueSize int // maximal size for an entry's value buffer, default: 0 (unbounded)
	withMaxEntries   int // maximal number of entries in store (counted as number of keys), default: 0 (unbounded)
}

func getDefaultOptions() options {
	return options{
		withMaxValueSize: 0,
		withMaxEntries:   0,
	}
}

// WithMaxValueSize sets the maximal size of the value field in an entry
func WithMaxValueSize(value int) Option {
	return func(o *options) {
		o.withMaxValueSize = value
	}
}

// WithMaxEntries sets the maximal number of entries in storage
func WithMaxEntries(value int) Option {
	return func(o *options) {
		o.withMaxEntries = value
	}
}
