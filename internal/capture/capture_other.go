//go:build !linux

package capture

func open(ifindex int) (source, error) { return nil, ErrUnsupported }
