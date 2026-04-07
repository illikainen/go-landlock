//go:build !linux

package landlock

import (
	"runtime"

	"github.com/pkg/errors"
)

func New(_ *Options) (*Landlock, error) {
	return nil, errors.Errorf("landlock does not support %s", runtime.GOOS)
}

func (l *Landlock) Close() error {
	return errors.Errorf("landlock does not support %s", runtime.GOOS)
}

func (l *Landlock) AddPathRules(_ ...*PathOptions) error {
	return errors.Errorf("landlock does not support %s", runtime.GOOS)
}

func (l *Landlock) AddNetworkRules(_ ...*NetworkOptions) error {
	return errors.Errorf("landlock does not support %s", runtime.GOOS)
}

func (l *Landlock) Confine() error {
	return errors.Errorf("landlock does not support %s", runtime.GOOS)
}
