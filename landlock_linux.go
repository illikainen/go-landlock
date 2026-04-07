//go:build linux

package landlock

import (
	errs "errors"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func New(opts *Options) (*Landlock, error) {
	version, err := abiVersion()
	if err != nil {
		return nil, err
	}
	slog.Debug("landlock", "abi", version)

	ruleset, err := createRuleset()
	if err != nil {
		return nil, err
	}

	l := &Landlock{
		Options: opts,
		version: version,
		ruleset: ruleset,
	}

	if opts.AllowMinimalDev {
		if err := l.AddPathRules(
			&PathOptions{Path: "/dev/null", Mode: ModeRead | ModeWrite},
			&PathOptions{Path: "/dev/random", Mode: ModeRead},
			&PathOptions{Path: "/dev/urandom", Mode: ModeRead},
		); err != nil {
			return nil, err
		}
	}

	if opts.AllowMinimalSystem {
		if err := l.AddPathRules(
			&PathOptions{Path: "/usr", Mode: ModeRead | ModeExec | ModeDir},
			&PathOptions{Path: "/lib", Mode: ModeRead | ModeDir},
			&PathOptions{Path: "/lib64", Mode: ModeRead | ModeDir},
		); err != nil {
			return nil, err
		}
	}

	if opts.AllowMinimalNetwork {
		if err := l.AddPathRules(
			&PathOptions{Path: "/etc/hosts", Mode: ModeRead},
			&PathOptions{Path: "/etc/ssl/certs", Mode: ModeRead | ModeDir},
			&PathOptions{Path: "/etc/nsswitch.conf", Mode: ModeRead},
			&PathOptions{Path: "/etc/resolv.conf", Mode: ModeRead},
		); err != nil {
			return nil, err
		}
	}

	return l, nil
}

func (l *Landlock) AddPathRules(opts ...*PathOptions) (err error) {
	for _, o := range opts {
		if err := l.addPathRule(o); err != nil {
			return err
		}
	}
	return nil
}

func (l *Landlock) addPathRule(opts *PathOptions) (err error) {
	path, err := filepath.Abs(opts.Path)
	if err != nil {
		return errors.WithStack(err)
	}

	mode := unix.O_PATH | unix.O_CLOEXEC
	if opts.Mode&ModeDir != 0 {
		mode |= unix.O_DIRECTORY
	}

	fd, err := unix.Open(path, mode, 0)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return errors.Wrap(err, opts.Path)
		}

		if opts.OnMissing == MissingIgnore {
			return nil
		} else if opts.OnMissing == MissingCreate {
			if opts.Mode&ModeDir != 0 {
				if err := os.MkdirAll(path, 0o700); err != nil { // nosemgrep
					return errors.WithStack(err)
				}
			} else {
				f, err := os.OpenFile(
					path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|unix.O_CLOEXEC, 0o600,
				) // #nosec G304
				if err != nil {
					return errors.Wrap(err, opts.Path)
				}

				if err := f.Close(); err != nil {
					return errors.Wrap(err, opts.Path)
				}
			}

			fd, err = unix.Open(path, mode, 0)
			if err != nil {
				return errors.Wrap(err, opts.Path)
			}
		}
	}
	defer func() { err = errs.Join(err, unix.Close(fd)) }()

	var perm string
	var access uint64

	if opts.Mode&ModeDir != 0 {
		perm += "d"
	}
	if opts.Mode&ModeRead != 0 {
		access |= unix.LANDLOCK_ACCESS_FS_READ_FILE
		perm += "r"
		if opts.Mode&ModeDir != 0 {
			access |= unix.LANDLOCK_ACCESS_FS_READ_DIR
		}
	}
	if opts.Mode&ModeWrite != 0 {
		access |= unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
		perm += "w"
		if opts.Mode&ModeDir != 0 {
			access |= unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
				unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
				unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
				unix.LANDLOCK_ACCESS_FS_MAKE_REG |
				unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
				unix.LANDLOCK_ACCESS_FS_REFER
		}
	}
	if opts.Mode&ModeExec != 0 {
		access |= unix.LANDLOCK_ACCESS_FS_EXECUTE
		perm += "x"
	}
	if opts.Mode&ModeSock != 0 {
		access |= unix.LANDLOCK_ACCESS_FS_MAKE_SOCK
		perm += "s"
	}

	if fd < math.MinInt32 || fd > math.MaxInt32 {
		return errors.Errorf("landlock: unable to cast within bounds")
	}
	attr := unix.LandlockPathBeneathAttr{
		Allowed_access: access,
		Parent_fd:      int32(fd),
	}

	slog.Debug("landlock add", "path", path, "perm", perm)
	_, _, errno := syscall.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		l.ruleset,
		uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
		uintptr(unsafe.Pointer(&attr)), // #nosec G103 nosemgrep
		0,
		0,
		0,
	) // #nosec G103
	if errno != 0 {
		return errors.Errorf("landlock: add: %s: %v", path, errno)
	}

	return nil
}

// not available in golang.org/x/sys/unix yet
// revive:disable-next-line
const LANDLOCK_RULE_NET_PORT = 2 //nolint:staticcheck

type LandlockNetPortAttr struct {
	// revive:disable-next-line
	Allowed_access uint64 //nolint:staticcheck
	Port           uint64
}

func (l *Landlock) AddNetworkRules(opts ...*NetworkOptions) (err error) {
	for _, o := range opts {
		if err := l.addNetworkRule(o); err != nil {
			return err
		}
	}
	return nil
}

func (l *Landlock) addNetworkRule(opts *NetworkOptions) (err error) {
	if opts.Proto != ProtocolTCP {
		return errors.Errorf("unsupported protocol: %d", opts.Proto)
	}

	var dir string
	var access uint64

	switch opts.Dir {
	case DirectionOut:
		dir = "egress"
		access = unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	case DirectionIn:
		dir = "ingress"
		access = unix.LANDLOCK_ACCESS_NET_BIND_TCP
	default:
		return errors.Errorf("invalid direction")
	}

	attr := LandlockNetPortAttr{
		Allowed_access: access,
		Port:           opts.Port,
	}

	slog.Debug("landlock add", "proto", "tcp", "port", opts.Port, "dir", dir)
	_, _, errno := syscall.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		l.ruleset,
		uintptr(LANDLOCK_RULE_NET_PORT),
		uintptr(unsafe.Pointer(&attr)), // #nosec G103 nosemgrep
		0,
		0,
		0,
	) // #nosec G103
	if errno != 0 {
		return errors.Errorf("landlock: add: tcp: %d: %v", opts.Port, errno)
	}

	return nil
}

func (l *Landlock) Confine() error {
	_, _, err := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0)
	if err != 0 {
		return errors.Wrap(err, "prctl: PR_SET_NO_NEW_PRIVS")
	}

	_, _, err = syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, l.ruleset, 0, 0)
	if err != 0 {
		return errors.Wrap(err, "landlock_restrict_self")
	}

	slog.Debug("process is confined by landlock")
	return nil
}

func (l *Landlock) Close() error {
	ruleset := int(l.ruleset)
	if ruleset < 0 || uintptr(ruleset) != l.ruleset {
		return errors.Errorf("landlock: unable to cast within bounds")
	}

	return unix.Close(ruleset)
}

func abiVersion() (int, error) {
	v, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
	) // #nosec G103
	if errno != 0 {
		return 0, errors.Errorf("landlock: version: %v", errno)
	}

	version := int(v)
	if version < 0 || uintptr(version) != v {
		return 0, errors.Errorf("landlock: unable to cast within bounds")
	}

	return version, nil
}

func createRuleset() (uintptr, error) {
	attr := unix.LandlockRulesetAttr{
		Access_fs: unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_TRUNCATE |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
			unix.LANDLOCK_ACCESS_FS_REFER |
			unix.LANDLOCK_ACCESS_FS_IOCTL_DEV,
		Access_net: unix.LANDLOCK_ACCESS_NET_BIND_TCP |
			unix.LANDLOCK_ACCESS_NET_CONNECT_TCP,
		Scoped: unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
			unix.LANDLOCK_SCOPE_SIGNAL,
	}

	ruleset, _, errno := syscall.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), // nosemgrep
		unsafe.Sizeof(attr),            // nosemgrep
		0,
	) // #nosec G103
	if errno != 0 {
		return 0, errors.Errorf("landlock: ruleset: %v", errno)
	}

	fd := int(ruleset)
	if fd < 0 || uintptr(fd) != ruleset {
		return 0, errors.Errorf("landlock: unable to cast within bounds")
	}
	syscall.CloseOnExec(fd)

	return ruleset, nil
}
