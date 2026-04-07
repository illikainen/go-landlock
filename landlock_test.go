package landlock_test

import (
	"bytes"
	errs "errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/illikainen/go-landlock"
)

func TestFS(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestFS") {
		return
	}

	tmp := os.Getenv("SANDBOX")
	foo := filepath.Join(tmp, "foo")
	bar := filepath.Join(tmp, "bar")
	subdir := filepath.Join(tmp, "subdir")
	otherdir := filepath.Join(tmp, "otherdir")
	anotherdir := filepath.Join(tmp, "anotherdir")

	sbox := newLandlock(t)
	require.NoError(t, sbox.AddPathRules(
		&landlock.PathOptions{Path: foo, Mode: landlock.ModeRead},
		&landlock.PathOptions{Path: subdir, Mode: landlock.ModeRead | landlock.ModeDir},
		&landlock.PathOptions{Path: otherdir, Mode: landlock.ModeRead | landlock.ModeWrite | landlock.ModeDir},
	))
	require.NoError(t, sbox.Confine())

	f, err := os.Open(foo) // #nosec G304
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = os.OpenFile(foo, os.O_WRONLY, 0o600) // #nosec G304
	require.ErrorIs(t, err, os.ErrPermission)

	_, err = os.Open(bar) // #nosec G304
	require.ErrorIs(t, err, os.ErrPermission)

	_, err = os.OpenFile(filepath.Join(tmp, "other"), os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304
	require.ErrorIs(t, err, os.ErrPermission)

	_, err = os.ReadDir(subdir)
	require.NoError(t, err)

	_, err = os.ReadDir(anotherdir)
	require.ErrorIs(t, err, os.ErrPermission)

	f, err = os.OpenFile(filepath.Join(otherdir, "file"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600) // #nosec G304
	require.NoError(t, err)
	require.NoError(t, f.Close())
}

func TestTCPConnect(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestTCPConnect") {
		return
	}

	allow, err := serveTCP("127.0.0.1:0")
	require.NoError(t, err)
	defer allow.Close(t)

	deny, err := serveTCP("127.0.0.1:0")
	require.NoError(t, err)
	defer deny.Close(t)

	denyDir, err := serveTCP("127.0.0.1:0")
	require.NoError(t, err)
	defer denyDir.Close(t)

	sbox := newLandlock(t)
	require.NoError(t, sbox.AddNetworkRules(
		&landlock.NetworkOptions{Dir: landlock.DirectionOut, Port: allow.port},
		&landlock.NetworkOptions{Dir: landlock.DirectionIn, Port: denyDir.port},
	))
	require.NoError(t, sbox.Confine())

	require.NoError(t, dialTCP(allow.address))
	assert.True(t, allow.seen)

	require.ErrorIs(t, dialTCP(deny.address), os.ErrPermission)
	assert.False(t, deny.seen)

	require.ErrorIs(t, dialTCP(denyDir.address), os.ErrPermission)
	assert.False(t, denyDir.seen)
}

func TestTCPBind(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestTCPBind") {
		return
	}

	sbox := newLandlock(t)
	require.NoError(t, sbox.AddNetworkRules(
		&landlock.NetworkOptions{Dir: landlock.DirectionIn, Port: 1298},
		&landlock.NetworkOptions{Dir: landlock.DirectionOut, Port: 9812},
	))
	require.NoError(t, sbox.Confine())

	allow, err := serveTCP("127.0.0.1:1298")
	require.NoError(t, err)
	allow.Close(t)

	_, err = serveTCP("127.0.0.1:9812")
	require.ErrorIs(t, err, os.ErrPermission)

	_, err = serveTCP("127.0.0.1:1234")
	require.ErrorIs(t, err, os.ErrPermission)
}

// TODO: landlock version <=6 can't restrict UDP connect.
func TestUDPConnect(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestUDPConnect") {
		return
	}

	allow, err := serveUDP("127.0.0.1:0")
	require.NoError(t, err)
	defer allow.Close(t)

	deny, err := serveUDP("127.0.0.1:0")
	require.NoError(t, err)
	defer deny.Close(t)

	sbox := newLandlock(t)
	require.NoError(t, sbox.Confine())

	require.NoError(t, dialUDP(allow.address))
	assert.True(t, allow.seen)

	require.NoError(t, dialUDP(deny.address))
	assert.True(t, deny.seen)
}

// TODO: landlock version <=6 can't restrict binding UDP.
func TestUDPBind(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestUDPBind") {
		return
	}

	sbox := newLandlock(t)
	require.NoError(t, sbox.Confine())

	allow, err := serveUDP("127.0.0.1:1298")
	require.NoError(t, err)
	allow.Close(t)

	deny, err := serveUDP("127.0.0.1:1234")
	require.NoError(t, err)
	deny.Close(t)
}

// TODO: landlock version <=6 can't restrict UNIX connect.
func TestUNIXConnect(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestUNIXConnect") {
		return
	}

	tmp := os.Getenv("SANDBOX")
	allow, err := serveUNIX(filepath.Join(tmp, "allow"))
	require.NoError(t, err)
	defer allow.Close(t)

	deny, err := serveUNIX(filepath.Join(tmp, "deny"))
	require.NoError(t, err)
	defer deny.Close(t)

	sbox := newLandlock(t)
	require.NoError(t, sbox.Confine())

	require.NoError(t, dialUNIX(allow.address))
	assert.True(t, allow.seen)

	require.NoError(t, dialUNIX(deny.address))
	assert.True(t, deny.seen)
}

func TestUNIXBind(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestUNIXBind") {
		return
	}

	tmp := os.Getenv("SANDBOX")
	allowDir := filepath.Join(tmp, "allow")

	sbox := newLandlock(t)
	require.NoError(t, sbox.AddPathRules(&landlock.PathOptions{
		Path:      allowDir,
		Mode:      landlock.ModeRead | landlock.ModeWrite | landlock.ModeDir | landlock.ModeSock,
		OnMissing: landlock.MissingCreate,
	}))
	require.NoError(t, sbox.Confine())

	allow, err := serveUNIX(filepath.Join(allowDir, "sock"))
	require.NoError(t, err)
	defer allow.Close(t)

	_, err = serveUNIX(filepath.Join(tmp, "deny"))
	require.ErrorIs(t, err, os.ErrPermission)
}

func TestAbstractConnect(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestAbstractConnect") {
		return
	}

	deny, err := serveUNIX("\x00deny")
	require.NoError(t, err)
	defer deny.Close(t)

	sbox := newLandlock(t)
	require.NoError(t, sbox.Confine())

	require.ErrorIs(t, dialUNIX(deny.address), os.ErrPermission)
}

// TODO: landlock version <=6 can't restrict binding abstract UNIX sockets.
func TestAbstractBind(t *testing.T) {
	t.Parallel()
	if respawn(t, "TestAbstractBind") {
		return
	}

	sbox := newLandlock(t)
	require.NoError(t, sbox.Confine())

	allow, err := serveUNIX("\x00allow")
	require.NoError(t, err)
	allow.Close(t)
}

func newLandlock(t *testing.T) *landlock.Landlock {
	t.Helper()
	sbox, err := landlock.New(&landlock.Options{})
	require.NoError(t, err)

	cwd, err := os.Getwd()
	require.NoError(t, err)

	require.NoError(t, sbox.AddPathRules(
		&landlock.PathOptions{
			Path: "/tmp",
			Mode: landlock.ModeRead | landlock.ModeWrite | landlock.ModeDir,
		},
		&landlock.PathOptions{
			Path: filepath.Join(cwd, "build"),
			Mode: landlock.ModeRead | landlock.ModeWrite | landlock.ModeDir,
		},
	))
	return sbox
}

func respawn(t *testing.T, name string) bool {
	t.Helper()
	if os.Getenv("SANDBOX") != "" {
		return false
	}

	cwd, err := os.Getwd()
	require.NoError(t, err)

	tmp, err := os.MkdirTemp(cwd, "") //nolint
	require.NoError(t, err)
	require.NoError(t, copyDir("./tests/data", tmp))

	cmd := exec.Command(os.Args[0], "-test.run="+name) // #nosec G204
	cmd.Env = append(os.Environ(), "SANDBOX="+tmp)
	stdout := &bytes.Buffer{}
	cmd.Stdout = stdout
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if e := os.RemoveAll(tmp); e != nil {
			err = errs.Join(err, e)
		}
		t.Fatalf("cmd:\n%s\nstdout:\n%s\nstderr:\n%s\nerr:\n%v", cmd, stdout, stderr, err)
	}

	require.NoError(t, os.RemoveAll(tmp))
	return true
}

func copyDir(src string, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		tgt := filepath.Join(dst, rel)
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}

			if err := os.MkdirAll(tgt, info.Mode()); err != nil {
				return err
			}
		} else {
			in, err := os.Open(path) // #nosec G304
			if err != nil {
				return err
			}
			defer func() {
				if err := in.Close(); err != nil {
					slog.Error(err.Error())
				}
			}()

			stat, err := in.Stat()
			if err != nil {
				return err
			}

			out, err := os.OpenFile(tgt, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_CLOEXEC,
				stat.Mode()) // #nosec G304
			if err != nil {
				return err
			}
			defer func() {
				if err := out.Close(); err != nil {
					slog.Error(err.Error())
				}
			}()

			if n, err := io.Copy(out, in); err != nil || n != stat.Size() {
				return fmt.Errorf("failed to copy %s to %s: %w", src, tgt, err)
			}
		}

		return nil
	})
}

type TCPServer struct {
	address  string
	port     uint64
	seen     bool
	listener net.Listener
	err      error
}

func serveTCP(address string) (*TCPServer, error) {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}

	spec, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid TCPAddr")
	}

	srv := &TCPServer{
		listener: ln,
		address:  fmt.Sprintf("%s:%d", strings.Split(address, ":")[0], spec.Port),
		port:     uint64(spec.Port), // #nosec G115
	}

	go func() {
		for {
			if conn, err := ln.Accept(); err == nil {
				srv.seen = true

				if _, err := conn.Write([]byte{0x00}); err != nil {
					srv.err = errs.Join(srv.err, err)
					return
				}

				if err := conn.Close(); err != nil {
					srv.err = errs.Join(srv.err, err)
					return
				}
			}
		}
	}()

	return srv, nil
}

func (s *TCPServer) Close(t *testing.T) {
	t.Helper()
	require.NoError(t, s.listener.Close())
	require.NoError(t, s.err)
}

func dialTCP(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}

	data := make([]byte, 1)
	if _, err = conn.Read(data); err != nil {
		return err
	}

	return conn.Close()
}

type UDPServer struct {
	address string
	port    uint64
	seen    bool
	conn    *net.UDPConn
	err     error
}

func serveUDP(address string) (*UDPServer, error) {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	spec, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("bad UDPAddr")
	}

	srv := &UDPServer{
		conn:    conn,
		address: fmt.Sprintf("%s:%d", strings.Split(address, ":")[0], spec.Port),
		port:    uint64(spec.Port), // #nosec G115
	}

	go func() {
		for {
			data := make([]byte, 1)
			_, client, err := srv.conn.ReadFromUDP(data)
			if err != nil {
				return
			}

			srv.seen = true

			if _, err := srv.conn.WriteToUDP([]byte{0x00}, client); err != nil {
				srv.err = errs.Join(srv.err, err)
				return
			}
		}
	}()

	return srv, nil
}

func (s *UDPServer) Close(t *testing.T) {
	t.Helper()
	require.NoError(t, s.conn.Close())
	require.NoError(t, s.err)
}

func dialUDP(address string) error {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}

	if _, err = conn.Write([]byte{0x00}); err != nil {
		return err
	}

	data := make([]byte, 1)
	if _, err = conn.Read(data); err != nil {
		return err
	}

	return conn.Close()
}

type UNIXServer struct {
	address  string
	seen     bool
	listener net.Listener
	err      error
}

func serveUNIX(address string) (*UNIXServer, error) {
	ln, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}

	srv := &UNIXServer{
		listener: ln,
		address:  address,
	}

	go func() {
		for {
			if conn, err := ln.Accept(); err == nil {
				srv.seen = true

				if _, err := conn.Write([]byte{0x00}); err != nil {
					srv.err = errs.Join(srv.err, err)
					return
				}

				if err := conn.Close(); err != nil {
					srv.err = errs.Join(srv.err, err)
					return
				}
			}
		}
	}()

	return srv, nil
}

func (s *UNIXServer) Close(t *testing.T) {
	t.Helper()
	require.NoError(t, s.listener.Close())
	require.NoError(t, s.err)
}

func dialUNIX(address string) error {
	conn, err := net.Dial("unix", address)
	if err != nil {
		return err
	}

	data := make([]byte, 1)
	if _, err = conn.Read(data); err != nil {
		return err
	}

	return conn.Close()
}
