package landlock

type Options struct {
	AllowMinimalDev     bool
	AllowMinimalSystem  bool
	AllowMinimalNetwork bool
}

type Landlock struct {
	*Options

	version int
	ruleset uintptr
}

type Mode uint64

const (
	ModeRead Mode = 1 << iota
	ModeWrite
	ModeExec
	ModeSock
	ModeDir
)

type Missing uint64

const (
	MissingErr Missing = iota
	MissingIgnore
	MissingCreate
)

type PathOptions struct {
	Path      string
	Mode      Mode
	OnMissing Missing
}

type Protocol int

const (
	ProtocolTCP Protocol = iota
)

type Direction uint64

const (
	DirectionOut Direction = iota
	DirectionIn
)

type NetworkOptions struct {
	Proto Protocol
	Dir   Direction
	Port  uint64
}
