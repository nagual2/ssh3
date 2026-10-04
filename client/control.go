package client

// Control operations of the ControlMaster (the `-O <op>` family). check,
// stop and exit all travel over one control frame carrying the operation
// name, so a master can grow a new operation without touching the framing;
// exit keeps its historical MsgExit frame (ExitMaster) so a master that
// predates this extension still understands it.
//
// Wire compatibility: msgControlOp is a new frame type, so a v0.1.22/v0.1.23
// master answers it from its "unexpected message" branch and closes the
// connection. The client maps that refusal to an explicit "does not support"
// error, so an operation a master predates fails fast instead of hanging.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/francoismichel/ssh3/client/cm"
)

// Control operation names accepted by `ssh -O <op>`.
const (
	ControlOpCheck = "check"
	ControlOpStop  = "stop"
	ControlOpExit  = "exit"
)

// msgControlOp carries one control operation: the payload is the operation
// name (uint32 length + bytes). check replies with a JSON MasterStatus,
// stop/exit reply OK and then close the control socket.
const msgControlOp cm.MsgType = 12

// masterPollInterval is the retry step while waiting for a master to release
// its socket. Small, like waitForMaster in the CLI: the shutdown is local
// and must not add a visible delay to a control op.
const masterPollInterval = 2 * time.Millisecond

// errEmptyCheckReply marks a check acknowledged without a status payload.
var errEmptyCheckReply = errors.New("the control master sent an empty check reply")

// MasterStatus is the snapshot a check op reports about a live master.
type MasterStatus struct {
	Path     string  `json:"path"`     // control socket path
	PID      int     `json:"pid"`      // pid of the serving process
	Protocol int     `json:"protocol"` // control-channel protocol version
	Uptime   float64 `json:"uptime_s"` // seconds since the master started serving
	Sessions int     `json:"sessions"` // bridged sessions currently running
	Forwards int     `json:"forwards"` // forwards opened through the master
}

// String renders the status as a single line for the CLI.
func (s MasterStatus) String() string {
	return fmt.Sprintf("Master running (pid=%d), uptime %s, %d session(s), %d forward(s)",
		s.PID, time.Duration(s.Uptime*float64(time.Second)).Round(time.Millisecond), s.Sessions, s.Forwards)
}

// RunControlOp runs one `ssh -O <op>` operation against the master listening
// on controlPath. check returns the master status; stop and exit return a
// zero status. exit is routed through ExitMaster so a master that predates
// the control-op extension still shuts down; an operation this build does not
// know is passed to the master, which refuses it with a clear error.
func RunControlOp(ctx context.Context, controlPath, op string) (MasterStatus, error) {
	switch op {
	case ControlOpCheck:
		return CheckMaster(ctx, controlPath)
	case ControlOpStop:
		return MasterStatus{}, StopMaster(ctx, controlPath)
	case ControlOpExit:
		return MasterStatus{}, ExitMaster(ctx, controlPath)
	default:
		if _, err := SendControlCommand(ctx, controlPath, op); err != nil {
			return MasterStatus{}, err
		}
		// accepted by the master, but nothing this build can report
		return MasterStatus{}, nil
	}
}

// CheckMaster asks the master for its status snapshot (the -O check op). It
// fails without dialing a session, so it is cheap enough for scripts and
// orchestrators to poll.
func CheckMaster(ctx context.Context, controlPath string) (MasterStatus, error) {
	payload, err := SendControlCommand(ctx, controlPath, ControlOpCheck)
	if err != nil {
		return MasterStatus{}, err
	}
	return decodeMasterStatus(payload)
}

// StopMaster asks the master to stop serving and closes it down (-O stop).
// It returns once the master acknowledged and released its control socket,
// so the caller can rely on the path being free and no stale socket left.
func StopMaster(ctx context.Context, controlPath string) error {
	if _, err := SendControlCommand(ctx, controlPath, ControlOpStop); err != nil {
		return err
	}
	return waitMasterReleased(ctx, controlPath)
}

// SendControlCommand sends one raw control operation and returns the reply
// payload. An unknown operation is refused by the master with an explicit
// error, and the connection stays usable for a correct retry.
func SendControlCommand(ctx context.Context, controlPath, op string) ([]byte, error) {
	conn, err := dialCM(ctx, controlPath)
	if err != nil {
		return nil, fmt.Errorf("no control master is listening on %s: %w", controlPath, err)
	}
	defer conn.Close()
	if err := cm.Hello(conn); err != nil {
		return nil, fmt.Errorf("the peer on %s is not a control master: %w", controlPath, err)
	}
	payload, err := cm.Call(conn, msgControlOp, encodeControlOp(op))
	if err != nil {
		return nil, controlOpError(op, err)
	}
	return payload, nil
}

// controlOpError turns the generic refusal of a master that predates the
// control-op extension (it answers "unexpected message 12" from its default
// branch) into an explicit "unsupported" error instead of leaking the wire
// detail to the user.
func controlOpError(op string, err error) error {
	if strings.Contains(err.Error(), "unexpected message") {
		return fmt.Errorf("the control master does not support the %q control operation (it predates the -O check/stop extension)", op)
	}
	return err
}

// waitMasterReleased polls until the master stopped serving on controlPath.
// The wait is bounded by ctx: a master that acknowledged the operation but
// never closes reports a timeout instead of hanging the caller.
func waitMasterReleased(ctx context.Context, controlPath string) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("the control master has not released %s: %w", controlPath, err)
		}
		if !masterServing(controlPath) {
			return nil
		}
		time.Sleep(masterPollInterval)
	}
}

// masterServing reports whether a master still answers on controlPath. The
// dial has its own short timeout so the wait is not skewed by a nearly
// exhausted ctx.
func masterServing(controlPath string) bool {
	conn, err := net.DialTimeout("unix", controlPath, 200*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return cm.Hello(conn) == nil
}

func decodeMasterStatus(payload []byte) (MasterStatus, error) {
	if len(payload) == 0 {
		return MasterStatus{}, errEmptyCheckReply
	}
	var status MasterStatus
	if err := json.Unmarshal(payload, &status); err != nil {
		return MasterStatus{}, fmt.Errorf("malformed check reply from the control master: %w", err)
	}
	return status, nil
}

// encodeControlOp marshals an operation name (uint32 length + bytes).
func encodeControlOp(op string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(op))), op...)
}

// decodeControlOp unmarshals an operation name; trailing bytes are ignored so
// a newer client may extend the payload.
func decodeControlOp(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", errors.New("truncated control operation")
	}
	n := binary.BigEndian.Uint32(payload)
	if uint64(len(payload)-4) < uint64(n) {
		return "", errors.New("truncated control operation")
	}
	return string(payload[4 : 4+n]), nil
}
