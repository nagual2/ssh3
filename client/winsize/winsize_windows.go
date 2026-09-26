//go:build windows

package winsize

import (
	"os"

	"golang.org/x/term"
)

func GetWinsize(tty *os.File) (ws WindowSize, err error) {
	// on Windows the input handle (CONIN$) carries no screen buffer, so the
	// query on it fails: fall back to the output handles, which have one
	for _, f := range []*os.File{tty, os.Stdout, os.Stderr} {
		if f == nil {
			continue
		}
		var width, height int
		width, height, err = term.GetSize(int(f.Fd()))
		if err != nil {
			continue
		}
		ws.NCols = uint16(width)
		ws.NRows = uint16(height)
		ws.PixelWidth = 0
		ws.PixelHeight = 0
		return ws, nil
	}
	return ws, err
}
