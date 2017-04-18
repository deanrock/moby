package aufs

import (
	"os"
	"os/exec"
	"path"
	"strings"
)

func (a *Driver) squashfsMount(name string) error {
	source := path.Join(a.rootPath(), "squashfs", name)
	layer := path.Join(a.rootPath(), "diff", name)

	if _, err := os.Stat(source); err == nil {
		out, err := exec.Command("mount").Output()
		if err != nil {
			return err
		}

		if !strings.Contains(string(out), layer) {
			out, err = exec.Command("mount", "-t", "squashfs", source, layer).Output()
			if err != nil {
				return err
			}
		}
	}

	return nil
}
