package tunnel

import (
	"fmt"
	"os/exec"
	"os/user"

	"github.com/VitalyDubovets/claudeguard/internal/sysutil"
)

// protectKey leaves the private key readable by its owner alone. A file
// mode means nothing on Windows: the key inherits the access list of the
// folder above, and OpenSSH ignores a key that anyone else can read. One
// extra group on the profile folder (a sandbox, a backup tool) is enough
// for "bad permissions" and a tunnel that never comes up.
func protectKey(path string) error {
	me, err := user.Current()
	if err != nil {
		return err
	}
	// On Windows Uid is the SID, which icacls takes with a leading star.
	cmd := exec.Command(sysutil.SysTool("icacls.exe"), path, "/inheritance:r", "/grant:r", "*"+me.Uid+":(F)")
	sysutil.HideChildWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("icacls %s: %w\n%s", path, err, out)
	}
	return nil
}
