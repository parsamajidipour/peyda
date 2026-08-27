package deps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Mode string

const (
	Ensure Mode = "ensure"
	Check  Mode = "check"
	Update Mode = "update"
)

func Run(root string, mode Mode, out io.Writer) error {
	manager := Manager{Root: root, Out: out}
	return manager.Run(mode)
}

func RunCommand(root string, out io.Writer, args ...string) error {
	cmd := exec.Command("bash", args...)
	cmd.Dir = root
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Stdin = os.Stdin
	cmd.Env = WithGoBinFirst(os.Environ())
	fmt.Fprintf(out, "[reconx] %s\n", strings.Join(args, " "))
	return cmd.Run()
}

type Manager struct {
	Root string
	Out  io.Writer
}

type ToolStatus struct {
	Name     string
	Path     string
	OK       bool
	Optional bool
	Shadowed bool
	Message  string
}

type goTool struct {
	name   string
	module string
}

var goTools = []goTool{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest"},
}

var requiredSystemTools = []string{"curl", "jq", "git"}
var optionalSystemTools = []string{"rg"}

func (m Manager) Run(mode Mode) error {
	if m.Out == nil {
		m.Out = io.Discard
	}
	if mode == "" {
		mode = Ensure
	}

	fmt.Fprintln(m.Out, "[deps] Recon dependency check")
	fmt.Fprintf(m.Out, "[deps] Go bin is preferred first in PATH: %s\n", DetectGoBin())

	if mode != Check {
		if err := m.installSystemPackages(); err != nil {
			return err
		}
	}

	var missing []string
	for _, tool := range requiredSystemTools {
		status := m.checkTool(tool, false)
		m.printStatus(status)
		if !status.OK {
			missing = append(missing, tool)
		}
	}
	for _, tool := range optionalSystemTools {
		status := m.checkTool(tool, true)
		m.printStatus(status)
	}

	for _, tool := range goTools {
		status := m.checkGoTool(tool)
		m.printStatus(status)
		if status.OK && mode != Update {
			continue
		}
		if mode == Check {
			if !status.Optional {
				missing = append(missing, tool.name)
			}
			continue
		}
		if err := m.installGoTool(tool); err != nil {
			return err
		}
		status = m.checkGoTool(tool)
		m.printStatus(status)
		if !status.OK {
			return fmt.Errorf("%s installation finished, but the expected tool is still unavailable", tool.name)
		}
	}

	if len(missing) > 0 && mode == Check {
		return fmt.Errorf("missing required tools: %s", strings.Join(missing, ", "))
	}

	fmt.Fprintln(m.Out, "[deps] Ready.")
	return nil
}

func (m Manager) checkTool(name string, optional bool) ToolStatus {
	path, err := LookPath(name)
	if err != nil {
		return ToolStatus{Name: name, Optional: optional, Message: "missing"}
	}
	return ToolStatus{Name: name, Path: path, OK: true, Optional: optional}
}

func (m Manager) checkGoTool(tool goTool) ToolStatus {
	status := m.checkTool(tool.name, false)
	if !status.OK {
		return status
	}
	if tool.name == "httpx" && !isProjectDiscoveryHTTPX(status.Path) {
		status.OK = false
		status.Shadowed = true
		status.Message = "httpx exists, but it is not ProjectDiscovery httpx"
	}
	return status
}

func (m Manager) printStatus(status ToolStatus) {
	if status.OK {
		fmt.Fprintf(m.Out, "[deps] OK: %s (%s)\n", status.Name, status.Path)
		return
	}
	if status.Optional {
		fmt.Fprintf(m.Out, "[deps] Optional missing: %s\n", status.Name)
		return
	}
	if status.Shadowed {
		fmt.Fprintf(m.Out, "[deps] Shadowed tool: %s\n", status.Message)
		fmt.Fprintf(m.Out, "[deps] Current %s path: %s\n", status.Name, status.Path)
		return
	}
	fmt.Fprintf(m.Out, "[deps] Missing: %s\n", status.Name)
}

func (m Manager) installSystemPackages() error {
	if os.Getenv("RECON_SKIP_APT") == "1" {
		return nil
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil
	}

	var packages []string
	for _, name := range append(requiredSystemTools, optionalSystemTools...) {
		if _, err := LookPath(name); err == nil {
			continue
		}
		if name == "rg" {
			packages = append(packages, "ripgrep")
		} else {
			packages = append(packages, name)
		}
	}
	if len(packages) == 0 {
		return nil
	}

	fmt.Fprintf(m.Out, "[deps] Installing system packages: %s\n", strings.Join(packages, " "))
	args := []string{"apt-get", "update"}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			return errors.New("sudo is not available; install missing system packages manually")
		}
		args = append([]string{"sudo"}, args...)
	}
	if err := m.exec(args[0], args[1:]...); err != nil {
		return err
	}

	args = []string{"apt-get", "install", "-y"}
	args = append(args, packages...)
	if os.Geteuid() != 0 {
		args = append([]string{"sudo"}, args...)
	}
	return m.exec(args[0], args[1:]...)
}

func (m Manager) installGoTool(tool goTool) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go is required to install %s", tool.name)
	}

	goBin := DetectGoBin()
	if err := os.MkdirAll(goBin, 0o755); err != nil {
		return err
	}

	fmt.Fprintf(m.Out, "[deps] Installing/updating %s from %s\n", tool.name, tool.module)
	cmd := exec.Command("go", "install", tool.module)
	cmd.Stdout = m.Out
	cmd.Stderr = m.Out
	cmd.Env = append(WithGoBinFirst(os.Environ()), "GOBIN="+goBin)
	return cmd.Run()
}

func (m Manager) exec(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = m.Root
	cmd.Stdout = m.Out
	cmd.Stderr = m.Out
	cmd.Stdin = os.Stdin
	cmd.Env = WithGoBinFirst(os.Environ())
	return cmd.Run()
}

func isProjectDiscoveryHTTPX(path string) bool {
	cmd := exec.Command(path, "-version")
	cmd.Env = WithGoBinFirst(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	text := strings.ToLower(string(out))
	return strings.Contains(text, "projectdiscovery") ||
		strings.Contains(text, "current httpx version") ||
		strings.Contains(text, "httpx version")
}

func LookPath(name string) (string, error) {
	if goBin := DetectGoBin(); goBin != "" {
		path := filepath.Join(goBin, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return exec.LookPath(name)
}

func WithGoBinFirst(env []string) []string {
	path := os.Getenv("PATH")
	if goBin := DetectGoBin(); goBin != "" {
		path = goBin + string(os.PathListSeparator) + path
	}

	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		if !strings.HasPrefix(item, "PATH=") {
			out = append(out, item)
		}
	}
	return append(out, "PATH="+path)
}

func DetectGoBin() string {
	if gopath := strings.TrimSpace(os.Getenv("GOPATH")); gopath != "" {
		return filepath.Join(gopath, "bin")
	}
	if out, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		gopath := strings.TrimSpace(string(out))
		if gopath != "" {
			return filepath.Join(gopath, "bin")
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "go", "bin")
	}
	return ""
}
