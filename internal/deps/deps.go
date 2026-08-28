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
	fmt.Fprintf(out, "[peyda] %s\n", strings.Join(args, " "))
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
	name     string
	module   string
	optional bool
}

type systemTool struct {
	name     string
	pkg      string
	optional bool
}

type pythonTool struct {
	name     string
	pkg      string
	optional bool
}

var goTools = []goTool{
	{"subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", false},
	{"dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", false},
	{"httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", false},
	{"naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", true},
	{"gau", "github.com/lc/gau/v2/cmd/gau@latest", true},
	{"katana", "github.com/projectdiscovery/katana/cmd/katana@latest", false},
}

var requiredSystemTools []string
var systemTools = []systemTool{
	{"rg", "ripgrep", true},
	{"whois", "whois", true},
	{"dig", "dnsutils", true},
	{"nmap", "nmap", true},
}

var pythonTools = []pythonTool{
	{"arjun", "arjun", true},
	{"xnLinkFinder", "xnLinkFinder", true},
}

func (m Manager) Run(mode Mode) error {
	if m.Out == nil {
		m.Out = io.Discard
	}
	if mode == "" {
		mode = Ensure
	}

	fmt.Fprintln(m.Out, "[deps] Recon dependency check")
	fmt.Fprintf(m.Out, "[deps] Go bin is preferred first in PATH: %s\n", DetectGoBin())
	fmt.Fprintf(m.Out, "[deps] Python local bin is also searched: %s\n", DetectLocalBin())

	if mode != Check {
		if err := m.installSystemPackages(mode); err != nil {
			fmt.Fprintf(m.Out, "[deps] System package install skipped or failed: %v\n", err)
		}
		if err := m.installPythonTools(mode); err != nil {
			fmt.Fprintf(m.Out, "[deps] Python tool install skipped or failed: %v\n", err)
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
	for _, tool := range systemTools {
		status := m.checkTool(tool.name, tool.optional)
		m.printStatus(status)
	}
	for _, tool := range pythonTools {
		status := m.checkTool(tool.name, tool.optional)
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
		if tool.optional {
			if _, err := exec.LookPath("go"); err != nil {
				fmt.Fprintf(m.Out, "[deps] Optional missing: %s (Go required to install)\n", tool.name)
				continue
			}
		}
		if err := m.installGoTool(tool); err != nil {
			if tool.optional {
				fmt.Fprintf(m.Out, "[deps] Optional install failed: %s (%v)\n", tool.name, err)
				continue
			}
			return err
		}
		status = m.checkGoTool(tool)
		m.printStatus(status)
		if !status.OK {
			if tool.optional {
				continue
			}
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
	status := m.checkTool(tool.name, tool.optional)
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

func (m Manager) installSystemPackages(mode Mode) error {
	if os.Getenv("RECON_SKIP_APT") == "1" {
		return nil
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil
	}

	var packages []string
	for _, tool := range systemTools {
		if mode != Update {
			if _, err := LookPath(tool.name); err == nil {
				continue
			}
		}
		packages = append(packages, tool.pkg)
	}
	for _, name := range requiredSystemTools {
		if mode != Update {
			if _, err := LookPath(name); err == nil {
				continue
			}
		}
		packages = append(packages, aptPackageName(name))
	}
	packages = uniqueStrings(packages)
	if len(packages) == 0 {
		return nil
	}

	fmt.Fprintf(m.Out, "[deps] Installing/updating system packages: %s\n", strings.Join(packages, " "))
	args := []string{"apt-get", "update"}
	if os.Geteuid() != 0 {
		if _, err := exec.LookPath("sudo"); err != nil {
			return errors.New("sudo is not available; install missing system packages manually")
		}
		args = append([]string{"sudo"}, args...)
	}
	if err := m.exec(args[0], args[1:]...); err != nil {
		fmt.Fprintf(m.Out, "[deps] apt-get update failed; trying install with existing package cache: %v\n", err)
	}

	args = []string{"apt-get", "install", "-y"}
	args = append(args, packages...)
	if os.Geteuid() != 0 {
		args = append([]string{"sudo"}, args...)
	}
	return m.exec(args[0], args[1:]...)
}

func (m Manager) installPythonTools(mode Mode) error {
	for _, tool := range pythonTools {
		if mode != Update {
			if _, err := LookPath(tool.name); err == nil {
				continue
			}
		}
		if err := m.installPythonTool(tool, mode); err != nil {
			if tool.optional {
				fmt.Fprintf(m.Out, "[deps] Optional Python install failed: %s (%v)\n", tool.name, err)
				continue
			}
			return err
		}
	}
	return nil
}

func (m Manager) installPythonTool(tool pythonTool, mode Mode) error {
	if path, err := exec.LookPath("pipx"); err == nil {
		args := []string{"install", tool.pkg}
		if mode == Update {
			args = []string{"install", tool.pkg, "--force"}
		}
		fmt.Fprintf(m.Out, "[deps] Installing/updating %s with pipx\n", tool.name)
		if err := m.exec(path, args...); err == nil {
			return nil
		}
	}

	python := ""
	for _, name := range []string{"python3", "python"} {
		if path, err := exec.LookPath(name); err == nil {
			python = path
			break
		}
	}
	if python == "" {
		return fmt.Errorf("pipx or python is required to install %s", tool.name)
	}

	fmt.Fprintf(m.Out, "[deps] Installing/updating %s with pip --user\n", tool.name)
	return m.exec(python, "-m", "pip", "install", "--user", "--upgrade", tool.pkg)
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func aptPackageName(name string) string {
	if name == "rg" {
		return "ripgrep"
	}
	return name
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
	if localBin := DetectLocalBin(); localBin != "" {
		path := filepath.Join(localBin, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return exec.LookPath(name)
}

func WithGoBinFirst(env []string) []string {
	path := os.Getenv("PATH")
	if localBin := DetectLocalBin(); localBin != "" {
		path = localBin + string(os.PathListSeparator) + path
	}
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

func DetectLocalBin() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "bin")
	}
	return ""
}
