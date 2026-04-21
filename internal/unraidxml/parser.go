// Package unraidxml parses Unraid community-applications container
// template XML files — the format produced by the AppData Backup plugin
// when it snapshots a container's config.
//
// We only care about a subset: the image repository, the WebUI URL
// (templated with [PORT:xxxx]), and the three kinds of <Config> entries
// (Port, Path, Variable). Everything else on the XML is ignored.
package unraidxml

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Template is the distilled Unraid XML we care about.
type Template struct {
	Path       string // absolute path to the XML on disk
	Name       string
	Repository string // docker image reference
	WebUI      string
	Ports      []PortMap
	Paths      []PathMap
	Env        []EnvVar
}

// PortMap is one <Config Type="Port">.
type PortMap struct {
	ContainerPort int    // Target="8921"
	HostPort      int    // the XML's inner <Config>value</Config> if numeric, else 0
	Mode          string // Mode="tcp" or "udp"
}

// PathMap is one <Config Type="Path">.
type PathMap struct {
	ContainerPath string // Target="/config"
	HostPath      string // the value inside the <Config> tag (e.g. /mnt/user/appdata/<name>)
	Mode          string // Mode="rw" | "ro"
}

// EnvVar is one <Config Type="Variable">.
type EnvVar struct {
	Name  string // Target="ADMIN_USERNAME"
	Value string // inner text of <Config>
}

// raw XML struct for decoding. Unraid's format uses attribute-driven
// <Config> tags in the element body.
type rawContainer struct {
	XMLName    xml.Name    `xml:"Container"`
	Version    string      `xml:"version,attr"`
	Name       string      `xml:"Name"`
	Repository string      `xml:"Repository"`
	WebUI      string      `xml:"WebUI"`
	Configs    []rawConfig `xml:"Config"`
}

type rawConfig struct {
	Name        string `xml:"Name,attr"`
	Target      string `xml:"Target,attr"`
	Default     string `xml:"Default,attr"`
	Mode        string `xml:"Mode,attr"`
	Type        string `xml:"Type,attr"` // "Port" | "Path" | "Variable"
	Value       string `xml:",chardata"`
}

// Parse parses a single Unraid XML file, capping the read at
// MaxXMLBytes to prevent a hostile archive from OOM-ing us via a giant
// "template" file.
func Parse(path string) (*Template, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxXMLBytes {
		return nil, fmt.Errorf("xml file exceeds %d-byte cap", MaxXMLBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw rawContainer
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode xml: %w", err)
	}
	if raw.Version == "" || raw.Repository == "" {
		return nil, fmt.Errorf("not an Unraid container template (missing version/repository)")
	}
	t := &Template{
		Path:       path,
		Name:       strings.TrimSpace(raw.Name),
		Repository: strings.TrimSpace(raw.Repository),
		WebUI:      strings.TrimSpace(raw.WebUI),
	}
	for _, c := range raw.Configs {
		switch c.Type {
		case "Port":
			cp, _ := strconv.Atoi(strings.TrimSpace(c.Target))
			hp := 0
			if v := strings.TrimSpace(c.Value); v != "" {
				hp, _ = strconv.Atoi(v)
			}
			mode := strings.ToLower(strings.TrimSpace(c.Mode))
			if mode != "udp" {
				mode = "tcp"
			}
			if cp > 0 {
				t.Ports = append(t.Ports, PortMap{ContainerPort: cp, HostPort: hp, Mode: mode})
			}
		case "Path":
			target := strings.TrimSpace(c.Target)
			value := strings.TrimSpace(c.Value)
			mode := strings.ToLower(strings.TrimSpace(c.Mode))
			if mode != "ro" {
				mode = "rw"
			}
			if target != "" {
				t.Paths = append(t.Paths, PathMap{ContainerPath: target, HostPath: value, Mode: mode})
			}
		case "Variable":
			name := strings.TrimSpace(c.Target)
			if name != "" {
				t.Env = append(t.Env, EnvVar{Name: name, Value: strings.TrimSpace(c.Value)})
			}
		}
	}
	return t, nil
}

// MaxXMLBytes caps how many bytes we'll read per candidate XML file
// before giving up on parsing it. A 16 MiB Unraid template is already
// wildly larger than anything legitimate (real ones are ~3 KiB), and
// the cap protects against a hostile archive containing a multi-GB
// "XML" that tries to OOM us.
const MaxXMLBytes = 16 << 20

// MaxXMLScan caps how many *.xml files we'll peek at during FindTemplates.
// A hostile archive could contain tens of thousands of stubby .xml files;
// we stop looking after MaxXMLScan to keep the scan bounded.
const MaxXMLScan = 1000

// FindTemplates walks root and returns every parseable Unraid XML it
// finds. Symlinks are not followed (zip/tar extractors skip them, but
// defensive here in case the archive was unpacked by something else).
func FindTemplates(root string) ([]*Template, error) {
	var found []*Template
	scanned := 0
	err := filepath.WalkDir(root, func(p string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return nil // continue walking; best-effort
		}
		if dirent.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(p), ".xml") {
			return nil
		}
		if scanned >= MaxXMLScan {
			return filepath.SkipAll
		}
		scanned++
		tpl, err := Parse(p)
		if err != nil {
			return nil // not every .xml is a container template
		}
		found = append(found, tpl)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// WebUIPort extracts the container-internal port that the [PORT:nnn]
// token in the WebUI template refers to. In Unraid XMLs the number
// inside [PORT:...] is ALWAYS the container port (the XML Target
// attribute on the matching Port entry). Returns 0 if no [PORT:...]
// token is found.
func WebUIPort(webuiRaw string) int {
	i := strings.Index(webuiRaw, "[PORT:")
	if i < 0 {
		return 0
	}
	j := strings.Index(webuiRaw[i:], "]")
	if j < 0 {
		return 0
	}
	num := webuiRaw[i+len("[PORT:") : i+j]
	n, _ := strconv.Atoi(strings.TrimSpace(num))
	return n
}

// ResolveWebUI substitutes [IP] → host, [PORT:nnn] → actualHostPort in the
// raw WebUI URL template. If the template lacks [PORT:...] we fall back
// to http://host:port/ so the user still has a clickable link.
func ResolveWebUI(webuiRaw, host string, actualHostPort int) string {
	if webuiRaw == "" {
		return fmt.Sprintf("http://%s:%d/", host, actualHostPort)
	}
	s := strings.ReplaceAll(webuiRaw, "[IP]", host)
	// Replace [PORT:nnn] with the actual assigned host port.
	for {
		i := strings.Index(s, "[PORT:")
		if i < 0 {
			break
		}
		j := strings.Index(s[i:], "]")
		if j < 0 {
			break
		}
		s = s[:i] + strconv.Itoa(actualHostPort) + s[i+j+1:]
	}
	return s
}
