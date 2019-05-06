package log

import (
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

type TextFormatter struct {
	prefixed.TextFormatter
}

func (f *TextFormatter) Format(entry *log.Entry) ([]byte, error) {

	var re *regexp.Regexp
	var u string

	// Remove mentions of "acme: "
	entry.Message = strings.Replace(entry.Message, "acme: ", "", -1)

	// Remove timestamps, e.g. "2019/01/23 13:26:28"
	re = regexp.MustCompile(`\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\]`)
	entry.Message = re.ReplaceAllString(entry.Message, "")

	// From: [INFO] [acmeproxy.mdbraber.net] acme: Trying to solve DNS-01
	// To: [acmeproxy.mdbraber.net] Trying to solve DNS-01
	re = regexp.MustCompile(`\[INFO\]`)
	if u = re.ReplaceAllString(entry.Message, ""); entry.Message != u {
		entry.Message = u
		entry.Level = log.InfoLevel
	}

	// Find all warning messages and set the appropriate level
	re = regexp.MustCompile(`\[WARN(ING)?\]`)
	if u = re.ReplaceAllString(entry.Message, ""); entry.Message != u {
		entry.Message = u
		entry.Level = log.InfoLevel
	}

	re = regexp.MustCompile(`\[((?:[a-z0-9\*](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\]`)
	domainMatch := re.FindAllStringSubmatch(entry.Message, -1)
	if len(domainMatch) > 0 && !strings.Contains(entry.Data["prefix"].(string), domainMatch[0][1]) {
		entry.Data["prefix"] = entry.Data["prefix"].(string) + ": " + domainMatch[0][1]
	}
	entry.Message = re.ReplaceAllString(entry.Message, "")

	// Change [string:string] message to fields, e.g. [FileStorage:/etc/acmeproxy/certmagic]
	re = regexp.MustCompile(`\[\s*((?:(?:(?:[a-zA-Z0-9]*))\s*(?::|=)\s*(?:[^\]\s]*)|(?:[^\]]*, [^\]]*))*)\s*\]`)
	for _, match := range re.FindAllStringSubmatch(entry.Message, -1) {
		rePair := regexp.MustCompile(`(?:(\w+)(?::|=)\s+(\w+)(?:,\s)?)`)
		for _, pair := range rePair.FindAllStringSubmatch(match[1], -1) {
			entry.Data[pair[1]] = pair[2]
		}
	}
	entry.Message = re.ReplaceAllString(entry.Message, "")

	// Remove all double spaces
	entry.Message = strings.Replace(entry.Message, "  ", " ", -1)

	// Finally trim the message
	entry.Message = strings.TrimSpace(entry.Message)
	return f.TextFormatter.Format(entry)
}
