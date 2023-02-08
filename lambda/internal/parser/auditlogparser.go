package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"rdsauditlogss3/internal/entity"
	"strconv"
	"strings"
	"time"
)

type AuditLogParser struct {
}

func NewAuditLogParser() *AuditLogParser {
	return &AuditLogParser{}
}

func (p *AuditLogParser) ParseEntries(data io.Reader, logFileTimestamp int64) ([]*entity.LogEntry, error) {
	var entries []*entity.LogEntry
	var currentEntry *entity.LogEntry

	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		txt := scanner.Text()
		if txt == "" {
			continue
		}

		record := strings.Split(txt, ",")

		if len(record) < 2 {
			return nil, fmt.Errorf("could not parse data")
		}

		// TODO: probably need to consider all timestamp formats
		s, err := strconv.ParseInt(record[0][0:10], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse seconds: %v", err)
		}
		ns, err := strconv.ParseInt(record[0][10:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse nanoseconds: %v", err)
		}

		ts := time.Unix(s, ns)

		newTS := entity.LogEntryTimestamp{
			Year:  ts.Year(),
			Month: int(ts.Month()),
			Day:   ts.Day(),
			Hour:  ts.Hour(),
		}

		if currentEntry != nil && currentEntry.Timestamp != newTS {
			entries = append(entries, currentEntry)
			currentEntry = nil
		}

		if currentEntry == nil {
			currentEntry = &entity.LogEntry{
				Timestamp:        newTS,
				LogLine:          new(bytes.Buffer),
				LogFileTimestamp: logFileTimestamp,
			}
		}

		currentEntry.LogLine.WriteString(txt)
		currentEntry.LogLine.WriteString("\n")
	}

	entries = append(entries, currentEntry)

	return entries, nil
}
