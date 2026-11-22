package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
	"gopkg.in/yaml.v3"
)

// Format represents the output format
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// Formatter handles output formatting
type Formatter struct {
	format Format
	writer io.Writer
}

// NewFormatter creates a new formatter
func NewFormatter(format string) *Formatter {
	f := Format(strings.ToLower(format))
	if f != FormatTable && f != FormatJSON && f != FormatYAML {
		f = FormatTable
	}

	return &Formatter{
		format: f,
		writer: os.Stdout,
	}
}

// SetWriter sets the output writer
func (f *Formatter) SetWriter(w io.Writer) {
	f.writer = w
}

// Print outputs data in the configured format
func (f *Formatter) Print(data any) error {
	switch f.format {
	case FormatJSON:
		return f.printJSON(data)
	case FormatYAML:
		return f.printYAML(data)
	default:
		return fmt.Errorf("cannot print arbitrary data as table, use PrintTable")
	}
}

// PrintTable outputs data as a table, reporting a write failure on stderr
func (f *Formatter) PrintTable(headers []string, rows [][]string) {
	if err := f.printTable(headers, rows); err != nil {
		Error("Failed to print output: %v", err)
	}
}

func (f *Formatter) printTable(headers []string, rows [][]string) error {
	if f.format == FormatJSON {
		return f.printTableAsJSON(headers, rows)
	}
	if f.format == FormatYAML {
		return f.printTableAsYAML(headers, rows)
	}

	table := tablewriter.NewTable(f.writer,
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithRowAlignment(tw.AlignLeft),
	)
	table.Header(headers)
	if err := table.Bulk(rows); err != nil {
		return err
	}
	return table.Render()
}

func (f *Formatter) printTableAsJSON(headers []string, rows [][]string) error {
	var result []map[string]string
	for _, row := range rows {
		item := make(map[string]string)
		for i, header := range headers {
			if i < len(row) {
				item[header] = row[i]
			}
		}
		result = append(result, item)
	}
	return f.printJSON(result)
}

func (f *Formatter) printTableAsYAML(headers []string, rows [][]string) error {
	var result []map[string]string
	for _, row := range rows {
		item := make(map[string]string)
		for i, header := range headers {
			if i < len(row) {
				item[header] = row[i]
			}
		}
		result = append(result, item)
	}
	return f.printYAML(result)
}

func (f *Formatter) printJSON(data any) error {
	enc := json.NewEncoder(f.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func (f *Formatter) printYAML(data any) error {
	enc := yaml.NewEncoder(f.writer)
	enc.SetIndent(2)
	return enc.Encode(data)
}

// Color helpers

// Success prints a success message
func Success(format string, args ...any) {
	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf("%s %s\n", green("✓"), fmt.Sprintf(format, args...))
}

// Error prints an error message
func Error(format string, args ...any) {
	red := color.New(color.FgRed).SprintFunc()
	fmt.Fprintf(os.Stderr, "%s %s\n", red("✗"), fmt.Sprintf(format, args...))
}

// Warning prints a warning message
func Warning(format string, args ...any) {
	yellow := color.New(color.FgYellow).SprintFunc()
	fmt.Printf("%s %s\n", yellow("!"), fmt.Sprintf(format, args...))
}

// Info prints an info message
func Info(format string, args ...any) {
	blue := color.New(color.FgBlue).SprintFunc()
	fmt.Printf("%s %s\n", blue("ℹ"), fmt.Sprintf(format, args...))
}

// Bold returns bold text
func Bold(text string) string {
	return color.New(color.Bold).Sprint(text)
}

// Dim returns dimmed text
func Dim(text string) string {
	return color.New(color.Faint).Sprint(text)
}

// StatusColor returns colored status text
func StatusColor(status string) string {
	switch strings.ToLower(status) {
	case "success", "completed":
		return color.GreenString(status)
	case "failed":
		return color.RedString(status)
	case "started", "triggered", "requested":
		return color.YellowString(status)
	default:
		return status
	}
}

// SeverityColor returns colored severity text
func SeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return color.New(color.FgRed, color.Bold).Sprint(severity)
	case "high":
		return color.RedString(severity)
	case "medium":
		return color.YellowString(severity)
	case "low":
		return color.BlueString(severity)
	default:
		return severity
	}
}
