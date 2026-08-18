package diffx

import (
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"mdp-cysec/internal/models"
)

type Analysis struct {
	Kind         string         `json:"kind"`
	Summary      string         `json:"summary"`
	BaselinePath string         `json:"baseline_path,omitempty"`
	CurrentPath  string         `json:"current_path,omitempty"`
	BaselineSize int64          `json:"baseline_size_bytes,omitempty"`
	CurrentSize  int64          `json:"current_size_bytes,omitempty"`
	Text         *TextAnalysis  `json:"text,omitempty"`
	Image        *ImageAnalysis `json:"image,omitempty"`
	Available    bool           `json:"available"`
}

type TextAnalysis struct {
	LineCountBefore int      `json:"line_count_before"`
	LineCountAfter  int      `json:"line_count_after"`
	Operations      []TextOp `json:"operations,omitempty"`
}

type TextOp struct {
	Type       string `json:"type"`
	BeforeLine int    `json:"before_line,omitempty"`
	AfterLine  int    `json:"after_line,omitempty"`
	Before     string `json:"before,omitempty"`
	After      string `json:"after,omitempty"`
}

func AnalyzeChange(expected models.Artifact, currentPath, snapshotDir string) (*Analysis, error) {
	baselinePath, err := resolveBaselinePath(expected, snapshotDir)
	if err != nil {
		return nil, err
	}

	baseline, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("read baseline snapshot: %w", err)
	}

	current, err := os.ReadFile(currentPath)
	if err != nil {
		return nil, fmt.Errorf("read current file: %w", err)
	}

	analysis := &Analysis{
		BaselinePath: baselinePath,
		CurrentPath:  currentPath,
		BaselineSize: int64(len(baseline)),
		CurrentSize:  int64(len(current)),
	}

	if baselineImage, ok := decodeImage(baseline); ok {
		if currentImage, ok := decodeImage(current); ok {
			imageAnalysis := compareImages(baselineImage, currentImage)
			analysis.Kind = "image"
			analysis.Image = imageAnalysis
			analysis.Summary = imageSummary(imageAnalysis)
			analysis.Available = true
			return analysis, nil
		}
	}

	if looksLikeText(baseline) && looksLikeText(current) {
		textAnalysis := compareText(baseline, current)
		analysis.Kind = "text"
		analysis.Text = textAnalysis
		analysis.Summary = textSummary(textAnalysis)
		analysis.Available = true
		return analysis, nil
	}

	analysis.Kind = "unsupported"
	analysis.Available = false
	analysis.Summary = "Deep analysis is only supported for text and image files."
	return analysis, nil
}

func resolveBaselinePath(expected models.Artifact, snapshotDir string) (string, error) {
	if expected.BaselineSnapshotPath == "" {
		return "", fmt.Errorf("baseline snapshot unavailable for %s", expected.Path)
	}

	if filepath.IsAbs(expected.BaselineSnapshotPath) {
		return expected.BaselineSnapshotPath, nil
	}
	if snapshotDir == "" {
		return "", fmt.Errorf("snapshot directory unavailable for %s", expected.Path)
	}
	return filepath.Join(snapshotDir, expected.BaselineSnapshotPath), nil
}

func looksLikeText(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	sample := data
	if len(sample) > 1024 {
		sample = sample[:1024]
	}

	if !utf8.Valid(sample) {
		return false
	}

	controls := 0
	for _, b := range sample {
		if b == 0 {
			return false
		}
		if b < 0x09 || (b > 0x0D && b < 0x20) {
			controls++
		}
	}

	return float64(controls)/float64(len(sample)) < 0.02
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return []string{}
	}
	var lines []string
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			end := i
			if i > start && data[i-1] == '\r' {
				end = i - 1
			}
			lines = append(lines, string(data[start:end]))
			start = i + 1
		} else if data[i] == '\r' {
			if i+1 < len(data) && data[i+1] != '\n' {
				lines = append(lines, string(data[start:i]))
				start = i + 1
			} else if i+1 == len(data) {
				lines = append(lines, string(data[start:i]))
				start = i + 1
			}
		}
	}
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

func compareText(before, after []byte) *TextAnalysis {
	beforeLines := splitLines(before)
	afterLines := splitLines(after)

	ops := diffLines(beforeLines, afterLines)
	return &TextAnalysis{
		LineCountBefore: len(beforeLines),
		LineCountAfter:  len(afterLines),
		Operations:      ops,
	}
}

func diffLines(before, after []string) []TextOp {
	n, m := len(before), len(after)
	if n == 0 && m == 0 {
		return nil
	}

	if n*m <= 750000 {
		return exactLineDiff(before, after)
	}

	return coarseLineDiff(before, after)
}

func exactLineDiff(before, after []string) []TextOp {
	n, m := len(before), len(after)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}

	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if before[i] == after[j] {
				dp[i][j] = dp[i+1][j+1] + 1
				continue
			}
			if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	ops := make([]TextOp, 0, absInt(n-m)+1)
	i, j := 0, 0
	for i < n && j < m {
		if before[i] == after[j] {
			i++
			j++
			continue
		}
		if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, TextOp{
				Type:       "remove",
				BeforeLine: i + 1,
				Before:     before[i],
			})
			i++
			continue
		}
		ops = append(ops, TextOp{
			Type:      "add",
			AfterLine: j + 1,
			After:     after[j],
		})
		j++
	}

	for ; i < n; i++ {
		ops = append(ops, TextOp{
			Type:       "remove",
			BeforeLine: i + 1,
			Before:     before[i],
		})
	}
	for ; j < m; j++ {
		ops = append(ops, TextOp{
			Type:      "add",
			AfterLine: j + 1,
			After:     after[j],
		})
	}

	return ops
}

func coarseLineDiff(before, after []string) []TextOp {
	pre := 0
	for pre < len(before) && pre < len(after) && before[pre] == after[pre] {
		pre++
	}

	suf := 0
	for suf < len(before)-pre && suf < len(after)-pre && before[len(before)-1-suf] == after[len(after)-1-suf] {
		suf++
	}

	beforeMid := before[pre : len(before)-suf]
	afterMid := after[pre : len(after)-suf]
	ops := make([]TextOp, 0, len(beforeMid)+len(afterMid))
	for i, line := range beforeMid {
		ops = append(ops, TextOp{Type: "remove", BeforeLine: pre + i + 1, Before: line})
	}
	for i, line := range afterMid {
		ops = append(ops, TextOp{Type: "add", AfterLine: pre + i + 1, After: line})
	}
	return ops
}

func textSummary(t *TextAnalysis) string {
	if t == nil {
		return "Text diff unavailable."
	}
	removed := 0
	added := 0
	for _, op := range t.Operations {
		switch op.Type {
		case "remove":
			removed++
		case "add":
			added++
		}
	}
	if removed == 0 && added == 0 {
		return "No textual differences detected."
	}
	return fmt.Sprintf("%d line(s) removed, %d line(s) added.", removed, added)
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
