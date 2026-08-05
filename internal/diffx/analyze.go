package diffx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"unicode/utf8"

	"mdp-cysec/internal/models"
)

type Analysis struct {
	Kind         string          `json:"kind"`
	Summary      string          `json:"summary"`
	BaselinePath string          `json:"baseline_path,omitempty"`
	CurrentPath  string          `json:"current_path,omitempty"`
	BaselineSize int64           `json:"baseline_size_bytes,omitempty"`
	CurrentSize  int64           `json:"current_size_bytes,omitempty"`
	Text         *TextAnalysis   `json:"text,omitempty"`
	Image        *ImageAnalysis  `json:"image,omitempty"`
	Binary       *BinaryAnalysis `json:"binary,omitempty"`
	Available    bool            `json:"available"`
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

type ImageAnalysis struct {
	BeforeWidth          int          `json:"before_width"`
	BeforeHeight         int          `json:"before_height"`
	AfterWidth           int          `json:"after_width"`
	AfterHeight          int          `json:"after_height"`
	OverlapChangedPixels int          `json:"overlap_changed_pixels"`
	OverlapTotalPixels   int          `json:"overlap_total_pixels"`
	ChangedPercent       float64      `json:"changed_percent"`
	Bounds               *ImageBounds `json:"bounds,omitempty"`
	SuspectedCrop        bool         `json:"suspected_crop"`
	Notes                []string     `json:"notes,omitempty"`
}

type ImageBounds struct {
	MinX int `json:"min_x"`
	MinY int `json:"min_y"`
	MaxX int `json:"max_x"`
	MaxY int `json:"max_y"`
}

type BinaryAnalysis struct {
	FirstDifferentOffset int64  `json:"first_different_offset"`
	DifferingByteCount   int    `json:"differing_byte_count"`
	BeforePreview        string `json:"before_preview"`
	AfterPreview         string `json:"after_preview"`
	SizeBefore           int64  `json:"size_before_bytes"`
	SizeAfter            int64  `json:"size_after_bytes"`
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
		Available:    true,
	}

	if baselineImage, ok := decodeImage(baseline); ok {
		if currentImage, ok := decodeImage(current); ok {
			imageAnalysis := compareImages(baselineImage, currentImage)
			analysis.Kind = "image"
			analysis.Image = imageAnalysis
			analysis.Summary = imageSummary(imageAnalysis)
			return analysis, nil
		}
	}

	if looksLikeText(baseline) && looksLikeText(current) {
		textAnalysis := compareText(baseline, current)
		analysis.Kind = "text"
		analysis.Text = textAnalysis
		analysis.Summary = textSummary(textAnalysis)
		return analysis, nil
	}

	binaryAnalysis := compareBinary(baseline, current)
	analysis.Kind = "binary"
	analysis.Binary = binaryAnalysis
	analysis.Summary = binarySummary(binaryAnalysis)
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

func compareImages(before, after image.Image) *ImageAnalysis {
	boundsBefore := before.Bounds()
	boundsAfter := after.Bounds()

	overlapW := min(boundsBefore.Dx(), boundsAfter.Dx())
	overlapH := min(boundsBefore.Dy(), boundsAfter.Dy())

	changed := 0
	total := max(boundsBefore.Dx()*boundsBefore.Dy(), boundsAfter.Dx()*boundsAfter.Dy())
	if total == 0 {
		total = 1
	}

	var minX, minY, maxX, maxY int
	foundBounds := false
	
	beforeRGBA, beforeIsRGBA := before.(*image.RGBA)
	afterRGBA, afterIsRGBA := after.(*image.RGBA)
	useFastPath := beforeIsRGBA && afterIsRGBA

	for y := 0; y < overlapH; y++ {
		for x := 0; x < overlapW; x++ {
			isSame := false
			if useFastPath {
				bOff := beforeRGBA.PixOffset(boundsBefore.Min.X+x, boundsBefore.Min.Y+y)
				aOff := afterRGBA.PixOffset(boundsAfter.Min.X+x, boundsAfter.Min.Y+y)
				isSame = bytes.Equal(beforeRGBA.Pix[bOff:bOff+4], afterRGBA.Pix[aOff:aOff+4])
			} else {
				isSame = samePixel(before, after, x, y)
			}
			
			if !isSame {
				changed++
				if !foundBounds {
					minX, minY, maxX, maxY = x, y, x, y
					foundBounds = true
				} else {
					minX = min(minX, x)
					minY = min(minY, y)
					maxX = max(maxX, x)
					maxY = max(maxY, y)
				}
			}
		}
	}

	changed += boundsBefore.Dx()*boundsBefore.Dy() - overlapW*overlapH
	changed += boundsAfter.Dx()*boundsAfter.Dy() - overlapW*overlapH

	notes := make([]string, 0, 4)
	if boundsBefore.Dx() != boundsAfter.Dx() || boundsBefore.Dy() != boundsAfter.Dy() {
		notes = append(notes, fmt.Sprintf("dimensions changed from %dx%d to %dx%d", boundsBefore.Dx(), boundsBefore.Dy(), boundsAfter.Dx(), boundsAfter.Dy()))
	}
	if foundBounds {
		notes = append(notes, fmt.Sprintf("changed region spans x=%d..%d, y=%d..%d", minX, maxX, minY, maxY))
	}

	suspectedCrop := false
	if boundsBefore.Dx() != boundsAfter.Dx() || boundsBefore.Dy() != boundsAfter.Dy() {
		if foundBounds {
			touchesEdge := minX <= 3 || minY <= 3 || maxX >= overlapW-4 || maxY >= overlapH-4
			if touchesEdge {
				suspectedCrop = true
				notes = append(notes, "differences are concentrated near an image edge, which suggests cropping or canvas resize")
			}
		} else {
			suspectedCrop = true
			notes = append(notes, "image dimensions changed without overlap, which suggests a crop or replacement")
		}
	}

	percent := 0.0
	if total > 0 {
		percent = float64(changed) * 100 / float64(total)
	}

	var bounds *ImageBounds
	if foundBounds {
		bounds = &ImageBounds{MinX: minX, MinY: minY, MaxX: maxX, MaxY: maxY}
	}

	return &ImageAnalysis{
		BeforeWidth:          boundsBefore.Dx(),
		BeforeHeight:         boundsBefore.Dy(),
		AfterWidth:           boundsAfter.Dx(),
		AfterHeight:          boundsAfter.Dy(),
		OverlapChangedPixels: changed,
		OverlapTotalPixels:   total,
		ChangedPercent:       percent,
		Bounds:               bounds,
		SuspectedCrop:        suspectedCrop,
		Notes:                notes,
	}
}

func imageSummary(img *ImageAnalysis) string {
	if img == nil {
		return "Image diff unavailable."
	}
	if img.BeforeWidth == img.AfterWidth && img.BeforeHeight == img.AfterHeight {
		return fmt.Sprintf("%.2f%% of pixels changed.", img.ChangedPercent)
	}
	if img.SuspectedCrop {
		return fmt.Sprintf("Image dimensions changed from %dx%d to %dx%d; likely crop or resize.", img.BeforeWidth, img.BeforeHeight, img.AfterWidth, img.AfterHeight)
	}
	return fmt.Sprintf("Image dimensions changed from %dx%d to %dx%d.", img.BeforeWidth, img.BeforeHeight, img.AfterWidth, img.AfterHeight)
}

func samePixel(a, b image.Image, x, y int) bool {
	ar, ag, ab, aa := a.At(a.Bounds().Min.X+x, a.Bounds().Min.Y+y).RGBA()
	br, bg, bb, ba := b.At(b.Bounds().Min.X+x, b.Bounds().Min.Y+y).RGBA()
	return ar == br && ag == bg && ab == bb && aa == ba
}

func decodeImage(data []byte) (image.Image, bool) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	return img, true
}

func compareBinary(before, after []byte) *BinaryAnalysis {
	limit := min(len(before), len(after))
	firstDiff := limit
	diffCount := 0
	for i := 0; i < limit; i++ {
		if before[i] != after[i] {
			diffCount++
			if firstDiff == limit {
				firstDiff = i
			}
		}
	}
	diffCount += absInt(len(before) - len(after))
	if firstDiff == limit && len(before) != len(after) {
		firstDiff = limit
	}

	return &BinaryAnalysis{
		FirstDifferentOffset: int64(firstDiff),
		DifferingByteCount:   diffCount,
		BeforePreview:        hexPreview(before, firstDiff),
		AfterPreview:         hexPreview(after, firstDiff),
		SizeBefore:           int64(len(before)),
		SizeAfter:            int64(len(after)),
	}
}

func binarySummary(b *BinaryAnalysis) string {
	if b == nil {
		return "Binary diff unavailable."
	}
	if b.SizeBefore == b.SizeAfter {
		return fmt.Sprintf("Binary content differs at byte offset %d (%d differing bytes).", b.FirstDifferentOffset, b.DifferingByteCount)
	}
	return fmt.Sprintf("Binary size changed from %d to %d bytes; first difference at byte offset %d.", b.SizeBefore, b.SizeAfter, b.FirstDifferentOffset)
}

func hexPreview(data []byte, center int) string {
	if len(data) == 0 {
		return ""
	}
	if center < 0 {
		center = 0
	}
	start := center - 8
	if start < 0 {
		start = 0
	}
	end := center + 8
	if end > len(data) {
		end = len(data)
	}
	return hex.EncodeToString(data[start:end])
}



func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
