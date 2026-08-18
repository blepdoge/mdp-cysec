package diffx

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"mdp-cysec/internal/models"
)

func TestAnalyzeChangeText(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	snapshotName := "baseline.snapshot"
	if err := os.WriteFile(filepath.Join(snapshotDir, snapshotName), []byte("line one\nline two\nline three\n"), 0644); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}
	currentPath := filepath.Join(root, "current.txt")
	if err := os.WriteFile(currentPath, []byte("line one\nline 2 changed\nline three\n"), 0644); err != nil {
		t.Fatalf("write current file: %v", err)
	}

	analysis, err := AnalyzeChange(models.Artifact{
		Path:                 "/current.txt",
		BaselineSnapshotPath: snapshotName,
	}, currentPath, snapshotDir)
	if err != nil {
		t.Fatalf("AnalyzeChange returned error: %v", err)
	}
	if !analysis.Available || analysis.Kind != "text" {
		t.Fatalf("kind = %q, available = %v, want text and true", analysis.Kind, analysis.Available)
	}
	if analysis.Text == nil || len(analysis.Text.Operations) == 0 {
		t.Fatal("expected text operations to be populated")
	}
}

func TestAnalyzeChangeUnsupportedBinary(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	snapshotName := "baseline.snapshot"
	if err := os.WriteFile(filepath.Join(snapshotDir, snapshotName), []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}
	currentPath := filepath.Join(root, "current.bin")
	if err := os.WriteFile(currentPath, []byte{0x00, 0x01, 0xFF, 0x03}, 0644); err != nil {
		t.Fatalf("write current file: %v", err)
	}

	analysis, err := AnalyzeChange(models.Artifact{
		Path:                 "/current.bin",
		BaselineSnapshotPath: snapshotName,
	}, currentPath, snapshotDir)
	if err != nil {
		t.Fatalf("AnalyzeChange returned error: %v", err)
	}
	if analysis.Available {
		t.Fatalf("expected Available to be false for binary file, got %v", analysis.Available)
	}
	if analysis.Kind != "unsupported" {
		t.Fatalf("expected Kind unsupported, got %q", analysis.Kind)
	}
}

func TestAnalyzeChangePNG(t *testing.T) {
	img1 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img1, img1.Bounds(), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	img2 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img2, img2.Bounds(), &image.Uniform{C: color.RGBA{B: 255, A: 255}}, image.Point{}, draw.Src)

	var b1, b2 bytes.Buffer
	png.Encode(&b1, img1)
	png.Encode(&b2, img2)

	runImageTest(t, b1.Bytes(), b2.Bytes(), "test.png")
}

func TestAnalyzeChangeJPEG(t *testing.T) {
	img1 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img1, img1.Bounds(), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	img2 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img2, img2.Bounds(), &image.Uniform{C: color.RGBA{B: 255, A: 255}}, image.Point{}, draw.Src)

	var b1, b2 bytes.Buffer
	jpeg.Encode(&b1, img1, nil)
	jpeg.Encode(&b2, img2, nil)

	runImageTest(t, b1.Bytes(), b2.Bytes(), "test.jpg")
}

func TestAnalyzeChangeGIF(t *testing.T) {
	img1 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img1, img1.Bounds(), &image.Uniform{C: color.RGBA{R: 255, A: 255}}, image.Point{}, draw.Src)
	img2 := image.NewRGBA(image.Rect(0, 0, 10, 10))
	draw.Draw(img2, img2.Bounds(), &image.Uniform{C: color.RGBA{B: 255, A: 255}}, image.Point{}, draw.Src)

	var b1, b2 bytes.Buffer
	gif.Encode(&b1, img1, nil)
	gif.Encode(&b2, img2, nil)

	runImageTest(t, b1.Bytes(), b2.Bytes(), "test.gif")
}

func TestAnalyzeChangeBMP(t *testing.T) {
	bmp1 := create24BitBMP(10, 10, color.RGBA{R: 255, G: 0, B: 0, A: 255})
	bmp2 := create24BitBMP(10, 10, color.RGBA{R: 0, G: 255, B: 0, A: 255})

	runImageTest(t, bmp1, bmp2, "test.bmp")
}

func TestAnalyzeChangeTIFF(t *testing.T) {
	tiff1 := createUncompressedTIFF(10, 10, color.RGBA{R: 200, G: 100, B: 50, A: 255})
	tiff2 := createUncompressedTIFF(10, 10, color.RGBA{R: 50, G: 100, B: 200, A: 255})

	runImageTest(t, tiff1, tiff2, "test.tiff")
}

func TestAnalyzeChangeRAW_PPM(t *testing.T) {
	ppm1 := []byte("P6\n10 10\n255\n" + string(bytes.Repeat([]byte{255, 0, 0}, 100)))
	ppm2 := []byte("P6\n10 10\n255\n" + string(bytes.Repeat([]byte{0, 255, 0}, 100)))

	runImageTest(t, ppm1, ppm2, "test.ppm")
}

func TestAnalyzeChangeRAW_PAM(t *testing.T) {
	pam1 := []byte("P7\nWIDTH 10\nHEIGHT 10\nDEPTH 3\nMAXVAL 255\nTUPLTYPE RGB\nENDHDR\n" + string(bytes.Repeat([]byte{128, 64, 32}, 100)))
	pam2 := []byte("P7\nWIDTH 10\nHEIGHT 10\nDEPTH 3\nMAXVAL 255\nTUPLTYPE RGB\nENDHDR\n" + string(bytes.Repeat([]byte{32, 64, 128}, 100)))

	runImageTest(t, pam1, pam2, "test.pam")
}

func TestAnalyzeChangeWebP(t *testing.T) {
	webp1 := createWebPVP8(10, 10, byte(100))
	webp2 := createWebPVP8(10, 10, byte(200))

	runImageTest(t, webp1, webp2, "test.webp")
}

func runImageTest(t *testing.T, data1, data2 []byte, filename string) {
	t.Helper()
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	snapshotName := "baseline.snapshot"
	if err := os.WriteFile(filepath.Join(snapshotDir, snapshotName), data1, 0644); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}
	currentPath := filepath.Join(root, filename)
	if err := os.WriteFile(currentPath, data2, 0644); err != nil {
		t.Fatalf("write current file: %v", err)
	}

	analysis, err := AnalyzeChange(models.Artifact{
		Path:                 "/" + filename,
		BaselineSnapshotPath: snapshotName,
	}, currentPath, snapshotDir)
	if err != nil {
		t.Fatalf("AnalyzeChange returned error: %v", err)
	}
	if !analysis.Available || analysis.Kind != "image" {
		t.Fatalf("expected image analysis, got kind=%q available=%v", analysis.Kind, analysis.Available)
	}
	if analysis.Image == nil || analysis.Image.BeforeWidth != 10 || analysis.Image.BeforeHeight != 10 {
		t.Fatalf("expected 10x10 image analysis, got %+v", analysis.Image)
	}
}

func create24BitBMP(w, h int, c color.RGBA) []byte {
	rowStride := ((w*24 + 31) / 32) * 4
	dataSize := rowStride * h
	fileSize := 14 + 40 + dataSize

	buf := make([]byte, fileSize)
	// BMP Header (14 bytes)
	buf[0], buf[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(buf[2:6], uint32(fileSize))
	binary.LittleEndian.PutUint32(buf[10:14], 54) // offset

	// DIB Header (40 bytes)
	binary.LittleEndian.PutUint32(buf[14:18], 40)
	binary.LittleEndian.PutUint32(buf[18:22], uint32(w))
	binary.LittleEndian.PutUint32(buf[22:26], uint32(h))
	binary.LittleEndian.PutUint16(buf[26:28], 1)  // planes
	binary.LittleEndian.PutUint16(buf[28:30], 24) // bpp
	binary.LittleEndian.PutUint32(buf[34:38], uint32(dataSize))

	offset := 54
	for y := 0; y < h; y++ {
		rowStart := offset + y*rowStride
		for x := 0; x < w; x++ {
			buf[rowStart+x*3] = c.B
			buf[rowStart+x*3+1] = c.G
			buf[rowStart+x*3+2] = c.R
		}
	}
	return buf
}

func createUncompressedTIFF(w, h int, c color.RGBA) []byte {
	rawPixels := make([]byte, w*h*3)
	for i := 0; i < w*h; i++ {
		rawPixels[i*3] = c.R
		rawPixels[i*3+1] = c.G
		rawPixels[i*3+2] = c.B
	}

	var buf bytes.Buffer
	// TIFF Little Endian Header
	buf.Write([]byte{'I', 'I', 42, 0})
	binary.Write(&buf, binary.LittleEndian, uint32(8)) // IFD offset at byte 8

	numEntries := uint16(8)
	binary.Write(&buf, binary.LittleEndian, numEntries)

	pixelDataOffset := uint32(8 + 2 + numEntries*12 + 4 + 6) // header + IFD + nextIFD + BitsPerSample values (3 shorts)

	writeTag := func(tag, typ uint16, count uint32, val uint32) {
		binary.Write(&buf, binary.LittleEndian, tag)
		binary.Write(&buf, binary.LittleEndian, typ)
		binary.Write(&buf, binary.LittleEndian, count)
		binary.Write(&buf, binary.LittleEndian, val)
	}

	bitsOffset := uint32(8 + 2 + numEntries*12 + 4)

	writeTag(256, 3, 1, uint32(w))                       // ImageWidth (SHORT)
	writeTag(257, 3, 1, uint32(h))                       // ImageLength (SHORT)
	writeTag(258, 3, 3, bitsOffset)                     // BitsPerSample (SHORT, count 3 -> offset)
	writeTag(259, 3, 1, 1)                              // Compression = 1 (Uncompressed)
	writeTag(262, 3, 1, 2)                              // PhotometricInterpretation = 2 (RGB)
	writeTag(273, 4, 1, pixelDataOffset)                // StripOffsets
	writeTag(277, 3, 1, 3)                              // SamplesPerPixel = 3
	writeTag(279, 4, 1, uint32(len(rawPixels)))         // StripByteCounts

	binary.Write(&buf, binary.LittleEndian, uint32(0)) // Next IFD = 0

	// BitsPerSample values (3 shorts: 8, 8, 8)
	binary.Write(&buf, binary.LittleEndian, uint16(8))
	binary.Write(&buf, binary.LittleEndian, uint16(8))
	binary.Write(&buf, binary.LittleEndian, uint16(8))

	buf.Write(rawPixels)
	return buf.Bytes()
}

func createWebPVP8(w, h int, fill byte) []byte {
	vp8Payload := make([]byte, 10+w*h)
	// Frame tag: keyframe
	vp8Payload[0] = 0
	vp8Payload[1] = 0
	vp8Payload[2] = 0
	// Start code
	vp8Payload[3] = 0x9D
	vp8Payload[4] = 0x01
	vp8Payload[5] = 0x2A
	// Dimensions
	binary.LittleEndian.PutUint16(vp8Payload[6:8], uint16(w))
	binary.LittleEndian.PutUint16(vp8Payload[8:10], uint16(h))
	for i := 10; i < len(vp8Payload); i++ {
		vp8Payload[i] = fill
	}

	var buf bytes.Buffer
	buf.WriteString("RIFF")
	totalSize := uint32(4 + 8 + len(vp8Payload))
	binary.Write(&buf, binary.LittleEndian, totalSize)
	buf.WriteString("WEBP")

	buf.WriteString("VP8 ")
	binary.Write(&buf, binary.LittleEndian, uint32(len(vp8Payload)))
	buf.Write(vp8Payload)

	return buf.Bytes()
}
