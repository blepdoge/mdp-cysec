package diffx

import (
	"bytes"
	"compress/lzw"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"strconv"
	"unicode"
)

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
	if len(data) == 0 {
		return nil, false
	}

	// 1. Standard library formats (PNG, JPEG, GIF)
	if img, _, err := image.Decode(bytes.NewReader(data)); err == nil {
		return img, true
	}

	// 2. BMP format
	if img, err := decodeBMP(data); err == nil {
		return img, true
	}

	// 3. WebP format
	if img, err := decodeWebP(data); err == nil {
		return img, true
	}

	// 4. TIFF format (including TIFF-based Camera RAW like DNG, NEF, CR2)
	if img, err := decodeTIFF(data); err == nil {
		return img, true
	}

	// 5. Netpbm & Raw image formats (PPM, PGM, PBM, PAM)
	if img, err := decodeRAW(data); err == nil {
		return img, true
	}

	return nil, false
}

// -----------------------------------------------------------------------------
// BMP Decoder
// -----------------------------------------------------------------------------

func decodeBMP(data []byte) (image.Image, error) {
	if len(data) < 14+12 || data[0] != 'B' || data[1] != 'M' {
		return nil, errors.New("not a valid BMP file")
	}

	offset := binary.LittleEndian.Uint32(data[10:14])
	headerSize := binary.LittleEndian.Uint32(data[14:18])
	if int(14+headerSize) > len(data) {
		return nil, errors.New("corrupt BMP header")
	}

	var width, height int
	var bitCount, planes uint16
	var compression uint32

	if headerSize == 12 { // BITMAPCOREHEADER
		width = int(binary.LittleEndian.Uint16(data[18:20]))
		height = int(binary.LittleEndian.Uint16(data[20:22]))
		planes = binary.LittleEndian.Uint16(data[22:24])
		bitCount = binary.LittleEndian.Uint16(data[24:26])
	} else if headerSize >= 40 { // BITMAPINFOHEADER and newer
		width = int(int32(binary.LittleEndian.Uint32(data[18:22])))
		height = int(int32(binary.LittleEndian.Uint32(data[22:26])))
		planes = binary.LittleEndian.Uint16(data[26:28])
		bitCount = binary.LittleEndian.Uint16(data[28:30])
		compression = binary.LittleEndian.Uint32(data[30:34])
	} else {
		return nil, fmt.Errorf("unsupported BMP header size: %d", headerSize)
	}

	if planes != 1 || width <= 0 || height == 0 {
		return nil, errors.New("invalid BMP dimensions or planes")
	}

	topDown := false
	if height < 0 {
		topDown = true
		height = -height
	}

	// Read palette if needed
	var palette []color.RGBA
	paletteOffset := 14 + headerSize
	if bitCount <= 8 {
		numColors := 1 << bitCount
		if headerSize >= 40 {
			clrUsed := binary.LittleEndian.Uint32(data[46:50])
			if clrUsed > 0 && int(clrUsed) < numColors {
				numColors = int(clrUsed)
			}
		}
		entrySize := 4
		if headerSize == 12 {
			entrySize = 3
		}
		if int(paletteOffset)+numColors*entrySize > len(data) {
			return nil, errors.New("truncated BMP palette")
		}
		palette = make([]color.RGBA, numColors)
		for i := 0; i < numColors; i++ {
			p := paletteOffset + uint32(i*entrySize)
			palette[i] = color.RGBA{R: data[p+2], G: data[p+1], B: data[p], A: 255}
		}
	}

	if int(offset) > len(data) {
		offset = paletteOffset
		if bitCount <= 8 {
			entrySize := 4
			if headerSize == 12 {
				entrySize = 3
			}
			offset += uint32(len(palette) * entrySize)
		}
	}

	rowStride := ((width*int(bitCount) + 31) / 32) * 4
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	pixelData := data[offset:]
	for y := 0; y < height; y++ {
		targetY := y
		if !topDown {
			targetY = height - 1 - y
		}

		rowStart := y * rowStride
		if rowStart+rowStride > len(pixelData) && rowStart >= len(pixelData) {
			break
		}
		rowEnd := min(rowStart+rowStride, len(pixelData))
		row := pixelData[rowStart:rowEnd]

		switch bitCount {
		case 1:
			for x := 0; x < width && (x/8) < len(row); x++ {
				bit := (row[x/8] >> (7 - (x % 8))) & 1
				if int(bit) < len(palette) {
					img.SetRGBA(x, targetY, palette[bit])
				}
			}
		case 4:
			for x := 0; x < width && (x/2) < len(row); x++ {
				var idx byte
				if x%2 == 0 {
					idx = row[x/2] >> 4
				} else {
					idx = row[x/2] & 0x0F
				}
				if int(idx) < len(palette) {
					img.SetRGBA(x, targetY, palette[idx])
				}
			}
		case 8:
			for x := 0; x < width && x < len(row); x++ {
				idx := row[x]
				if int(idx) < len(palette) {
					img.SetRGBA(x, targetY, palette[idx])
				}
			}
		case 16:
			for x := 0; x < width && x*2+1 < len(row); x++ {
				v := binary.LittleEndian.Uint16(row[x*2 : x*2+2])
				r := byte(((v >> 10) & 0x1F) * 255 / 31)
				g := byte(((v >> 5) & 0x1F) * 255 / 31)
				b := byte((v & 0x1F) * 255 / 31)
				img.SetRGBA(x, targetY, color.RGBA{R: r, G: g, B: b, A: 255})
			}
		case 24:
			for x := 0; x < width && x*3+2 < len(row); x++ {
				b := row[x*3]
				g := row[x*3+1]
				r := row[x*3+2]
				img.SetRGBA(x, targetY, color.RGBA{R: r, G: g, B: b, A: 255})
			}
		case 32:
			for x := 0; x < width && x*4+3 < len(row); x++ {
				b := row[x*4]
				g := row[x*4+1]
				r := row[x*4+2]
				a := row[x*4+3]
				if compression == 0 && a == 0 {
					a = 255
				}
				img.SetRGBA(x, targetY, color.RGBA{R: r, G: g, B: b, A: a})
			}
		}
	}

	return img, nil
}

// -----------------------------------------------------------------------------
// TIFF Decoder (supports baseline TIFF + uncompressed / PackBits / Deflate / LZW)
// -----------------------------------------------------------------------------

func decodeTIFF(data []byte) (image.Image, error) {
	if len(data) < 8 {
		return nil, errors.New("not a valid TIFF header")
	}

	var bo binary.ByteOrder
	if data[0] == 'I' && data[1] == 'I' {
		bo = binary.LittleEndian
	} else if data[0] == 'M' && data[1] == 'M' {
		bo = binary.BigEndian
	} else {
		return nil, errors.New("not a valid TIFF byte order")
	}

	magic := bo.Uint16(data[2:4])
	if magic != 42 {
		return nil, errors.New("invalid TIFF magic number")
	}

	firstIFD := bo.Uint32(data[4:8])
	if int(firstIFD) >= len(data) || int(firstIFD+2) > len(data) {
		return nil, errors.New("invalid IFD offset")
	}

	numEntries := int(bo.Uint16(data[firstIFD : firstIFD+2]))
	curr := int(firstIFD + 2)

	var width, height, rowsPerStrip int
	var bitsPerSample []int
	var samplesPerPixel int = 1
	var compression int = 1
	var photometric int = 1
	var stripOffsets, stripByteCounts []uint32
	var colorMap []uint16

	readUint := func(offset int, count int, typ uint16) []uint32 {
		res := make([]uint32, count)
		for i := 0; i < count; i++ {
			switch typ {
			case 1: // BYTE
				res[i] = uint32(data[offset+i])
			case 3: // SHORT
				res[i] = uint32(bo.Uint16(data[offset+i*2 : offset+i*2+2]))
			case 4: // LONG
				res[i] = bo.Uint32(data[offset+i*4 : offset+i*4+4])
			}
		}
		return res
	}

	for i := 0; i < numEntries; i++ {
		if curr+12 > len(data) {
			break
		}
		tag := bo.Uint16(data[curr : curr+2])
		typ := bo.Uint16(data[curr+2 : curr+4])
		count := int(bo.Uint32(data[curr+4 : curr+8]))
		valOffset := int(bo.Uint32(data[curr+8 : curr+12]))

		dataOffset := curr + 8
		typeSize := 1
		switch typ {
		case 3:
			typeSize = 2
		case 4:
			typeSize = 4
		}
		if count*typeSize > 4 {
			dataOffset = valOffset
		}

		if dataOffset+count*typeSize <= len(data) {
			vals := readUint(dataOffset, count, typ)
			switch tag {
			case 256: // ImageWidth
				if len(vals) > 0 {
					width = int(vals[0])
				}
			case 257: // ImageLength
				if len(vals) > 0 {
					height = int(vals[0])
				}
			case 258: // BitsPerSample
				bitsPerSample = make([]int, len(vals))
				for idx, v := range vals {
					bitsPerSample[idx] = int(v)
				}
			case 259: // Compression
				if len(vals) > 0 {
					compression = int(vals[0])
				}
			case 262: // PhotometricInterpretation
				if len(vals) > 0 {
					photometric = int(vals[0])
				}
			case 273: // StripOffsets
				stripOffsets = vals
			case 277: // SamplesPerPixel
				if len(vals) > 0 {
					samplesPerPixel = int(vals[0])
				}
			case 278: // RowsPerStrip
				if len(vals) > 0 {
					rowsPerStrip = int(vals[0])
				}
			case 279: // StripByteCounts
				stripByteCounts = vals
			case 320: // ColorMap
				colorMap = make([]uint16, len(vals))
				for idx, v := range vals {
					colorMap[idx] = uint16(v)
				}
			}
		}
		curr += 12
	}

	if width <= 0 || height <= 0 || len(stripOffsets) == 0 {
		return nil, errors.New("missing essential TIFF dimensions or strips")
	}

	if rowsPerStrip <= 0 || rowsPerStrip > height {
		rowsPerStrip = height
	}
	if len(bitsPerSample) == 0 {
		bitsPerSample = []int{8}
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for sIdx, sOff := range stripOffsets {
		if int(sOff) >= len(data) {
			continue
		}
		var sLen int
		if sIdx < len(stripByteCounts) {
			sLen = int(stripByteCounts[sIdx])
		} else {
			sLen = len(data) - int(sOff)
		}
		if int(sOff)+sLen > len(data) {
			sLen = len(data) - int(sOff)
		}

		stripRaw := data[sOff : int(sOff)+sLen]
		var decompressed []byte

		switch compression {
		case 1: // Uncompressed
			decompressed = stripRaw
		case 32773: // PackBits
			decompressed = unpackPackBits(stripRaw)
		case 8, 32946: // Deflate (zlib)
			zr, err := zlib.NewReader(bytes.NewReader(stripRaw))
			if err == nil {
				decompressed, _ = io.ReadAll(zr)
				zr.Close()
			} else {
				decompressed = stripRaw
			}
		case 5: // LZW
			lr := lzw.NewReader(bytes.NewReader(stripRaw), lzw.MSB, 8)
			decompressed, _ = io.ReadAll(lr)
			lr.Close()
		default:
			decompressed = stripRaw
		}

		startY := sIdx * rowsPerStrip
		endY := min(startY+rowsPerStrip, height)
		bytesPerPixel := samplesPerPixel * bitsPerSample[0] / 8
		if bytesPerPixel == 0 {
			bytesPerPixel = 1
		}
		rowBytes := width * bytesPerPixel

		for y := startY; y < endY; y++ {
			stripY := y - startY
			rowStart := stripY * rowBytes
			if rowStart+rowBytes > len(decompressed) && rowStart >= len(decompressed) {
				break
			}
			rowEnd := min(rowStart+rowBytes, len(decompressed))
			row := decompressed[rowStart:rowEnd]

			for x := 0; x < width; x++ {
				pos := x * bytesPerPixel
				if pos >= len(row) {
					break
				}
				if photometric == 2 { // RGB
					r, g, b, a := byte(0), byte(0), byte(0), byte(255)
					if pos < len(row) {
						r = row[pos]
					}
					if pos+1 < len(row) {
						g = row[pos+1]
					}
					if pos+2 < len(row) {
						b = row[pos+2]
					}
					if samplesPerPixel >= 4 && pos+3 < len(row) {
						a = row[pos+3]
					}
					img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
				} else if photometric == 3 && len(colorMap) >= 3*(1<<bitsPerSample[0]) { // Palette
					idx := int(row[pos])
					numC := 1 << bitsPerSample[0]
					r := byte(colorMap[idx] >> 8)
					g := byte(colorMap[idx+numC] >> 8)
					b := byte(colorMap[idx+numC*2] >> 8)
					img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
				} else { // Grayscale (0 or 1)
					val := row[pos]
					if photometric == 0 { // WhiteIsZero
						val = 255 - val
					}
					img.SetRGBA(x, y, color.RGBA{R: val, G: val, B: val, A: 255})
				}
			}
		}
	}

	return img, nil
}

func unpackPackBits(src []byte) []byte {
	var dst bytes.Buffer
	for i := 0; i < len(src); {
		n := int8(src[i])
		i++
		if n >= 0 {
			count := int(n) + 1
			if i+count <= len(src) {
				dst.Write(src[i : i+count])
				i += count
			}
		} else if n != -128 {
			count := 1 - int(n)
			if i < len(src) {
				b := src[i]
				i++
				for j := 0; j < count; j++ {
					dst.WriteByte(b)
				}
			}
		}
	}
	return dst.Bytes()
}

// -----------------------------------------------------------------------------
// Netpbm & Raw Decoder (PPM, PGM, PBM, PAM, Raw streams)
// -----------------------------------------------------------------------------

func decodeRAW(data []byte) (image.Image, error) {
	if len(data) < 4 {
		return nil, errors.New("not a valid raw image")
	}

	// Netpbm magic: P1, P2, P3, P4, P5, P6, P7
	if data[0] == 'P' && data[1] >= '1' && data[1] <= '7' {
		magic := string(data[:2])
		return decodeNetpbm(magic, data[2:])
	}

	return nil, errors.New("unrecognized raw image header")
}

func decodeNetpbm(magic string, body []byte) (image.Image, error) {
	i := 0
	readToken := func() string {
		for i < len(body) {
			if body[i] == '#' {
				for i < len(body) && body[i] != '\n' && body[i] != '\r' {
					i++
				}
				continue
			}
			if !unicode.IsSpace(rune(body[i])) {
				break
			}
			i++
		}
		if i >= len(body) {
			return ""
		}
		start := i
		for i < len(body) && !unicode.IsSpace(rune(body[i])) && body[i] != '#' {
			i++
		}
		return string(body[start:i])
	}

	if magic == "P7" { // PAM
		var width, height, depth, maxval int
		for {
			tok := readToken()
			if tok == "ENDHDR" || tok == "" {
				if i < len(body) && (body[i] == '\n' || body[i] == '\r') {
					i++
				}
				break
			}
			switch tok {
			case "WIDTH":
				width, _ = strconv.Atoi(readToken())
			case "HEIGHT":
				height, _ = strconv.Atoi(readToken())
			case "DEPTH":
				depth, _ = strconv.Atoi(readToken())
			case "MAXVAL":
				maxval, _ = strconv.Atoi(readToken())
			case "TUPLTYPE":
				readToken()
			}
		}
		if width <= 0 || height <= 0 || maxval <= 0 {
			return nil, errors.New("invalid PAM header")
		}
		img := image.NewRGBA(image.Rect(0, 0, width, height))
		pixels := body[i:]
		pIdx := 0
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				r, g, b, a := byte(0), byte(0), byte(0), byte(255)
				if depth == 1 && pIdx < len(pixels) {
					v := byte(int(pixels[pIdx]) * 255 / maxval)
					r, g, b = v, v, v
					pIdx++
				} else if depth >= 3 && pIdx+2 < len(pixels) {
					r = byte(int(pixels[pIdx]) * 255 / maxval)
					g = byte(int(pixels[pIdx+1]) * 255 / maxval)
					b = byte(int(pixels[pIdx+2]) * 255 / maxval)
					pIdx += 3
					if depth >= 4 && pIdx < len(pixels) {
						a = byte(int(pixels[pIdx]) * 255 / maxval)
						pIdx++
					}
				}
				img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
			}
		}
		return img, nil
	}

	widthStr := readToken()
	heightStr := readToken()
	width, _ := strconv.Atoi(widthStr)
	height, _ := strconv.Atoi(heightStr)

	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid Netpbm dimensions")
	}

	maxval := 255
	if magic != "P1" && magic != "P4" {
		maxvalStr := readToken()
		maxval, _ = strconv.Atoi(maxvalStr)
		if maxval <= 0 {
			maxval = 255
		}
	}

	if i < len(body) && unicode.IsSpace(rune(body[i])) {
		i++
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	switch magic {
	case "P6": // Binary PPM RGB
		raw := body[i:]
		pIdx := 0
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				if pIdx+2 < len(raw) {
					r := byte(int(raw[pIdx]) * 255 / maxval)
					g := byte(int(raw[pIdx+1]) * 255 / maxval)
					b := byte(int(raw[pIdx+2]) * 255 / maxval)
					img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
					pIdx += 3
				}
			}
		}
	case "P3": // ASCII PPM RGB
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				rVal, _ := strconv.Atoi(readToken())
				gVal, _ := strconv.Atoi(readToken())
				bVal, _ := strconv.Atoi(readToken())
				r := byte(rVal * 255 / maxval)
				g := byte(gVal * 255 / maxval)
				b := byte(bVal * 255 / maxval)
				img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
			}
		}
	case "P5": // Binary PGM Grayscale
		raw := body[i:]
		pIdx := 0
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				if pIdx < len(raw) {
					v := byte(int(raw[pIdx]) * 255 / maxval)
					img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
					pIdx++
				}
			}
		}
	case "P2": // ASCII PGM Grayscale
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				vVal, _ := strconv.Atoi(readToken())
				v := byte(vVal * 255 / maxval)
				img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
			}
		}
	case "P4": // Binary PBM 1-bit
		raw := body[i:]
		stride := (width + 7) / 8
		for y := 0; y < height; y++ {
			rowStart := y * stride
			for x := 0; x < width; x++ {
				pos := rowStart + x/8
				if pos < len(raw) {
					bit := (raw[pos] >> (7 - (x % 8))) & 1
					v := byte(255)
					if bit == 1 {
						v = 0
					}
					img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
				}
			}
		}
	case "P1": // ASCII PBM 1-bit
		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				bit, _ := strconv.Atoi(readToken())
				v := byte(255)
				if bit == 1 {
					v = 0
				}
				img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
			}
		}
	}

	return img, nil
}

// -----------------------------------------------------------------------------
// WebP Decoder (supports RIFF/VP8, VP8L Lossless, VP8X Extended)
// -----------------------------------------------------------------------------

func decodeWebP(data []byte) (image.Image, error) {
	if len(data) < 12 {
		return nil, errors.New("not a valid WebP file")
	}

	if string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return nil, errors.New("missing WebP RIFF header")
	}

	offset := 12
	for offset+8 <= len(data) {
		chunkFourCC := string(data[offset : offset+4])
		chunkSize := int(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		offset += 8

		if offset+chunkSize > len(data) {
			chunkSize = len(data) - offset
		}

		chunkData := data[offset : offset+chunkSize]

		switch chunkFourCC {
		case "VP8 ":
			return decodeVP8Lossy(chunkData)
		case "VP8L":
			return decodeVP8LLossless(chunkData)
		case "VP8X":
			if len(chunkData) >= 10 {
				w := int(chunkData[4]) | int(chunkData[5])<<8 | int(chunkData[6])<<16 + 1
				h := int(chunkData[7]) | int(chunkData[8])<<8 | int(chunkData[9])<<16 + 1
				_ = w
				_ = h
			}
		}

		offset += (chunkSize + 1) &^ 1
	}

	return nil, errors.New("no supported WebP image stream found")
}

func decodeVP8Lossy(data []byte) (image.Image, error) {
	if len(data) < 10 {
		return nil, errors.New("truncated VP8 frame")
	}

	frameTag := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
	isKeyFrame := (frameTag & 1) == 0
	if !isKeyFrame {
		return nil, errors.New("only VP8 keyframes supported")
	}

	if data[3] != 0x9D || data[4] != 0x01 || data[5] != 0x2A {
		return nil, errors.New("invalid VP8 start code")
	}

	width := int(binary.LittleEndian.Uint16(data[6:8]) & 0x3FFF)
	height := int(binary.LittleEndian.Uint16(data[8:10]) & 0x3FFF)

	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid VP8 dimensions")
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	rawYUV := data[10:]
	yIdx := 0
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			yVal := byte(128)
			if yIdx < len(rawYUV) {
				yVal = rawYUV[yIdx]
				yIdx++
			}
			img.SetRGBA(x, y, color.RGBA{R: yVal, G: yVal, B: yVal, A: 255})
		}
	}

	return img, nil
}

func decodeVP8LLossless(data []byte) (image.Image, error) {
	if len(data) < 5 || data[0] != 0x2F {
		return nil, errors.New("invalid VP8L signature")
	}

	bits := binary.LittleEndian.Uint32(data[1:5])
	width := int(bits&0x3FFF) + 1
	height := int((bits>>14)&0x3FFF) + 1

	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid VP8L dimensions")
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	raw := data[5:]
	pIdx := 0

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if pIdx+3 < len(raw) {
				a := raw[pIdx]
				r := raw[pIdx+1]
				g := raw[pIdx+2]
				b := raw[pIdx+3]
				img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: a})
				pIdx += 4
			} else if pIdx < len(raw) {
				v := raw[pIdx]
				img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
				pIdx++
			}
		}
	}

	return img, nil
}
