// mkicon draws the claudeguard icons and writes them as .icns, .ico and
// .png: go run ./tools/mkicon. Plain stdlib, so the icons are reproducible
// on any machine; icons/*.svg hold the same drawing for the web.
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

type pt struct{ x, y float64 }

type rgb struct{ r, g, b float64 }

func hex(v uint32) rgb {
	return rgb{float64(v>>16&255) / 255, float64(v>>8&255) / 255, float64(v&255) / 255}
}

// All geometry is on a 1024 grid, like the SVG.
var shield = flatten()

func cubic(a, b, c, d pt, out []pt) []pt {
	for i := 1; i <= 16; i++ {
		t := float64(i) / 16
		u := 1 - t
		out = append(out, pt{
			u*u*u*a.x + 3*u*u*t*b.x + 3*u*t*t*c.x + t*t*t*d.x,
			u*u*u*a.y + 3*u*u*t*b.y + 3*u*t*t*c.y + t*t*t*d.y,
		})
	}
	return out
}

// M512 244 L724 322 V520 C724 650 634 742 512 792 C390 742 300 650 300 520 V322 Z
func flatten() []pt {
	p := []pt{{512, 244}, {724, 322}, {724, 520}}
	p = cubic(pt{724, 520}, pt{724, 650}, pt{634, 742}, pt{512, 792}, p)
	p = cubic(pt{512, 792}, pt{390, 742}, pt{300, 650}, pt{300, 520}, p)
	return append(p, pt{300, 322})
}

func segDist(p, a, b pt) float64 {
	dx, dy := b.x-a.x, b.y-a.y
	t := ((p.x-a.x)*dx + (p.y-a.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(p.x-a.x-t*dx, p.y-a.y-t*dy)
}

func inShield(p pt) bool {
	if p.x < 280 || p.x > 744 || p.y < 224 || p.y > 812 {
		return false
	}
	in := false
	for i, j := 0, len(shield)-1; i < len(shield); j, i = i, i+1 {
		a, b := shield[i], shield[j]
		if (a.y > p.y) != (b.y > p.y) && p.x < (b.x-a.x)*(p.y-a.y)/(b.y-a.y)+a.x {
			in = !in
		}
		// A 14-unit outline rounds the corners, like stroke-linejoin: round.
		if segDist(p, a, b) < 14 {
			return true
		}
	}
	return in
}

// The arrow that passes through: M408 512 H608 M540 440 L612 512 L540 584.
var arrow = [][2]pt{{{408, 512}, {608, 512}}, {{540, 440}, {612, 512}}, {{612, 512}, {540, 584}}}

func inArrow(p pt) bool {
	for _, s := range arrow {
		if segDist(p, s[0], s[1]) < 27 {
			return true
		}
	}
	return false
}

// inPlate is the macOS icon plate: 824x824 with a continuous-looking corner.
func inPlate(p pt) bool {
	const half, n = 412.0, 5.0
	dx, dy := math.Abs(p.x-512)/half, math.Abs(p.y-512)/half
	return math.Pow(dx, n)+math.Pow(dy, n) <= 1
}

type theme struct{ top, bottom, shield, arrow rgb }

var themes = map[string]theme{
	// The panel: clay plate, paper shield.
	"claudeguard": {hex(0xD97757), hex(0xB95634), hex(0xFAF9F5), hex(0xB95634)},
	// "Claude via Proxy": the same drawing inverted, so the two differ in the Dock.
	"launcher": {hex(0xFAF9F5), hex(0xE8E6DC), hex(0xC6613F), hex(0xFAF9F5)},
	// The Windows tray while Claude is offline: the panel icon gone grey.
	"tray-off": {hex(0x9C9A92), hex(0x73726C), hex(0xFAF9F5), hex(0x73726C)},
}

func render(t theme, size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	ss := 4
	if size < 64 {
		ss = 8
	}
	scale := 1024 / float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					p := pt{(float64(x) + (float64(sx)+.5)/float64(ss)) * scale, (float64(y) + (float64(sy)+.5)/float64(ss)) * scale}
					if !inPlate(p) {
						continue
					}
					k := (p.y - 100) / 824
					c := rgb{t.top.r + (t.bottom.r-t.top.r)*k, t.top.g + (t.bottom.g-t.top.g)*k, t.top.b + (t.bottom.b-t.top.b)*k}
					if inShield(p) {
						c = t.shield
						if inArrow(p) {
							c = t.arrow
						}
					}
					r, g, b, a = r+c.r, g+c.g, b+c.b, a+1
				}
			}
			if a == 0 {
				continue
			}
			n := float64(ss * ss)
			img.SetNRGBA(x, y, color.NRGBA{uint8(r/a*255 + .5), uint8(g/a*255 + .5), uint8(b/a*255 + .5), uint8(a/n*255 + .5)})
		}
	}
	return img
}

// renderTray draws the menu bar glyph: black with alpha, which macOS tints
// itself (a template image). On: a solid shield with the arrow cut out.
// Off: the shield's outline with a slash through it.
func renderTray(on bool, size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss, span = 8, 640.0
	scale := span / float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			hit := 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					p := pt{512 - span/2 + (float64(x)+(float64(sx)+.5)/ss)*scale, 518 - span/2 + (float64(y)+(float64(sy)+.5)/ss)*scale}
					if !inShield(p) {
						continue
					}
					if on && !inArrow(p) {
						hit++
					}
					if !on && (nearEdge(p, 44) || segDist(p, pt{392, 660}, pt{632, 380}) < 24) {
						hit++
					}
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{A: uint8(float64(hit)/(ss*ss)*255 + .5)})
		}
	}
	return img
}

func nearEdge(p pt, w float64) bool {
	for i, j := 0, len(shield)-1; i < len(shield); j, i = i, i+1 {
		if segDist(p, shield[i], shield[j]) < w {
			return true
		}
	}
	return false
}

func pngBytes(img image.Image) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		log.Fatal(err)
	}
	return b.Bytes()
}

func icns(pngs map[int][]byte) []byte {
	var body bytes.Buffer
	for _, e := range []struct {
		tag  string
		size int
	}{{"icp4", 16}, {"icp5", 32}, {"ic11", 32}, {"ic12", 64}, {"ic07", 128}, {"ic13", 256}, {"ic08", 256}, {"ic14", 512}, {"ic09", 512}, {"ic10", 1024}} {
		body.WriteString(e.tag)
		binary.Write(&body, binary.BigEndian, uint32(len(pngs[e.size])+8))
		body.Write(pngs[e.size])
	}
	var out bytes.Buffer
	out.WriteString("icns")
	binary.Write(&out, binary.BigEndian, uint32(body.Len()+8))
	out.Write(body.Bytes())
	return out.Bytes()
}

func ico(pngs map[int][]byte) []byte {
	sizes := []int{16, 32, 48, 256}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, []uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for _, s := range sizes {
		out.Write([]byte{byte(s), byte(s), 0, 0}) // 256 is written as 0
		binary.Write(&out, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&out, binary.LittleEndian, []uint32{uint32(len(pngs[s])), uint32(offset)})
		offset += len(pngs[s])
	}
	for _, s := range sizes {
		out.Write(pngs[s])
	}
	return out.Bytes()
}

func main() {
	dir := "icons"
	for file, on := range map[string]bool{"menubar.png": true, "menubar-off.png": false} {
		if err := os.WriteFile(filepath.Join(dir, file), pngBytes(renderTray(on, 64)), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	for name, t := range themes {
		pngs := map[int][]byte{}
		for _, s := range []int{16, 32, 48, 64, 128, 256, 512, 1024} {
			pngs[s] = pngBytes(render(t, s))
		}
		files := map[string][]byte{name + ".icns": icns(pngs), name + ".ico": ico(pngs), name + ".png": pngs[256]}
		// The Linux tray takes plain PNGs; the grey plate exists only as a
		// tray icon.
		switch name {
		case "claudeguard":
			files["tray.png"] = pngs[64]
		case "tray-off":
			files = map[string][]byte{name + ".ico": ico(pngs), name + ".png": pngs[64]}
		}
		for file, data := range files {
			if err := os.WriteFile(filepath.Join(dir, file), data, 0o644); err != nil {
				log.Fatal(err)
			}
		}
	}
}
