// Package ppi reads PPI (Per-Packet Information) capture headers — the
// wrapper wardriving tools put in front of each 802.11 frame to carry what the
// radio knew at the moment of capture, most usefully the GPS fix.
//
// TRAZIP needs it for one reason: a WiFi survey saved by a tool like Kismet
// arrives as link type 192, and without unwrapping it every frame reads as an
// undecodable blob. With it, the capture becomes ordinary 802.11 — beacons,
// SSIDs, channels — plus, when the capture had a GPS attached, where each frame
// was heard.
//
// Reading position out of a capture the operator already owns is not the same
// thing as looking up someone else's access point in a location service: the
// coordinates here were recorded by whoever ran the capture, on their own gear,
// and TRAZIP sends nothing anywhere to interpret them.
package ppi

import (
	"encoding/binary"
	"errors"
	"math"
)

// LinkType is the pcap link type that marks a PPI-wrapped capture.
const LinkType = 192

// headerLen is the fixed part: version, flags, length, DLT.
const headerLen = 8

// fieldHeaderLen is type + length, ahead of every optional field.
const fieldHeaderLen = 4

// fieldGPS is the PPI field type carrying the geolocation tag
// (PPI-GEOLOCATION, "GPS" tag).
const fieldGPS = 30002

// flagAlign is bit 0 of pph_flags: when set, every TLV starts on a 32-bit
// boundary, so a field whose length is not a multiple of 4 is followed by
// padding. Ignoring it desynchronises the walk from the first odd-length field
// onwards, which loses any geotag sitting behind it.
const flagAlign = 1 << 0

// pad4 is the padding after a field ending at off when alignment is in effect.
func pad4(off int) int { return (off + 3) & ^3 }

// Bits of the GPS tag's "present" mask, in the order the fields follow it.
const (
	bitGPSFlags = 1 << 0
	bitLatitude = 1 << 1
	bitLongitud = 1 << 2
	bitAltitude = 1 << 3
	bitAltG     = 1 << 4
)

var (
	// ErrTooShort means the buffer cannot hold a PPI header at all.
	ErrTooShort = errors.New("demasiado corto para una cabecera PPI")
	// ErrVersion means a PPI version this package does not read.
	ErrVersion = errors.New("versión de cabecera PPI no soportada")
	// ErrLength means the declared header length is inconsistent with the data.
	ErrLength = errors.New("la longitud declarada en la cabecera PPI no cuadra")
)

// Fix is a GPS position recorded with a frame. Fields are pointers because
// "not present" and "zero" are different things: latitude 0 is a real place,
// and a capture with no fix must not be drawn on the equator.
type Fix struct {
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
	// AltitudeM is height above sea level in metres.
	AltitudeM *float64 `json:"altitudeM,omitempty"`
}

// HasPosition reports whether the fix carries usable coordinates.
func (f *Fix) HasPosition() bool {
	return f != nil && f.Latitude != nil && f.Longitude != nil
}

// Packet is one decoded PPI record.
type Packet struct {
	// DLT is the link type of the frame inside, to keep decoding with.
	DLT uint32
	// Payload is the encapsulated frame.
	Payload []byte
	// Fix is the GPS position, or nil when the capture carried none.
	Fix *Fix
}

// Parse reads a PPI record: the header, any geolocation tag, and the frame
// underneath.
//
// Every length is treated as untrusted. These files come from other people's
// tools, and a declared length that runs past the buffer is exactly how a
// parser like this gets turned into a crash.
func Parse(data []byte) (Packet, error) {
	if len(data) < headerLen {
		return Packet{}, ErrTooShort
	}
	if version := data[0]; version != 0 {
		// Only version 0 has ever been published; anything else means the
		// layout below does not apply and guessing would produce nonsense.
		return Packet{}, ErrVersion
	}
	total := int(binary.LittleEndian.Uint16(data[2:4]))
	if total < headerLen || total > len(data) {
		return Packet{}, ErrLength
	}
	p := Packet{
		DLT:     binary.LittleEndian.Uint32(data[4:8]),
		Payload: data[total:],
	}

	aligned := data[1]&flagAlign != 0

	// Walk the optional fields between the fixed header and the frame.
	for off := headerLen; off+fieldHeaderLen <= total; {
		ftype := binary.LittleEndian.Uint16(data[off : off+2])
		flen := int(binary.LittleEndian.Uint16(data[off+2 : off+4]))
		body := off + fieldHeaderLen
		end := body + flen
		if end > total {
			break // a field that overruns the header: stop, keep what we have
		}
		if ftype == fieldGPS {
			if fix := parseGPS(data[body:end]); fix != nil {
				p.Fix = fix
			}
		}
		if aligned {
			end = pad4(end)
		}
		off = end
	}
	return p, nil
}

// parseGPS reads a PPI-GEOLOCATION tag. It returns nil rather than an error:
// a malformed or unfamiliar geotag means "no position", never a failure to
// read the frame, which is the part that matters.
func parseGPS(b []byte) *Fix {
	const gpsHeaderLen = 8 // version, pad, len, present mask
	if len(b) < gpsHeaderLen {
		return nil
	}
	present := binary.LittleEndian.Uint32(b[4:8])

	off := gpsHeaderLen
	// read consumes the next 4-byte value when its bit is set. Fields appear
	// in bit order, so every earlier present bit shifts the later ones along.
	read := func(bit uint32) (uint32, bool) {
		if present&bit == 0 {
			return 0, false
		}
		if off+4 > len(b) {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		return v, true
	}

	read(bitGPSFlags) // consumed for its position only
	rawLat, haveLat := read(bitLatitude)
	rawLon, haveLon := read(bitLongitud)
	rawAlt, haveAlt := read(bitAltitude)
	read(bitAltG)

	fix := &Fix{}
	if haveLat {
		if v, ok := degrees(rawLat, 90); ok {
			fix.Latitude = &v
		}
	}
	if haveLon {
		if v, ok := degrees(rawLon, 180); ok {
			fix.Longitude = &v
		}
	}
	if haveAlt {
		v := float64(rawAlt)/1e4 - 180000.0
		fix.AltitudeM = &v
	}
	if fix.Latitude == nil && fix.Longitude == nil && fix.AltitudeM == nil {
		return nil
	}
	return fix
}

// degrees converts PPI's fixed3_7 encoding to signed degrees, rejecting values
// outside the range a coordinate can occupy — a capture with a garbled geotag
// should read as "no position", not place a frame off the planet.
func degrees(raw uint32, limit float64) (float64, bool) {
	v := float64(raw)/1e7 - 180.0
	if math.IsNaN(v) || v < -limit || v > limit {
		return 0, false
	}
	return v, true
}

// EncodeGPS builds a PPI record wrapping frame with a geolocation tag. It
// exists so the tests can produce the exact bytes a wardriving tool writes,
// rather than asserting the parser against its own assumptions.
func EncodeGPS(dlt uint32, frame []byte, lat, lon, altM float64) []byte {
	const gpsBodyLen = 8 + 4*4 // header + flags, lat, lon, alt
	geo := make([]byte, 0, fieldHeaderLen+gpsBodyLen)
	geo = binary.LittleEndian.AppendUint16(geo, fieldGPS)
	geo = binary.LittleEndian.AppendUint16(geo, gpsBodyLen)
	geo = append(geo, 2, 0) // geotag version 2, pad
	geo = binary.LittleEndian.AppendUint16(geo, gpsBodyLen)
	geo = binary.LittleEndian.AppendUint32(geo, bitGPSFlags|bitLatitude|bitLongitud|bitAltitude)
	geo = binary.LittleEndian.AppendUint32(geo, 0) // GPSFlags
	geo = binary.LittleEndian.AppendUint32(geo, uint32(math.Round((lat+180.0)*1e7)))
	geo = binary.LittleEndian.AppendUint32(geo, uint32(math.Round((lon+180.0)*1e7)))
	geo = binary.LittleEndian.AppendUint32(geo, uint32(math.Round((altM+180000.0)*1e4)))

	total := headerLen + len(geo)
	out := make([]byte, 0, total+len(frame))
	out = append(out, 0, 0) // version 0, flags
	out = binary.LittleEndian.AppendUint16(out, uint16(total))
	out = binary.LittleEndian.AppendUint32(out, dlt)
	out = append(out, geo...)
	return append(out, frame...)
}
