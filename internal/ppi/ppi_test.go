package ppi

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

const tolerance = 1e-5

func closeTo(got, want float64) bool { return math.Abs(got-want) < tolerance }

// El caso normal: una trama envuelta con una posición, que es lo que graba una
// herramienta de wardriving con GPS conectado.
func TestParseRoundTripsPositionAndFrame(t *testing.T) {
	frame := []byte{0x80, 0x00, 0xde, 0xad, 0xbe, 0xef}
	// Ciudad de Panamá.
	const lat, lon, alt = 8.9824, -79.5199, 12.5

	got, err := Parse(EncodeGPS(105, frame, lat, lon, alt))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.DLT != 105 {
		t.Errorf("DLT = %d, se esperaba 105 (802.11)", got.DLT)
	}
	if string(got.Payload) != string(frame) {
		t.Errorf("la trama interior salió alterada: %x", got.Payload)
	}
	if !got.Fix.HasPosition() {
		t.Fatalf("no se leyó la posición: %+v", got.Fix)
	}
	if !closeTo(*got.Fix.Latitude, lat) {
		t.Errorf("latitud = %f, se esperaba %f", *got.Fix.Latitude, lat)
	}
	if !closeTo(*got.Fix.Longitude, lon) {
		t.Errorf("longitud = %f, se esperaba %f", *got.Fix.Longitude, lon)
	}
	if got.Fix.AltitudeM == nil || math.Abs(*got.Fix.AltitudeM-alt) > 1e-3 {
		t.Errorf("altitud = %v, se esperaba %f", got.Fix.AltitudeM, alt)
	}
}

// Latitud y longitud 0 es un sitio real (golfo de Guinea). Si "ausente" y
// "cero" se confundieran, una captura sin GPS aparecería ahí.
func TestZeroCoordinatesAreNotConfusedWithAbsent(t *testing.T) {
	got, err := Parse(EncodeGPS(105, []byte{1, 2, 3}, 0, 0, 0))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !got.Fix.HasPosition() {
		t.Fatal("una posición 0,0 debe leerse como posición presente")
	}
	if *got.Fix.Latitude != 0 || *got.Fix.Longitude != 0 {
		t.Errorf("0,0 se leyó como %f,%f", *got.Fix.Latitude, *got.Fix.Longitude)
	}
}

// Una captura PPI sin geotag es perfectamente válida: se lee la trama y no hay
// posición, sin error.
func TestParseWithoutGeotag(t *testing.T) {
	frame := []byte{0xaa, 0xbb, 0xcc}
	data := make([]byte, 0, headerLen+len(frame))
	data = append(data, 0, 0)
	data = binary.LittleEndian.AppendUint16(data, headerLen)
	data = binary.LittleEndian.AppendUint32(data, 105)
	data = append(data, frame...)

	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Fix != nil {
		t.Errorf("se inventó una posición: %+v", got.Fix)
	}
	if string(got.Payload) != string(frame) {
		t.Errorf("trama = %x", got.Payload)
	}
}

// Estos archivos vienen de herramientas ajenas: una longitud declarada que se
// sale del buffer es justo la forma de convertir un parser en un crash.
func TestParseRejectsHostileLengths(t *testing.T) {
	good := EncodeGPS(105, []byte{1, 2, 3, 4}, 8.98, -79.51, 10)

	cases := map[string][]byte{
		"vacío":                     {},
		"más corto que la cabecera": good[:4],
		"versión desconocida":       append([]byte{9}, good[1:]...),
	}
	// Longitud total mayor que los datos.
	overrun := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(overrun[2:4], uint16(len(good)+500))
	cases["longitud total desbordada"] = overrun

	// Longitud total menor que la cabecera fija.
	tiny := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(tiny[2:4], 2)
	cases["longitud total imposible"] = tiny

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("pánico con entrada %q: %v", name, r)
				}
			}()
			if _, err := Parse(data); err == nil {
				t.Errorf("se aceptó una entrada inválida")
			}
		})
	}
}

// Un campo cuya longitud se sale de la cabecera no debe tumbar la lectura: se
// corta el recorrido y se entrega la trama, que es lo que importa.
func TestFieldOverrunStopsWithoutLosingTheFrame(t *testing.T) {
	frame := []byte{0x11, 0x22, 0x33}
	good := EncodeGPS(105, frame, 8.98, -79.51, 10)
	// Inflar la longitud del campo GPS sin tocar la de la cabecera.
	binary.LittleEndian.PutUint16(good[headerLen+2:headerLen+4], 60000)

	got, err := Parse(good)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if string(got.Payload) != string(frame) {
		t.Errorf("se perdió la trama: %x", got.Payload)
	}
	if got.Fix != nil {
		t.Errorf("se leyó una posición de un campo corrupto: %+v", got.Fix)
	}
}

// Un geotag con coordenadas fuera de rango se descarta: mejor "sin posición"
// que un punto imposible en un mapa.
func TestOutOfRangeCoordinatesAreDropped(t *testing.T) {
	data := EncodeGPS(105, []byte{1}, 8.98, -79.51, 10)
	// El campo de latitud empieza tras cabecera PPI + cabecera de campo +
	// cabecera del geotag + GPSFlags.
	latOff := headerLen + fieldHeaderLen + 8 + 4
	binary.LittleEndian.PutUint32(data[latOff:latOff+4], math.MaxUint32)

	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Fix != nil && got.Fix.Latitude != nil {
		t.Errorf("se aceptó una latitud imposible: %f", *got.Fix.Latitude)
	}
}

func TestLatitudeBetween90And180IsDropped(t *testing.T) {
	got, err := Parse(EncodeGPS(105, []byte{1}, 100, -79.51, 10))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Fix != nil && got.Fix.Latitude != nil {
		t.Errorf("se aceptó una latitud imposible: %f", *got.Fix.Latitude)
	}
	if got.Fix == nil || got.Fix.Longitude == nil {
		t.Error("descartar la latitud no debe perder una longitud válida")
	}
}

func TestHasPositionOnNilFix(t *testing.T) {
	var f *Fix
	if f.HasPosition() {
		t.Error("un Fix nil no tiene posición")
	}
	if (&Fix{}).HasPosition() {
		t.Error("un Fix vacío no tiene posición")
	}
}

// buildAligned arma un registro PPI con el bit de alineación puesto, un campo
// previo de longitud impar (con su relleno) y el geotag detrás. Es la forma que
// escriben las herramientas que anuncian alineación, y la que desincronizaba el
// recorrido de campos cuando el relleno se ignoraba.
func buildAligned(dlt uint32, frame []byte, lat, lon, alt float64, firstLen int) []byte {
	// Campo previo cualquiera (tipo 2 = Common Radio Info en la práctica; aquí
	// solo importa su longitud).
	first := make([]byte, 0, fieldHeaderLen+firstLen+3)
	first = binary.LittleEndian.AppendUint16(first, 2)
	first = binary.LittleEndian.AppendUint16(first, uint16(firstLen))
	first = append(first, make([]byte, firstLen)...)
	for len(first)%4 != 0 {
		first = append(first, 0) // relleno a 32 bits
	}

	// El geotag se reutiliza tal cual lo genera EncodeGPS, recortando su
	// cabecera PPI para quedarnos solo con el TLV.
	base := EncodeGPS(dlt, nil, lat, lon, alt)
	geo := base[headerLen:]

	total := headerLen + len(first) + len(geo)
	out := make([]byte, 0, total+len(frame))
	out = append(out, 0, flagAlign)
	out = binary.LittleEndian.AppendUint16(out, uint16(total))
	out = binary.LittleEndian.AppendUint32(out, dlt)
	out = append(out, first...)
	out = append(out, geo...)
	return append(out, frame...)
}

// Un campo de longitud no múltiplo de 4 delante del geotag: sin aplicar el
// relleno que anuncia pph_flags, el walk cae en medio del siguiente TLV y la
// posición se pierde en silencio.
func TestAlignedFieldsArePadded(t *testing.T) {
	frame := []byte{0x80, 0x00, 0xff}
	const lat, lon, alt = 8.9824, -79.5199, 15.0

	for _, firstLen := range []int{1, 2, 3, 5, 6, 7} {
		data := buildAligned(105, frame, lat, lon, alt, firstLen)
		got, err := Parse(data)
		if err != nil {
			t.Fatalf("firstLen=%d Parse: %v", firstLen, err)
		}
		if !got.Fix.HasPosition() {
			t.Errorf("firstLen=%d: se perdió la posición tras un campo sin alinear", firstLen)
			continue
		}
		if !closeTo(*got.Fix.Latitude, lat) || !closeTo(*got.Fix.Longitude, lon) {
			t.Errorf("firstLen=%d: posición = %f,%f", firstLen, *got.Fix.Latitude, *got.Fix.Longitude)
		}
		if !bytes.Equal(got.Payload, frame) {
			t.Errorf("firstLen=%d: payload = %x", firstLen, got.Payload)
		}
	}
}

// Sin el bit de alineación no se debe rellenar nada: hacerlo saltaría por
// encima de campos legítimos que empiezan en offsets impares.
func TestUnalignedRecordIsNotPadded(t *testing.T) {
	data := EncodeGPS(105, []byte{1, 2, 3}, 8.98, -79.51, 10)
	if data[1]&flagAlign != 0 {
		t.Fatal("EncodeGPS no debería anunciar alineación")
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !got.Fix.HasPosition() {
		t.Error("se perdió la posición en un registro sin alineación")
	}
}
