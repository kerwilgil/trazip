// Package phoneintel identifies what a phone number is, entirely offline.
//
// It answers the questions that matter when a number shows up in a VoIP trace,
// a CDR or a client's complaint: is it valid at all, what country and carrier
// does it belong to, and — the one that changes how a call is routed and
// billed — is it a mobile, a landline or a VoIP number.
//
// The metadata comes compiled into the binary via libphonenumber (the same
// dataset Android uses to format numbers), so a lookup sends nothing anywhere.
// That is a deliberate choice over the online lookup services that do this:
// a phone number is personal data, and the ones being checked here are
// typically a client's or a caller's, not the operator's own.
package phoneintel

import (
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// DefaultRegion is the region assumed for numbers written without a country
// code. Panama, because that is where a locally-dialled number without "+507"
// comes from in this operator's daily work; anything starting with "+" ignores
// it entirely.
const DefaultRegion = "PA"

// Result is what a number turned out to be.
type Result struct {
	Input string `json:"input"`
	Valid bool   `json:"valid"`

	// E164 is the canonical form ("+50761234567") — the one to store and
	// compare with, since the same number can be written many ways.
	E164          string `json:"e164,omitempty"`
	International string `json:"international,omitempty"`
	National      string `json:"national,omitempty"`
	RFC3966       string `json:"rfc3966,omitempty"` // tel: URI, the form SIP headers carry

	CountryCode int `json:"countryCode,omitempty"` // 507, 1, 34...

	// Region is the ISO 3166-1 alpha-2 code and not a country name on purpose:
	// the view resolves it with Intl.DisplayNames in the active language, so
	// there is no table of ~250 country names to carry and translate here.
	Region string `json:"region,omitempty"`
	Area   string `json:"area,omitempty"` // descripción geográfica si la hay

	// Kind is the line type, and the field with the most operational weight:
	// it decides interconnection cost, whether SMS will arrive, and whether a
	// "mobile" in a client's list is actually a VoIP DID.
	Kind     string `json:"kind"`
	KindNote string `json:"kindNote,omitempty"`

	Carrier string `json:"carrier,omitempty"`
	// CarrierNote rides with Carrier instead of going into Notes: it applies
	// every single time there is a carrier, and a caveat that is always true
	// would take the prominent slot on screen permanently.
	CarrierNote string   `json:"carrierNote,omitempty"`
	Timezones   []string `json:"timezones"`

	Notes []string `json:"notes"`
	Err   string   `json:"err,omitempty"`
}

// kindInfo maps libphonenumber's type to a label and an explanation of what it
// means in practice, which is the part an operator actually acts on.
func kindInfo(t phonenumbers.PhoneNumberType) (string, string) {
	switch t {
	case phonenumbers.MOBILE:
		return "móvil", "acepta SMS y llamadas; tarifa de interconexión móvil"
	case phonenumbers.FIXED_LINE:
		return "fijo", "línea fija: normalmente no recibe SMS"
	case phonenumbers.FIXED_LINE_OR_MOBILE:
		return "fijo o móvil", "el plan de numeración del país no distingue ambos en este rango"
	case phonenumbers.TOLL_FREE:
		return "gratuito", "lo paga el destinatario; suele rechazar llamadas desde el extranjero"
	case phonenumbers.PREMIUM_RATE:
		return "tarifa premium", "coste elevado por minuto para quien llama — verificar antes de marcar"
	case phonenumbers.SHARED_COST:
		return "coste compartido", "tarifa repartida entre quien llama y quien recibe"
	case phonenumbers.VOIP:
		return "VoIP", "número asignado a un servicio de voz sobre IP, no a una línea de operador tradicional"
	case phonenumbers.PERSONAL_NUMBER:
		return "personal", "número personal que redirige a otros destinos"
	case phonenumbers.PAGER:
		return "buscapersonas", ""
	case phonenumbers.UAN:
		return "UAN", "número único de acceso corporativo, independiente de la ubicación"
	case phonenumbers.VOICEMAIL:
		return "buzón de voz", ""
	default:
		return "desconocido", "el rango existe pero el plan de numeración no dice de qué tipo es"
	}
}

// Analyze parses and classifies a number. region is an ISO 3166-1 alpha-2 code
// used only for numbers written without "+"; empty means DefaultRegion.
func Analyze(input, region string) Result {
	in := strings.TrimSpace(input)
	res := Result{Input: in, Timezones: []string{}, Notes: []string{}}
	if in == "" {
		res.Err = "número vacío"
		return res
	}
	if region == "" {
		region = DefaultRegion
	}

	num, err := phonenumbers.Parse(in, region)
	if err != nil {
		res.Err = "no se pudo interpretar como número: " + err.Error()
		if !strings.HasPrefix(in, "+") {
			res.Notes = append(res.Notes,
				"sin prefijo internacional se asume "+region+"; escribí el número con \"+\" y su código de país para evitar la suposición")
		}
		return res
	}

	res.CountryCode = int(num.GetCountryCode())
	res.Region = phonenumbers.GetRegionCodeForNumber(num)
	res.E164 = phonenumbers.Format(num, phonenumbers.E164)
	res.International = phonenumbers.Format(num, phonenumbers.INTERNATIONAL)
	res.National = phonenumbers.Format(num, phonenumbers.NATIONAL)
	res.RFC3966 = phonenumbers.Format(num, phonenumbers.RFC3966)

	res.Valid = phonenumbers.IsValidNumber(num)
	res.Kind, res.KindNote = kindInfo(phonenumbers.GetNumberType(num))

	if c, cerr := phonenumbers.GetCarrierForNumber(num, "es"); cerr == nil && c != "" {
		res.Carrier = c
	}
	if a, aerr := phonenumbers.GetGeocodingForNumber(num, "es"); aerr == nil && a != "" {
		res.Area = a
	}
	if tz, terr := phonenumbers.GetTimezonesForNumber(num); terr == nil {
		res.Timezones = append(res.Timezones, tz...)
	}

	if !res.Valid {
		// Distinguir "el formato cuadra" de "el número existe en el plan" evita
		// que alguien descarte un número por un dígito de más o de menos.
		if phonenumbers.IsPossibleNumber(num) {
			res.Notes = append(res.Notes,
				"la longitud es plausible pero el número no cae en ningún rango asignado del país: probablemente esté mal transcrito")
		} else {
			res.Notes = append(res.Notes,
				"la longitud no corresponde a ningún rango del país indicado")
		}
	}
	// El operador que trae libphonenumber es el de la asignación original: la
	// portabilidad numérica no se refleja en ninguna base offline.
	if res.Carrier != "" {
		res.CarrierNote = "asignación original del rango; si el número fue portado, el operador actual puede ser otro"
	}
	return res
}
