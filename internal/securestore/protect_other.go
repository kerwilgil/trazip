//go:build !windows && !darwin

package securestore

import "fmt"

func Protect([]byte) ([]byte, error) {
	return nil, fmt.Errorf("el almacenamiento seguro de credenciales aún no está disponible en esta plataforma")
}

func Unprotect([]byte) ([]byte, error) {
	return nil, fmt.Errorf("el almacenamiento seguro de credenciales aún no está disponible en esta plataforma")
}
