//go:build windows

package securestore

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptprotectUIForbidden = 0x1

func blob(data []byte) windows.DataBlob {
	b := windows.DataBlob{Size: uint32(len(data))}
	if len(data) > 0 {
		b.Data = &data[0]
	}
	return b
}

func Protect(plain []byte) ([]byte, error) {
	in := blob(plain)
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, cryptprotectUIForbidden, &out); err != nil {
		return nil, fmt.Errorf("DPAPI ProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func Unprotect(cipher []byte) ([]byte, error) {
	in := blob(cipher)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, cryptprotectUIForbidden, &out); err != nil {
		return nil, fmt.Errorf("DPAPI UnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
