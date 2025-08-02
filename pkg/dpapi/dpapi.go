//go:build windows
// +build windows

package dpapi

import (
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32           = syscall.NewLazyDLL("Crypt32.dll")
	kernel32          = syscall.NewLazyDLL("Kernel32.dll")
	procUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree     = kernel32.NewProc("LocalFree")
)

func Unprotect(data, entropy []byte, scope uint32) ([]byte, error) {
	inBlob := toBlob(data)

	var entropyBlob *dataBlob
	if len(entropy) > 0 {
		tmp := toBlob(entropy)
		entropyBlob = &tmp
	}

	var outBlob dataBlob
	r, _, err := procUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		uintptr(unsafe.Pointer(entropyBlob)),
		0,
		0,
		uintptr(scope),
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))

	return fromBlob(outBlob), nil
}

func toBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

func fromBlob(b dataBlob) []byte {
	return unsafe.Slice(b.pbData, b.cbData)
}
