package localssh

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// POSIX mode bits cannot prevent inherited NTFS access. Create the key with a
// protected owner-only DACL before writing even its first byte.
func createLoginKeyFile(path string) (*os.File, error) {
	fail := func(err error) (*os.File, error) {
		return nil, &os.PathError{Op: "create private SSH key", Path: path, Err: err}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fail(err)
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;GA;;;" + sid + ")")
	if err != nil {
		return fail(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fail(err)
	}
	attrs := windows.SecurityAttributes{
		SecurityDescriptor: descriptor,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, &attrs,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fail(err)
	}
	return os.NewFile(uintptr(handle), path), nil
}
