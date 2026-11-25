package localssh

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestLoginKeyDACLIsProtectedAndOwnedByCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "login.key")
	if _, err := NewLoginKey(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(user.User.Sid) {
		t.Fatal("ephemeral SSH key is not owned by the launching account")
	}
	control, _, err := sd.Control()
	dacl, _, daclErr := sd.DACL()
	if err != nil || daclErr != nil || control&windows.SE_DACL_PROTECTED == 0 || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("key must not inherit access from its directory: control=%x, errors=%v/%v", control, err, daclErr)
	}
}
