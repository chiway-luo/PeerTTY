package identitystate

import "os"

// Windows uses the account's directory ACL rather than POSIX mode bits.
func checkPermissions(_ string, _ os.FileInfo) error { return nil }
