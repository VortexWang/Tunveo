package master

// Windows file Sync is performed before publication. Directory fsync semantics
// are not portable here; power-loss durability of the directory is not claimed.
func syncStateDirectory(string) error { return nil }
