package securestore

// FileTier returns the file tier. It is always available. Its protector
// returns the DEK unchanged, so the key is only as safe as the permissions
// of the file it is stored in.
func FileTier() Tier {
	return Tier{
		Name:  TierFile,
		Probe: func() error { return nil },
		Open:  func(string) KeyProtector { return fileProtector{} },
	}
}

// fileProtector stores the DEK as is.
type fileProtector struct{}

func (fileProtector) Name() string { return TierFile }

// Wrap returns a copy of dek.
func (fileProtector) Wrap(dek []byte) ([]byte, error) {
	return append([]byte(nil), dek...), nil
}

// Unwrap returns a copy of wrapped.
func (fileProtector) Unwrap(wrapped []byte) ([]byte, error) {
	return append([]byte(nil), wrapped...), nil
}
