//go:build !darwin && !windows && !linux

package browser

func systemPAC(string) (pacState, string, error) { return nil, "", errNoSystemPAC }

func setSystemPAC(string) error { return errNoSystemPAC }

func restoreSystemPAC(pacState, string) error { return errNoSystemPAC }

func systemPACIs(string) bool { return false }
