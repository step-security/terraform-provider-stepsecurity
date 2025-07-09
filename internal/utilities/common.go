package utilities

func ConvertBoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ConvertStringToBool(s string) bool {
	return s == "true"
}
