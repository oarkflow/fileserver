package utils

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

var phoneRegex = regexp.MustCompile(`^[0-9]{10}$`)
var emailRegex = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)

func ValidatePhoneNumber(number string) bool {
	return phoneRegex.MatchString(number)
}

func ValidateEmailAddress(email string) bool {
	return emailRegex.MatchString(email)
}

func HumanSize(size int64) string {
	if size == 0 {
		return "0"
	}
	sizes := []string{"B", "K", "M", "G"}
	i := int(math.Floor(math.Log(float64(size)) / math.Log(1024)))
	return fmt.Sprintf("%.1f %s", float64(size)/math.Pow(1024, float64(i)), sizes[i])
}

var imageTypes = []string{".png", ".jpg", "jpeg", ".gif"}

func IsImage(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, imgType := range imageTypes {
		if ext == imgType {
			return true
		}
	}
	return false
}
