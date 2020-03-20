package regexplib

import (
	"errors"
	"regexp"
	"strconv"
)

var (

	// WholeNumbers matches whole numbers
	WholeNumbers = regexp.MustCompile(`/^\d+$/`)
	// DecimalNumbers matches decimaal numbers
	DecimalNumbers = regexp.MustCompile(`/^\d+$/`)
	// WholeAndDecimalNumbers matches whole and decimal numbers
	WholeAndDecimalNumbers = regexp.MustCompile(`/^\d*(\.\d+)?$/`)
	// NegativePositiveWholeAndDecimal matches both negative and positive whole and decimal numbers
	NegativePositiveWholeAndDecimal = regexp.MustCompile(`/^-?\d*(\.\d+)?$/`)
	// WholeAndDecimalAndFraction matches whole numbers, decimal numbers, and fractions
	WholeAndDecimalAndFraction = regexp.MustCompile(`/[-]?[0-9]+[,.]?[0-9]*([\/][0-9]+[,.]?[0-9]*)*/`)

	// AlphaNumericNoSpace matches alphanumeric characters
	AlphaNumericNoSpace = regexp.MustCompile(`/^[a-zA-Z0-9]*$/`)
	// AlphaNumericWithSpace matches alphanumeric characters and space
	AlphaNumericWithSpace = regexp.MustCompile(`/^[a-zA-Z0-9 ]*$/`)

	// SimpleEmail matches common emails
	SimpleEmail = regexp.MustCompile(`/^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$/`)
	// Email matches emails including uncommon emails
	Email = regexp.MustCompile(`/^([a-z0-9_\.\+-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/`)

	// ComplexPassword matches passwords.
	// Should have 1 lowercase letter, 1 uppercase letter, 1 number, 1 special character and be at least 8 characters long
	ComplexPassword = regexp.MustCompile("/(?=(.*[0-9]))(?=.*[\\!@#$%^&*()\\[\\]{}\\-_+=~`|:;\"'<>,./?])(?=.*[a-z])(?=(.*[A-Z]))(?=(.*)).{8,}/")

	// ModeratePassword matches passwords.
	// Should have 1 lowercase letter, 1 uppercase letter, 1 number, and be at least 8 characters long
	ModeratePassword = regexp.MustCompile(`/(?=(.*[0-9]))((?=.*[A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z]))^.{8,}$/`)

	// Username matches any alphanumeric string including _ and - between 3 and 16 characters
	Username = regexp.MustCompile(`/^[a-z0-9_-]{3,16}$/`)

	// IPv4Address matches IPv4 addresses
	IPv4Address = regexp.MustCompile(`/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/`)
	// IPv6Address matches IPv6 addresses
	IPv6Address = regexp.MustCompile(`/(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/`)
	// IPv4AndIPv6Addresses matches both IPv4 and IPv6 addresses
	IPv4AndIPv6Addresses = regexp.MustCompile(`/((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/`)

	// HTMLTagsWithAttrs matches HTML tags with attributes
	HTMLTagsWithAttrs = regexp.MustCompile(`/<\/?[\w\s]*>|<.+[\W]>/`)
	// InlineJS matches inline javascript
	InlineJS = regexp.MustCompile(`/\bon\w+=\S+(?=.*>)/`)
	// InlineJSWithElem matches an element containing inline JS
	InlineJSWithElem = regexp.MustCompile(`/(?:<[^>]+\s)(on\S+)=["']?((?:.(?!["']?\s+(?:\S+)=|[>"']))+.)["']?/`)

	// Slug matches strings with >=1 hyphen in the middle of the string
	Slug = regexp.MustCompile(`/^[a-z0-9]+(?:-[a-z0-9]+)*$/`)

	// Duplicates matches duplicates in a string
	Duplicates = regexp.MustCompile(`/(\b\w+\b)(?=.*\b\1\b)/`)

	// InternationalPhoneNumbers matches international phone numbers.
	// Lots of false positives!
	InternationalPhoneNumbers = regexp.MustCompile(`/^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$/`)

	// FilepathWithNameAndExt matches a filepath containing a filename and its extension
	FilepathWithNameAndExt = regexp.MustCompile(`/((\/|\\|\/\/|https?:\\\\|https?:\/\/)[a-z0-9 _@\-^!#$%&+={}.\/\\\[\]]+)+\.[a-z]+$/`)
	// FilepathOptNameAndExt matches filepaths with filename and extension optional
	FilepathOptNameAndExt = regexp.MustCompile(`/^(.+)/([^/]+)$/`)
	// Filepath3CharExt matches filepaths with 3 character extensions
	Filepath3CharExt = regexp.MustCompile(`/^[\w,\s-]+\.[A-Za-z]{3}$/`)

	// SimpleZipCode matches zip codes worldwide. Lots of false positives!
	SimpleZipCode = regexp.MustCompile(`(?i)^[a-z0-9][a-z0-9\- ]{0,10}[a-z0-9]$`)

	// CreditCardNumber matches Visa, Discover, Mastercard, AmEx, Diners Club, and JCB cards
	// Strip spaces and special characters before checking
	CreditCardNumber = regexp.MustCompile(`^(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})$`)
	// SimpleCreditCardNumber matches generic credit card number formats
	SimpleCreditCardNumber = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)

	// SocialSecurityNumber matches social security numbers
	SocialSecurityNumber = regexp.MustCompile(`/^((?!219-09-9999|078-05-1120)(?!666|000|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4})|((?!219 09 9999|078 05 1120)(?!666|000|9\d{2})\d{3} (?!00)\d{2} (?!0{4})\d{4})|((?!219099999|078051120)(?!666|000|9\d{2})\d{3}(?!00)\d{2}(?!0{4})\d{4})$/`)

	// Passport matches passport numbers
	Passport = regexp.MustCompile(`/^[A-PR-WY][1-9]\d\s?\d{4}[1-9]$/`)

	// Hexadecimal matches strings of hex digits
	Hexadecimal = regexp.MustCompile(`/^#?([a-f0-9]{6}|[a-f0-9]{3})$/`)

	// URL matches all types of URLs
	// Failure case: https://foo_bar.example.com/ (false positive) All others check out
	// @diegoperini https://mathiasbynens.be/demo/url-regex
	URL = regexp.MustCompile(`_^(?:(?:https?|ftp)://)(?:\S+(?::\S*)?@)?(?:(?!10(?:\.\d{1,3}){3})(?!127(?:\.\d{1,3}){3})(?!169\.254(?:\.\d{1,3}){2})(?!192\.168(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\x{00a1}-\x{ffff}0-9]+-?)*[a-z\x{00a1}-\x{ffff}0-9]+)(?:\.(?:[a-z\x{00a1}-\x{ffff}0-9]+-?)*[a-z\x{00a1}-\x{ffff}0-9]+)*(?:\.(?:[a-z\x{00a1}-\x{ffff}]{2,})))(?::\d{2,5})?(?:/[^\s]*)?$_iuS`)
)

// ValidateCreditCard uses the Luhn algorithm
// Wikipedia's pseudocode rewritten in Go
// Regex match at the beginning to reject non-valid numbers before Luhn
func ValidateCreditCard(cc string) (valid bool, err error) {
	if !CreditCardNumber.MatchString(cc) {
		return false, errors.New("Not a valid CC number")
	}
	sum, err := strconv.ParseInt(string(cc[len(cc)-1]), 10, 64)
	if err != nil {
		return false, err
	}
	digits := len(cc)
	parity := digits % 2
	for i := 0; i < digits/2; i++ {
		digit, err := strconv.ParseInt(string(cc[i]), 10, 64)
		if err != nil {
			return false, err
		}
		if i%2 == parity {
			digit *= 2
		}
		if digit > 9 {
			digit = digit - 9
		}
		sum += digit
	}
	return sum%10 == 0, nil
}
