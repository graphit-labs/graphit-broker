package broker

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	passwordArgon2Memory       = 64 * 1024
	passwordArgon2Iterations   = 3
	passwordArgon2Parallelism  = 4
	passwordSaltLength         = 16
	passwordHashLength         = 32
	passwordPepperMinimumBytes = 32

	passwordArgon2MaxMemory      = 1024 * 1024
	passwordArgon2MaxIterations  = 10
	passwordArgon2MaxParallelism = 16
	passwordMaxBytes             = 4096
	localPasswordPepperDomain    = "graphit-broker/local-password/v1"
)

type passwordVerifier struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

// HashPassword creates a PHC-formatted Argon2id verifier bound to an external pepper. The caller
// must discard both sensitive inputs after this function returns and store only the verifier.
func HashPassword(password, pepper []byte) (string, error) {
	if len(password) == 0 {
		return "", errors.New("password must not be empty")
	}
	if len(password) > passwordMaxBytes {
		return "", fmt.Errorf("password must not exceed %d bytes", passwordMaxBytes)
	}
	peppered, err := pepperPassword(password, pepper)
	if err != nil {
		return "", err
	}
	defer clear(peppered)
	salt := make([]byte, passwordSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey(peppered, salt, passwordArgon2Iterations, passwordArgon2Memory, passwordArgon2Parallelism, passwordHashLength)
	defer clear(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		passwordArgon2Memory, passwordArgon2Iterations, passwordArgon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func parsePasswordVerifier(encoded string) (passwordVerifier, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return passwordVerifier{}, errors.New("must use the PHC Argon2id format")
	}
	version, err := parsePHCVersion(parts[2])
	if err != nil || version != argon2.Version {
		return passwordVerifier{}, fmt.Errorf("must use Argon2 version %d", argon2.Version)
	}
	memory, iterations, parallelism, err := parseArgon2Parameters(parts[3])
	if err != nil {
		return passwordVerifier{}, err
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < passwordSaltLength || len(salt) > 64 {
		return passwordVerifier{}, fmt.Errorf("salt must be valid unpadded base64 containing %d to 64 bytes", passwordSaltLength)
	}
	hash, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(hash) < passwordHashLength || len(hash) > 64 {
		return passwordVerifier{}, fmt.Errorf("hash must be valid unpadded base64 containing %d to 64 bytes", passwordHashLength)
	}
	return passwordVerifier{memory: memory, iterations: iterations, parallelism: parallelism, salt: salt, hash: hash}, nil
}

func parsePHCVersion(value string) (int, error) {
	if !strings.HasPrefix(value, "v=") {
		return 0, errors.New("missing Argon2 version")
	}
	return strconv.Atoi(strings.TrimPrefix(value, "v="))
}

func parseArgon2Parameters(value string) (uint32, uint32, uint8, error) {
	var memory, iterations uint64
	var parallelism uint64
	fields := strings.Split(value, ",")
	if len(fields) != 3 {
		return 0, 0, 0, errors.New("Argon2id parameters must contain m, t, and p")
	}
	seen := map[string]bool{}
	for _, field := range fields {
		pair := strings.SplitN(field, "=", 2)
		if len(pair) != 2 || seen[pair[0]] {
			return 0, 0, 0, errors.New("Argon2id parameters are invalid")
		}
		seen[pair[0]] = true
		parsed, err := strconv.ParseUint(pair[1], 10, 32)
		if err != nil {
			return 0, 0, 0, errors.New("Argon2id parameters must be decimal integers")
		}
		switch pair[0] {
		case "m":
			memory = parsed
		case "t":
			iterations = parsed
		case "p":
			parallelism = parsed
		default:
			return 0, 0, 0, fmt.Errorf("unsupported Argon2id parameter %q", pair[0])
		}
	}
	if memory < passwordArgon2Memory || memory > passwordArgon2MaxMemory {
		return 0, 0, 0, fmt.Errorf("Argon2id memory must be between %d and %d KiB", passwordArgon2Memory, passwordArgon2MaxMemory)
	}
	if iterations < passwordArgon2Iterations || iterations > passwordArgon2MaxIterations {
		return 0, 0, 0, fmt.Errorf("Argon2id iterations must be between %d and %d", passwordArgon2Iterations, passwordArgon2MaxIterations)
	}
	if parallelism < passwordArgon2Parallelism || parallelism > passwordArgon2MaxParallelism {
		return 0, 0, 0, fmt.Errorf("Argon2id parallelism must be between %d and %d", passwordArgon2Parallelism, passwordArgon2MaxParallelism)
	}
	return uint32(memory), uint32(iterations), uint8(parallelism), nil
}

func (v passwordVerifier) verify(password, pepper []byte) bool {
	if len(password) == 0 || len(password) > passwordMaxBytes {
		return false
	}
	peppered, err := pepperPassword(password, pepper)
	if err != nil {
		return false
	}
	defer clear(peppered)
	actual := argon2.IDKey(peppered, v.salt, v.iterations, v.memory, v.parallelism, uint32(len(v.hash)))
	defer clear(actual)
	return subtle.ConstantTimeCompare(actual, v.hash) == 1
}

func pepperPassword(password, pepper []byte) ([]byte, error) {
	if len(pepper) < passwordPepperMinimumBytes {
		return nil, fmt.Errorf("password pepper must contain at least %d bytes", passwordPepperMinimumBytes)
	}
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(localPasswordPepperDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(password)
	return mac.Sum(nil), nil
}
