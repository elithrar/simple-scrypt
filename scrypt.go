// Package scrypt provides a convenience wrapper around Go's existing scrypt package
// that makes it easier to securely derive strong keys from weak
// inputs (i.e. user passwords).
// The package provides password generation, constant-time comparison and
// parameter upgrading for scrypt derived keys.
package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

// Constants
const (
	maxInt     = 1<<31 - 1
	minDKLen   = 16 // the minimum derived key length in bytes.
	minSaltLen = 8  // the minimum allowed salt length in bytes.
)

// Params describes the input parameters to the scrypt
// key derivation function as per Colin Percival's scrypt
// paper: http://www.tarsnap.com/scrypt/scrypt.pdf
type Params struct {
	N       int // CPU/memory cost parameter (logN)
	R       int // block size parameter (octets)
	P       int // parallelisation parameter (positive int)
	SaltLen int // bytes to use as salt (octets)
	DKLen   int // length of the derived key (octets)
}

// DefaultParams provides sensible default inputs into the scrypt function
// for interactive use (i.e. web applications).
// These defaults will consume approxmiately 16MB of memory (128 * r * N).
// The default key length is 256 bits.
var DefaultParams = Params{N: 16384, R: 8, P: 1, SaltLen: 16, DKLen: 32}

// ErrInvalidHash is returned when failing to parse a provided scrypt
// hash and/or parameters.
var ErrInvalidHash = errors.New("scrypt: the provided hash is not in the correct format")

// ErrInvalidParams is returned when the cost parameters (N, r, p), salt length
// or derived key length are invalid.
var ErrInvalidParams = errors.New("scrypt: the parameters provided are invalid")

// ErrMismatchedHashAndPassword is returned when a password (hashed) and
// given hash do not match.
var ErrMismatchedHashAndPassword = errors.New("scrypt: the hashed password does not match the hash of the given password")

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateFromPassword returns the derived key of the password using the
// parameters provided. The parameters are prepended to the derived key and
// separated by the "$" character (0x24).
// If the parameters provided are less than the minimum acceptable values,
// an error will be returned.
func GenerateFromPassword(password []byte, params Params) ([]byte, error) {
	salt, err := GenerateRandomBytes(params.SaltLen)
	if err != nil {
		return nil, err
	}

	if err := params.Check(); err != nil {
		return nil, err
	}

	// scrypt.Key returns the raw scrypt derived key.
	dk, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return nil, err
	}

	// Prepend the params and the salt to the derived key, each separated
	// by a "$" character. The salt and the derived key are hex encoded.
	return params.printKey(salt, dk), err
}

// CompareHashAndPassword compares a derived key with the possible cleartext
// equivalent. The parameters used in the provided derived key are used.
// The comparison performed by this function is constant-time. It returns nil
// on success, and an error if the derived keys do not match.
func CompareHashAndPassword(hash []byte, password []byte) error {
	// Decode existing hash, retrieve params and salt.
	params, salt, dk, err := decodeHash(hash)
	if err != nil {
		return err
	}

	// scrypt the cleartext password with the same parameters and salt
	other, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return err
	}

	// Constant time comparison
	if subtle.ConstantTimeCompare(dk, other) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

// Check checks that the parameters are valid for input into the
// scrypt key derivation function.
func (p *Params) Check() error {
	// Validate N
	if p.N > maxInt || p.N <= 1 || p.N%2 != 0 {
		return ErrInvalidParams
	}

	// Validate r
	if p.R < 1 || p.R > maxInt {
		return ErrInvalidParams
	}

	// Validate p
	if p.P < 1 || p.P > maxInt {
		return ErrInvalidParams
	}

	// Validate that r & p don't exceed 2^30 and that N, r, p values don't
	// exceed the limits defined by the scrypt algorithm.
	if uint64(p.R)*uint64(p.P) >= 1<<30 || p.R > maxInt/128/p.P || p.R > maxInt/256 || p.N > maxInt/128/p.R {
		return ErrInvalidParams
	}

	// Validate the salt length
	if p.SaltLen < minSaltLen || p.SaltLen > maxInt {
		return ErrInvalidParams
	}

	// Validate the derived key length
	if p.DKLen < minDKLen || p.DKLen > maxInt {
		return ErrInvalidParams
	}

	return nil
}

// decodeHash extracts the parameters, salt and derived key from the
// provided hash. It returns an error if the hash format is invalid and/or
// the parameters are invalid.
func decodeHash(hash []byte) (Params, []byte, []byte, error) {
	vals := strings.Split(string(hash), "$")

	// P, N, R, salt, scrypt derived key
	if len(vals) != 5 {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var params Params
	var err error

	params.N, err = strconv.Atoi(vals[0])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	params.R, err = strconv.Atoi(vals[1])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	params.P, err = strconv.Atoi(vals[2])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}

	salt, err := hex.DecodeString(vals[3])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.SaltLen = len(salt)

	dk, err := hex.DecodeString(vals[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.DKLen = len(dk)

	if err := params.Check(); err != nil {
		return params, nil, nil, err
	}

	return params, salt, dk, nil
}

// Cost returns the scrypt parameters used to generate the derived key. This
// allows a package user to increase the cost (in time & resources) used as
// computational performance increases over time.
func Cost(hash []byte) (Params, error) {
	params, _, _, err := decodeHash(hash)

	return params, err
}

func (p Params) printKey(salt, dk []byte) []byte {
	return []byte(fmt.Sprintf("%d$%d$%d$%x$%x", p.N, p.R, p.P, salt, dk))
}

func (p Params) generatePasswordWithLimit(password []byte, timeout time.Duration, memBytes int) ([]byte, Params, error) {
	if p.N == 0 || p.R == 0 || p.P == 0 || p.SaltLen == 0 || p.DKLen == 0 {
		p = DefaultParams
	} else if err := p.Check(); err != nil {
		return nil, p, err
	}

	deadline := time.Now().Add(timeout)
	salt, err := GenerateRandomBytes(p.SaltLen)
	if err != nil {
		return nil, p, err
	}

	var dur time.Duration
	var dk []byte
	lng := p
	p.N <<= 1
	now := time.Now()
	// memory = (128 * r * N).
	for actMem := 128 * p.N * p.R; (memBytes == 0 || actMem <= memBytes) &&
		(timeout == 0 || now.Add(dur).Before(deadline)); {
		//log.Printf("N=%d actMem=%d memBytes=%d", p.N, actMem, memBytes)
		start := now
		if dk, err = scrypt.Key(password, salt, p.N, p.R, p.P, p.DKLen); err != nil {
			return nil, lng, err
		}
		now = time.Now()
		dur = now.Sub(start)
		if err := p.Check(); err != nil {
			return lng.printKey(salt, dk), lng, nil // yes, no error
		}
		lng = p
		p.N <<= 1
		actMem <<= 1
	}

	return lng.printKey(salt, dk), lng, nil
}

// Harden the params within the given limits.
// Memory limit is in bytes, and zero means no limit.
func (p Params) Harden(timeout time.Duration, memBytes int) (Params, error) {
	_, p, err := p.generatePasswordWithLimit([]byte("password"), timeout, memBytes)
	return p, err
}

// Calibrate the system starting from DefaultParams, within the given limits.
func Calibrate(timeout time.Duration, memBytes int) (Params, error) {
	return DefaultParams.Harden(timeout, memBytes)
}

// GenerateFromPasswordWithLimit returns the derived key of the password using the
// parameters provided, just as GenerateFromPassword, but within the given limits.
//
// If params is zero (Params{}), then DefaultParams is used.
func GenerateFromPasswordWithLimit(
	password []byte, params Params,
	timeout time.Duration, memBytes int,
) ([]byte, error) {
	sdk, _, err := params.generatePasswordWithLimit(password, timeout, memBytes)
	return sdk, err
}
