package broker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Filesystem storage sessions are self-contained: the session token carries the authorization
// snapshot and is authenticated with a key derived from the broker's token pepper, and the
// secret key is derived from the token. Nothing about a session is stored, so any broker
// process holding the same pepper verifies it, and a session simply expires like an STS one.
const (
	filesystemSessionDomain   = "graphit-broker/filesystem-storage-session/v2"
	filesystemSecretDomain    = "graphit-broker/filesystem-storage-secret/v1"
	filesystemSessionVersion  = 2
	filesystemAccessKeyPrefix = "GRAPHIT"
)

var (
	errStorageSessionInvalid = errors.New("the security token is not valid")
	errStorageSessionExpired = errors.New("the security token has expired")
)

// filesystemStorageSession is the authorization snapshot one credential set carries. Access
// maps a grant operation to the complete object prefixes it covers, base prefix included.
type filesystemStorageSession struct {
	Version     int                 `json:"v"`
	AccessKeyID string              `json:"akid"`
	Bucket      string              `json:"bkt"`
	Region      string              `json:"rgn"`
	Subject     string              `json:"sub"`
	Scope       string              `json:"scp"`
	ProjectID   string              `json:"prj,omitempty"`
	Module      string              `json:"mod"`
	Revision    string              `json:"rev"`
	IssuedAt    int64               `json:"iat"`
	ExpiresAt   int64               `json:"exp"`
	Access      map[string][]string `json:"acc"`
}

// FilesystemCredentialService mints the credentials that reach this broker's own storage
// gateway. It is the filesystem driver's answer to STS.
type FilesystemCredentialService struct {
	now    func() time.Time
	key    [32]byte
	secret [32]byte
}

func NewFilesystemCredentialService(pepper string) *FilesystemCredentialService {
	return &FilesystemCredentialService{now: time.Now,
		key:    deriveOIDCKey(pepper, filesystemSessionDomain),
		secret: deriveOIDCKey(pepper, filesystemSecretDomain)}
}

func (s *FilesystemCredentialService) Issue(_ context.Context, route S3RouteConfig, grant S3SessionGrant, principal Principal) (S3CredentialsResponse, error) {
	access := map[string][]string{}
	for operation, prefixes := range grant.Access {
		for _, prefix := range prefixes {
			access[operation] = append(access[operation], joinPrefix(route.BasePrefix, prefix))
		}
		sort.Strings(access[operation])
	}
	if len(access) == 0 {
		return S3CredentialsResponse{}, ErrForbidden
	}
	accessKeyID, err := newStorageAccessKeyID()
	if err != nil {
		return S3CredentialsResponse{}, err
	}
	now := s.now().UTC()
	expires := now.Add(route.SessionDuration)
	session := filesystemStorageSession{Version: filesystemSessionVersion, AccessKeyID: accessKeyID,
		Bucket: route.Bucket, Region: route.Region, Subject: principal.CanonicalSubject(),
		Scope: grant.Scope.Kind, ProjectID: grant.Scope.ProjectID, Module: grant.Scope.Module, Revision: grant.Revision,
		IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), Access: access}
	token, signature, err := s.encodeSession(session)
	if err != nil {
		return S3CredentialsResponse{}, err
	}
	return S3CredentialsResponse{
		AccessKeyID:           accessKeyID,
		SecretAccessKey:       s.sessionSecret(accessKeyID, signature),
		SessionToken:          token,
		ExpiresAt:             expires,
		Bucket:                route.Bucket,
		Region:                route.Region,
		Endpoint:              route.Endpoint,
		Prefixes:              []string{strings.Trim(route.BasePrefix, "/")},
		AuthorizationRevision: grant.Revision,
		Scope:                 grant.Scope.Kind,
		ProjectID:             grant.Scope.ProjectID,
		Module:                grant.Scope.Module,
	}, nil
}

func (s *FilesystemCredentialService) encodeSession(session filesystemStorageSession) (string, string, error) {
	raw, err := json.Marshal(session)
	if err != nil {
		return "", "", fmt.Errorf("encode storage session: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	signature := base64.RawURLEncoding.EncodeToString(sigV4Sign(s.key[:], payload))
	return payload + "." + signature, signature, nil
}

// Authenticate verifies one presented session token and returns what it authorizes.
func (s *FilesystemCredentialService) Authenticate(token, accessKeyID string, now time.Time) (filesystemStorageSession, string, error) {
	payload, signature, found := strings.Cut(token, ".")
	if !found || payload == "" || signature == "" {
		return filesystemStorageSession{}, "", errStorageSessionInvalid
	}
	expected := base64.RawURLEncoding.EncodeToString(sigV4Sign(s.key[:], payload))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return filesystemStorageSession{}, "", errStorageSessionInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return filesystemStorageSession{}, "", errStorageSessionInvalid
	}
	var session filesystemStorageSession
	if err := json.Unmarshal(raw, &session); err != nil || session.Version != filesystemSessionVersion {
		return filesystemStorageSession{}, "", errStorageSessionInvalid
	}
	if session.AccessKeyID != accessKeyID {
		return filesystemStorageSession{}, "", errStorageSessionInvalid
	}
	if now.UTC().Unix() >= session.ExpiresAt {
		return filesystemStorageSession{}, "", errStorageSessionExpired
	}
	return session, s.sessionSecret(session.AccessKeyID, signature), nil
}

// sessionSecret binds the signing secret to both the key id and the signed session, so a
// credential cannot be moved onto another session.
func (s *FilesystemCredentialService) sessionSecret(accessKeyID, signature string) string {
	mac := hmac.New(sha256.New, s.secret[:])
	_, _ = mac.Write([]byte(accessKeyID + "\x00" + signature))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func newStorageAccessKeyID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate storage access key: %w", err)
	}
	return filesystemAccessKeyPrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// storageOperation is what one gateway request needs to be allowed to do.
type storageOperation string

const (
	storageOperationGet    storageOperation = "get"
	storageOperationList   storageOperation = "list"
	storageOperationPut    storageOperation = "put"
	storageOperationDelete storageOperation = "delete"
)

// grantOperations maps a gateway operation onto the grant operations that confer it. It
// mirrors the STS session policy exactly: read, write, and publish all read; write and publish
// write; publish and delete remove.
var grantOperations = map[storageOperation][]string{
	storageOperationGet:    {"read", "write", "publish"},
	storageOperationList:   {"read", "write", "publish"},
	storageOperationPut:    {"write", "publish"},
	storageOperationDelete: {"publish", "delete"},
}

// Allows reports whether the session may perform operation on key. The prefix comparison is the
// same one the STS policy expresses as a resource of `prefix` plus `prefix/*`.
func (s filesystemStorageSession) Allows(operation storageOperation, key string) bool {
	for _, granted := range grantOperations[operation] {
		for _, prefix := range s.Access[granted] {
			if key == prefix || strings.HasPrefix(key, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// AllowsListing reports whether a listing may see keys under prefix, matching the `s3:prefix`
// condition the STS policy attaches to ListBucket.
func (s filesystemStorageSession) AllowsListing(prefix string) bool {
	for _, granted := range grantOperations[storageOperationList] {
		for _, allowed := range s.Access[granted] {
			if prefix == allowed || strings.HasPrefix(prefix, allowed+"/") {
				return true
			}
		}
	}
	return false
}
