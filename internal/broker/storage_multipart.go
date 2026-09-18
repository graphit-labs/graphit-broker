package broker

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Multipart upload is not an optimization here: a client that cannot buffer a whole object
// starts one for anything past its own threshold — LanceDB does so above 5 MiB — so a store
// without it cannot hold a dataset. Parts are staged as separate files under one upload
// directory and concatenated once the client says the upload is complete.
const (
	filesystemUploadDirectory = "uploads"
	uploadManifestFile        = "upload.json"
	maximumUploadParts        = 10000
	abandonedUploadLifetime   = 24 * time.Hour
)

var (
	errStorageNoSuchUpload = errors.New("the upload does not exist")
	errStorageInvalidPart  = errors.New("a part is missing or does not match its ETag")
)

var uploadIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// uploadManifest records what an upload is for, so a part or a completion cannot be redirected
// onto another key by reusing its identifier.
type uploadManifest struct {
	Key         string    `json:"key"`
	ContentType string    `json:"content_type"`
	Created     time.Time `json:"created"`
}

type uploadedPart struct {
	Number   int
	ETag     string
	Size     int64
	Modified time.Time
}

func (s *filesystemStore) uploadPath(uploadID string, elements ...string) string {
	parts := append([]string{s.root, filesystemUploadDirectory, uploadID}, elements...)
	return filepath.Join(parts...)
}

func partFileName(number int) string { return fmt.Sprintf("part-%05d", number) }

// CreateUpload opens an upload and returns its identifier.
func (s *filesystemStore) CreateUpload(key, contentType string) (string, error) {
	if err := validateObjectKey(key); err != nil {
		return "", err
	}
	s.pruneAbandonedUploads()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate upload identifier: %w", err)
	}
	uploadID := hex.EncodeToString(raw)
	if err := os.MkdirAll(s.uploadPath(uploadID), 0o700); err != nil {
		return "", fmt.Errorf("open upload for %s: %w", key, err)
	}
	if contentType == "" {
		contentType = contentTypeForKey(key)
	}
	manifest, err := json.Marshal(uploadManifest{Key: key, ContentType: contentType, Created: time.Now().UTC()})
	if err != nil {
		return "", fmt.Errorf("encode upload manifest for %s: %w", key, err)
	}
	if err := os.WriteFile(s.uploadPath(uploadID, uploadManifestFile), manifest, 0o600); err != nil {
		return "", fmt.Errorf("open upload for %s: %w", key, err)
	}
	return uploadID, nil
}

// upload reads one open upload, confirming it belongs to the key the request names.
func (s *filesystemStore) upload(uploadID, key string) (uploadManifest, error) {
	if !uploadIDPattern.MatchString(uploadID) {
		return uploadManifest{}, errStorageNoSuchUpload
	}
	raw, err := os.ReadFile(s.uploadPath(uploadID, uploadManifestFile))
	if err != nil {
		return uploadManifest{}, errStorageNoSuchUpload
	}
	var manifest uploadManifest
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.Key != key {
		return uploadManifest{}, errStorageNoSuchUpload
	}
	return manifest, nil
}

// UploadPart stores one part and returns its ETag, which the completion must quote back.
func (s *filesystemStore) UploadPart(uploadID, key string, number int, body io.Reader) (string, error) {
	if _, err := s.upload(uploadID, key); err != nil {
		return "", err
	}
	if number < 1 || number > maximumUploadParts {
		return "", errStorageInvalidPart
	}
	staged, err := s.stage()
	if err != nil {
		return "", err
	}
	defer os.Remove(staged.Name())
	digest := md5.New()
	size, err := io.Copy(io.MultiWriter(staged, digest), io.LimitReader(body, s.maxObjectBytes+1))
	if err != nil {
		staged.Close()
		return "", fmt.Errorf("receive part %d of %s: %w", number, key, err)
	}
	if size > s.maxObjectBytes {
		staged.Close()
		return "", errStorageTooLarge
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return "", fmt.Errorf("persist part %d of %s: %w", number, key, err)
	}
	if err := staged.Close(); err != nil {
		return "", fmt.Errorf("persist part %d of %s: %w", number, key, err)
	}
	if err := os.Rename(staged.Name(), s.uploadPath(uploadID, partFileName(number))); err != nil {
		return "", fmt.Errorf("commit part %d of %s: %w", number, key, err)
	}
	return quotedETag(digest.Sum(nil)), nil
}

// ListUploadParts reports the parts received so far, in part order.
func (s *filesystemStore) ListUploadParts(uploadID, key string) ([]uploadedPart, error) {
	if _, err := s.upload(uploadID, key); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.uploadPath(uploadID))
	if err != nil {
		return nil, errStorageNoSuchUpload
	}
	parts := make([]uploadedPart, 0, len(entries))
	for _, entry := range entries {
		number, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "part-"))
		if err != nil || !strings.HasPrefix(entry.Name(), "part-") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		etag, err := s.partETag(uploadID, number)
		if err != nil {
			return nil, err
		}
		parts = append(parts, uploadedPart{Number: number, ETag: etag, Size: info.Size(), Modified: info.ModTime()})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Number < parts[j].Number })
	return parts, nil
}

func (s *filesystemStore) partETag(uploadID string, number int) (string, error) {
	file, err := os.Open(s.uploadPath(uploadID, partFileName(number)))
	if err != nil {
		return "", errStorageInvalidPart
	}
	defer file.Close()
	digest := md5.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("digest part %d: %w", number, err)
	}
	return quotedETag(digest.Sum(nil)), nil
}

// completedPart is one entry of the client's completion request.
type completedPart struct {
	Number int
	ETag   string
}

// CompleteUpload concatenates the named parts, in the order the client lists them, into the
// object. The parts are verified against the ETags this store issued, so a part lost or
// truncated in transit fails the upload instead of producing a corrupt object.
func (s *filesystemStore) CompleteUpload(uploadID, key string, parts []completedPart, conditions putConditions) (storageObject, error) {
	manifest, err := s.upload(uploadID, key)
	if err != nil {
		return storageObject{}, err
	}
	if len(parts) == 0 {
		return storageObject{}, errStorageInvalidPart
	}
	for i := 1; i < len(parts); i++ {
		if parts[i].Number <= parts[i-1].Number {
			return storageObject{}, errStorageInvalidPart
		}
	}
	staged, err := s.stage()
	if err != nil {
		return storageObject{}, err
	}
	defer os.Remove(staged.Name())
	digest := md5.New()
	var size int64
	for _, part := range parts {
		etag, err := s.partETag(uploadID, part.Number)
		if err != nil {
			staged.Close()
			return storageObject{}, err
		}
		if part.ETag != "" && !etagMatches(part.ETag, etag) {
			staged.Close()
			return storageObject{}, errStorageInvalidPart
		}
		file, err := os.Open(s.uploadPath(uploadID, partFileName(part.Number)))
		if err != nil {
			staged.Close()
			return storageObject{}, errStorageInvalidPart
		}
		written, err := io.Copy(io.MultiWriter(staged, digest), file)
		file.Close()
		if err != nil {
			staged.Close()
			return storageObject{}, fmt.Errorf("assemble %s: %w", key, err)
		}
		size += written
		if size > s.maxObjectBytes {
			staged.Close()
			return storageObject{}, errStorageTooLarge
		}
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return storageObject{}, fmt.Errorf("persist %s: %w", key, err)
	}
	if err := staged.Close(); err != nil {
		return storageObject{}, fmt.Errorf("persist %s: %w", key, err)
	}
	// The ETag is the digest of the assembled object rather than S3's digest-of-digests, so it
	// stays the same value this store would compute for the object by reading it back.
	object, err := s.commit(key, staged.Name(), objectMetadata{ETag: quotedETag(digest.Sum(nil)),
		ContentType: manifest.ContentType, Size: size}, conditions)
	if err != nil {
		return storageObject{}, err
	}
	_ = os.RemoveAll(s.uploadPath(uploadID))
	return object, nil
}

// AbortUpload discards an open upload and everything staged for it.
func (s *filesystemStore) AbortUpload(uploadID, key string) error {
	if _, err := s.upload(uploadID, key); err != nil {
		return err
	}
	if err := os.RemoveAll(s.uploadPath(uploadID)); err != nil {
		return fmt.Errorf("abort upload of %s: %w", key, err)
	}
	return nil
}

// pruneAbandonedUploads drops uploads a client never completed or aborted, which otherwise hold
// their parts on the volume forever.
//
// It runs at startup and whenever an upload begins rather than on a timer: there is no clock to
// keep, nothing to shut down, and an upload's directory mtime advances with every part it
// receives, so an upload still being written is never old enough to collect.
func (s *filesystemStore) pruneAbandonedUploads() {
	entries, err := os.ReadDir(filepath.Join(s.root, filesystemUploadDirectory))
	if err != nil {
		return
	}
	deadline := time.Now().Add(-abandonedUploadLifetime)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.ModTime().After(deadline) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(s.root, filesystemUploadDirectory, entry.Name()))
	}
}

// Copy duplicates one object inside the bucket. S3 clients use it to move an object without
// sending its bytes twice, which is how a rename reaches an object store.
func (s *filesystemStore) Copy(sourceKey, destinationKey string, conditions putConditions) (storageObject, error) {
	if err := validateObjectKey(sourceKey); err != nil {
		return storageObject{}, err
	}
	if err := validateObjectKey(destinationKey); err != nil {
		return storageObject{}, err
	}
	source, object, err := s.Get(sourceKey)
	if err != nil {
		return storageObject{}, err
	}
	defer source.Close()
	staged, err := s.stage()
	if err != nil {
		return storageObject{}, err
	}
	defer os.Remove(staged.Name())
	if _, err := io.Copy(staged, source); err != nil {
		staged.Close()
		return storageObject{}, fmt.Errorf("copy %s: %w", sourceKey, err)
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return storageObject{}, fmt.Errorf("persist %s: %w", destinationKey, err)
	}
	if err := staged.Close(); err != nil {
		return storageObject{}, fmt.Errorf("persist %s: %w", destinationKey, err)
	}
	return s.commit(destinationKey, staged.Name(), objectMetadata{ETag: object.ETag,
		ContentType: object.ContentType, Size: object.Size}, conditions)
}
