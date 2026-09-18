package broker

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The filesystem driver keeps Hub objects on a mounted volume and serves them through this
// broker's own S3-compatible gateway. Object bytes, their metadata, and in-flight uploads live
// in separate trees so a listing never sees anything but real objects.
const (
	defaultFilesystemMaxObjectBytes = 5 << 30
	filesystemDataDirectory         = "data"
	filesystemMetaDirectory         = "meta"
	filesystemTempDirectory         = "tmp"
	filesystemMetaSuffix            = ".json"
	maximumObjectKeyBytes           = 1024
)

var (
	errStorageNotFound     = errors.New("the specified key does not exist")
	errStoragePrecondition = errors.New("at least one precondition did not hold")
	errStorageTooLarge     = errors.New("the object exceeds the configured maximum size")
	errStorageBadDigest    = errors.New("the payload does not match the declared digest")
	errStorageInvalidKey   = errors.New("the object key is not storable")
)

// Bucket names follow the DNS-style S3 rules because the gateway serves each bucket at its own
// root path, which is what an S3 client addresses in path style.
var storageBucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// reservedStoragePathSegments are the first path segments this broker already answers on. A
// bucket served at the root must not shadow one of them.
var reservedStoragePathSegments = map[string]struct{}{
	"admin": {}, "healthz": {}, "readyz": {}, "oauth": {}, "v1": {}, "favicon.svg": {},
	".well-known": {}, "metrics": {}, "api": {},
}

func validateStorageBucketName(bucket string) error {
	if !storageBucketNamePattern.MatchString(bucket) || strings.Contains(bucket, "..") {
		return errors.New("must be 3 to 63 characters of lowercase letters, digits, dots, and hyphens, starting and ending alphanumerically")
	}
	if _, reserved := reservedStoragePathSegments[bucket]; reserved {
		return fmt.Errorf("%q is a reserved broker path", bucket)
	}
	return nil
}

// storageObject is one stored object as the gateway reports it.
type storageObject struct {
	Key         string
	Size        int64
	ETag        string
	ContentType string
	Modified    time.Time
}

// objectMetadata is the sidecar written next to every object. The recorded size and
// modification time let a stale sidecar be detected when the volume is edited out of band.
type objectMetadata struct {
	ETag        string    `json:"etag"`
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
}

// filesystemStore is one bucket backed by one directory.
//
// Conditional writes are the Hub's optimistic concurrency, so every mutation of a key is
// serialized here and lands through an atomic rename. That makes this driver single-node: one
// broker process owns its directory.
type filesystemStore struct {
	root           string
	bucket         string
	maxObjectBytes int64
	locks          [256]sync.Mutex
}

func newFilesystemStore(route S3RouteConfig) (*filesystemStore, error) {
	store := &filesystemStore{root: route.Directory, bucket: route.Bucket, maxObjectBytes: route.MaxObjectBytes}
	for _, directory := range []string{filesystemDataDirectory, filesystemMetaDirectory,
		filesystemTempDirectory, filesystemUploadDirectory} {
		if err := os.MkdirAll(filepath.Join(store.root, directory), 0o700); err != nil {
			return nil, fmt.Errorf("prepare storage directory for bucket %s: %w", route.Bucket, err)
		}
	}
	// A crash leaves half-written staging files behind; nothing references them by definition.
	entries, err := os.ReadDir(filepath.Join(store.root, filesystemTempDirectory))
	if err != nil {
		return nil, fmt.Errorf("read storage staging directory for bucket %s: %w", route.Bucket, err)
	}
	for _, entry := range entries {
		_ = os.RemoveAll(filepath.Join(store.root, filesystemTempDirectory, entry.Name()))
	}
	// Open multipart uploads are not staging files: a client whose connection failed mid-upload
	// may still resume one. So they are aged out rather than wiped, here as well as when the
	// next upload begins, which is what keeps a restart from being the only collection point.
	store.pruneAbandonedUploads()
	return store, nil
}

// validateObjectKey accepts the keys Graphit writes and rejects everything that would escape
// the data directory or depend on the host filesystem's tolerance.
func validateObjectKey(key string) error {
	if key == "" || len(key) > maximumObjectKeyBytes {
		return errStorageInvalidKey
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") || strings.Contains(key, "//") {
		return errStorageInvalidKey
	}
	for _, r := range key {
		if r < 0x20 || r > 0x7e || r == '\\' || r == '"' {
			return errStorageInvalidKey
		}
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "." || segment == ".." {
			return errStorageInvalidKey
		}
	}
	return nil
}

func (s *filesystemStore) dataPath(key string) string {
	return filepath.Join(s.root, filesystemDataDirectory, filepath.FromSlash(key))
}

func (s *filesystemStore) metaPath(key string) string {
	return filepath.Join(s.root, filesystemMetaDirectory, filepath.FromSlash(key)+filesystemMetaSuffix)
}

func (s *filesystemStore) lockFor(key string) *sync.Mutex {
	sum := sha256.Sum256([]byte(key))
	return &s.locks[sum[0]]
}

// Head returns the current object without opening its body.
func (s *filesystemStore) Head(key string) (storageObject, error) {
	if err := validateObjectKey(key); err != nil {
		return storageObject{}, err
	}
	return s.describe(key)
}

// Get returns the object body together with its metadata. The caller closes the file.
func (s *filesystemStore) Get(key string) (*os.File, storageObject, error) {
	if err := validateObjectKey(key); err != nil {
		return nil, storageObject{}, err
	}
	object, err := s.describe(key)
	if err != nil {
		return nil, storageObject{}, err
	}
	file, err := os.Open(s.dataPath(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, storageObject{}, errStorageNotFound
		}
		return nil, storageObject{}, fmt.Errorf("open object %s: %w", key, err)
	}
	return file, object, nil
}

// describe reports the object, repairing or creating the sidecar when it is missing or stale so
// a directory seeded outside the broker still answers with a correct ETag.
func (s *filesystemStore) describe(key string) (storageObject, error) {
	info, err := os.Stat(s.dataPath(key))
	if err != nil || info.IsDir() {
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return storageObject{}, errStorageNotFound
		}
		return storageObject{}, fmt.Errorf("stat object %s: %w", key, err)
	}
	metadata, ok := s.readMetadata(key)
	if !ok || metadata.Size != info.Size() || !metadata.Modified.Equal(info.ModTime()) {
		metadata, err = s.rebuildMetadata(key, info)
		if err != nil {
			return storageObject{}, err
		}
	}
	return storageObject{Key: key, Size: info.Size(), ETag: metadata.ETag,
		ContentType: metadata.ContentType, Modified: info.ModTime()}, nil
}

func (s *filesystemStore) readMetadata(key string) (objectMetadata, bool) {
	raw, err := os.ReadFile(s.metaPath(key))
	if err != nil {
		return objectMetadata{}, false
	}
	var metadata objectMetadata
	if err := json.Unmarshal(raw, &metadata); err != nil || metadata.ETag == "" {
		return objectMetadata{}, false
	}
	return metadata, true
}

func (s *filesystemStore) rebuildMetadata(key string, info os.FileInfo) (objectMetadata, error) {
	file, err := os.Open(s.dataPath(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return objectMetadata{}, errStorageNotFound
		}
		return objectMetadata{}, fmt.Errorf("open object %s: %w", key, err)
	}
	defer file.Close()
	digest := md5.New()
	if _, err := io.Copy(digest, file); err != nil {
		return objectMetadata{}, fmt.Errorf("digest object %s: %w", key, err)
	}
	metadata := objectMetadata{ETag: quotedETag(digest.Sum(nil)), ContentType: contentTypeForKey(key),
		Size: info.Size(), Modified: info.ModTime()}
	// A read-only volume or a concurrent write must not fail the read this repairs.
	_ = s.writeMetadata(key, metadata)
	return metadata, nil
}

func (s *filesystemStore) writeMetadata(key string, metadata objectMetadata) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode metadata for %s: %w", key, err)
	}
	target := s.metaPath(key)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("prepare metadata directory for %s: %w", key, err)
	}
	staged, err := s.stage()
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err := staged.Write(raw); err != nil {
		staged.Close()
		return fmt.Errorf("write metadata for %s: %w", key, err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("write metadata for %s: %w", key, err)
	}
	if err := os.Rename(staged.Name(), target); err != nil {
		return fmt.Errorf("commit metadata for %s: %w", key, err)
	}
	return nil
}

func (s *filesystemStore) stage() (*os.File, error) {
	file, err := os.CreateTemp(filepath.Join(s.root, filesystemTempDirectory), "upload-")
	if err != nil {
		return nil, fmt.Errorf("stage upload for bucket %s: %w", s.bucket, err)
	}
	return file, nil
}

// putConditions carries the S3 conditional-write headers.
type putConditions struct {
	IfMatch     string
	IfNoneMatch string
}

func (c putConditions) evaluate(current storageObject, exists bool) error {
	if c.IfNoneMatch != "" {
		if c.IfNoneMatch == "*" && exists {
			return errStoragePrecondition
		}
		if c.IfNoneMatch != "*" && exists && etagMatches(c.IfNoneMatch, current.ETag) {
			return errStoragePrecondition
		}
	}
	if c.IfMatch != "" {
		if !exists {
			return errStoragePrecondition
		}
		if c.IfMatch != "*" && !etagMatches(c.IfMatch, current.ETag) {
			return errStoragePrecondition
		}
	}
	return nil
}

func etagMatches(candidates, etag string) bool {
	for _, candidate := range strings.Split(candidates, ",") {
		candidate = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(candidate), "W/"))
		if candidate == etag || strings.Trim(candidate, `"`) == strings.Trim(etag, `"`) {
			return true
		}
	}
	return false
}

// Put stores one object atomically. expectedSHA256 is verified while the body streams when the
// client signed its payload, so a truncated or altered upload never becomes an object.
func (s *filesystemStore) Put(key string, body io.Reader, contentType, expectedSHA256 string, conditions putConditions) (storageObject, error) {
	if err := validateObjectKey(key); err != nil {
		return storageObject{}, err
	}
	staged, err := s.stage()
	if err != nil {
		return storageObject{}, err
	}
	defer os.Remove(staged.Name())
	contentDigest := md5.New()
	var payloadDigest hash.Hash
	writers := []io.Writer{staged, contentDigest}
	if expectedSHA256 != "" {
		payloadDigest = sha256.New()
		writers = append(writers, payloadDigest)
	}
	size, err := io.Copy(io.MultiWriter(writers...), io.LimitReader(body, s.maxObjectBytes+1))
	if err != nil {
		staged.Close()
		return storageObject{}, fmt.Errorf("receive object %s: %w", key, err)
	}
	if size > s.maxObjectBytes {
		staged.Close()
		return storageObject{}, errStorageTooLarge
	}
	if err := staged.Sync(); err != nil {
		staged.Close()
		return storageObject{}, fmt.Errorf("persist object %s: %w", key, err)
	}
	if err := staged.Close(); err != nil {
		return storageObject{}, fmt.Errorf("persist object %s: %w", key, err)
	}
	if payloadDigest != nil && !strings.EqualFold(hex.EncodeToString(payloadDigest.Sum(nil)), expectedSHA256) {
		return storageObject{}, errStorageBadDigest
	}
	if contentType == "" {
		contentType = contentTypeForKey(key)
	}
	return s.commit(key, staged.Name(), objectMetadata{ETag: quotedETag(contentDigest.Sum(nil)),
		ContentType: contentType, Size: size}, conditions)
}

// commit moves one fully staged file into place. Every write ends here, so the conditional
// check, the atomic rename, and the metadata sidecar stay one behaviour whether the object
// arrived in one request or as assembled upload parts.
func (s *filesystemStore) commit(key, staged string, metadata objectMetadata, conditions putConditions) (storageObject, error) {
	lock := s.lockFor(key)
	lock.Lock()
	defer lock.Unlock()
	current, err := s.describe(key)
	exists := err == nil
	if err != nil && !errors.Is(err, errStorageNotFound) {
		return storageObject{}, err
	}
	if err := conditions.evaluate(current, exists); err != nil {
		return storageObject{}, err
	}
	target := s.dataPath(key)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return storageObject{}, fmt.Errorf("prepare object directory for %s: %w", key, err)
	}
	if err := os.Rename(staged, target); err != nil {
		return storageObject{}, fmt.Errorf("commit object %s: %w", key, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return storageObject{}, fmt.Errorf("stat committed object %s: %w", key, err)
	}
	metadata.Modified = info.ModTime()
	if err := s.writeMetadata(key, metadata); err != nil {
		return storageObject{}, err
	}
	return storageObject{Key: key, Size: metadata.Size, ETag: metadata.ETag,
		ContentType: metadata.ContentType, Modified: metadata.Modified}, nil
}

// Delete removes one object. A missing key succeeds, as it does on S3, unless the caller
// demanded a matching ETag.
func (s *filesystemStore) Delete(key string, conditions putConditions) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	lock := s.lockFor(key)
	lock.Lock()
	defer lock.Unlock()
	current, err := s.describe(key)
	if err != nil && !errors.Is(err, errStorageNotFound) {
		return err
	}
	exists := err == nil
	if conditions.IfMatch != "" {
		if !exists || (conditions.IfMatch != "*" && !etagMatches(conditions.IfMatch, current.ETag)) {
			return errStoragePrecondition
		}
	}
	if !exists {
		return nil
	}
	if err := os.Remove(s.dataPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete object %s: %w", key, err)
	}
	if err := os.Remove(s.metaPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete metadata for %s: %w", key, err)
	}
	s.pruneEmptyDirectories(filesystemDataDirectory, key)
	s.pruneEmptyDirectories(filesystemMetaDirectory, key)
	return nil
}

func (s *filesystemStore) pruneEmptyDirectories(tree, key string) {
	root := filepath.Join(s.root, tree)
	current := filepath.Dir(filepath.Join(root, filepath.FromSlash(key)))
	for current != root && strings.HasPrefix(current, root) {
		if err := os.Remove(current); err != nil {
			return
		}
		current = filepath.Dir(current)
	}
}

// listRequest is one ListObjectsV2 query.
type listRequest struct {
	Prefix     string
	Delimiter  string
	StartAfter string
	MaxKeys    int
}

type listResult struct {
	Objects        []storageObject
	CommonPrefixes []string
	Truncated      bool
	NextStartAfter string
}

// List answers in S3 key order by walking only the directories a prefix can contain and
// stopping once the page is full, so paging stays proportional to the page and not to the
// bucket.
func (s *filesystemStore) List(request listRequest) (listResult, error) {
	if request.MaxKeys <= 0 || request.MaxKeys > 1000 {
		request.MaxKeys = 1000
	}
	walk := &listWalk{store: s, request: request, prefixes: map[string]struct{}{}}
	start := ""
	if index := strings.LastIndex(request.Prefix, "/"); index >= 0 {
		start = request.Prefix[:index+1]
	}
	if err := walk.visit(start); err != nil {
		return listResult{}, err
	}
	result := listResult{Objects: walk.objects, CommonPrefixes: walk.commonPrefixes}
	if len(walk.entries) > request.MaxKeys {
		result.Truncated = true
		result.NextStartAfter = walk.entries[request.MaxKeys-1]
		result.Objects, result.CommonPrefixes = walk.trim(request.MaxKeys)
	}
	return result, nil
}

type listWalk struct {
	store          *filesystemStore
	request        listRequest
	entries        []string
	objects        []storageObject
	commonPrefixes []string
	prefixes       map[string]struct{}
	done           bool
}

// trim cuts the collected page back to limit entries, keeping the objects and common prefixes
// that belong to it.
func (w *listWalk) trim(limit int) ([]storageObject, []string) {
	last := w.entries[limit-1]
	objects := make([]storageObject, 0, limit)
	for _, object := range w.objects {
		if object.Key <= last {
			objects = append(objects, object)
		}
	}
	prefixes := make([]string, 0, limit)
	for _, prefix := range w.commonPrefixes {
		if prefix <= last {
			prefixes = append(prefixes, prefix)
		}
	}
	return objects, prefixes
}

// visit walks one directory in key order. A directory entry sorts as its key including the
// trailing slash, which is the order S3 reports.
func (w *listWalk) visit(directory string) error {
	if w.done {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(w.store.root, filesystemDataDirectory, filepath.FromSlash(directory)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("list bucket %s: %w", w.store.bucket, err)
	}
	keys := make([]string, 0, len(entries))
	children := map[string]bool{}
	for _, entry := range entries {
		key := directory + entry.Name()
		if entry.IsDir() {
			key += "/"
		}
		keys = append(keys, key)
		children[key] = entry.IsDir()
	}
	sort.Strings(keys)
	for _, key := range keys {
		if w.done {
			return nil
		}
		if children[key] {
			if err := w.descend(key); err != nil {
				return err
			}
			continue
		}
		w.consider(key)
	}
	return nil
}

func (w *listWalk) descend(key string) error {
	// Nothing inside a directory can match a prefix the directory neither extends nor leads to.
	if !strings.HasPrefix(key, w.request.Prefix) && !strings.HasPrefix(w.request.Prefix, key) {
		return nil
	}
	// Every key inside sorts above the directory key, so a start-after beyond it skips it all.
	if after := w.request.StartAfter; after > key && !strings.HasPrefix(after, key) {
		return nil
	}
	if w.request.Delimiter != "" && strings.HasPrefix(key, w.request.Prefix) && len(key) > len(w.request.Prefix) {
		if grouped, ok := w.group(key); ok {
			w.record(grouped, storageObject{}, false)
			return nil
		}
	}
	return w.visit(key)
}

func (w *listWalk) consider(key string) {
	if !strings.HasPrefix(key, w.request.Prefix) || key <= w.request.StartAfter {
		return
	}
	if w.request.Delimiter != "" {
		if grouped, ok := w.group(key); ok {
			w.record(grouped, storageObject{}, false)
			return
		}
	}
	object, err := w.store.describe(key)
	if err != nil {
		// A key removed between the directory read and this describe is simply not listed.
		return
	}
	w.record(key, object, true)
}

// group reports the common prefix a key collapses into, if the delimiter appears after the
// requested prefix.
func (w *listWalk) group(key string) (string, bool) {
	remainder := key[len(w.request.Prefix):]
	index := strings.Index(remainder, w.request.Delimiter)
	if index < 0 {
		return "", false
	}
	return w.request.Prefix + remainder[:index+len(w.request.Delimiter)], true
}

func (w *listWalk) record(entry string, object storageObject, isObject bool) {
	if !isObject {
		if _, seen := w.prefixes[entry]; seen {
			return
		}
		if entry <= w.request.StartAfter {
			return
		}
		w.prefixes[entry] = struct{}{}
		w.commonPrefixes = append(w.commonPrefixes, entry)
	} else {
		w.objects = append(w.objects, object)
	}
	w.entries = append(w.entries, entry)
	// One entry beyond the page proves the listing is truncated without walking any further.
	if len(w.entries) > w.request.MaxKeys {
		w.done = true
	}
}

func quotedETag(digest []byte) string { return `"` + hex.EncodeToString(digest) + `"` }

func contentTypeForKey(key string) string {
	if detected := mime.TypeByExtension(path.Ext(key)); detected != "" {
		return detected
	}
	return "application/octet-stream"
}
