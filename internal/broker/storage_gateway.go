package broker

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The storage gateway is the S3 API this broker serves over a local directory. Graphit clients
// reach it with exactly the code they use for a real bucket — the AWS SDK for control paths and
// the engine's httpfs extension for queries — because it speaks path-style S3 with Signature
// Version 4 over the credentials the broker itself minted.
//
// It is deliberately a narrow S3: the object operations Graphit performs, no multipart, no
// versioning, no bucket management.
const (
	storageTransferWindow      = 30 * time.Minute
	maximumBatchDeleteBytes    = 1 << 20
	storageXMLNamespace        = "http://s3.amazonaws.com/doc/2006-03-01/"
	storageDefaultStorageClass = "STANDARD"
)

type storageGateway struct {
	stores      map[string]*filesystemStore
	credentials *FilesystemCredentialService
	now         func() time.Time
}

func newStorageGateway(cfg Config, credentials *FilesystemCredentialService) (*storageGateway, error) {
	gateway := &storageGateway{stores: map[string]*filesystemStore{}, credentials: credentials, now: time.Now}
	for name, route := range cfg.Services.S3.Routes {
		if !route.isFilesystem() {
			continue
		}
		store, err := newFilesystemStore(route)
		if err != nil {
			return nil, fmt.Errorf("services.s3.routes.%s: %w", name, err)
		}
		gateway.stores[route.Bucket] = store
	}
	if len(gateway.stores) == 0 {
		return nil, nil
	}
	return gateway, nil
}

func (g *storageGateway) register(mux *http.ServeMux) {
	for bucket := range g.stores {
		handler := g.handlerFor(bucket)
		mux.Handle("GET /"+bucket, handler)
		mux.Handle("HEAD /"+bucket, handler)
		mux.Handle("POST /"+bucket, handler)
		for _, method := range []string{"GET", "HEAD", "PUT", "POST", "DELETE"} {
			mux.Handle(method+" /"+bucket+"/{key...}", handler)
		}
	}
}

func (g *storageGateway) handlerFor(bucket string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, bucket)
	})
}

func (g *storageGateway) serve(w http.ResponseWriter, r *http.Request, bucket string) {
	w.Header().Set("x-amz-request-id", requestID(r.Context()))
	// Object transfers outlast the API timeouts the rest of the broker runs with.
	controller := http.NewResponseController(w)
	deadline := g.now().Add(storageTransferWindow)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)

	store := g.stores[bucket]
	if store == nil {
		writeStorageError(w, r, http.StatusNotFound, "NoSuchBucket", "the specified bucket does not exist")
		return
	}
	session, body, digest, err := g.authenticate(r, bucket)
	if err != nil {
		writeStorageAuthenticationError(w, r, err)
		return
	}
	key := r.PathValue("key")
	if key == "" {
		g.serveBucket(w, r, store, session)
		return
	}
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && query.Has("uploadId"):
		g.listUploadParts(w, r, store, session, key)
	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		g.getObject(w, r, store, session, key)
	case r.Method == http.MethodPost && query.Has("uploads"):
		g.createUpload(w, r, store, session, key)
	case r.Method == http.MethodPost && query.Has("uploadId"):
		g.completeUpload(w, r, store, session, key)
	case r.Method == http.MethodPut && query.Has("uploadId"):
		g.uploadPart(w, r, store, session, key, body)
	case r.Method == http.MethodPut && r.Header.Get("X-Amz-Copy-Source") != "":
		g.copyObject(w, r, store, session, key)
	case r.Method == http.MethodPut:
		g.putObject(w, r, store, session, key, body, digest)
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		g.abortUpload(w, r, store, session, key)
	case r.Method == http.MethodDelete:
		g.deleteObject(w, r, store, session, key)
	default:
		writeStorageError(w, r, http.StatusNotImplemented, "NotImplemented",
			"the gateway does not serve this operation")
	}
}

func (g *storageGateway) serveBucket(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession) {
	switch {
	case r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		g.listObjects(w, r, store, session)
	case r.Method == http.MethodPost && r.URL.Query().Has("delete"):
		g.deleteObjects(w, r, store, session)
	default:
		writeStorageError(w, r, http.StatusNotImplemented, "NotImplemented",
			"the gateway serves ListObjectsV2 and batch delete on a bucket")
	}
}

// authenticate proves the caller holds a live broker-minted session and signed this exact
// request. It returns the request body already stripped of any chunked upload framing.
func (g *storageGateway) authenticate(r *http.Request, bucket string) (filesystemStorageSession, io.Reader, string, error) {
	signature, err := parseSigV4Request(r)
	if err != nil {
		return filesystemStorageSession{}, nil, "", err
	}
	token := strings.TrimSpace(r.Header.Get("X-Amz-Security-Token"))
	if token == "" {
		return filesystemStorageSession{}, nil, "", errStorageSessionInvalid
	}
	session, secret, err := g.credentials.Authenticate(token, signature.AccessKeyID, g.now())
	if err != nil {
		return filesystemStorageSession{}, nil, "", err
	}
	if session.Bucket != bucket {
		return filesystemStorageSession{}, nil, "", errStorageSessionInvalid
	}
	if err := verifySigV4(r, signature, secret, g.now()); err != nil {
		return filesystemStorageSession{}, nil, "", err
	}
	digest, chunked := payloadExpectation(signature.PayloadHash)
	body := io.Reader(r.Body)
	if chunked {
		body = newChunkedPayloadReader(r.Body, signature, secret)
	}
	return session, body, digest, nil
}

func (g *storageGateway) getObject(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationGet, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	file, object, err := store.Get(key)
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	defer file.Close()
	w.Header().Set("ETag", object.ETag)
	w.Header().Set("Content-Type", object.ContentType)
	w.Header().Set("Accept-Ranges", "bytes")
	// ServeContent applies the range and conditional headers S3 clients rely on, including the
	// ranged reads the query engine issues over httpfs.
	http.ServeContent(w, r, key, object.Modified, file)
}

func (g *storageGateway) putObject(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string, body io.Reader, digest string) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	conditions := putConditions{IfMatch: strings.TrimSpace(r.Header.Get("If-Match")),
		IfNoneMatch: strings.TrimSpace(r.Header.Get("If-None-Match"))}
	object, err := store.Put(key, body, strings.TrimSpace(r.Header.Get("Content-Type")), digest, conditions)
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	w.Header().Set("ETag", object.ETag)
	w.WriteHeader(http.StatusOK)
}

func (g *storageGateway) deleteObject(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationDelete, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	if err := store.Delete(key, putConditions{IfMatch: strings.TrimSpace(r.Header.Get("If-Match"))}); err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type listBucketResult struct {
	XMLName               xml.Name              `xml:"ListBucketResult"`
	Namespace             string                `xml:"xmlns,attr"`
	Name                  string                `xml:"Name"`
	Prefix                string                `xml:"Prefix"`
	StartAfter            string                `xml:"StartAfter,omitempty"`
	ContinuationToken     string                `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string                `xml:"NextContinuationToken,omitempty"`
	KeyCount              int                   `xml:"KeyCount"`
	MaxKeys               int                   `xml:"MaxKeys"`
	Delimiter             string                `xml:"Delimiter,omitempty"`
	EncodingType          string                `xml:"EncodingType,omitempty"`
	IsTruncated           bool                  `xml:"IsTruncated"`
	Contents              []listBucketObject    `xml:"Contents"`
	CommonPrefixes        []listBucketPrefixSet `xml:"CommonPrefixes"`
}

type listBucketObject struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type listBucketPrefixSet struct {
	Prefix string `xml:"Prefix"`
}

func (g *storageGateway) listObjects(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession) {
	query := r.URL.Query()
	request := listRequest{Prefix: query.Get("prefix"), Delimiter: query.Get("delimiter"),
		StartAfter: query.Get("start-after")}
	if token := query.Get("continuation-token"); token != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			writeStorageError(w, r, http.StatusBadRequest, "InvalidArgument", "the continuation token is not valid")
			return
		}
		request.StartAfter = string(decoded)
	}
	if raw := query.Get("max-keys"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeStorageError(w, r, http.StatusBadRequest, "InvalidArgument", "max-keys must be a non-negative integer")
			return
		}
		request.MaxKeys = parsed
	}
	// A listing is authorized by the prefix it asks for, exactly as the STS policy conditions
	// ListBucket on `s3:prefix`. An unscoped listing is therefore refused, not silently filtered.
	if !session.AllowsListing(request.Prefix) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	result, err := store.List(request)
	if err != nil {
		slog.Error("storage listing failed", "request_id", requestID(r.Context()), "bucket", store.bucket, "error", err)
		writeStorageError(w, r, http.StatusInternalServerError, "InternalError", "the listing could not be completed")
		return
	}
	encode := func(value string) string { return value }
	encodingType := ""
	if strings.EqualFold(query.Get("encoding-type"), "url") {
		encodingType = "url"
		encode = url.QueryEscape
	}
	response := listBucketResult{Namespace: storageXMLNamespace, Name: store.bucket,
		Prefix: encode(request.Prefix), Delimiter: encode(request.Delimiter), EncodingType: encodingType,
		StartAfter: encode(query.Get("start-after")), ContinuationToken: query.Get("continuation-token"),
		MaxKeys: request.MaxKeys, IsTruncated: result.Truncated}
	if response.MaxKeys == 0 {
		response.MaxKeys = 1000
	}
	for _, object := range result.Objects {
		response.Contents = append(response.Contents, listBucketObject{Key: encode(object.Key),
			LastModified: object.Modified.UTC().Format(time.RFC3339), ETag: object.ETag,
			Size: object.Size, StorageClass: storageDefaultStorageClass})
	}
	for _, prefix := range result.CommonPrefixes {
		response.CommonPrefixes = append(response.CommonPrefixes, listBucketPrefixSet{Prefix: encode(prefix)})
	}
	response.KeyCount = len(response.Contents) + len(response.CommonPrefixes)
	if result.Truncated {
		response.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(result.NextStartAfter))
	}
	writeStorageXML(w, http.StatusOK, response)
}

type batchDeleteRequest struct {
	XMLName xml.Name              `xml:"Delete"`
	Quiet   bool                  `xml:"Quiet"`
	Objects []batchDeleteObjectID `xml:"Object"`
}

type batchDeleteObjectID struct {
	Key string `xml:"Key"`
}

type batchDeleteResult struct {
	XMLName xml.Name              `xml:"DeleteResult"`
	Deleted []batchDeleteObjectID `xml:"Deleted"`
	Errors  []batchDeleteFailure  `xml:"Error"`
}

type batchDeleteFailure struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (g *storageGateway) deleteObjects(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maximumBatchDeleteBytes+1))
	if err != nil || len(raw) > maximumBatchDeleteBytes {
		writeStorageError(w, r, http.StatusBadRequest, "MalformedXML", "the delete request could not be read")
		return
	}
	var request batchDeleteRequest
	if err := xml.Unmarshal(raw, &request); err != nil {
		writeStorageError(w, r, http.StatusBadRequest, "MalformedXML", "the delete request is not valid XML")
		return
	}
	result := batchDeleteResult{}
	for _, object := range request.Objects {
		if !session.Allows(storageOperationDelete, object.Key) {
			result.Errors = append(result.Errors, batchDeleteFailure{Key: object.Key, Code: "AccessDenied", Message: "access denied"})
			continue
		}
		if err := store.Delete(object.Key, putConditions{}); err != nil {
			code, _, message := storageFailure(err)
			result.Errors = append(result.Errors, batchDeleteFailure{Key: object.Key, Code: code, Message: message})
			continue
		}
		if !request.Quiet {
			result.Deleted = append(result.Deleted, batchDeleteObjectID{Key: object.Key})
		}
	}
	writeStorageXML(w, http.StatusOK, result)
}

type storageErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

func writeStorageXML(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(value)
}

func writeStorageError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if r.Method == http.MethodHead {
		// A HEAD response carries no body, so the status alone reports the failure.
		w.WriteHeader(status)
		return
	}
	writeStorageXML(w, status, storageErrorResponse{Code: code, Message: message,
		Resource: r.URL.Path, RequestID: requestID(r.Context())})
}

// storageFailure maps a store error onto the S3 error the client library understands.
func storageFailure(err error) (string, int, string) {
	switch {
	case errors.Is(err, errStorageNotFound):
		return "NoSuchKey", http.StatusNotFound, "the specified key does not exist"
	case errors.Is(err, errStoragePrecondition):
		return "PreconditionFailed", http.StatusPreconditionFailed, "at least one precondition did not hold"
	case errors.Is(err, errStorageInvalidKey):
		return "InvalidArgument", http.StatusBadRequest, "the object key is not storable"
	case errors.Is(err, errStorageTooLarge):
		return "EntityTooLarge", http.StatusBadRequest, "the object exceeds the configured maximum size"
	case errors.Is(err, errStorageBadDigest):
		return "BadDigest", http.StatusBadRequest, "the payload does not match the signed digest"
	case errors.Is(err, errSignatureMismatch):
		return "SignatureDoesNotMatch", http.StatusForbidden, "the request signature does not match"
	case errors.Is(err, errStorageNoSuchUpload):
		return "NoSuchUpload", http.StatusNotFound, "the upload does not exist for this key"
	case errors.Is(err, errStorageInvalidPart):
		return "InvalidPart", http.StatusBadRequest, "a part is missing or does not match its ETag"
	}
	return "InternalError", http.StatusInternalServerError, "the request could not be completed"
}

func writeStorageFailure(w http.ResponseWriter, r *http.Request, err error, key string) {
	code, status, message := storageFailure(err)
	if status == http.StatusInternalServerError {
		slog.Error("storage request failed", "request_id", requestID(r.Context()), "key", key, "error", err)
	}
	writeStorageError(w, r, status, code, message)
}

func writeStorageAuthenticationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errStorageSessionExpired):
		writeStorageError(w, r, http.StatusBadRequest, "ExpiredToken", "the security token has expired")
	case errors.Is(err, errSignatureSkew):
		writeStorageError(w, r, http.StatusForbidden, "RequestTimeTooSkewed", "the request time is too far from the server time")
	case errors.Is(err, errSignatureMalformed):
		writeStorageError(w, r, http.StatusBadRequest, "AuthorizationHeaderMalformed", "the authorization header is malformed")
	case errors.Is(err, errStorageSessionInvalid):
		writeStorageError(w, r, http.StatusForbidden, "InvalidAccessKeyId", "the access key is not valid for this bucket")
	default:
		writeStorageError(w, r, http.StatusForbidden, "SignatureDoesNotMatch", "the request signature does not match")
	}
}

type initiateUploadResult struct {
	XMLName   xml.Name `xml:"InitiateMultipartUploadResult"`
	Namespace string   `xml:"xmlns,attr"`
	Bucket    string   `xml:"Bucket"`
	Key       string   `xml:"Key"`
	UploadID  string   `xml:"UploadId"`
}

type completeUploadRequest struct {
	XMLName xml.Name              `xml:"CompleteMultipartUpload"`
	Parts   []completeUploadEntry `xml:"Part"`
}

type completeUploadEntry struct {
	Number int    `xml:"PartNumber"`
	ETag   string `xml:"ETag"`
}

type completeUploadResult struct {
	XMLName   xml.Name `xml:"CompleteMultipartUploadResult"`
	Namespace string   `xml:"xmlns,attr"`
	Location  string   `xml:"Location"`
	Bucket    string   `xml:"Bucket"`
	Key       string   `xml:"Key"`
	ETag      string   `xml:"ETag"`
}

type listPartsResult struct {
	XMLName     xml.Name         `xml:"ListPartsResult"`
	Namespace   string           `xml:"xmlns,attr"`
	Bucket      string           `xml:"Bucket"`
	Key         string           `xml:"Key"`
	UploadID    string           `xml:"UploadId"`
	MaxParts    int              `xml:"MaxParts"`
	IsTruncated bool             `xml:"IsTruncated"`
	Parts       []listPartsEntry `xml:"Part"`
}

type listPartsEntry struct {
	Number       int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	Namespace    string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

func (g *storageGateway) createUpload(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	uploadID, err := store.CreateUpload(key, strings.TrimSpace(r.Header.Get("Content-Type")))
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	writeStorageXML(w, http.StatusOK, initiateUploadResult{Namespace: storageXMLNamespace,
		Bucket: store.bucket, Key: key, UploadID: uploadID})
}

func (g *storageGateway) uploadPart(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string, body io.Reader) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	if r.Header.Get("X-Amz-Copy-Source") != "" {
		writeStorageError(w, r, http.StatusNotImplemented, "NotImplemented", "a part cannot be copied from another object")
		return
	}
	number, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
	if err != nil {
		writeStorageError(w, r, http.StatusBadRequest, "InvalidArgument", "partNumber must be an integer")
		return
	}
	etag, err := store.UploadPart(r.URL.Query().Get("uploadId"), key, number, body)
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (g *storageGateway) completeUpload(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maximumBatchDeleteBytes+1))
	if err != nil || len(raw) > maximumBatchDeleteBytes {
		writeStorageError(w, r, http.StatusBadRequest, "MalformedXML", "the completion request could not be read")
		return
	}
	var request completeUploadRequest
	if err := xml.Unmarshal(raw, &request); err != nil {
		writeStorageError(w, r, http.StatusBadRequest, "MalformedXML", "the completion request is not valid XML")
		return
	}
	parts := make([]completedPart, 0, len(request.Parts))
	for _, part := range request.Parts {
		parts = append(parts, completedPart{Number: part.Number, ETag: part.ETag})
	}
	object, err := store.CompleteUpload(r.URL.Query().Get("uploadId"), key, parts,
		putConditions{IfMatch: strings.TrimSpace(r.Header.Get("If-Match")),
			IfNoneMatch: strings.TrimSpace(r.Header.Get("If-None-Match"))})
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	writeStorageXML(w, http.StatusOK, completeUploadResult{Namespace: storageXMLNamespace,
		Location: "/" + store.bucket + "/" + key, Bucket: store.bucket, Key: key, ETag: object.ETag})
}

func (g *storageGateway) abortUpload(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	if err := store.AbortUpload(r.URL.Query().Get("uploadId"), key); err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *storageGateway) listUploadParts(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	if !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	uploadID := r.URL.Query().Get("uploadId")
	parts, err := store.ListUploadParts(uploadID, key)
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	result := listPartsResult{Namespace: storageXMLNamespace, Bucket: store.bucket, Key: key,
		UploadID: uploadID, MaxParts: maximumUploadParts}
	for _, part := range parts {
		result.Parts = append(result.Parts, listPartsEntry{Number: part.Number,
			LastModified: part.Modified.UTC().Format(time.RFC3339), ETag: part.ETag, Size: part.Size})
	}
	writeStorageXML(w, http.StatusOK, result)
}

// copyObject serves the server-side copy an S3 client uses to move an object without resending
// it. Only a copy inside this bucket is served, and both keys are authorized separately.
func (g *storageGateway) copyObject(w http.ResponseWriter, r *http.Request, store *filesystemStore, session filesystemStorageSession, key string) {
	source, err := url.PathUnescape(strings.TrimPrefix(strings.TrimSpace(r.Header.Get("X-Amz-Copy-Source")), "/"))
	if err != nil {
		writeStorageError(w, r, http.StatusBadRequest, "InvalidArgument", "the copy source is not a valid path")
		return
	}
	if index := strings.Index(source, "?"); index >= 0 {
		source = source[:index]
	}
	bucket, sourceKey, found := strings.Cut(source, "/")
	if !found || bucket != store.bucket {
		writeStorageError(w, r, http.StatusNotImplemented, "NotImplemented", "a copy must name a source in the same bucket")
		return
	}
	if !session.Allows(storageOperationGet, sourceKey) || !session.Allows(storageOperationPut, key) {
		writeStorageError(w, r, http.StatusForbidden, "AccessDenied", "access denied")
		return
	}
	object, err := store.Copy(sourceKey, key, putConditions{IfMatch: strings.TrimSpace(r.Header.Get("If-Match")),
		IfNoneMatch: strings.TrimSpace(r.Header.Get("If-None-Match"))})
	if err != nil {
		writeStorageFailure(w, r, err, key)
		return
	}
	writeStorageXML(w, http.StatusOK, copyObjectResult{Namespace: storageXMLNamespace,
		LastModified: object.Modified.UTC().Format(time.RFC3339), ETag: object.ETag})
}
