package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// lanceBranchKeys are the objects Lance writes for a dataset with a native branch, as
// graphit-code's project versions create them: the main lineage, the branch's own tree and
// the branch reference, all inside the table dataset under the module prefix. A branch name
// with a slash nests under tree/ and is percent-encoded in its reference file.
func lanceBranchKeys(modulePrefix string) (objects, listings []string) {
	dataset := modulePrefix + "/memory-project-P.lance"
	objects = []string{
		dataset + "/data/0.lance",
		dataset + "/_versions/1.manifest",
		dataset + "/_versions/latest_version_hint.json",
		dataset + "/_transactions/0-a.txn",
		dataset + "/_refs/branches/feature%2Fx.json",
		dataset + "/tree/feature/x/data/1.lance",
		dataset + "/tree/feature/x/_versions/2.manifest",
		dataset + "/tree/feature/x/_versions/latest_version_hint.json",
		dataset + "/tree/feature/x/_transactions/1-b.txn",
	}
	listings = []string{dataset + "/_refs/branches/", dataset + "/tree/feature/x/_versions/", dataset + "/_versions/"}
	return objects, listings
}

// matchesStringLike is the subset of IAM StringLike/resource matching the session policy
// uses: an exact value or a trailing `*` that spans slashes.
func matchesStringLike(pattern, value string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

// A module grant covers every object and listing a project version's Lance branch needs,
// in the STS policy and in the filesystem gateway alike, without reaching another module.
func TestModuleGrantCoversLanceBranchObjects(t *testing.T) {
	const module = "v2/projects/P/memory"
	grant := S3SessionGrant{Access: map[string][]string{"write": {module}}}
	policy, err := buildS3SessionPolicy(S3RouteConfig{Bucket: "bucket"}, grant)
	if err != nil {
		t.Fatal(err)
	}
	var document sessionPolicy
	if err := json.Unmarshal([]byte(policy), &document); err != nil {
		t.Fatal(err)
	}
	allowed := func(action, resource string) bool {
		for _, statement := range document.Statement {
			if !contains(statement.Action, action) {
				continue
			}
			for _, pattern := range statement.Resource {
				if matchesStringLike(pattern, resource) {
					return true
				}
			}
		}
		return false
	}
	listable := func(prefix string) bool {
		for _, statement := range document.Statement {
			if !contains(statement.Action, "s3:ListBucket") {
				continue
			}
			condition, _ := statement.Condition["StringLike"].(map[string]interface{})
			patterns, _ := condition["s3:prefix"].([]interface{})
			for _, pattern := range patterns {
				if text, _ := pattern.(string); matchesStringLike(text, prefix) {
					return true
				}
			}
		}
		return false
	}
	session := filesystemStorageSession{Access: grant.Access}

	objects, listings := lanceBranchKeys(module)
	for _, key := range objects {
		for _, action := range []string{"s3:GetObject", "s3:PutObject"} {
			if !allowed(action, "arn:aws:s3:::bucket/"+key) {
				t.Errorf("STS policy denies %s on %s:\n%s", action, key, policy)
			}
		}
		if !session.Allows(storageOperationGet, key) || !session.Allows(storageOperationPut, key) {
			t.Errorf("filesystem session denies get or put on %s", key)
		}
	}
	for _, prefix := range listings {
		if !listable(prefix) {
			t.Errorf("STS policy denies listing %s:\n%s", prefix, policy)
		}
		if !session.AllowsListing(prefix) {
			t.Errorf("filesystem session denies listing %s", prefix)
		}
	}

	otherObjects, _ := lanceBranchKeys("v2/projects/P/tasks")
	for _, key := range otherObjects {
		if allowed("s3:PutObject", "arn:aws:s3:::bucket/"+key) || session.Allows(storageOperationPut, key) {
			t.Errorf("the memory grant reaches another module's branch object %s", key)
		}
	}
}
