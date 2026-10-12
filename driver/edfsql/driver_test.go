package edfsql

import (
	"database/sql"
	"database/sql/driver"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lib-x/edf"
)

func TestParseDataSourceNameKeepsPlainPath(t *testing.T) {
	got, err := parseDataSourceName("notes.edf")
	if err != nil {
		t.Fatalf("parseDataSourceName() error = %v", err)
	}
	if got.path != "notes.edf" {
		t.Fatalf("path = %q, want notes.edf", got.path)
	}
	if len(got.password) != 0 {
		t.Fatalf("password was unexpectedly set")
	}
}

func TestParseDataSourceNameReadsPasswordFile(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	got, err := parseDataSourceName("notes.edf?password_file=" + url.QueryEscape(passwordPath))
	if err != nil {
		t.Fatalf("parseDataSourceName() error = %v", err)
	}
	if got.path != "notes.edf" {
		t.Fatalf("path = %q, want notes.edf", got.path)
	}
	if string(got.password) != "secret" {
		t.Fatalf("password = %q, want secret", got.password)
	}
}

func TestParseDataSourceNameReadsPasswordEnv(t *testing.T) {
	t.Setenv("EDFSQL_TEST_PASSWORD", "secret\n")

	got, err := parseDataSourceName("notes.edf?password_env=EDFSQL_TEST_PASSWORD")
	if err != nil {
		t.Fatalf("parseDataSourceName() error = %v", err)
	}
	if string(got.password) != "secret" {
		t.Fatalf("password = %q, want secret", got.password)
	}
}

func TestParseDataSourceNameUsesDirectPassword(t *testing.T) {
	got, err := parseDataSourceName("notes.edf?password=" + url.QueryEscape("a+b c"))
	if err != nil {
		t.Fatalf("parseDataSourceName() error = %v", err)
	}
	if string(got.password) != "a+b c" {
		t.Fatalf("password = %q, want direct value", got.password)
	}
}

func TestParseDataSourceNameRejectsUnknownOption(t *testing.T) {
	if _, err := parseDataSourceName("notes.edf?passwrod=secret"); err == nil {
		t.Fatalf("expected unknown option error")
	}
}

func TestDriverValueDecodesInt64(t *testing.T) {
	got := driverValue(edf.DecodedValue{Kind: edf.DecodedInt64, Int64: 9876543210})
	if got != driver.Value(int64(9876543210)) {
		t.Fatalf("driverValue() = %v, want 9876543210", got)
	}
}

func TestLocalSQLDriverWithPasswordFileDoesNotRegressReadableSignals(t *testing.T) {
	sampleDir := os.Getenv("EDF_SAMPLE_DIR")
	passwordFile := os.Getenv("EDF_PASSWORD_FILE")
	if sampleDir == "" || passwordFile == "" {
		t.Skip("set EDF_SAMPLE_DIR and EDF_PASSWORD_FILE to verify encrypted SQL decoding")
	}

	matches, err := filepath.Glob(filepath.Join(sampleDir, "*.edf"))
	if err != nil {
		t.Fatalf("glob EDF_SAMPLE_DIR: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("no .edf files found in %s", sampleDir)
	}

	hexID := regexp.MustCompile(`^[0-9a-f]{32}$`)
	queryFields := []string{
		`select Id from Document`,
		`select Id from AttachContent`,
		`select Id from AttachMeta`,
		`select ContentId from AttachMeta`,
		`select OwnerId from AttachMeta`,
		`select TagName from DiaryTag`,
	}
	withoutPassword := 0
	withPassword := 0
	verifiedFiles := 0
	for _, path := range matches {
		plainDB, err := sql.Open("edfsql", path)
		if err != nil {
			t.Fatalf("sql.Open(%s) error = %v", filepath.Base(path), err)
		}
		encryptedDB, err := sql.Open("edfsql", path+"?password_file="+url.QueryEscape(passwordFile))
		if err != nil {
			_ = plainDB.Close()
			t.Fatalf("sql.Open with password_file %s error = %v", filepath.Base(path), err)
		}

		for _, query := range queryFields {
			withoutPassword += countSQLReadableSignals(t, plainDB, filepath.Base(path), query, hexID)
			withPassword += countSQLReadableSignals(t, encryptedDB, filepath.Base(path), query, hexID)
		}
		_, verified := queryPasswordStatus(t, encryptedDB, filepath.Base(path))
		if verified {
			verifiedFiles++
		}

		if err := plainDB.Close(); err != nil {
			t.Fatalf("close db %s: %v", filepath.Base(path), err)
		}
		if err := encryptedDB.Close(); err != nil {
			t.Fatalf("close password db %s: %v", filepath.Base(path), err)
		}
	}
	if verifiedFiles == 0 {
		t.Fatal("supplied password did not authenticate any local EDF sample")
	}
	if withPassword < withoutPassword {
		t.Fatalf("readable signal count with password = %d, without password = %d; want no regression", withPassword, withoutPassword)
	}
}

func countSQLReadableSignals(t *testing.T, db *sql.DB, fileName string, query string, hexID *regexp.Regexp) int {
	t.Helper()

	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("query %s %q: %v", fileName, query, err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var value any
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan %s %q: %v", fileName, query, err)
		}
		text, ok := value.(string)
		if !ok {
			continue
		}
		if hexID.MatchString(text) || strings.TrimSpace(text) != "" {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s %q: %v", fileName, query, err)
	}
	return count
}

func queryPasswordStatus(t *testing.T, db *sql.DB, fileName string) (bool, bool) {
	t.Helper()

	var supplied bool
	var verified bool
	if err := db.QueryRow(`select password_supplied, password_verified from __database`).Scan(&supplied, &verified); err != nil {
		t.Fatalf("query password verification %s: %v", fileName, err)
	}
	if !supplied {
		t.Fatalf("password_supplied = false for %s, want true", fileName)
	}
	return supplied, verified
}
