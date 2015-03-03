package config

import (
	"crypto/rsa"
	"os"
	"sort"
	"testing"
)

// UnlinkIfExists removes a file if it exists.
func UnlinkIfExists(file string) {
	_, err := os.Stat(file)
	if err != nil && os.IsNotExist(err) {
		panic("failed to remove " + file)
	}
	os.Remove(file)
}

// stringSlicesEqual compares two string lists, checking that they
// contain the same elements.
func stringSlicesEqual(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}

	for i := range slice2 {
		if slice1[i] != slice2[i] {
			return false
		}
	}
	return true
}

func TestGoodConfig(t *testing.T) {
	testFile := "testdata/test.conf"
	cmap, err := parseFile(testFile)
	if err != nil {
		t.Fatalf("%v", err)
	} else if len(cmap) != 2 {
		t.Fatal("expected 2 sections, have", len(cmap))
	}
}

func TestGoodConfig2(t *testing.T) {
	testFile := "testdata/test2.conf"
	cmap, err := parseFile(testFile)
	if err != nil {
		t.Fatalf("%v", err)
	} else if len(cmap) != 1 {
		t.Fatal("expected 1 section, have", len(cmap))
	} else if len(cmap["default"]) != 3 {
		t.Fatal("expected 3 items in default section, have", len(cmap["default"]))
	}
}

func TestBadConfig(t *testing.T) {
	testFile := "testdata/bad.conf"
	_, err := parseFile(testFile)
	if err == nil {
		t.Fatal("expected invalid config file to fail")
	}
}

func TestWriteConfigFile(t *testing.T) {
	const testFile = "testdata/test.conf"
	const testOut = "testdata/test.out"

	cmap, err := parseFile(testFile)
	if err != nil {
		t.Fatalf("%v", err)
	}

	defer UnlinkIfExists(testOut)
	err = cmap.WriteFile(testOut)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cmap2, err := parseFile(testOut)
	if err != nil {
		t.Fatalf("%v", err)
	}

	sectionList1 := cmap.ListSections()
	sectionList2 := cmap2.ListSections()
	sort.Strings(sectionList1)
	sort.Strings(sectionList2)
	if !stringSlicesEqual(sectionList1, sectionList2) {
		t.Fatal("section lists don't match")
	}

	for _, section := range sectionList1 {
		for _, k := range cmap[section] {
			if cmap[section][k] != cmap2[section][k] {
				t.Fatal("config key doesn't match")
			}
		}
	}

	if cmap.WriteFile("testdata") == nil {
		t.Fatal("expected writing to fail when file is invalid")
	}
}

func TestQuotedValue(t *testing.T) {
	testFile := "testdata/test.conf"
	cmap, _ := parseFile(testFile)
	val := cmap["sectionName"]["key4"]
	if val != " space at beginning and end " {
		t.Fatal("Wrong value in double quotes [", val, "]")
	}

	if !cmap.SectionInConfig("sectionName") {
		t.Fatal("expected SectionInConfig to return true")
	}

	val = cmap["sectionName"]["key5"]
	if val != " is quoted with single quotes " {
		t.Fatal("Wrong value in single quotes [", val, "]")
	}
}

func TestENoEnt(t *testing.T) {
	_, err := parseFile("testdata/enoent")
	if err == nil {
		t.Fatal("expected error on non-existent file")
	}
}

func TestLoadRoots(t *testing.T) {
	roots, err := Parse("testdata/roots.conf")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(roots) != 2 {
		t.Fatal("expected one CA in the roots")
	}

	if root, ok := roots["primary"]; !ok {
		t.Fatal("expected a primary CA section")
	} else if _, ok := root.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatal("expected an RSA private key")
	}
}

func TestLoadKSMRoot(t *testing.T) {
	_, err := Parse("testdata/roots_ksm.conf")
	if err == nil {
		t.Fatal("ksm specs are not supported yet")
	}
}

func TestLoadBadRootConfs(t *testing.T) {
	confs := []string{
		"testdata/roots_missing_certificate.conf",
		"testdata/roots_missing_private_key.conf",
		"testdata/roots_bad_certificate.conf",
		"testdata/roots_bad_private_key.conf",
		"testdata/roots_missing_private_key_entry.conf",
		"testdata/roots_missing_certificate_entry.conf",
		"testdata/roots_badspec.conf",
		"testdata/roots_badspec2.conf",
		"testdata/roots_badspec3.conf",
	}

	for _, cf := range confs {
		_, err := Parse(cf)
		if err == nil {
			t.Fatalf("expected config file %s to fail", cf)
		}
	}
}
