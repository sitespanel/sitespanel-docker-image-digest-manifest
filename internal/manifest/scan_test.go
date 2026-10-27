package manifest

import "testing"

func TestParseTrivyKeepsFixableHighAndCritical(t *testing.T) {
	out := []byte(`{"Results":[
	  {"Target":"debian","Vulnerabilities":[
	    {"VulnerabilityID":"CVE-2","PkgName":"libc6","InstalledVersion":"1","FixedVersion":"2","Severity":"CRITICAL"},
	    {"VulnerabilityID":"CVE-1","PkgName":"zlib","InstalledVersion":"1","FixedVersion":"","Severity":"CRITICAL"},
	    {"VulnerabilityID":"CVE-3","PkgName":"curl","InstalledVersion":"1","FixedVersion":"2","Severity":"MEDIUM"}]},
	  {"Target":"gobinary","Vulnerabilities":[
	    {"VulnerabilityID":"CVE-2","PkgName":"libc6","InstalledVersion":"1","FixedVersion":"2","Severity":"CRITICAL"},
	    {"VulnerabilityID":"CVE-0","PkgName":"stdlib","InstalledVersion":"1.24","FixedVersion":"1.25","Severity":"HIGH"}]},
	  {"Target":"empty"}]}`)
	fs, err := parseTrivy(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].ID != "CVE-0" || fs[1].ID != "CVE-2" || fs[1].Package != "libc6" {
		t.Fatalf("%+v", fs)
	}
	if _, err := parseTrivy([]byte("not json")); err == nil {
		t.Fatal("bad output parsed")
	}
}
