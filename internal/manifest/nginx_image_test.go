package manifest

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TEST-317 (image half, TASK-0117): the nginx image the manifest tracks holds every module it promises, the configuration with all of
// them loaded tests clean, and a module built for another nginx is refused (nginx says `module "…" version 1030005 instead of 1031008`). It runs only when SITESPANEL_TEST_NGINX_IMAGE names a local
// image (make nginx-image-test builds one from the founder's nginx-docker repository); SITESPANEL_TEST_NGINX_OTHER names an official
// nginx image of another version for the refusal check. Nothing is pushed or pulled by the test itself.
func TestNginxImageHoldsAllModulesAndRefusesAMismatch(t *testing.T) {
	ref := os.Getenv("SITESPANEL_TEST_NGINX_IMAGE")
	if ref == "" {
		t.Skip("SITESPANEL_TEST_NGINX_IMAGE is not set; run make nginx-image-test")
	}
	cfg, err := LoadConfig("../../images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var contract Contract
	for _, im := range cfg.Images {
		if im.Name == "nginx" {
			contract = im.Contract
		}
	}
	if len(contract.Paths) < 8 {
		t.Fatalf("the nginx contract names %d paths", len(contract.Paths))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	problems, _, err := checkContract(ctx, Docker{Program: "docker"}, ref, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("the image does not hold its contract: %v", problems)
	}

	// Every module file in the image (the -debug builds apart) is loaded by the generated include, so nginx -t above proved they all load into this nginx.
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", ref, "-c",
		"ls /usr/lib/nginx/modules/*.so | grep -vc -- -debug.so; grep -c load_module /etc/nginx/modules-enabled/10-modules.conf").Output()
	if err != nil {
		t.Fatal(err)
	}
	counts := strings.Fields(string(out))
	if len(counts) != 2 || counts[0] != counts[1] {
		t.Errorf("module files and load_module lines differ: %v", counts)
	}

	other := os.Getenv("SITESPANEL_TEST_NGINX_OTHER")
	if other == "" {
		t.Log("SITESPANEL_TEST_NGINX_OTHER is not set; the refusal of a mismatched module was not checked")
		return
	}
	// Copy one module out of the image and try to load it into another nginx version: nginx must refuse it.
	id, err := exec.CommandContext(ctx, "docker", "create", ref).Output()
	if err != nil {
		t.Fatal(err)
	}
	cid := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", cid).Run()
	dir := t.TempDir()
	if err := exec.CommandContext(ctx, "docker", "cp", cid+":/usr/lib/nginx/modules/ngx_http_headers_more_filter_module.so", dir+"/m.so").Run(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none", "-v", dir+"/m.so:/m.so:ro", "--entrypoint", "sh", other, "-c",
		"printf 'load_module /m.so;\\nevents {}\\nhttp {}\\n' > /tmp/n.conf && nginx -t -c /tmp/n.conf 2>&1")
	res, err := cmd.CombinedOutput()
	if err == nil || !(strings.Contains(string(res), "not binary compatible") || strings.Contains(string(res), "instead of")) {
		t.Fatalf("a module built for another nginx must be refused (\"version … instead of …\" or \"not binary compatible\"); got err=%v output=%s", err, res)
	}
}
