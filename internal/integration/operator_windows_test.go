// Operator file access on Windows, read from the actual access control lists.

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Alex-Zechariah-02/apiward/internal/gatewaytest"
	"github.com/Alex-Zechariah-02/apiward/internal/store"
)

// Inspect actual DACLs, including sidecars, rather than interpreting Unix
// permission bits as Windows access control. This is current-user evidence;
// it does not impersonate another account or claim cross-account isolation.
func TestNativeOperatorWindowsAccess(t *testing.T) {
	e := gatewaytest.NewEnv(t)
	if _, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "install", "--admin", "root"); code != 0 {
		t.Fatalf("install exit %d", code)
	}
	backup := filepath.Join(e.Dir, "backup.db")
	if out, code := e.RunOperator(gatewaytest.Binaries.Plain, nil, "backup", "--output", backup); code != 0 {
		t.Fatalf("backup exit %d: %s", code, out)
	}
	// An open store keeps the -wal and -shm sidecars present for inspection.
	st, err := store.OpenStore(e.Database)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{e.Dir, e.Config, e.PublicKey, e.Database, e.Database + "-wal", e.Database + "-shm", e.AuditLog, backup, manifestOf(backup)}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("pwsh.exe", "-NoProfile", "-Command", `$ErrorActionPreference = 'Stop'; @(Get-Item -LiteralPath $env:GATEWAY_ACL_DIR) + @(Get-ChildItem -Force -LiteralPath $env:GATEWAY_ACL_DIR) | ForEach-Object { $acl = Get-Acl -LiteralPath $_.FullName; [pscustomobject]@{Name = $_.Name; Sddl = $acl.Sddl; Protected = $acl.AreAccessRulesProtected} | ConvertTo-Json -Compress }`)
	cmd.Env = append(os.Environ(), "GATEWAY_ACL_DIR="+e.Dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("DACL inspection: %v: %s", err, output)
	}
	if len(output) == 0 {
		t.Fatal("DACL inspection returned no descriptors")
	}
	t.Logf("DACLs on actual operator artifacts:\n%s", output)
	t.Log("current user created, read and wrote this deployment; other-user access is NOT TESTED; administrative access is not excluded")
	// The store's exclusive lock alone would make backup exit 1, so it is
	// released before the probe and the refusal must name the denied access.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	before := gatewaytest.FileSHA256(t, e.Database)
	cmd = exec.Command("pwsh.exe", "-NoProfile", "-Command", `$ErrorActionPreference = 'Stop'; $path = Join-Path $env:GATEWAY_ACL_DIR 'gateway.json'; $saved = Get-Acl -LiteralPath $path; $denied = Get-Acl -LiteralPath $path; $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User; $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Deny); $denied.AddAccessRule($rule); try { Set-Acl -LiteralPath $path -AclObject $denied; & $env:GATEWAY_ACL_BINARY backup --config $path --output (Join-Path $env:GATEWAY_ACL_DIR 'denied.db'); if ($LASTEXITCODE -ne 1) { throw "expected permission refusal exit 1, got $LASTEXITCODE" }; 'access-denied native backup: exit 1' } finally { Set-Acl -LiteralPath $path -AclObject $saved }`)
	cmd.Env = append(os.Environ(), "GATEWAY_ACL_DIR="+e.Dir, "GATEWAY_ACL_BINARY="+gatewaytest.Binaries.Plain)
	output, err = cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Access is denied") {
		t.Fatalf("test-owned access denial: %v: %s", err, output)
	}
	if gatewaytest.FileSHA256(t, e.Database) != before {
		t.Fatal("permission refusal changed live authority")
	}
	t.Logf("current-user access-denial probe (original DACL restored): %s", output)
}
