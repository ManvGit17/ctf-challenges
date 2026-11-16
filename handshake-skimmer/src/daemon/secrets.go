package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"strings"
	"time"
)

// Generated fresh at container start, so every run has its own session
// token, auth token and journal text.

const kdfKey = "microtun-seed-v1"

const kdfNotesPlaintext = `--- legacy onboarding notes (DO NOT USE IN PROD) ---
found this in an old ops repo, keeping it around in case the forensics
API token ever needs to be regenerated locally without going through vault:

  raw   = bytes.fromhex(session_token)     # from the audit log line
  mac   = hmac_sha256(key=b"microtun-seed-v1", msg=raw)
  token = hex(mac)[:20]

(unrelated: someone also left a note here that the legacy admin token is
just "changeme" -- that has not been true since the 2021 image rebuild,
ignore it)
--- end notes ---
`

func rot13(s string) string {
	buf := []byte(s)
	for i, b := range buf {
		switch {
		case b >= 'a' && b <= 'z':
			buf[i] = 'a' + (b-'a'+13)%26
		case b >= 'A' && b <= 'Z':
			buf[i] = 'A' + (b-'A'+13)%26
		}
	}
	return string(buf)
}

func kdfNotes() string {
	return rot13(kdfNotesPlaintext)
}

func generateSessionToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// computeAuthToken mirrors the formula described (ROT13'd) in kdfNotes.
func computeAuthToken(sessionTokenHex string) string {
	raw, err := hex.DecodeString(sessionTokenHex)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha256.New, []byte(kdfKey))
	mac.Write(raw)
	full := hex.EncodeToString(mac.Sum(nil))
	return full[:20]
}

const journalTemplate = `-- Logs begin at {{LOG_START}}, end at {{LOG_END}}. --
{{T0}} pesu-lab-04 systemd[1]: Starting Network Manager Script Dispatcher Service...
{{T1}} pesu-lab-04 systemd[1]: Started Network Manager Script Dispatcher Service.
{{T2}} pesu-lab-04 cron[612]: (root) CMD (/usr/lib/cron/logrotate-hourly.sh)
{{T3}} pesu-lab-04 kernel: [   14.221033] microtun: interface mt0 registered
{{T4}} pesu-lab-04 microtund[798]: forensics API listening on 0.0.0.0:8080
{{T5}} pesu-lab-04 auditd[611]: audit_pid=611
{{T6}} pesu-lab-04 audit[812]: TOKEN_MINT pid=812 uid=0 auid=1000 ses=7 subj=unconfined msg='op=token:mint svc="forensics-api" exe="/usr/local/bin/microtund" res=success session_token={{SESSION_TOKEN}}'
{{T7}} pesu-lab-04 systemd-logind[615]: New session 7 of user svc-onboard.
{{T8}} pesu-lab-04 microtund[812]: token issued for scope=forensics
{{T9}} pesu-lab-04 sudo[830]:  svc-onboard : TTY=pts/0 ; PWD=/home/svc-onboard ; USER=root ; COMMAND=/usr/bin/systemctl status microtund
{{T10}} pesu-lab-04 systemd[1]: microtund.service: Deactivated successfully.
{{T11}} pesu-lab-04 systemd-logind[615]: Session 7 logged out. Waiting for processes to exit.
{{T12}} pesu-lab-04 kernel: [   88.442210] audit: type=1106 audit(1730000000.442:4522): pid=812 uid=0 auid=1000 ses=7 msg='op=token:revoke svc="forensics-api" res=success'
{{T13}} pesu-lab-04 systemd[1]: Reloading.
-- Logs end at {{LOG_END}}. --
`

func buildJournal(sessionTokenHex string, r *mrand.Rand) string {
	baseTS := time.Now().Add(-time.Duration(3600+r.Intn(86400-3600)) * time.Second)
	out := journalTemplate
	ts := baseTS
	for i := 0; i < 14; i++ {
		ts = ts.Add(time.Duration(1+r.Intn(7)) * time.Second)
		out = strings.ReplaceAll(out, fmt.Sprintf("{{T%d}}", i), ts.Format("Jan 02 15:04:05"))
	}
	out = strings.ReplaceAll(out, "{{LOG_START}}", baseTS.Format("Jan 02 15:04:05"))
	out = strings.ReplaceAll(out, "{{LOG_END}}", ts.Add(5*time.Second).Format("Jan 02 15:04:05"))
	out = strings.ReplaceAll(out, "{{SESSION_TOKEN}}", sessionTokenHex)
	return out
}
