/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import "testing"

func FuzzDetectLFIFromResponse(f *testing.F) {
	f.Add("root:x:0:0:root:/root:/bin/bash")
	f.Add("<html><body>Hello World</body></html>")
	f.Add("[boot loader]\ntimeout=30")
	f.Add("DOCUMENT_ROOT=/var/www/html")
	f.Add("<?php echo 'hello'; ?>")
	f.Add("127.0.0.1   localhost")
	f.Add("")
	f.Add("PD9waHAgZWNobyAnaGVsbG8nOyA/Pg==")

	f.Fuzz(func(t *testing.T, body string) {
		// should never panic
		DetectLFIFromResponse(body)
	})
}

func FuzzIsAdminPanel(f *testing.F) {
	f.Add("<html>phpMyAdmin</html>", "phpMyAdmin")
	f.Add("<html>adminer</html>", "Adminer")
	f.Add("<html>pgadmin</html>", "pgAdmin")
	f.Add("<html>nothing here</html>", "phpMyAdmin")
	f.Add("", "unknown")
	f.Add("<html>database query mysql</html>", "generic")

	f.Fuzz(func(t *testing.T, body string, panelType string) {
		// should never panic
		isAdminPanel(body, panelType)
	})
}

func FuzzDatabaseErrorPatterns(f *testing.F) {
	f.Add("you have an error in your sql syntax")
	f.Add("Warning: mysql_fetch_array()")
	f.Add("postgresql error at character 42")
	f.Add("ORA-12345: some oracle error")
	f.Add("sqlite3_prepare_v2 failed")
	f.Add("document bson error in mongodb")
	f.Add("<html>normal page</html>")
	f.Add("")

	f.Fuzz(func(t *testing.T, body string) {
		// should never panic on any input
		for _, pattern := range databaseErrorPatterns {
			pattern.pattern.MatchString(body)
		}
	})
}
