# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-06

### Breaking Changes

- **Module path migration**: Changed Go module path from `github.com/dropalldatabases/sif` to `github.com/vmfunc/sif`
  - **Impact**: Users importing sif as a Go library must update their import statements
  - **Action required**: Replace all imports: `github.com/dropalldatabases/sif` → `github.com/vmfunc/sif`, then run `go mod tidy`
  - **Note**: Binary users (Homebrew, AUR, releases) are unaffected - no action required

### Added

- Official v1.0.0 release with proper semantic versioning (SemVer)
- Package manager compliance for official Linux distribution repositories
  - Enables inclusion in Void Linux, Debian, Fedora, Arch official repos, and more
- Standardized repository references across all documentation and code

### Changed

- All documentation updated to reflect new `github.com/vmfunc/sif` repository location
- External runtime data URLs updated to `github.com/vmfunc/sif-runtime`
- Discord server URL updated to `discord.com/invite/sifcli`
- Adopted proper semantic versioning going forward:
  - `v1.x.0` - New features (minor version bumps)
  - `v1.0.x` - Bug fixes (patch version bumps)
  - `v2.0.0` - Future breaking changes (major version bumps)

### Migration Guide

#### For Binary Users (No Action Required)

If you install sif via:
- Homebrew: `brew install vmfunc/sif/sif`
- AUR: `yay -S sif` or `paru -S sif`
- Pre-built binaries from [releases](https://github.com/vmfunc/sif/releases)
- Linux package managers (Void, Arch, etc. - once available)

**You don't need to do anything.** The binary name (`sif`) and functionality remain the same.

#### For Go Library Users (Action Required)

If you import sif packages in your Go code:

1. **Update your imports**:
   ```go
   // Before (v2024.10.12 and earlier)
   import "github.com/dropalldatabases/sif/internal/config"
   import "github.com/dropalldatabases/sif/internal/scan"

   // After (v1.0.0+)
   import "github.com/vmfunc/sif/internal/config"
   import "github.com/vmfunc/sif/internal/scan"
   ```

2. **Update your go.mod**:
   ```bash
   go mod tidy
   ```

3. **Rebuild your project**:
   ```bash
   go build ./...
   ```

### Why This Change?

This migration enables sif to be packaged in official Linux distribution repositories, which require:
- Proper semantic versioning (not date-based or commit-based versions)
- Tagged, stable releases announced as ready for public use
- Consistent repository naming and branding

With v1.0.0, sif can now be:
- ✅ Packaged in official distribution repositories (not just user-maintained packages)
- ✅ Managed by system package managers with automatic updates
- ✅ Vetted and trusted by distribution maintainers
- ✅ Easier to install for users across all major Linux distributions

### Technical Details

This release updates **86 occurrences across 36 files**:
- 1 Go module declaration (`go.mod`)
- 72 Go import statements across 33 source files
- 5 external runtime data URLs
- 6 documentation references
- 2 workspace configuration entries

### Related

- GitHub Issue: [#57 - Module Migration to v1.0.0 for Package Manager Compliance](https://github.com/vmfunc/sif/issues/57)
- Previous release: v2024.10.12 (CalVer format)

---

## [v2024.10.12] - 2024-10-12

Last release using CalVer (calendar versioning) format. See commit history for details of changes in this and earlier releases.

---

**Note**: This CHANGELOG will be maintained going forward for all future releases following semantic versioning.
