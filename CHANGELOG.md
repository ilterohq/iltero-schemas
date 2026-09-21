# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `iltero_schemas.opa`: the pinned Open Policy Agent release (`PIN`, loaded from
  `PIN.json`) with the SHA-256 digest of its binary for Linux, macOS and Windows
  on x86_64 and aarch64, and `platform_key()` to select the entry for a host.
