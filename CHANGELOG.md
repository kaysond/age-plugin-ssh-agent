# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/kaysond/age-plugin-ssh-agent/compare/v0.1.0...v0.1.1) - 2026-10-12

### Added

- add dependabot.yml

### Fixed

- require identity arg to be specified as SHA256 to avoid ambiguity
- update dependabot.yml to only include security fixes
- *(release)* don't tag every commit for release
- add audit.toml to ignore unused RSA advisory

### Other

- *(deps)* align crypto crate versions with age to reduce dependencies
- *(identity)* rename Identity.salt to the more appropriate "secret"
- *(deps)* bump base64 from 0.22.1 to 0.23.1 ([#5](https://github.com/kaysond/age-plugin-ssh-agent/pull/5))
- fix test review issues and fill coverage gaps
- add status badges to README.md
