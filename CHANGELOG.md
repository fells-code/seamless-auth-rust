# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/fells-code/seamless-auth-rust/compare/v0.1.0...v0.2.0) - 2026-10-08

### Added

- serve the admin console through console_router

## [0.1.0](https://github.com/fells-code/seamless-auth-rust/releases/tag/v0.1.0) - 2026-10-08

### Added

- Seamless Auth server adapter for Axum, driven by the auth API's adapter manifest: cookie and
  bearer transports, silent refresh shared for 5 seconds per refresh token, session tokens verified
  against the API's JWKS before any cookie is issued, kind-bound cookies, a `require_auth` tower
  layer and `User` extractor, `TrustedProxies`, and external delivery
- Passes the seamless-cli adapter conformance suite (25 of 25)
