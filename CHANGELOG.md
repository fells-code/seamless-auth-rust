# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0](https://github.com/fells-code/seamless-auth-rust/compare/v0.3.0...v0.4.0) - 2026-10-31

### Added

- verify-only resource server mode with audience, scope, role and step-up guards

### Fixed

- refuse scope and role guards that require nothing
- Origin allowlist with Sec-Fetch-Site, and verify the cookie's inner access token

## [0.3.0](https://github.com/fells-code/seamless-auth-rust/compare/v0.2.1...v0.3.0) - 2026-10-25

### Added

- deliver account recovery notices and pass through the v0.20 recovery routes
- refuse recovery sessions in require_auth and refresh them after enrollment

### Documentation

- link the governance document and license pledge

### Fixed

- cancel a recovery request when no owner notice was delivered
- refuse known placeholder secrets at startup
- *(console)* keep the API's framing and content-type headers on the console proxy

## [0.2.1](https://github.com/fells-code/seamless-auth-rust/compare/v0.2.0...v0.2.1) - 2026-10-18

### Documentation

- name the app-side service token SEAMLESS_SERVICE_TOKEN

### Fixed

- forward the pre-auth token on magic link verify and serve the confirm route ([#8](https://github.com/fells-code/seamless-auth-rust/pull/8))

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
