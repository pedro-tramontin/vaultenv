# Changelog

## [0.1.1](https://github.com/pedro-tramontin/vaultenv/compare/v0.1.0...v0.1.1) (2026-06-03)


### Features

* align vaultenv with upstream vault CLI token & env-var conventions ([#33](https://github.com/pedro-tramontin/vaultenv/issues/33)) ([56fcfff](https://github.com/pedro-tramontin/vaultenv/commit/56fcfffafb75c1711bc7b770aa4de0ad6a8ae4d8))


### Bug Fixes

* **parser:** accept # comments in V2 secrets files ([#29](https://github.com/pedro-tramontin/vaultenv/issues/29)) ([31f97cf](https://github.com/pedro-tramontin/vaultenv/commit/31f97cf4ecd8f37881f39e7653f00f19fa200f45))
* **release:** use RELEASE_PLEASE_TOKEN PAT to allow downstream release workflow ([#34](https://github.com/pedro-tramontin/vaultenv/issues/34)) ([93b4d63](https://github.com/pedro-tramontin/vaultenv/commit/93b4d63a85096fbd855a0b1895d79198c3c904c4))

## 0.1.0 (2026-06-01)


### Features

* add AppRole, LDAP, and Okta auth backends ([#10](https://github.com/pedro-tramontin/vaultenv/issues/10)) ([6fd4b17](https://github.com/pedro-tramontin/vaultenv/commit/6fd4b17b786ef0a045c59f2e83d615002d970124))
* add Azure MSI, GCP GCE, and AWS EC2 cloud auth backends ([#12](https://github.com/pedro-tramontin/vaultenv/issues/12)) ([ea1aaad](https://github.com/pedro-tramontin/vaultenv/commit/ea1aaada1794664113fe0a3d3ead3e90a4038957))
* add Release Please automation + CHANGELOG generation ([#20](https://github.com/pedro-tramontin/vaultenv/issues/20)) ([8edf693](https://github.com/pedro-tramontin/vaultenv/commit/8edf693707fc16bfe9baca53d4e59f3145671f3f))
* add Windows x64/x32 and Linux x32 release targets ([#18](https://github.com/pedro-tramontin/vaultenv/issues/18)) ([5de1616](https://github.com/pedro-tramontin/vaultenv/commit/5de1616acf26ecf6b95a6ba71a2dc6ecd2783b0d))
* **auth:** add JWT/OIDC pre-exchanged token authentication ([#13](https://github.com/pedro-tramontin/vaultenv/issues/13)) ([0f37b90](https://github.com/pedro-tramontin/vaultenv/commit/0f37b90653671cca1880bbb529e0633fea8330c1))
* cargo scaffold + module skeleton for Rust rewrite ([#1](https://github.com/pedro-tramontin/vaultenv/issues/1)) ([2c7260c](https://github.com/pedro-tramontin/vaultenv/commit/2c7260c11e7bba3cb7f74e4d5256bffee7cd7688))
* config validation, VAULT_ADDR parsing, env-file loading, auth resolution ([#4](https://github.com/pedro-tramontin/vaultenv/issues/4)) ([ca9db8d](https://github.com/pedro-tramontin/vaultenv/commit/ca9db8dde7d79e2d9abc1a7426c0687b843c07f0))
* end-to-end orchestration + execve (Phase 5) ([#7](https://github.com/pedro-tramontin/vaultenv/issues/7)) ([72f41d8](https://github.com/pedro-tramontin/vaultenv/commit/72f41d8f3e6b7916640dd5c82a55e1684beec608))
* tracing info-level logging + integration test strategy ([#8](https://github.com/pedro-tramontin/vaultenv/issues/8)) ([39761bb](https://github.com/pedro-tramontin/vaultenv/commit/39761bb6d0f935f22a262a96d3d5183550418f55))
* V2-only secrets file parser with winnow ([#5](https://github.com/pedro-tramontin/vaultenv/issues/5)) ([2ce76b9](https://github.com/pedro-tramontin/vaultenv/commit/2ce76b913887f9f7ea6f3b7585a6665097be40de))
* wiremock integration tests, improved logging, README ([#9](https://github.com/pedro-tramontin/vaultenv/issues/9)) ([ff58eca](https://github.com/pedro-tramontin/vaultenv/commit/ff58eca800dabc49089c39a4838e0df188c1977b))
