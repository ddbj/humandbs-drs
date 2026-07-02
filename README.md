# humandbs-drs

GA4GH DRS と Passport/Visa による controlled-access data サービス。
「認可（grant）を持つ利用者だけが controlled データを download できる」control plane を提供する。

## 概要

- 対象は controlled access に特化する。認証付きの upload/download や公開データ配信は範囲外であり、別サービスが担う。
- Passport/Visa による認可判断（Clearinghouse）と、認可された byte の配信を担う。presigned URL は使わず、配信 request ごとに認証・失効判定を行う。
- Go の同一 module・別 binary で構成する。
  - `cmd/drs` — DRS 1.5 API、Passport Clearinghouse、storage backend、認可付き配信。
  - `cmd/issuer` — 自前の Visa Issuer。grant を管理し、GA4GH 準拠の Visa を署名して発行する。

## 構成

| 構成要素 | 役割 | ポート |
| --- | --- | --- |
| humandbs-drs | DRS API + Clearinghouse + 配信 | 28000 |
| humandbs-issuer | Visa 発行 + grant DB | 28001 |
| Keycloak | identity provider（authN のみ） | 8180 |
| SeaweedFS | s3 モードの実データ保管先 | s3 8333 / master 9333 / filer 8888 / volume 8082 |

DRS の base path は `/ga4gh/drs/v1`。公開経路の TLS 終端と routing は上流の service-gateway が担う。

storage backend は s3（SeaweedFS）と filesystem（既存ディレクトリを read-only で DRS 化）の 2 モードを持ち、
暗号化はそれと直交する `none` / `at-rest` を選べる。

## ドキュメント

仕様は `docs/` を SSOT とする。

- [`docs/requirements.md`](docs/requirements.md) — 要件定義。
- [`docs/architecture.md`](docs/architecture.md) — アーキテクチャ（構成・controlled access フロー・各コンポーネント設計）。

## 現状

仕様（`docs/`）を策定済み。実装はこの仕様に基づいて進める。

## ライセンス

Apache License 2.0。詳細は [`LICENSE`](LICENSE) を参照。
