# humandbs-drs

GA4GH DRS と Passport/Visa による controlled-access data サービス。
「認可（grant）を持つ利用者だけが controlled データを download できる」control plane を提供する。

## 概要

- 対象は controlled access に特化する。認証付きの upload/download や公開データ配信は範囲外であり、別サービスが担う。
- Passport/Visa による認可判断（Clearinghouse）と、認可された byte の配信を担う。presigned URL は使わず、配信 request ごとに認証・失効判定を行う。
- Go の同一 module・別 binary で構成する。
  - `cmd/drs` — DRS 1.5 API、Passport Clearinghouse、storage backend、認可付き配信。
  - `cmd/issuer` — 自前の Visa Issuer。grant を管理し、GA4GH 準拠の Visa を署名して発行する。
- 補助 CLI として `cmd/drs-s3-ingest`（s3 backend への object 取り込みと DRS ID 採番）と
  `cmd/drs-encrypt`（filesystem at-rest 用に平文 file を envelope 形式へ変換）を同梱する。

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

## ローカルスタック

`compose.yaml` は 4 コンポーネント（drs / issuer / Keycloak / SeaweedFS）の骨格
（ポート・依存関係・healthcheck・内部配線）だけを定義する。動かすには site 固有の設定
（Keycloak realm、drs の storage 設定と service 情報、issuer の grant seed）を
override file で与える。`test/e2e/compose.e2e.yaml` がその実例である。

```console
$ make e2e-up     # compose.yaml + test/e2e/compose.e2e.yaml を build して起動
$ make test-e2e   # 起動済みスタックに対して end-to-end テストを実行
$ make e2e-down   # スタックと volume を破棄
```

## テスト

| コマンド | 内容 | 前提 |
| --- | --- | --- |
| `make test` | unit テスト | なし（外部依存なしで green） |
| `make test-integration` | SeaweedFS を使う storage / ingest の統合テスト | `docker compose up -d seaweedfs` |
| `make test-e2e` | controlled-access フローの end-to-end テスト（fs / s3 両モードの happy-path・剥奪即時性・401/403） | `make e2e-up` |

e2e テストは `HUMANDBS_E2E` が未設定なら skip するため、既定の `go test ./...` は
スタックなしで green を保つ。AccessURL の scheme は https（TLS 終端は上流 gateway の責務）
だが、compose には gateway を含めないため、テストは http に差し替えて drs を直接叩く。

## 現状

`docs/` の仕様のうち controlled-access の縦 slice（DRS 1.5 API、Passport
Clearinghouse、storage 2 モード、at-rest 暗号化、session token と剥奪即時反映、
Visa Issuer）を実装済み。grant 投入は seed file で行う（admin API と申請・審査
UI は未実装）。

## ライセンス

Apache License 2.0。詳細は [`LICENSE`](LICENSE) を参照。
