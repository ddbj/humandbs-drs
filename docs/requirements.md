# humandbs-drs 要件定義

## 1. 概要とスコープ

humandbs-drs は、GA4GH DRS と Passport/Visa を用いた controlled-access data サービスである。
「認可（grant）を持つ利用者だけが controlled データを download できる」control plane を提供する。

対象は controlled access に限定する。認証付きの upload/download、公開データ配信、anonymous 配信、
利用者ごとの upload は範囲外であり、別サービス（public/private file server）が担う。
本サービスはそれらの配信基盤を持ち込まず、controlled data への認可判断と認可付き配信だけに責務を絞る。

システムは 2 つの binary から成る。

- DRS server: DRS 1.5.0 API、Passport Clearinghouse、認可付き byte 配信。
- Visa Issuer: 自前実装の Visa 発行者。grant を管理し、GA4GH 準拠の Visa を署名して発行する。

## 2. 用語

| 用語 | 意味 |
| --- | --- |
| DRS | GA4GH Data Repository Service。データオブジェクトを ID で参照・取得する API 規格 |
| DrsObject | DRS が返すデータオブジェクトのメタデータ（id, size, checksums, access_methods 等） |
| Passport | GA4GH Passport。複数の Visa を束ねた集合（`ga4gh_passport_v1`） |
| Visa | 個々の認可主張を表す署名付き JWT。本サービスは `ControlledAccessGrants` 型を扱う |
| Clearinghouse | Passport/Visa を検証して認可を判断する主体。DRS server が兼ねる |
| Issuer | Visa を署名・発行する主体。humandbs-issuer が担う |
| DAC | Data Access Committee。dataset へのアクセス承認を行う主体 |
| grant | 特定利用者に特定 dataset へのアクセスを認めた記録。Visa の裏付け |
| dataset | controlled data の認可単位。安定した resource URL で識別する |
| session token | 配信時の認可に使う短命 token。DRS が発行し request ごとに検証する |

## 3. アクターと構成要素

- 研究者（client）: dataset へのアクセスを申請し、承認後に controlled data を download する。
- DAC: 申請を審査し、grant を承認・取り消す。
- Keycloak: identity provider。利用者の認証（authN）だけを担い、Visa は発行しない。
- humandbs-issuer: Keycloak で認証された利用者に対し、grant に基づく Visa を署名して発行する。
- humandbs-drs: DRS API を提供し、Passport を検証し、認可された byte を配信する。
- storage: 実データの保管先。managed な S3、または既存ディレクトリ。

## 4. 機能要件

### 4.1 DRS API（DRS 1.5.0 最小 tier）

base path は `/ga4gh/drs/v1`。以下を提供する。bundle（`contents`）は提供しない。

- `GET /service-info`: サービス情報を返す。
- `GET /objects/{id}` / `POST /objects/{id}`: DrsObject を返す。POST は body で passport を受け取れる。
- `OPTIONS /objects/{id}`: 対応する認可方式（PassportAuth）を広告する。
- `GET /objects/{id}/access/{access_id}` / `POST /objects/{id}/access/{access_id}`: 配信用の AccessURL を返す。controlled data は POST で passport を提示して認可する。

### 4.2 Passport Clearinghouse

DRS server は提示された Passport（署名付き JWT）と、それに内包される各 Visa を検証し、認可を判断する。

- Passport 自体の署名・`typ`・有効期限を検証する。検証に失敗する Passport を含む request は全体を拒否する。
- 署名アルゴリズムを RS256 / ES256 に限定する（`none` や HMAC を拒否し、alg confusion を防ぐ）。
- `iss` を trusted-issuer allowlist で確認する。検証鍵は issuer ごとに設定した JWKS から out-of-band に取得して pin する。
- 鍵解決に用いる `jku` が当該 `iss` に対して信頼済み（pin 済み JWKS URL と一致）かを、fetch 前に検証する。
- `exp`（必須）が未来であること、`iat` が妥当であることを確認する。
- Visa の `sub` が Passport の `sub` と一致することを確認する。
- `ga4gh_visa_v1.type` が `ControlledAccessGrants` であること、`value` が対象 object の所属 dataset の識別子と一致すること、`by` が許容値（`dac` / `so` / `system`）であることを確認する。
- `conditions` がある場合は同一 Passport 内の他 Visa と合わせて DNF 評価し、条件を満たす時のみ受理する。

### 4.3 認可付き配信

- 認可が成立した object に対し、AccessURL として DRS 自身の配信 endpoint と `Authorization: Bearer <session token>` header を返す。
- 配信は DRS が byte stream として行う。presigned URL は提供しない。
- DRS は配信 request ごとに session token を検証する。

### 4.4 Visa Issuer

- `GET /permissions/{user}`: 利用者の grant に基づく署名済み Passport（`ga4gh_passport_v1` claim に Visa を内包する JWT）を返す。
- `GET /jwks`: Visa 署名の検証用公開鍵を返す。
- Keycloak の access token を検証して subject を確定する。
- grant を保持し、それを裏付けとして GA4GH 準拠の Visa を署名・発行する。

### 4.5 storage backend

- storage backend は 2 モードを持ち、interface で切り替える。
  - s3: managed な S3 に実データを載せる。upload も受けられる。
  - filesystem: 既存ディレクトリを移動せず read-only で DRS object 化する。
- どちらのモードでも DRS API から見た挙動は同一である。

### 4.6 暗号化

- 暗号化は storage backend と直交する EncryptionProvider として提供する。
- `none`（平文）と `at-rest`（保管中は暗号化し、配信時に server が復号）を提供する。at-rest を要件に含める。

### 4.7 grant 剥奪の即時反映

- DAC が grant を取り消した場合、その利用者の controlled data への配信を即時に停止できる。
- 停止は、発行済み session token の失効によって配信 request 単位で反映される。失効は認証付きの内部 admin 呼び出しで `(subject, dataset)` 単位に行い、次の配信 request（range 単位）から反映される（配信経路は architecture.md § 配信設計）。

## 5. 非機能要件

### 5.1 セキュリティ

- Visa 検証で alg confusion を遮断する（4.2）。
- `jku` の事前検証により、鍵すり替えや SSRF を防ぐ。JWKS は out-of-band に pin し、`jku` は補助的に扱う。
- grant 剥奪を即時に配信へ反映する。
- 配信を byte 単位で audit できる。配信 request ごとに認可判断を行い、object・subject・dataset・issuer・要求 range・送出 byte 数・結果を記録する。
- 公開 routing と TLS 終端は組織の service-gateway が担う。本サービスは TLS 終端を持たない前提とする。

### 5.2 可搬性

- storage backend と暗号化を独立した interface とし、組み合わせを差し替え可能にする。

### 5.3 運用・スケール

- 単一プロセスで動作する。配信性能が問題化した場合は水平スケールや前段 proxy の導入余地とする。

### 5.4 データ整合

- 実データを保持する storage（S3/FS）を SSOT とする。
- DRS が持つ index は storage から再構築可能な derived cache であり、破棄・再生成できる。

## 6. スコープ外

- public/private file server が担う機能（認証付き upload/download、公開データ配信、anonymous 配信、利用者ごとの upload）。
- DRS bundle（`contents`）。
- presigned URL による配信。
- 公開 routing・TLS 終端（service-gateway が担う）。

## 7. PoC スコープと将来余地

- 暗号化は `at-rest` を要件とする。client 側で復号する crypt4gh（E2E）は interface を用意するに留め、実装は将来とする。
- grant の投入は admin API と seed で行う（申請審査 UI は持たない）。本番の申請・審査 DB との接続は将来とする。
- CLI/workflow からの download 認証（device code flow 等）は将来とする。

## 8. 未確定事項

- at-rest 暗号化の鍵管理（rotation と KMS 連携の方針。暫定は config で与える鍵 file の単一鍵）。
- filesystem モードで既存の暗号化領域と接続する場合の復号方式。
- grant source の本番像（既存の申請・審査 DB との接続方法）。
- CLI/workflow からの download 認証フローの具体。
