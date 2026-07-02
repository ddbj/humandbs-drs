# humandbs-drs アーキテクチャ

## 1. 全体構成

4 つの構成要素から成る。humandbs-drs と humandbs-issuer は同一 Go module の別 binary である。

| 構成要素 | 実体 | 役割 |
| --- | --- | --- |
| humandbs-drs | Go binary `cmd/drs` | DRS 1.5 API、Passport Clearinghouse、storage backend、認可付き配信 |
| humandbs-issuer | Go binary `cmd/issuer` | Visa の署名・発行、grant DB |
| Keycloak | `quay.io/keycloak/keycloak:26` | identity provider（authN のみ） |
| SeaweedFS | `chrislusf/seaweedfs:4.x` | s3 モードの実データ保管先 |

ポート:

| 構成要素 | ポート |
| --- | --- |
| humandbs-drs | 28000 |
| humandbs-issuer | 28001 |
| Keycloak | 8180 |
| SeaweedFS | s3 8333 / master 9333 / filer 8888 / volume 8082 |

DRS の base path は `/ga4gh/drs/v1`（DRS 規格が要求する）。公開経路では上流の service-gateway が
`/ga4gh/` を humandbs-drs（28000）へ proxy し、TLS 終端も gateway が担う。

```
   client
     |
     v
+-----------+        +--------------------+
| gateway   | -----> | humandbs-drs       | --> storage (S3 / FS)
| (TLS,     |        | (DRS + CH +        |
|  routing) |        |  delivery)         |
+-----------+        +--------------------+
     |                        ^
     |                        | verify visa (jwks)
     v                        |
+-----------+        +--------------------+
| Keycloak  | <----- | humandbs-issuer    |
| (authN)   | authN  | (visa + grant DB)  |
+-----------+        +--------------------+
```

## 2. controlled access フロー

```
researcher       issuer          drs            storage
   | apply, DAC approve            |               |
   | login (Keycloak)             |               |
   |-------------->|              |               |
   | GET /permissions             |               |
   |-------------->|              |               |
   | passport      |              |               |
   |<--------------|              |               |
   | OPTIONS /objects/{id}         |              |
   |------------------------------>|              |
   | Authorizations (PassportAuth) |              |
   |<------------------------------|              |
   | POST /objects/{id}/access/{access_id} + passport
   |------------------------------>|              |
   |        verify each visa       |              |
   |        (sig, iss, jku, exp,   |              |
   |         value == dataset)     |              |
   | access_url + Bearer <token>   |              |
   |<------------------------------|              |
   | GET access_url + Bearer <token>              |
   |------------------------------>| read bytes   |
   |        verify token           |------------->|
   |        (per request)          |              |
   |        decrypt if at-rest     |<-------------|
   | byte stream                   |              |
   |<------------------------------|              |
```

1. 研究者が dataset にアクセス申請し、DAC が承認する。承認は issuer の grant として記録される。
2. 研究者は Keycloak で login し、issuer から Passport を取得する。
3. 研究者は DRS に `OPTIONS /objects/{id}` を投げ、対応する認可方式（PassportAuth と信頼する issuer）を得る。
4. 研究者は `POST /objects/{id}/access/{access_id}` に Passport を提示する。
5. DRS（Clearinghouse）が各 Visa を検証し、成立すれば AccessURL（配信 endpoint と `Authorization` header）を返す。
6. 研究者はその URL に Bearer token 付きで GET する。DRS は request ごとに token を検証し、storage から byte を stream する（at-rest なら stream 途中で復号）。
7. DAC が grant を取り消すと、issuer は以後 Visa を出さず、DRS は該当 session token を revoke して配信を即時に止める。

## 3. DRS server 設計

endpoint:

| endpoint | 役割 |
| --- | --- |
| `GET /service-info` | `type.group=org.ga4gh`, `type.artifact=drs`, `type.version="1.5"` と `id` / `name` / `organization` / `version` |
| `GET /objects/{id}` | DrsObject を返す。`expand` query に対応 |
| `POST /objects/{id}` | 同上。body で `expand` と `passports` を受け取れる |
| `OPTIONS /objects/{id}` | `Authorizations`（`supported_types:[PassportAuth]`, `passport_auth_issuers`）を返す |
| `GET /objects/{id}/access/{access_id}` | AccessURL を返す |
| `POST /objects/{id}/access/{access_id}` | 同上。body の `passports` で認可する |

DrsObject:

- 必須フィールドは `id`, `self_uri`, `size`, `created_time`, `checksums`（最低 1 つ）。blob では `access_methods` を持つ。
- `self_uri` は hostname-based で `drs://<host>/<id>`。
- checksum は `sha-256` を取り込み時に計算し、index に保存する。
- object ID の採番は下記「object ID scheme」に従う。
- bundle（`contents`）は作らない。
- cold storage は将来 `202 + Retry-After` と `access_method.available:false` で表現する余地を残す。

### object ID scheme

DRS URI は hostname-based（`drs://<host>/<id>`）とする。ID は opaque な文字列で、unreserved 文字（`[A-Za-z0-9.-_~]`）だけで構成し `/` を含めない。`/` を含む ID は API 呼び出し時に percent-encode が必要で、`/objects/{id}/access/{access_id}` の path 解釈と衝突しやすいためである。

ID の生成は取り込み時の scheme とし、storage backend ごとに異なる。いずれも一意かつ安定で、`self_uri` に載る canonical な ID を 1 つ持つ。

- s3 モード: server が UUID を採番し、object metadata に焼く。index を破棄しても metadata から ID を復元できる。
- filesystem モード（read-only）: file を書き換えられないため、dataset resource URL と相対 path から決定論的に ID を導く。`id = base64url(sha-256(dataset resource URL + NUL + 相対 path))`（padding なしの URL-safe base64、`[A-Za-z0-9_-]` は unreserved の部分集合で `/` を含まない）。区切りの NUL は URL にも POSIX path にも現れないため、`(URL, 相対 path)` の連結は単射で、異なる組が同じ入力に潰れない。ディレクトリを再 scan するだけで同じ ID を復元でき、index を derived cache のまま保てる。

1 つの object に複数の ID を割り当ててよい。将来 file に authoritative な accession が付与された場合は、それを alias として追加し、必要に応じて `self_uri` の canonical をその accession に昇格する。既存の `drs://` URI は引き続き解決可能に保つ。

## 4. Clearinghouse 設計

DRS server が Passport Clearinghouse を兼ねる。`POST /objects/{id}` および `.../access/{access_id}` の
body `{"passports":[JWT...]}` を受け、各 Visa を次の順で検証する。

- 署名アルゴリズムを RS256 / ES256 に限定する。
- `iss` を trusted-issuer allowlist で確認する。当面は humandbs-issuer 1 つを pin する。将来 NIH RAS や ELIXIR 等の外部 issuer を allowlist に追加できる。
- header の `jku` が当該 `iss` に対して信頼済みかを fetch 前に検証する。JWKS は out-of-band に pin し、`jku` は補助扱いとする。
- `exp`（必須）が未来であること、`iat` が妥当であることを確認する。
- `ga4gh_visa_v1.type == ControlledAccessGrants`、`value` が対象 object の所属 dataset の識別子と一致、`by` が許容値（`dac` 等）であることを確認する。
- `conditions` があれば同一 Passport 内の他 Visa と DNF 評価し、満たす時のみ受理する。

検証が成立すると、配信用の session token を発行する（§7）。

## 5. Issuer 設計

`cmd/issuer` が担う。

- endpoint: `GET /permissions/{user}` が Passport（`ga4gh_passport_v1`）を、`GET /jwks` が公開鍵を返す。
- 入力: Keycloak の access token を検証（`coreos/go-oidc`）して subject を確定する。
- grant DB: `(subject, dataset_id, dac_source, asserted, expires, conditions)`。SQLite に admin API/seed で投入する。grant は `(subject, dataset_id)` で一意（再投入は上書き）、`expires` は NULL で無期限を表す。
- Visa 組み立て（GA4GH 準拠）:
  - claim `ga4gh_visa_v1 = {type:"ControlledAccessGrants", value:<dataset resource URL>, source:<DAC URL>, by:"dac", asserted:<epoch>}`。
  - 標準 claim `iss`（issuer の public URL）, `sub`, `iat`, `exp`。
  - `exp` は発行時刻 + TTL（設定値、既定 1h）を上限とし、grant の `expires` がそれより早い場合は `expires` を用いる。無期限 grant（`expires` NULL）は TTL でキャップされる。
  - header `alg:RS256`, `kid`, `jku`（issuer の JWKS URL）。
  - Visa Document Token 形式（自前鍵で署名した self-contained な JWT）。
- 署名鍵: 自前の RSA-2048。`kid` を付す。rotation と JWKS の可用性は運用で担保する。

identity は issuer と DRS が同じ Keycloak を使うことで揃える。`visa.sub` が Keycloak の subject と一致し、
DRS が見る identity とも一致するため、account linking 用の別テーブルを持たない。

## 6. dataset 識別

controlled data の認可単位は dataset であり、安定した resource URL で識別する。

- object は 1 つの dataset resource URL に属する。この対応は index が保持する。
- Visa の `ControlledAccessGrants.value` はこの dataset resource URL と一致する。Clearinghouse はこの一致で認可を判断する。
- dataset resource URL は特定の識別体系に依存しない不透明な文字列として扱う。現状の具体値は DDBJ の JGA dataset entry URL（例 `https://ddbj.nig.ac.jp/search/entry/jga-dataset/JGAD000001`）を用いる。
- 認可判断は文字列の完全一致で行うため、canonical な形を 1 つに固定し、issuer と DRS で同一の文字列を用いる。同じ resource の別表現（`.json` などの representation URL）は value に用いない。

## 7. 配信設計

- controlled download は `GET <配信 endpoint>` に `Authorization: Bearer <session token>` を付けて行う。
- session token は opaque な token とし、DRS が server-side の session store で保持する。
- DRS は配信 request ごとに store を照合して token を検証し、storage backend から byte を stream する。EncryptionProvider が `at-rest` の場合は stream 途中で復号する。
- token の失効は 2 つの機構を持つ。
  - 短い TTL（数分）による自然失効。TTL 内は再認可なしに配信を継続できる。
  - admin/issuer からの明示 revoke。store から token を無効化し、進行中の download も次の request から拒否する。
- range request ごとに再認可が効く。
- byte を流すのは DRS プロセス自身である。配信性能が問題化した場合は水平スケールや前段 proxy の導入余地とする。

## 8. storage backend と暗号化

「どこに置くか」と「どう暗号化するか」を独立した interface とする。

StorageBackend（どこに置くか）:

- `s3`: SeaweedFS を建てて実データを載せる。upload も受けられる。
- `filesystem`: 既存ディレクトリを移動せず read-only で DRS object 化する。`(root directory, dataset resource URL)` の対応を manifest で与え、各 root subtree を 1 つの dataset として扱う。既存ディレクトリはその場で指すだけで、data tree には手を加えない。walk は regular file だけを object 化し、ID を採番して index に登録する。symlink（追うと tree 外へ脱出し得る）、dotfile / dot-directory（`.git` 等の system/VCS metadata）、その他の非 regular file は object 化しない。空 file（0 byte）は object として扱う。

いずれのモードでも DRS API からは同一に見える。filesystem は presign できないため、配信は Go が stream で統一する。

EncryptionProvider（どう暗号化するか）:

- `none`: 平文。
- `at-rest`: 保管中は暗号化し、配信時に server が復号して byte を流す。鍵は server が管理する。
- `crypt4gh`（将来）: 暗号化ファイルをそのまま流し、client が自分の鍵で復号する。server も経路も平文を見ない。

組み合わせ例: `(s3, at-rest)`, `(filesystem, none)`, `(filesystem, at-rest)`。将来 `(_, crypt4gh)`。

## 9. index

- 保持内容: `DRS ID` から、実データの所在（s3 key または FS path）、`size`、`sha-256`、所属 dataset（dataset resource URL）、`created_time` への対応。`created_time` は再 scan で復元できる storage 側の事実に取り、filesystem モードでは file の mtime を用いる。
- storage（S3/FS）を SSOT とし、index は破棄して再構築できる。DRS ID は「object ID scheme」に従い、s3 は object metadata から、filesystem は相対 path から決定論的に復元する。
- object の所属 dataset（dataset resource URL）は取り込み時に確定する。s3 モードは object metadata か key prefix 規約に、filesystem モードは manifest の `(root, dataset resource URL)` 対応に持たせる。この対応も storage 側の規約（と manifest）に載るため、index を再構築できる。
- 更新: s3 モードは SeaweedFS filer の `SubscribeMetadata` gRPC change feed もしくは定期 scan。filesystem モードは dir scan。再構築は現在の tree に対する全置換で、追加・削除が反映され、同一 tree なら同一 rows に収束する。
- エンジンは SQLite（単一ファイル。derived なので durability は要求しない）。
