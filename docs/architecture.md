# humandbs-drs アーキテクチャ

## 1. 全体構成

4 つの構成要素から成る。humandbs-drs と humandbs-issuer は同一 Go module の別 binary である。

| 構成要素 | 実体 | 役割 |
| --- | --- | --- |
| humandbs-drs | Go binary `cmd/drs` | DRS 1.5 API、Passport Clearinghouse、storage backend、認可付き配信 |
| humandbs-issuer | Go binary `cmd/issuer` | Visa の署名・発行、grant DB |
| Keycloak | `quay.io/keycloak/keycloak:26.3.1` | identity provider（authN のみ） |
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
| `OPTIONS /objects/{id}` | `Authorizations`（`supported_types:[PassportAuth]`, `passport_auth_issuers`, `drs_object_id`）を返す |
| `GET /objects/{id}/access/{access_id}` | AccessURL を返す |
| `POST /objects/{id}/access/{access_id}` | 同上。body の `passports` で認可する |

DrsObject:

- 必須フィールドは `id`, `self_uri`, `size`, `created_time`, `checksums`（最低 1 つ）。blob では `access_methods` を持つ。
- `access_methods` は 1 object につき 1 つ。`type: "https"` と `access_id` を持ち、`access_url` は直接載せない。配信 URL は access endpoint（`/objects/{id}/access/{access_id}`）を経て取得し、未認可の client に配信先を露出させない。
- `self_uri` は hostname-based で `drs://<host>/<id>`。
- `size` と checksum は client が受け取る平文（EncryptionProvider が返す byte 列。§8）に対する値である。checksum は取り込み時に平文の `sha-256` を計算して index に保存し、`{checksum: <hex>, type: "sha-256"}` の形で返す。
- object ID の採番は下記「object ID scheme」に従う。
- bundle（`contents`）は作らない。
- cold storage は将来 `202 + Retry-After` と `access_method.available:false` で表現する余地を残す。
- access endpoint は認可が成立した object にのみ AccessURL を返す。有効な Passport の提示が無ければ 401 で PassportAuth を要求し、Passport は有効だが対象 dataset への認可が無ければ 403 を返す（認可判断は §4 Clearinghouse が担う）。
- service-info の `id` / `name` / `organization`（`name`, `url`）は配備ごとの設定値で与える。`type` の group / artifact / version（`org.ga4gh` / `drs` / `1.5`）と service の `version`（build version）は server が固定的に供給する。bulk 非対応でも schema 準拠のため `maxBulkRequestLength` を出す。

### object ID scheme

DRS URI は hostname-based（`drs://<host>/<id>`）とする。ID は opaque な文字列で、unreserved 文字（`[A-Za-z0-9.-_~]`）だけで構成し `/` を含めない。`/` を含む ID は API 呼び出し時に percent-encode が必要で、`/objects/{id}/access/{access_id}` の path 解釈と衝突しやすいためである。

ID の生成は取り込み時の scheme とし、storage backend ごとに異なる。いずれも一意かつ安定で、`self_uri` に載る canonical な ID を 1 つ持つ。

- s3 モード: server が UUID を採番し、object metadata に焼く。index を破棄しても metadata から ID を復元できる。
- filesystem モード（read-only）: file を書き換えられないため、dataset resource URL と相対 path から決定論的に ID を導く。`id = base64url(sha-256(dataset resource URL + NUL + 相対 path))`（padding なしの URL-safe base64、`[A-Za-z0-9_-]` は unreserved の部分集合で `/` を含まない）。区切りの NUL は URL にも POSIX path にも現れないため、`(URL, 相対 path)` の連結は単射で、異なる組が同じ入力に潰れない。ディレクトリを再 scan するだけで同じ ID を復元でき、index を derived cache のまま保てる。

1 つの object に複数の ID を割り当ててよい。将来 file に authoritative な accession が付与された場合は、それを alias として追加し、必要に応じて `self_uri` の canonical をその accession に昇格する。既存の `drs://` URI は引き続き解決可能に保つ。

## 4. Clearinghouse 設計

DRS server が Passport Clearinghouse を兼ねる。`POST /objects/{id}` および `POST /objects/{id}/access/{access_id}` の
body `{"passports":[JWT...]}` を受ける。access endpoint はこれで認可を判断する。`POST /objects/{id}` は
同じ body を受けるが、DrsObject の metadata は公開 tier であり `access_url` を直載せしない（§3）ため、
passports を認可判断に用いない。

### 信頼設定

- trusted issuer は設定で「issuer URL と JWKS URL」の組として与える。当面は humandbs-issuer 1 つを pin する。将来 NIH RAS や ELIXIR 等の外部 issuer を追加できる。
- DRS は起動時に各 JWKS URL から公開鍵を取得して pin する（out-of-band 供給）。鍵 rotation の反映は再起動で行う。
- token の `jku` からの鍵取得は行わない。`jku` は「当該 `iss` の pin 済み JWKS URL と完全一致するか」の補助チェックに使う（AAI spec が求める「fetch 前の信頼検証」を、fetch しないことで満たす）。

### Passport（envelope）の検証

`passports` の各要素は署名付き Passport JWT であり、次を検証する。

- 署名アルゴリズムを RS256 / ES256 に限定する（`none` / HMAC を拒否し、alg confusion を防ぐ）。
- header `typ` が `vnd.ga4gh.passport+jwt` であること（RFC 7515 §4.1.9 の比較規則。case-insensitive、`application/` prefix 許容）。
- `iss` が trusted issuer allowlist にあり、pin 済み公開鍵（`kid` で選択）で署名を検証できること。
- `iat` / `exp`（いずれも必須）が妥当であること。
- `aud` が存在する token は受理しない（audience 制限付き token の転用を拒否する。Visa も同様）。
- `ga4gh_passport_v1` claim（Visa JWT の配列。空配列可）が存在すること。

検証に失敗する Passport が 1 つでも含まれる request は全体を拒否する（Passport spec §8.1）。

### Visa の検証

Passport に内包される各 Visa（Visa Document Token）を次の順で検証する。検証に失敗した Visa は無視する。

- 署名アルゴリズムを RS256 / ES256 に限定する。
- `iss` を trusted issuer allowlist で確認する。
- header の `jku`（Document Token では必須）が当該 `iss` の pin 済み JWKS URL と完全一致すること。
- pin 済み公開鍵で署名を検証できること。`exp`（必須）が未来、`iat` が妥当であること。
- `sub` が Passport の `sub` と一致すること（LinkedIdentities による別 identity の紐付けは行わない）。
- `ga4gh_visa_v1` の必須 field（`type` / `asserted` / `value` / `source`）が揃っていること。

### 認可判断

検証を通った Visa のうち、次を満たすものがあれば認可が成立する。

- `type == ControlledAccessGrants`
- `value` が対象 object の所属 dataset resource URL（§6）と case-sensitive に完全一致
- `by` が `dac` / `so` / `system` のいずれか（`self` / `peer` / 欠落は拒否）
- `conditions` があれば、同一 Passport 内の検証済み Visa と DNF 評価して真

`conditions` の評価は GA4GH Passport spec v1.2 の規則に従う。

- 外側 list = OR、内側 list = AND。各 condition clause は `type` と最低 1 つの他 claim（`value` / `source` / `by`）を持つ。
- 値は `const:`（case-sensitive 完全一致）/ `pattern:`（`?` `*` の case-sensitive glob、escape なし）/ `split_pattern:`（visa 側の claim 値を `;` で分割し各部分に pattern）。
- 1 つの clause 内の全 claim は同一の Visa にマッチしなければならない。
- `conditions` を持つ Visa は照合対象にならない（条件の再帰なし）。
- 未知の prefix・未知の claim key を含む clause は不成立として扱う。構造が不正な `conditions` を持つ Visa は拒否する。

認可が成立すると、配信用の session token を発行し AccessURL を返す（§7）。成立しない場合、有効な Passport が
1 つも提示されなければ 401、Passport は有効だが認可する Visa が無ければ 403 を返す（§3）。

### 上限

request body（1 MiB）、`passports` の要素数、Passport あたりの Visa 数、`conditions` の clause 数に上限を設け、超過は検証失敗として扱う。

## 5. Issuer 設計

`cmd/issuer` が担う。

- endpoint: `GET /permissions/{user}` が署名済み Passport JWT を `{"passport": "<JWT>"}` で、`GET /jwks` が公開鍵を返す。
- 入力: Keycloak の access token を検証（`coreos/go-oidc`）して subject を確定する。
- grant DB: `(subject, dataset_id, dac_source, asserted, expires, conditions)`。SQLite に起動時 seed（seed file の読み込み）で投入する。grant は `(subject, dataset_id)` で一意（再投入は上書き）、`expires` は NULL で無期限を表す。運用中の投入・剥奪 HTTP API は本番の grant source 連携と併せて将来とする（requirements § PoC スコープ）。
- Visa 組み立て（GA4GH 準拠）:
  - claim `ga4gh_visa_v1 = {type:"ControlledAccessGrants", value:<dataset resource URL>, source:<DAC URL>, by:"dac", asserted:<epoch>}`。
  - 標準 claim `iss`（issuer の public URL）, `sub`, `iat`, `exp`。
  - `exp` は発行時刻 + TTL（設定値、既定 1h）を上限とし、grant の `expires` がそれより早い場合は `expires` を用いる。無期限 grant（`expires` NULL）は TTL でキャップされる。
  - header `alg:RS256`, `kid`, `jku`（issuer の JWKS URL）。
  - Visa Document Token 形式（自前鍵で署名した self-contained な JWT）。
- Passport 組み立て（GA4GH AAI 準拠）:
  - visa 群を `ga4gh_passport_v1` claim（Visa JWT の配列）に載せ、標準 claim `iss` / `sub` / `iat` / `exp` を持つ JWT として同じ鍵で署名する。
  - header `alg:RS256`, `kid`, `typ:vnd.ga4gh.passport+jwt`。
  - `exp` は発行時刻 + TTL（visa と同じ設定値）。内包する各 visa の `exp` は grant によりこれより早くなりうる。
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

- controlled download は `GET /data/{object_id}`（`HEAD` も可）に `Authorization: Bearer <session token>` を付けて行う。認可成立時の AccessURL は `{url: "https://<host>/data/<object_id>", headers: ["Authorization: Bearer <session token>"]}` の形で返す。公開経路では `/data/` も service-gateway が humandbs-drs へ proxy する（§1 の `/ga4gh/` と同様）。
- session token は opaque な token（暗号論的乱数）とし、DRS が server-side の session store で保持する。token は発行時の object・dataset・subject に紐づき、別 object への流用はできない。
- DRS は配信 request ごとに store を照合して token を検証する。検証を通らない request は、token が無い・未知・失効なら 401（`WWW-Authenticate: Bearer`）で、他 object 宛の token なら 403 で拒否する。検証を通れば storage backend から byte を stream する。byte を平文へ変換するのは EncryptionProvider で、`none` は素通し、`at-rest` は stream 途中で復号する（§8）。配信 handler は range を EncryptionProvider が返す平文に対して適用するため、range と復号の対応は EncryptionProvider の内側で閉じる。
- token の失効は 2 つの機構を持つ。
  - 短い TTL（既定 5 分、設定値）による自然失効。TTL 内は再認可なしに配信を継続できる。
  - 明示 revoke。session store から該当 session を無効化し、進行中の download も次の request から拒否する。revoke の単位は `(subject, dataset)` で、DAC の grant 剥奪 1 件に対応する。subject だけを指定するとその利用者の全 session を止める。
- 明示 revoke は DRS の `POST /admin/revoke`（body `{"subject": <subject>, "dataset": <dataset resource URL>}`、`dataset` 省略で subject 全体）で行い、無効化した session 数を返す。この endpoint は内部の control-plane であり、公開 gateway からは front しない。issuer / admin が内部網から共有 admin secret（`Authorization: Bearer <admin secret>`）で呼ぶ。admin secret 未設定時は revoke を提供しない（503、fail-closed）。
- range request と条件付き request に対応する（RFC 7233 / 7232）。object の平文 sha-256 を強 ETag、file mtime を Last-Modified として出し、`If-Range` は range を、`If-None-Match` / `If-Modified-Since` は条件付き GET（304 Not Modified）を制御する。書き込み向けの `If-Match` / `If-Unmodified-Since` は read-only な配信では扱わない。単一 range は 206 と `Content-Range` で返し、範囲外の range は 416（`Content-Range: bytes */size`）、複数 range・解釈不能な `Range` header は Range を無視して 200 全体を返す。`Accept-Ranges: bytes` を広告し、応答は `Content-Type: application/octet-stream`・`Content-Disposition: attachment`（不透明 blob のため file 名は付けない）とする。range request ごとに token 再検証が効くため、剥奪は次の range から反映される。
- 配信は byte 単位で audit する。配信 request ごとに object・subject・dataset・issuer・要求 range・送出 byte 数・結果を記録する（§5.1）。
- byte を流すのは DRS プロセス自身である。配信性能が問題化した場合は水平スケールや前段 proxy の導入余地とする。

## 8. storage backend と暗号化

「どこに置くか」と「どう暗号化するか」を独立した interface とする。

StorageBackend（どこに置くか）:

- `s3`: SeaweedFS を建てて実データを載せる。upload も受けられる。
- `filesystem`: 既存ディレクトリを移動せず read-only で DRS object 化する。`(root directory, dataset resource URL)` の対応を manifest で与え、各 root subtree を 1 つの dataset として扱う。既存ディレクトリはその場で指すだけで、data tree には手を加えない。walk は regular file だけを object 化し、ID を採番して index に登録する。symlink（追うと tree 外へ脱出し得る）、dotfile / dot-directory（`.git` 等の system/VCS metadata）、その他の非 regular file は object 化しない。空 file（0 byte）は object として扱う。

いずれのモードでも DRS API からは同一に見える。filesystem は presign できないため、配信は Go が stream で統一する。

EncryptionProvider（どう暗号化するか）: 配信 handler は EncryptionProvider から object の平文に対する reader を得て range を当てる。`none` は storage の reader を素通しし、`at-rest` は復号 reader を返す。range と復号の対応はこの内側で閉じる（§7）。

- `none`: 平文。
- `at-rest`: 保管中は暗号化し、配信時に server が復号して byte を流す。鍵は server が管理する。
  - 方式は chunk 化 AES-256-GCM（chunk は既定 64 KiB）。chunk 境界へ seek して該当 chunk だけを復号するため range 配信でき、読んだ chunk は必ず AEAD の完全性検証を通る。鍵不一致や ciphertext の改竄は復号エラーとして配信を止める。
  - on-disk は envelope 形式: header（magic `HDRS`、version、chunk size、object ごとの乱数 nonce prefix）に chunk 列（各 chunk = 平文 chunk の GCM ciphertext + 認証 tag）が続く。chunk の nonce は `prefix ‖ chunk 番号 ‖ 最終 chunk flag` で構成し、chunk の並べ替え・切り詰め・伸長を検出する。header は各 chunk の additional data として認証され、header の改竄も検出する。空の object も空の最終 chunk 1 個を持つ。平文 size は格納 size と header から決定論的に導ける。
  - 鍵は 32 byte の単一鍵を鍵 file（hex）で与える。rotation・KMS 連携は未確定（requirements § 未確定事項）。
  - filesystem モードで at-rest を使う場合、root 配下の file は envelope 形式で置かれている前提である。平文 file からの変換には `cmd/drs-encrypt` を用いる。
- `crypt4gh`（将来）: 暗号化ファイルをそのまま流し、client が自分の鍵で復号する。server も経路も平文を見ない。

組み合わせ例: `(s3, at-rest)`, `(filesystem, none)`, `(filesystem, at-rest)`。将来 `(_, crypt4gh)`。

## 9. index

- 保持内容: `DRS ID` から、実データの所在（s3 key または FS path）、`size`、`sha-256`、所属 dataset（dataset resource URL）、`created_time` への対応。`size` と `sha-256` は EncryptionProvider が返す平文に対して計算する（DrsObject と配信の ETag は client が受け取る平文を指す。§3・§7）。加えて格納 byte 数（stored size）を保持し、配信時に EncryptionProvider へ渡す。`created_time` は再 scan で復元できる storage 側の事実に取り、filesystem モードでは file の mtime を用いる。
- storage（S3/FS）を SSOT とし、index は破棄して再構築できる。DRS ID は「object ID scheme」に従い、s3 は object metadata から、filesystem は相対 path から決定論的に復元する。
- object の所属 dataset（dataset resource URL）は取り込み時に確定する。s3 モードは object metadata か key prefix 規約に、filesystem モードは manifest の `(root, dataset resource URL)` 対応に持たせる。この対応も storage 側の規約（と manifest）に載るため、index を再構築できる。
- 再構築は現在の tree に対する全置換で、追加・削除が反映され、同一 tree なら同一 rows に収束する。DRS server は起動時に storage を full scan して index を全置換する。derived cache のため毎起動で再構築してよい。
- 現状は起動時 full scan のみで、稼働中に storage へ加えた追加・削除を反映するには再起動する。運用中の増分更新（s3 モードの SeaweedFS filer `SubscribeMetadata` gRPC change feed もしくは定期 scan、filesystem モードの dir 再 scan）は将来拡張とする。
- エンジンは SQLite（単一ファイル。derived なので durability は要求しない）。
