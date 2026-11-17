import type { ConsultingAudience, DualProverVerdict, GraphResult, Remediation, ReportLanguage, Severity } from '../types.ts';
import { executeEphemeralFernetDoDCycle } from '../airlock/destruction-certificate.ts';
import { redactSecrets } from '../airlock/sanitizer.ts';

export const severityRank: Record<Severity, number> = { blocker: 0, high: 1, medium: 2, low: 3, info: 4 };

export function meetsThreshold(graph: GraphResult, threshold: Severity): boolean {
  return [...graph.findings, ...graph.paths].some(item => severityRank[item.severity] <= severityRank[threshold]);
}

// Terminal control sequences and bidirectional controls cannot change the apparent report.
export function displayText(text: string): string {
  return redactSecrets(text).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ' ');
}

const RULE_TITLE_JA: Record<string, string> = {
  'firebase/public-read': '無条件の公開読み取りルール',
  'firebase/public-write': '無条件の公開書き込みルール',
  'firebase/recursive-wildcard': '再帰ワイルドカードによる公開データ露出',
  'firebase/privilege-fields': 'ユーザードキュメント書き込みのフィールド許可リスト欠如',
  'gcp/public-service': '公開IAM権限付与 (allUsers / allAuthenticatedUsers)',
  'gcp/public-ingress': '外部インターネットIngressの有効化',
  'iam/default-service-account': '既定サービスアカウントへの強力なロール付与',
  'iam/privilege-escalation': 'IAM権限昇格・なりすまし可能なロール付与',
  'wif/unpinned-provider': 'GitHub Actions WIFプロバイダーのリポジトリ制約欠如',
  'gke/node-identity-exposure': 'GKEノードの既定SA利用・Workload Identity未設定',
  'sql/public-authorized-network': 'Cloud SQLの全公開ネットワーク許可 (0.0.0.0/0)',
  'sql/unencrypted-public-ip': 'Cloud SQL公開IPv4のSSL/TLS必須化欠如',
  'sql/missing-resilience-guardrails': 'Cloud SQLの削除保護・自動バックアップ未設定',
  'vertex/public-workbench-exposure': 'Vertex AI Workbenchの公開IP露出',
  'bigquery/public-dataset-exposure': 'BigQueryデータセットの公開共有設定',
  'finops/unbounded-serverless-scaling': 'サーバーレスの最大インスタンス上限 (max_instance_count) 未設定',
  'gov/data-residency-violation': 'ガバメントクラウド・国内データ主権違反（国外・マルチリージョン配置）',
  'sre/single-zone-database': 'Cloud SQL単一ゾーン (ZONAL) 構成による災害時SPOFリスク',
  'finops/storage-missing-lifecycle': 'Cloud Storageライフサイクル管理 (lifecycle_rule) 未設定',
  'data/missing-cmek-encryption': '顧客管理暗号鍵 (CMEK / Cloud KMS) 未設定',
  'cicd/unpinned-workflow-action': 'GitHub Actionsの未固定ブランチ参照・過剰権限 (write-all)',
  'audit/logging-tampering': 'Cloud Audit Logs: ログシンク改ざん・監査設定の無効化',
  'audit/iam-persistence': 'Cloud Audit Logs: 永続化・特権IAM変更の検出',
  'audit/impersonation-chain': 'Cloud Audit Logs: サービスアカウントなりすまし・トークン発行チェーン',
  'audit/sensitive-data-access': 'Cloud Audit Logs: 機密データ・シークレットへの不審アクセス',
  'scc/active-finding': 'Security Command Center (SCC) アクティブ検出事項',
};

const RULE_MESSAGE_JA: Record<string, string> = {
  'firebase/public-read': '認証や条件なしでデータの読み取りが許可されています。最小権限の認証条件を追加してください。',
  'firebase/public-write': '認証や条件なしでデータの書き込み・改ざんが許可されています。最小権限の認証条件を追加してください。',
  'firebase/recursive-wildcard': '再帰ワイルドカード {document=**} により配下のサブコレクションまで公開読み取りが波及しています。',
  'firebase/privilege-fields': '書き込みルールに request.resource.data.keys().hasOnly([...]) によるフィールド制限がなく、権限属性の書き換えリスクがあります。',
  'gcp/public-service': 'allUsers または allAuthenticatedUsers に公開呼び出し権限が付与されています。',
  'gcp/public-ingress': '外部Ingressが有効です。認証ポリシーを別途確認してください。',
  'iam/default-service-account': 'Compute Engine / App Engine / Cloud Build の既定サービスアカウントに過剰な権限が付与されています。専用SAへ分離してください。',
  'iam/privilege-escalation': 'サービスアカウントのなりすましやIAMポリシー変更により権限昇格が可能なロールが付与されています。',
  'wif/unpinned-provider': 'Workload Identity Pool Provider に attribute.repository の固定条件がなく、外部リポジトリから認証されるリスクがあります。',
  'gke/node-identity-exposure': 'GKEクラスタまたはノードプールが既定SAまたは広範な cloud-platform スコープを使用しており、Workload Identity が未設定です。',
  'sql/public-authorized-network': 'Cloud SQL の承認済みネットワークに 0.0.0.0/0 が含まれており、全インターネットから接続可能です。',
  'sql/unencrypted-public-ip': 'Cloud SQL で公開IPv4が有効ですが、SSL/TLS通信の強制 (require_ssl / ENCRYPTED_ONLY) が設定されていません。',
  'sql/missing-resilience-guardrails': 'Cloud SQL で削除保護 (deletion_protection = true) または自動バックアップが有効化されていません。',
  'vertex/public-workbench-exposure': 'Vertex AI Workbench / Notebook インスタンスで公開IPの無効化 (disable_public_ip = true) が設定されていません。',
  'bigquery/public-dataset-exposure': 'BigQuery データセットが allUsers または allAuthenticatedUsers に公開されています。',
  'finops/unbounded-serverless-scaling': 'Cloud Run / Cloud Functions に正の max_instance_count 上限がなく、課金爆発 (Denial-of-Wallet) のリスクがあります。',
  'gov/data-residency-violation': 'データ基盤が日本国内リージョン（asia-northeast1 東京 / asia-northeast2 大阪）以外の国外またはマルチリージョンに配置されています。',
  'sre/single-zone-database': 'Cloud SQL が単一ゾーン (ZONAL) 構成のため、ゾーン障害や広域災害時に自動フェイルオーバーできません。REGIONAL (高可用性) 構成を推奨します。',
  'finops/storage-missing-lifecycle': 'バケットに lifecycle_rule が未設定のため、不要オブジェクトの蓄積による毎月のストレージ費用肥大化リスクがあります。',
  'data/missing-cmek-encryption': 'Cloud KMS の顧客管理暗号鍵 (default_kms_key_name) が未設定です。機密データ主権のためCMEK設定を推奨します。',
  'cicd/unpinned-workflow-action': 'GitHub Actions で可変ブランチ参照 (@main/@master) または permissions: write-all が使われており、CIサプライチェーン侵害リスクがあります。',
};

const RULE_DEEP_RATIONALE_JA: Record<string, string> = {
  'firebase/public-read': '【背景・攻撃メカニズム】プロジェクトIDと公開Web API Keyはクライアントバンドルから誰でも取得可能なため、未認証の `allow read: if true` が残存すると、REST API / SDK 経由でコレクション全件のバルク抽出（スクレイピング・個人情報漏洩）が数秒で成立します。【最新知見による根治策】公開カタログ等で単一ドキュメント取得のみを許可する場合は `allow get: if true; allow list: if false;` に分離し、ユーザー・テナント領域は `request.auth != null && request.auth.uid == userId`（または Custom Claims / メンバーシップ検証関数）で厳格に境界統制してください。',
  'firebase/public-write': '【背景・攻撃メカニズム】未認証または無条件の書き込み許可により、攻撃者が任意のJSONペイロードや悪성スクリプト格納オブジェクトを直接注入でき、DB汚染・ストレージ踏み台化・無制限書き込みによる課金爆発（Denial-of-Wallet）を引き起こします。【最新知見による根治策】`request.auth != null` に加え、オーナーシップ一致検証・スキーマ型検証・`request.resource.size` 上限および管理者ロール検証（`request.auth.token.admin == true`）を組み合わせてください。',
  'firebase/recursive-wildcard': '【背景・攻撃メカニズム】Firestore/Storage のセキュリティルールは「いずれか1つの match ブロックが true を返せば許可（OR評価）」される仕様です。上位で `{document=**}` や `{allPaths=**}` に公開許可を与えると、下位サブコレクションで厳格なルールを書いても全てバイパスされます。【最新知見による根治策】再帰ワイルドカードでの広域許可を廃止し、明示的なコレクション単位のマッチと `allow get` / `allow list` の粒度分離を徹底してください。',
  'firebase/privilege-fields': '【背景・攻撃メカニズム】ドキュメント全体の `update` を許可しフィールド制限を省くと、クライアントから `{"role":"admin","plan":"enterprise","isVerified":true}` を送信する Mass Assignment（権限昇格）攻撃が成立します。【最新知見による根治策】作成時は `request.resource.data.keys().hasOnly([...])`、更新時は `request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])` を強制し、特権属性の不変性（Immutability）をCEL ASTレベルで保証してください。',
  'gcp/public-service': '【背景・攻撃メカニズム】Cloud Run / Cloud Functions に `allUsers` または `allAuthenticatedUsers` の Invoker 権限を付与すると、IAM認証層を通過してアプリケーションエンドポイントが直接インターネットに露出します。内部APIや管理バッチの場合、認証バイパスやL7 DDoS/課金攻撃の直撃を受けます。【最新知見による根治策】内部マイクロサービスは `roles/run.invoker` を呼び出し元の専用サービスアカウントのみに限定し、公開Web APIの場合は Cloud Armor + IAP または API Gateway 経由に集約してください。',
  'gcp/public-ingress': '【背景・攻撃メカニズム】`INGRESS_TRAFFIC_ALL` が有効な状態では、VPC外部からデフォルトの `.run.app` / `.cloudfunctions.net` URL へ直接トラフィックを送信でき、WAF（Cloud Armor）やロードバランサーのセキュリティ統制を迂回されるリスクがあります。【最新知見による根治策】`INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` または `INGRESS_TRAFFIC_INTERNAL_ONLY` に設定し、全ての外部通信を Cloud Load Balancing + Cloud Armor 経由に強制してください。',
  'iam/default-service-account': '【背景・攻撃メカニズム】Compute Engine / App Engine / Cloud Build のデフォルトSAはプロジェクト編集者（`roles/editor`）相当の広範な権限を持つケースが多く、1つのワークロードでSSRFやRCEが発生すると、メタデータサーバー（`169.254.169.254`）からOAuthトークンを窃取されプロジェクト全体が掌握されます。【最新知見による根治策】ワークロード毎に専用の最小権限SAを作成し、リソース単位のIAMバインディングに分離してください。',
  'iam/privilege-escalation': '【背景・攻撃メカニズム】プロジェクト階層での `roles/iam.serviceAccountUser`、`serviceAccountTokenCreator`、`iam.securityAdmin`、`resourcemanager.projectIamAdmin` 付与は、上位権限SAへのなりすまし（Impersonation / `actAs` / トークン発行）を介した水平・垂直権限昇格チェーン（Privilege Escalation Path）を形成します。【最新知見による根治策】プロジェクト全体のバインディングを廃止し、`google_service_account_iam_member` で特定の非特権ランタイムSAリソース単体にのみスコープを限定してください。',
  'wif/unpinned-provider': '【背景・攻撃メカニズム】GitHub Actions 等の OIDC Workload Identity Pool Provider で `attribute_condition` によるリポジトリ制約がない場合、同一IdP（GitHub上の任意の第三者リポジトリやフォーク）から発行されたJWTトークンで本番GCPサービスアカウントへ認証・侵入される致命的な横断侵害が成立します。【最新知見による根治策】`attribute_condition = "assertion.repository == \'owner/repo\' && assertion.ref == \'refs/heads/main\'"` のようにリポジトリとブランチを暗号学的にピン留めしてください。',
  'gke/node-identity-exposure': '【背景・攻撃メカニズム】Workload Identity 未設定かつノードプールが既定Compute SAや `cloud-platform` スコープを持つ場合、コンテナ内の任意のPodからノードのメタデータサーバー経由でGCPプロジェクト全体のトークンを奪取可能です。【最新知見による根治策】クラスタで `workload_identity_config` を有効化して Pod 単位の IAM 境界を確立し、ノードプールには最小権限の専用SAを割り当ててください。',
  'sql/public-authorized-network': '【背景・攻撃メカニズム】Cloud SQL の `authorized_networks` に `0.0.0.0/0` を設定すると、全世界のボットネットからDBポート（5432/3306）へ直接ブルートフォース攻撃・ゼロデイ攻撃・クレデンシャルスタッフィングが可能になります。【最新知見による根治策】`0.0.0.0/0` を即時削除し、Private Service Connect (PSC) または Private IP + Cloud SQL Auth Proxy（IAM認証・mTLS強制）経由の閉域接続へ移行してください。',
  'sql/unencrypted-public-ip': '【背景・攻撃メカニズム】公開IPv4が有効なCloud SQLで `ssl_mode = "ENCRYPTED_ONLY"`（または `require_ssl = true`）が未設定の場合、平文でのDB認証情報・クエリ結果の盗聴や中間者攻撃（MITM）が成立します。【最新知見による根治策】`ssl_mode = "ENCRYPTED_ONLY"` でTLS 1.3/mTLSを強制し、不要な `ipv4_enabled` を `false` に設定してください。',
  'sql/missing-resilience-guardrails': '【背景・攻撃メカニズム】`deletion_protection = true` および自動バックアップ（Point-in-Time Recovery）が未設定の場合、Terraformの誤適用や侵害時の破壊工作（ランサムウェア・DB削除）により、基幹データが永久に消失（RPO=無限大）します。【最新知見による根治策】`deletion_protection = true` と `backup_configuration { enabled = true, point_in_time_recovery_enabled = true }` を必須ガードレールとしてIaCで固定してください。',
  'vertex/public-workbench-exposure': '【背景・攻撃メカニズム】Vertex AI Workbench / Notebook に公開IPが付与されていると、Jupyter環境が外部スキャンに晒され、付属SAの権限を通じた学習データ・独自モデル重み・BigQuery/GCS資産の流出経路となります。【最新知見による根治策】`disable_public_ip = true` で閉域VPC内に隔離し、Identity-Aware Proxy (IAP) 経由のゼロトラストアクセスおよび最小権限SAを強制してください。',
  'bigquery/public-dataset-exposure': '【背景・攻撃メカニズム】BigQuery データセットへの `allUsers` / `allAuthenticatedUsers` 付与は、全インターネットまたは任意のGoogleアカウント保有者に対してDWH内の顧客・財務・統計テーブル全件のクエリ実行とエクスポートを許します。【最新知見による根治策】公開プリンシパルを即時削除し、VPC Service Controls (VPC-SC) 境界と認可された組織内グループ・SAのみにアクセスを限定してください。',
  'finops/unbounded-serverless-scaling': '【背景・攻撃メカニズム】Cloud Run / Cloud Functions に正の `max_instance_count` 上限がない場合、L7フラッド攻撃や無限再帰バグ発生時に数千インスタンスへ無制限オートスケールし、数時間で数百万円規模のクラウド破産（Denial-of-Wallet）や下流DBのコネクション枯渇を引き起こします。【最新知見による根治策】ワークロードのキャパシティ設計に基づき明示的な `scaling { max_instance_count = N }` を設定し、予算アラートと併用してください。',
  'gov/data-residency-violation': '【背景・攻撃メカニズム】リソースが国外リージョンや広域マルチリージョン（`US` / `EU` 等）に配置されると、日本のデジタル庁ガバメントクラウド利用基準・ISMAP・経済安全保障および個人情報保護法第28条（越境移転規制）に抵触し、公共調達失格や外国法制によるデータ開示請求リスクが生じます。【最新知見による根治策】Organization Policy（`gcp.resourceLocations`）とTerraformで `asia-northeast1`（東京）および `asia-northeast2`（大阪）に厳格固定してください。',
  'sre/single-zone-database': '【背景・攻撃メカニズム】Cloud SQL が単一ゾーン（`ZONAL`）構成の場合、該当データセンターの電源・ネットワーク障害や広域災害時に自動フェイルオーバーが機能せず、数時間〜数日間の全面サービス停止（RTO違反・BCP破綻）に直結します。【最新知見による根治策】本番DBは `availability_type = "REGIONAL"`（プライマリ＋別ゾーン待機レプリカによる自動HAフェイルオーバー）を構成してください。',
  'finops/storage-missing-lifecycle': '【背景・攻撃メカニズム】Cloud Storage バケットに `lifecycle_rule` が未設定の場合、古いビルド成果物・一時ファイル・監査ログ・マルチパート未完了断片が永久にStandardクラスに蓄積し、複利的に毎月のストレージ課金を圧迫します。【最新知見による根治策】一定期間経過後の Nearline/Coldline/Archive 移行または自動削除（`Delete` / `AbortIncompleteMultipartUpload`）ルールを定義してください。',
  'data/missing-cmek-encryption': '【背景・攻撃メカニズム】Google管理のデフォルト暗号鍵（GMEK）のみに依存すると、自組織のセキュリティ部門側で暗号鍵の即時ローテーション・緊急失効（Crypto-Shredding）・鍵アクセス監査証跡の独立統制ができません。【最新知見による根治策】Cloud KMS の顧客管理暗号鍵（CMEK: `default_kms_key_name`）を適用し、鍵管理権限とデータアクセス権限の職務分掌（Separation of Duties）を確立してください。',
  'cicd/unpinned-workflow-action': '【背景・攻撃メカニズム】GitHub Actions で `@main` / `@v1` 等の可変タグ参照や `permissions: write-all` を使用すると、サードパーティActionの侵害（例: `tj-actions` 等のタグ書き換え攻撃）時にCIランナーから本番シークレット流出やリポジトリ改ざんが直ちに成立します。【最新知見による根治策】サードパーティActionは40桁のフルコミットSHAで不変ピン留めし、`permissions` はジョブ単位の最小権限（`contents: read` 等）に制限してください。',
  'audit/logging-tampering': '【背景・攻撃メカニズム】攻撃者は侵入直後に痕跡を消すため、`SetIamPolicy` や `UpdateSink` で Cloud Audit Logs のロギングシンク停止・フィルタ改ざんを行います。【最新知見による根治策】組織レベル集約シンク（Organization Aggregated Sink）とロック付きバケット（Bucket Lock / WORM）で監査証跡の不変性を保証し、ロギング管理権限をSOC専任者に限定してください。',
  'audit/iam-persistence': '【背景・攻撃メカニズム】侵害後の攻撃者が長期潜伏（Persistence）を図る際、不正なサービスアカウント鍵（`CreateServiceAccountKey`）の発行や外部WIFプロバイダーの追加を行います。【最新知見による根治策】該当クレデンシャルを即時失効させ、Organization Policy `iam.disableServiceAccountKeyCreation` で物理鍵の発行自体を恒久禁止してください。',
  'audit/impersonation-chain': '【背景・攻撃メカニズム】`GenerateAccessToken` / `SignBlob` / `SignJwt` の連鎖呼び出しは、低権限SAを踏み台にして高権限SAの短命トークンを動的生成する多段ラテラルムーブメントの決定的兆候です。【最新知見による根治策】委任チェーン上の不要な `serviceAccountTokenCreator` バインディングを剥奪し、IAM Conditions で呼び出し元IP・VPC・サービスを制限してください。',
  'audit/sensitive-data-access': '【背景・攻撃メカニズム】Secret Manager の `AccessSecretVersion` や BigQuery / Cloud Storage への異常なバルク読み取りは、奪取されたランタイムIDを用いた機密資産の外部流出（Exfiltration）フェーズを示します。【最新知見による根治策】VPC Service Controls で境界外へのデータ持ち出しを遮断し、シークレット参照権限を実際にそのシークレットを必要とする単一Cloud Runサービスのみに分離してください。',
  'scc/active-finding': '【背景・攻撃メカニズム】Security Command Center (SCC) の ACTIVE 指摘は、クラウド実環境上で現在進行形で露出・脆弱性・不審挙動が観測されていることを示します。【最新知見による根治策】IaC（Terraform）側の宣言コードと実環境ドリフトを突合し、本設計書の自動生成パッチで恒久修正を適用してください。',
};

const RULE_DEEP_RATIONALE_EN: Record<string, string> = {
  'firebase/public-read': '[Root-Cause & Attack Mechanics] Because Firebase project IDs and Web API keys are publicly embedded in client bundles, an unauthenticated `allow read: if true` grant lets any external actor bulk-enumerate and exfiltrate entire collections in seconds via REST/SDK calls. [2026 Best-Practice Prescription] For public catalogs, split read permissions into `allow get: if true; allow list: if false;`; for user or tenant data, enforce strict identity isolation (`request.auth != null && request.auth.uid == userId` or verified custom claims).',
  'firebase/public-write': '[Root-Cause & Attack Mechanics] Unconditional write permissions allow arbitrary payload injection, database poisoning, malware hosting, and unbounded storage/document creation (Denial-of-Wallet). [2026 Best-Practice Prescription] Enforce `request.auth != null`, strict ownership matching, schema field/type validation, payload size bounds, or explicit administrator claim checks (`request.auth.token.admin == true`).',
  'firebase/recursive-wildcard': '[Root-Cause & Attack Mechanics] Firebase Security Rules evaluate with OR-semantics across matching blocks: once a parent `{document=**}` or `{allPaths=**}` rule grants access, stricter rules on nested subcollections cannot revoke it. [2026 Best-Practice Prescription] Replace broad recursive wildcards with explicit collection-scoped match blocks and separate `get` vs. `list` semantics.',
  'firebase/privilege-fields': '[Root-Cause & Attack Mechanics] Allowing document writes without restricting modifiable keys enables Mass Assignment privilege escalation (e.g., a client injecting `{"role":"admin","tier":"enterprise"}`). [2026 Best-Practice Prescription] Enforce `request.resource.data.keys().hasOnly([...])` on create and `request.resource.data.diff(resource.data).affectedKeys().hasOnly([...])` on update so privileged attributes remain cryptographically immutable.',
  'gcp/public-service': '[Root-Cause & Attack Mechanics] Granting `allUsers` or `allAuthenticatedUsers` the `roles/run.invoker` or Cloud Functions invoker role bypasses Cloud IAM perimeter authentication, exposing internal microservices directly to L7 DDoS, auth bypass, and Denial-of-Wallet attacks. [2026 Best-Practice Prescription] Restrict invoker bindings to specific caller service accounts and front public endpoints with Cloud Load Balancing + Cloud Armor / IAP.',
  'gcp/public-ingress': '[Root-Cause & Attack Mechanics] Enabling `INGRESS_TRAFFIC_ALL` allows direct internet traffic to default `.run.app` / `.cloudfunctions.net` URLs, bypassing WAF (Cloud Armor) and perimeter load balancer controls. [2026 Best-Practice Prescription] Set ingress to `INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER` or `INGRESS_TRAFFIC_INTERNAL_ONLY` to enforce zero-trust network routing.',
  'iam/default-service-account': '[Root-Cause & Attack Mechanics] Default Compute Engine, App Engine, and Cloud Build service accounts often inherit broad `roles/editor` project permissions; a single SSRF or container escape lets an attacker harvest tokens from `169.254.169.254` and compromise the entire GCP project. [2026 Best-Practice Prescription] Provision a dedicated, workload-specific service account with minimal resource-scoped IAM bindings.',
  'iam/privilege-escalation': '[Root-Cause & Attack Mechanics] Project-wide grants of `roles/iam.serviceAccountUser`, `serviceAccountTokenCreator`, `iam.securityAdmin`, or `resourcemanager.projectIamAdmin` allow an identity to impersonate (`actAs` / mint tokens for) higher-privileged service accounts, creating a direct privilege-escalation path. [2026 Best-Practice Prescription] Eliminate project-level impersonation bindings and scope `google_service_account_iam_member` strictly to a single non-privileged target runtime service account.',
  'wif/unpinned-provider': '[Root-Cause & Attack Mechanics] Without a restrictive `attribute_condition` on a Workload Identity Pool Provider, OIDC JWTs minted from any untrusted GitHub repository or fork on the same IdP can authenticate into production GCP roles. [2026 Best-Practice Prescription] Pin `attribute_condition` to the exact repository owner/name and protected branch ref (`assertion.repository == \'owner/repo\'`).',
  'gke/node-identity-exposure': '[Root-Cause & Attack Mechanics] Running GKE node pools with the default Compute service account or `cloud-platform` OAuth scope without Workload Identity lets any compromised Pod query the node metadata server and steal node-level GCP credentials. [2026 Best-Practice Prescription] Enable `workload_identity_config` on the cluster for Pod-level IAM isolation and attach a dedicated least-privilege SA to every node pool.',
  'sql/public-authorized-network': '[Root-Cause & Attack Mechanics] Authorizing `0.0.0.0/0` on Cloud SQL exposes database ports directly to internet-wide brute-force, credential stuffing, and protocol exploitation. [2026 Best-Practice Prescription] Remove `0.0.0.0/0` immediately and connect exclusively via Private Service Connect (PSC), private VPC peering, or Cloud SQL Auth Proxy with IAM authentication.',
  'sql/unencrypted-public-ip': '[Root-Cause & Attack Mechanics] Exposing a Cloud SQL public IPv4 endpoint without `ssl_mode = "ENCRYPTED_ONLY"` (or `require_ssl = true`) permits cleartext database connections vulnerable to credential interception and MITM attacks. [2026 Best-Practice Prescription] Enforce `ssl_mode = "ENCRYPTED_ONLY"` and disable public IPv4 (`ipv4_enabled = false`) wherever private routing is available.',
  'sql/missing-resilience-guardrails': '[Root-Cause & Attack Mechanics] Omitting `deletion_protection = true` and automated point-in-time backups leaves production databases vulnerable to accidental Terraform destruction or ransomware wipe with unrecoverable data loss (infinite RPO). [2026 Best-Practice Prescription] Enforce `deletion_protection = true` and `backup_configuration { enabled = true, point_in_time_recovery_enabled = true }` in IaC.',
  'vertex/public-workbench-exposure': '[Root-Cause & Attack Mechanics] Vertex AI Workbench / Notebook instances with public IPs expose interactive compute environments that hold privileged service account credentials and direct access to proprietary training datasets and model weights. [2026 Best-Practice Prescription] Set `disable_public_ip = true`, isolate instances inside a private VPC subnet, and gate access through Identity-Aware Proxy (IAP).',
  'bigquery/public-dataset-exposure': '[Root-Cause & Attack Mechanics] Binding `allUsers` or `allAuthenticatedUsers` on a BigQuery dataset allows anyone on the internet to query and exfiltrate analytical, financial, or PII tables. [2026 Best-Practice Prescription] Revoke public principals immediately, enforce VPC Service Controls (VPC-SC) perimeters, and grant dataset access only to explicit organizational principals.',
  'finops/unbounded-serverless-scaling': '[Root-Cause & Attack Mechanics] Serverless workloads (Cloud Run / Cloud Functions) without a positive `max_instance_count` ceiling can scale to thousands of instances during traffic floods or retry storms, causing catastrophic Denial-of-Wallet billing spikes and exhausting downstream database connections. [2026 Best-Practice Prescription] Define an explicit `scaling { max_instance_count = N }` upper bound aligned with downstream capacity and FinOps budget guardrails.',
  'gov/data-residency-violation': '[Root-Cause & Attack Mechanics] Deploying storage or database resources in foreign or multi-regional locations violates sovereign Government Cloud mandates, ISMAP, and cross-border data transfer regulations (APPI Art.28 / GDPR), exposing data to extraterritorial legal jurisdiction. [2026 Best-Practice Prescription] Pin resource `location` / `region` to approved domestic regions (`asia-northeast1` Tokyo or `asia-northeast2` Osaka) and enforce `gcp.resourceLocations` via Organization Policy.',
  'sre/single-zone-database': '[Root-Cause & Attack Mechanics] A single-zone (`ZONAL`) Cloud SQL instance represents a single point of failure (SPOF); a zone outage or regional disaster halts all database operations without automatic failover, violating enterprise RTO/BCP targets. [2026 Best-Practice Prescription] Configure `availability_type = "REGIONAL"` to maintain synchronous multi-zone standby replicas with automatic failover.',
  'finops/storage-missing-lifecycle': '[Root-Cause & Attack Mechanics] Buckets lacking `lifecycle_rule` policies accumulate stale artifacts, logs, and incomplete multipart uploads indefinitely in Standard storage, driving compounding monthly FinOps waste. [2026 Best-Practice Prescription] Define automated `lifecycle_rule` transitions to Archive/Coldline tiers and expiration rules for transient objects.',
  'data/missing-cmek-encryption': '[Root-Cause & Attack Mechanics] Relying solely on provider-managed keys prevents independent cryptographic key rotation, instant crypto-shredding revocation, and separation of duties between cloud admins and key custodians. [2026 Best-Practice Prescription] Configure Customer-Managed Encryption Keys (`encryption { default_kms_key_name = ... }`) backed by Cloud KMS with hardware security module (HSM) protection.',
  'cicd/unpinned-workflow-action': '[Root-Cause & Attack Mechanics] Referencing mutable Git tags/branches (`@main`, `@v1`) or granting `permissions: write-all` in GitHub Actions exposes the CI/CD pipeline to upstream tag-hijacking supply-chain attacks and token exfiltration. [2026 Best-Practice Prescription] Pin every third-party action to an immutable 40-character commit SHA and scope `permissions` to least-privilege (`contents: read`).',
  'audit/logging-tampering': '[Root-Cause & Attack Mechanics] Adversaries routinely modify or disable Cloud Audit Log sinks (`UpdateSink`, `SetIamPolicy`) post-compromise to blind SIEM detection and erase forensic evidence. [2026 Best-Practice Prescription] Route logs through an immutable Organization Aggregated Sink backed by a Bucket-Locked (WORM) storage bucket and alert immediately on sink configuration changes.',
  'audit/iam-persistence': '[Root-Cause & Attack Mechanics] Unapproved IAM policy bindings or long-lived service account key creations (`CreateServiceAccountKey`) allow attackers to maintain persistent backdoor access independent of initial entry vectors. [2026 Best-Practice Prescription] Revoke unauthorized grants immediately and enforce Organization Policy `iam.disableServiceAccountKeyCreation`.',
  'audit/impersonation-chain': '[Root-Cause & Attack Mechanics] Chained `GenerateAccessToken`, `SignBlob`, or `SignJwt` audit events indicate active lateral movement where a low-privilege identity mints short-lived credentials for privileged service accounts. [2026 Best-Practice Prescription] Break unnecessary delegation chains and bind `roles/iam.serviceAccountTokenCreator` only with strict IAM Conditions.',
  'audit/sensitive-data-access': '[Root-Cause & Attack Mechanics] Anomalous `AccessSecretVersion` or bulk data read events indicate active credential harvesting and crown-jewel data exfiltration by a compromised workload identity. [2026 Best-Practice Prescription] Enforce VPC Service Controls egress boundaries and partition Secret Manager bindings per individual service account.',
  'scc/active-finding': '[Root-Cause & Attack Mechanics] An ACTIVE Security Command Center finding confirms a live runtime exposure or misconfiguration observed in the cloud environment. [2026 Best-Practice Prescription] Reconcile live cloud state with Terraform IaC and apply the review-only remediation patch to eliminate drift.',
};

function localizeLimitationJa(text: string): string {
  return displayText(text)
    .replace('Static rules analysis recognizes literal public grants and potential field-allowlist omissions; it does not evaluate functions, compound expressions, rule validity, or deployed configuration.', '静的ルール解析はリテラルの公開許可とフィールド許可リスト欠如を検出しますが、関数・複合式・実環境のデプロイ状態は評価しません。')
    .replace('Terraform analysis covers literal resources and direct references within one module; variables, provider defaults, modules, count/for_each, custom roles and dynamic expressions are not evaluated.', 'Terraform解析は単一モジュール内のリテラル定義と直接参照を対象とし、変数・モジュール・count/for_each・カスタムロール・動的な式は評価しません。')
    .replace('Workflow analysis reads literal auth-step inputs only; YAML aliases, expressions, triggers, repository restrictions and live IAM trust require review.', 'GitHubワークフロー解析は google-github-actions/auth のリテラル記述のみを読み取ります。YAMLエイリアス・動的な式・トリガー・実環境IAM信頼設定は確認が必要です。')
    .replace('GitHub auth inputs are dynamic, incomplete or unsupported; no identity connection was inferred.', 'GitHub認証ステップの入力が動的・不完全または非対応のため、ID接続は推論されませんでした。')
    .replace('IAM role or members are dynamic or unsupported; this grant was not resolved.', 'IAMのroleまたはmembersが動的表現または非対応のため、この権限付与は解決されませんでした。')
    .replace('Runtime identity could not be resolved safely; explicit account or project-number evidence is required for cross-file correlation.', '実行時サービスアカウントを安全に解決できませんでした（ファイル横断の関連付けには明示的なサービスアカウントまたはプロジェクト番号が必要です）。')
    .replace('Runtime service account is absent or unresolved; no default identity was inferred.', '実行時サービスアカウントが未指定または未解決のため、既定IDの推論は行われませんでした。')
    .replace('Runtime identity uses a service default inferred from the explicit project; deployed identity and account existence were not verified.', '明示されたプロジェクトから既定の実行時サービスアカウントを推論しました（実環境のデプロイ状態は未検証です）。')
    .replace('Excluded generated, cache, or worktree directories were not traversed: ', '自動生成・キャッシュ・worktree等の除外ディレクトリは走査対象外としました: ')
    .replace('. Audit a subdirectory directly if infrastructure configs reside there.', '（インフラ設定が含まれる場合はサブディレクトリを直接指定して監査してください）。')
    .replace('Exported Cloud Audit Logs and SCC findings reflect point-in-time observations and do not verify current live cloud state.', 'エクスポートされたCloud Audit LogsおよびSCCの検出事項は出力時点の記録であり、現在のクラウド実環境の状態を保証するものではありません。')
    .replace('Static analysis does not establish deployed policy, runtime exploitability or completeness for unsupported syntax; files must remain stable during scanning.', '静的解析はデプロイ済みポリシーや実行時の攻撃成立性、未対応構文の網羅性を保証しません。走査中は対象ファイルを変更しないでください。');
}

function localizePathJa(text: string): string {
  return displayText(text)
    .replace(/Unauthenticated Firebase client/g, '未認証のFirebaseクライアント')
    .replace(/Authenticated Firebase client/g, '認証済みのFirebaseクライアント')
    .replace(/Public internet \(0\.0\.0\.0\/0\)/g, '公開インターネット (0.0.0.0/0)')
    .replace(/SCC active public exposure/g, 'SCC検出の公開露出')
    .replace(/GitHub workflow using /g, 'GitHubワークフロー: ')
    .replace(/firestore rules /g, 'Firestoreルール ')
    .replace(/storage rules /g, 'Storageルール ')
    .replace(/firestore data matching /g, 'Firestoreデータ ')
    .replace(/storage data matching /g, 'Storageデータ ')
    .replace(/Potential privilege fields at /g, '権限昇格リスクのあるフィールド: ')
    .replace(/Secret Manager secrets in /g, 'Secret Managerシークレット: ')
    .replace(/BigQuery datasets in /g, 'BigQueryデータセット: ')
    .replace(/BigQuery dataset /g, 'BigQueryデータセット ')
    .replace(/Cloud Storage objects in /g, 'Cloud Storageオブジェクト: ')
    .replace(/Cloud SQL databases in /g, 'Cloud SQLデータベース: ')
    .replace(/Cloud SQL database in /g, 'Cloud SQLデータベース: ')
    .replace(/Cloud SQL instance /g, 'Cloud SQLインスタンス ')
    .replace(/Project administration in /g, 'プロジェクト管理権限: ')
    .replace(/Project resources in /g, 'プロジェクトリソース: ');
}

const REMEDIATION_JA: Record<string, string> = {
  'Deny public access until an application-specific authorization rule is reviewed. This proposal may interrupt intended public reads.': 'アプリケーション固有の認可ルールが確認されるまで公開アクセスを拒否します（意図した公開読み取りがある場合は `allow get: if true;` 等の最小範囲を検討してください）。',
  'Deny public writes until ownership and field validation are defined. Review availability impact before applying.': '所有者確認とフィールド検証が定義されるまで公開書き込みを拒否します。適用前に影響範囲を確認してください。',
  'Restrict recursive matches to intended collections or object prefixes and enforce ownership at every matching allow clause.': '再帰ワイルドカード `{allPaths=**}` の適用範囲を必要なコレクションやプレフィックスに限定し、各 allow 句で認証・所有者確認を強制してください。',
  'Use keys().hasOnly(approvedFields) for creates and diff(resource.data).affectedKeys().hasOnly(approvedFields) for updates. Choose allowed fields from the application schema.': '作成時は `keys().hasOnly(approvedFields)`、更新時は `diff(resource.data).affectedKeys().hasOnly(approvedFields)` を使用し、書き換え可能なフィールドを明示的に制限してください。',
  'Remove allUsers/allAuthenticatedUsers invoker grants and grant invocation to the required identities only.': '`allUsers` / `allAuthenticatedUsers` の公開呼び出し権限を削除し、必要なサービスアカウントや認証済みIDのみに付与してください。',
  'Restrict ingress to internal traffic; verify that required callers still have a supported route.': 'Ingress を内部トラフィック（または内部ロードバランサー経由）に制限し、正規の呼び出し元経路を確認してください。',
  'Use a dedicated runtime service account with resource-scoped permissions required by this workload.': '既定サービスアカウントの使用をやめ、ワークロード固有の最小権限を持つ専用サービスアカウントへ分離してください。',
  'Remove unnecessary impersonation or policy-administration grants; scope necessary grants to named service accounts.': '不要なサービスアカウントなりすまし権限やIAM管理権限を削除し、必要な場合は特定の対象サービスアカウントにスコープを限定してください。',
  'Bind the provider to an exact trusted repository and owner using a restrictive attribute condition; validate subject and branch claims.': 'Workload Identity Pool Provider の `attribute_condition` で信頼するGitHubリポジトリ（`owner/repo`）を厳密に固定してください。',
  'Pin the workload identity provider and service account, restrict token permissions to the deployment job, and constrain repository claims on the provider.': 'ワークフローの Workload Identity Provider とサービスアカウントを固定し、トークン権限を該当ジョブのみに制限してください。',
  'Review the recorded logging change, restore required audit collection and sink routing through an approved change, and restrict logging administration to designated responders.': '記録されたログ設定・シンク変更を確認して監査ログ収集を復旧し、ロギング管理権限を限定してください。',
  'Investigate the recorded identity or IAM policy change; revoke unapproved credentials and grants through incident response, and constrain workload identity providers to trusted subjects.': '記録されたID・IAMポリシー変更を調査し、未承認の鍵や権限付与を失効させてください。',
  'Review the observed caller and service account delegation chain, remove unnecessary impersonation grants, and scope approved delegation to named identities and resources.': '観測された呼び出し元とサービスアカウント委任チェーンを確認し、不要ななりすまし権限を削除してください。',
  'Validate the observed data access against workload requirements, investigate unapproved access, and restrict resource permissions to the intended identities.': '観測された機密データアクセスが業務要件通りか確認し、リソース権限を最小化してください。',
  'Review the active Security Command Center finding and affected resource configuration, confirm the exposure, and apply a resource-specific remediation through the approved change process.': 'アクティブな Security Command Center (SCC) 検出事項と対象リソース設定を確認し、露出を遮断してください。',
  'Configure workload_identity_config on the cluster and assign a dedicated, least-privilege service_account to every node pool instead of the default Compute Engine account.': 'GKEクラスタで `workload_identity_config` を有効化し、各ノードプールに既定SAではなく最小権限の専用サービスアカウントを割り当ててください。',
  'Remove 0.0.0.0/0 from authorized_networks and connect through Cloud SQL Auth Proxy, Private Service Connect, or private IP.': '`authorized_networks` から `0.0.0.0/0` を削除し、Cloud SQL Auth Proxy・Private Service Connect・プライベートIP経由で接続してください。',
  'Set ssl_mode = "ENCRYPTED_ONLY" (or require_ssl = true) and disable public IPv4 (ipv4_enabled = false) where private connectivity is available.': '`ssl_mode = "ENCRYPTED_ONLY"`（または `require_ssl = true`）を設定してTLS暗号化を強制し、プライベート接続が可能な場合は公開IPv4（`ipv4_enabled = false`）を無効化してください。',
  'Set deletion_protection = true and enable automated backups (backup_configuration { enabled = true }) on production Cloud SQL instances.': '本番 Cloud SQL インスタンスで削除保護（`deletion_protection = true`）と自動バックアップ（`backup_configuration { enabled = true }`）を有効化してください。',
  'Set disable_public_ip = true (or no_public_ip = true) on Vertex AI Workbench / Notebook instances and attach a dedicated least-privilege service account.': 'Vertex AI Workbench / Notebook インスタンスで公開IPを無効化（`disable_public_ip = true`）し、最小権限の専用サービスアカウントを割り当ててください。',
  'Remove allUsers and allAuthenticatedUsers from BigQuery dataset access blocks and grant access only to specific organizational principals.': 'BigQuery データセットのアクセス設定から `allUsers` / `allAuthenticatedUsers` を削除し、組織内の認可されたプリンシパルのみに権限を付与してください。',
  'Configure an explicit scaling { max_instance_count = ... } upper bound on Cloud Run and Cloud Functions to prevent Denial-of-Wallet cost spikes.': 'Cloud Run / Cloud Functions に明示的な `max_instance_count` 上限を設定し、Denial-of-Wallet（クラウド課金爆発）を防止してください。',
  'Pin resource location/region to approved domestic regions (such as asia-northeast1 Tokyo or asia-northeast2 Osaka for Japan Government Cloud & municipal workloads) instead of multi-region or foreign regions.': 'ガバメントクラウド・国内データ主権に準拠するため、リソースの `location` / `region` を日本国内リージョン（`asia-northeast1` 東京 または `asia-northeast2` 大阪）に固定してください。',
  'Upgrade Cloud SQL availability_type from "ZONAL" to "REGIONAL" to ensure automatic multi-zone failover for disaster recovery (BCP) and high availability.': '災害時BCP・業務継続性確保のため、Cloud SQL の `availability_type` を `"ZONAL"` から `"REGIONAL"`（マルチゾーン高可用性）へ変更してください。',
  'Add a lifecycle_rule block to transition or expire stale objects automatically and prevent unbounded monthly storage cost growth.': '不要データの自動アーカイブ・削除を行う `lifecycle_rule` ブロックを追加し、毎月のストレージ課金の肥大化を防止してください。',
  'Configure encryption { default_kms_key_name = ... } using a customer-managed Cloud KMS key (CMEK) to enforce cryptographic data sovereignty.': '顧客管理の Cloud KMS 暗号鍵（`encryption { default_kms_key_name = ... }`）を設定し、暗号鍵の主権・失効管理を自社統制下に置いてください。',
  'Pin GitHub Actions uses: steps to immutable commit SHAs (or verified release tags) and replace permissions: write-all with least-privilege read permissions.': 'GitHub Actions の `uses:` を不変のコミットSHA（または検証済みリリースタグ）に固定し、`permissions: write-all` を最小限の `contents: read` 等に縮小してください。',
};

function localizeRemediationJa(text: string): string {
  const clean = displayText(text);
  return REMEDIATION_JA[clean] ?? clean;
}

export function formatTable(graph: GraphResult, prover?: DualProverVerdict, remediations: Remediation[] = [], lang: ReportLanguage = 'en'): string {
  if (lang === 'ja') {
    const lines = ['Atlas Sovereign', '重大度    場所      検出内容'];
    for (const finding of graph.findings) {
      const titleJa = RULE_TITLE_JA[finding.ruleId] ?? displayText(finding.title);
      const msgJa = RULE_MESSAGE_JA[finding.ruleId] ?? displayText(finding.message);
      lines.push(`${finding.severity.toUpperCase().padEnd(8)}  ${displayText(finding.location.file)}:${finding.location.line}  ${titleJa} [${finding.ruleId}]`);
      lines.push(`          ${msgJa}`);
    }
    if (!graph.findings.length) lines.push('解析対象の入力で指摘は検出されませんでした（指摘なし・安全性の完全な保証ではありません）。');
    for (const path of graph.paths) lines.push(`攻撃経路 ${path.severity.toUpperCase()} (${path.confidence === 'confirmed' ? '確定' : '潜在'}): ${localizePathJa(path.description)}`);
    for (const limitation of graph.limitations) lines.push(`制約事項: ${localizeLimitationJa(limitation)}`);
    if (prover) {
      lines.push(`Prover判定 ${prover.mode}: ${prover.status}`);
      for (const [lane, verdict] of Object.entries(prover.lanes)) lines.push(`  ${lane}: ${verdict.status} — ${displayText(verdict.rationale)}`);
    }
    for (const remediation of remediations) {
      lines.push(`修正提案 ${remediation.findingId}: ${localizeRemediationJa(remediation.description)}`);
      if (remediation.diff) lines.push(remediation.diff.trimEnd());
    }
    return lines.join('\n') + '\n';
  }
  const lines = ['Atlas Sovereign', 'SEVERITY  LOCATION  FINDING'];
  for (const finding of graph.findings) {
    lines.push(`${finding.severity.toUpperCase().padEnd(8)}  ${displayText(finding.location.file)}:${finding.location.line}  ${displayText(finding.title)} [${finding.ruleId}]`);
    lines.push(`          ${displayText(finding.message)}`);
  }
  if (!graph.findings.length) lines.push('No findings in the analyzed inputs; this is not a completeness guarantee.');
  for (const path of graph.paths) lines.push(`PATH ${path.severity.toUpperCase()} (${path.confidence}): ${displayText(path.description)}`);
  for (const limitation of graph.limitations) lines.push(`LIMITATION: ${displayText(limitation)}`);
  if (prover) {
    lines.push(`PROVER ${prover.mode}: ${prover.status}`);
    for (const [lane, verdict] of Object.entries(prover.lanes)) lines.push(`  ${lane}: ${verdict.status} — ${displayText(verdict.rationale)}`);
  }
  for (const remediation of remediations) {
    lines.push(`PROPOSAL ${remediation.findingId}: ${displayText(remediation.description)}`);
    if (remediation.diff) lines.push(remediation.diff.trimEnd());
  }
  return lines.join('\n') + '\n';
}

function controlDomain(ruleId: string): string {
  if (ruleId.startsWith('firebase/') || ruleId.startsWith('bigquery/') || ruleId.startsWith('data/') || ruleId.startsWith('gov/')) return 'Firebase & Data Perimeter';
  if (ruleId.startsWith('iam/') || ruleId.startsWith('wif/') || ruleId.startsWith('cicd/')) return 'Identity & Workload Federation';
  if (ruleId.startsWith('gke/') || ruleId === 'sql/public-authorized-network' || ruleId === 'sql/unencrypted-public-ip' || ruleId.startsWith('gcp/')) return 'Cloud Workload & Database Hardening';
  if (ruleId.startsWith('vertex/') || ruleId.startsWith('audit/') || ruleId.startsWith('scc/')) return 'AI / Vertex & Runtime Threat Governance';
  if (ruleId.startsWith('finops/') || ruleId === 'sql/missing-resilience-guardrails' || ruleId.startsWith('sre/')) return 'FinOps Cost Guardrails & Resilience';
  return 'Scan Completeness & Input Safety';
}

interface ComplianceMapping {
  enterprise: string;
  municipalJa: string;
  municipalEn: string;
  smeJa: string;
  smeEn: string;
}

const COMPLIANCE_MAP: Record<string, ComplianceMapping> = {
  'firebase/public-read': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.8.3 / NIST PR.AA-03',
    municipalJa: '総務省ガイドライン(β\'モデル) アクセス制御 / ISMAP 9.4',
    municipalEn: 'MIC Municipal Security Guideline (Access Control) / ISMAP 9.4',
    smeJa: '個人情報保護法第23条(安全管理措置) / IPA 5か条(公開設定確認)',
    smeEn: 'APPI Art.23 (Data Safeguards) / IPA 5 Principles',
  },
  'firebase/public-write': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.8.3 / NIST PR.DS-01',
    municipalJa: '総務省ガイドライン 改ざん防止・認可統制 / ISMAP 9.4.1',
    municipalEn: 'MIC Municipal Security Guideline (Integrity) / ISMAP 9.4.1',
    smeJa: '経産省サプライチェーン評価(データ改ざん防止) / 個人情報保護法第23条',
    smeEn: 'METI Supply-Chain Security (Integrity) / APPI Art.23',
  },
  'firebase/recursive-wildcard': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.8.3 / NIST PR.AA-05',
    municipalJa: '総務省ガイドライン 最小権限原則 / デジタル庁GC基準',
    municipalEn: 'MIC Municipal Security Guideline (Least Privilege)',
    smeJa: '個人情報保護法第23条(意図せぬ情報露出防止)',
    smeEn: 'APPI Art.23 (Unintended Data Exposure Prevention)',
  },
  'firebase/privilege-fields': {
    enterprise: 'SOC2 CC6.3 / ISO27001 A.8.2 / NIST PR.AA-05',
    municipalJa: '総務省ガイドライン 職務分掌・権限昇格防止 / ISMAP 9.2',
    municipalEn: 'MIC Municipal Guideline (Privilege Separation) / ISMAP 9.2',
    smeJa: '経産省サプライチェーン評価(不正権限変更防止)',
    smeEn: 'METI Supply-Chain Security (Privilege Control)',
  },
  'gcp/public-service': {
    enterprise: 'SOC2 CC6.6 / ISO27001 A.8.20 / NIST PR.IR-01',
    municipalJa: '総務省 三層の対策(インターネット接続系分離) / ISMAP 13.1',
    municipalEn: 'MIC Three-Tier Isolation / ISMAP 13.1',
    smeJa: 'IPA サイバーセキュリティお助け隊基準(外部公開制限)',
    smeEn: 'IPA SME Cyber Security Standard (Perimeter Control)',
  },
  'gcp/public-ingress': {
    enterprise: 'SOC2 CC6.6 / ISO27001 A.8.22 / NIST PR.IR-01',
    municipalJa: 'デジタル庁ガバメントクラウド 閉域網・経路統制 / ISMAP 13.1.3',
    municipalEn: 'Digital Agency GovCloud Network Boundary / ISMAP 13.1.3',
    smeJa: '経産省サプライチェーン評価(ネットワーク境界防御)',
    smeEn: 'METI Supply-Chain Security (Network Boundary)',
  },
  'iam/default-service-account': {
    enterprise: 'SOC2 CC6.3 / ISO27001 A.8.2 / NIST PR.AA-05',
    municipalJa: 'デジタル庁ガバメントクラウド IAM最小権限 / ISMAP 9.2.3',
    municipalEn: 'Digital Agency GovCloud IAM Least Privilege / ISMAP 9.2.3',
    smeJa: '経産省サプライチェーン評価(特権ID管理・使い回し禁止)',
    smeEn: 'METI Supply-Chain Security (Privileged ID Hygiene)',
  },
  'iam/privilege-escalation': {
    enterprise: 'SOC2 CC6.2 / ISO27001 A.8.2 / NIST PR.AA-05',
    municipalJa: '総務省ガイドライン 特権ID統制 / ISMAP 9.2.3',
    municipalEn: 'MIC Municipal Privileged Access Control / ISMAP 9.2.3',
    smeJa: '経産省サプライチェーン評価(管理者権限の最小化)',
    smeEn: 'METI Supply-Chain Security (Admin Least Privilege)',
  },
  'wif/unpinned-provider': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.8.5 / NIST PR.AA-01',
    municipalJa: 'デジタル庁ガバメントクラウド 外部連携認証固定 / ISMAP 9.4.2',
    municipalEn: 'Digital Agency GovCloud Federated Trust / ISMAP 9.4.2',
    smeJa: '経産省サプライチェーン評価(委託先・外部接続認証の制限)',
    smeEn: 'METI Supply-Chain Security (Third-Party Auth Pinning)',
  },
  'gke/node-identity-exposure': {
    enterprise: 'SOC2 CC6.3 / ISO27001 A.8.9 / NIST PR.PS-01',
    municipalJa: 'デジタル庁ガバメントクラウド コンテナ分離統制 / ISMAP 12.1',
    municipalEn: 'Digital Agency GovCloud Container Hardening / ISMAP 12.1',
    smeJa: '経産省サプライチェーン評価(サーバー実行権限の分離)',
    smeEn: 'METI Supply-Chain Security (Workload Isolation)',
  },
  'sql/public-authorized-network': {
    enterprise: 'SOC2 CC6.6 / ISO27001 A.8.20 / NIST PR.DS-01',
    municipalJa: '総務省 三層の対策(基幹DBのインターネット直接接続禁止) / ISMAP 13.1',
    municipalEn: 'MIC Three-Tier DB Isolation / ISMAP 13.1',
    smeJa: '個人情報保護法第23条 / IPA(顧客DBの外部直結遮断)',
    smeEn: 'APPI Art.23 / IPA (Database Perimeter Isolation)',
  },
  'sql/unencrypted-public-ip': {
    enterprise: 'SOC2 CC6.7 / ISO27001 A.8.24 / NIST PR.DS-02',
    municipalJa: '総務省ガイドライン 通信経路の暗号化(TLS強制) / ISMAP 10.1',
    municipalEn: 'MIC Guideline In-Transit Encryption (TLS) / ISMAP 10.1',
    smeJa: '個人情報保護法第23条(通信の暗号化措置)',
    smeEn: 'APPI Art.23 (Encryption in Transit)',
  },
  'sql/missing-resilience-guardrails': {
    enterprise: 'SOC2 A1.2 / ISO27001 A.8.13 / NIST PR.IR-04',
    municipalJa: '総務省ガイドライン 業務継続計画(BCP)・データ保全 / ISMAP 12.3',
    municipalEn: 'MIC Municipal BCP & Backup Integrity / ISMAP 12.3',
    smeJa: 'IPA ランサムウェア対策(自動バックアップ＆誤削除防止)',
    smeEn: 'IPA Ransomware Resilience (Automated Backup & Deletion Lock)',
  },
  'vertex/public-workbench-exposure': {
    enterprise: 'SOC2 CC6.6 / ISO27001 A.8.20 / NIST AI RMF Manage-2',
    municipalJa: '総務省・デジタル庁 生成AI利活用ガイドライン(閉域AI環境)',
    municipalEn: 'Digital Agency GenAI Governance (Private AI Runtime)',
    smeJa: '経産省 AI事業者ガイドライン(AI開発環境の情報漏洩防止)',
    smeEn: 'METI AI Governance Guideline (AI Runtime Protection)',
  },
  'bigquery/public-dataset-exposure': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.8.3 / NIST PR.DS-01',
    municipalJa: '総務省ガイドライン 住民・統計データの非公開統制 / ISMAP 8.2',
    municipalEn: 'MIC Municipal Data Classification & Access / ISMAP 8.2',
    smeJa: '個人情報保護法第23条(分析データ・顧客名簿の外部漏洩防止)',
    smeEn: 'APPI Art.23 (Analytics & Customer Data Protection)',
  },
  'finops/unbounded-serverless-scaling': {
    enterprise: 'SOC2 A1.1 / ISO27001 A.8.6 / NIST PR.IR-03 (FinOps Capacity)',
    municipalJa: 'デジタル庁ガバメントクラウド 歳出予算超過防止・上限統制',
    municipalEn: 'Digital Agency GovCloud Budget Cap & Capacity Control',
    smeJa: '中小企業FinOps(クラウド請求書の突発的な高額課金防止)',
    smeEn: 'SME FinOps (Monthly Cloud Bill Spike Protection)',
  },
  'gov/data-residency-violation': {
    enterprise: 'SOC2 CC6.1 / ISO27001 A.5.34 / GDPR & Sovereign Data Residency',
    municipalJa: 'デジタル庁ガバメントクラウド 国内データ主権(東京・大阪リージョン限定)',
    municipalEn: 'Digital Agency GovCloud Domestic Data Residency (JP Only)',
    smeJa: '個人情報保護法第28条(外国にある第三者への提供制限・国内保管)',
    smeEn: 'APPI Art.28 (Cross-Border Data Transfer & Domestic Storage)',
  },
  'sre/single-zone-database': {
    enterprise: 'SOC2 A1.2 / ISO27001 A.8.14 / NIST PR.IR-04 (Multi-Zone HA)',
    municipalJa: '総務省 自治体BCP・震災時システム継続要件(マルチゾーン冗長化)',
    municipalEn: 'MIC Municipal Disaster BCP (Multi-Zone High Availability)',
    smeJa: '中小企業事業継続力強化計画(災害時のシステム停止防止)',
    smeEn: 'SME Business Continuity Plan (Disaster Failover)',
  },
  'finops/storage-missing-lifecycle': {
    enterprise: 'SOC2 A1.1 / ISO27001 A.8.10 / FinOps Storage Lifecycle',
    municipalJa: 'デジタル庁ガバメントクラウド 公文書・ログ保管期限と運用費最適化',
    municipalEn: 'Digital Agency GovCloud Retention & Storage Cost Optimization',
    smeJa: '中小企業FinOps(不要データの自動整理による毎月の固定費削減)',
    smeEn: 'SME FinOps (Automated Storage Cleanup & Cost Reduction)',
  },
  'data/missing-cmek-encryption': {
    enterprise: 'SOC2 CC6.7 / ISO27001 A.8.24 / NIST PR.DS-01 (CMEK Key Sovereignty)',
    municipalJa: 'デジタル庁ガバメントクラウド・ISMAP 10.1.2 暗号鍵の主体管理(CMEK)',
    municipalEn: 'Digital Agency GovCloud & ISMAP 10.1.2 Customer-Managed Keys',
    smeJa: '個人情報保護法第23条(高度暗号化・鍵管理の厳格化)',
    smeEn: 'APPI Art.23 (Customer-Controlled Encryption Keys)',
  },
  'cicd/unpinned-workflow-action': {
    enterprise: 'SOC2 CC8.1 / ISO27001 A.8.25 / NIST SR.1 (CI/CD Supply Chain)',
    municipalJa: '総務省ガイドライン 委託先・開発パイプラインの改ざん防止 / ISMAP 14.2',
    municipalEn: 'MIC Guideline Software Supply-Chain Integrity / ISMAP 14.2',
    smeJa: '経産省サプライチェーン評価(開発・更新プログラム経由の侵入防止)',
    smeEn: 'METI Supply-Chain Security (CI/CD Pipeline Integrity)',
  },
};

function getCompliance(ruleId: string): ComplianceMapping {
  return COMPLIANCE_MAP[ruleId] ?? {
    enterprise: 'SOC2 CC7.2 / ISO27001 A.8.15 / NIST DE.CM-01',
    municipalJa: '総務省ガイドライン 監査ログ・監視統制 / ISMAP 12.4',
    municipalEn: 'MIC Municipal Audit & Monitoring / ISMAP 12.4',
    smeJa: '経産省サプライチェーン評価(不正アクセス検知・証跡保全)',
    smeEn: 'METI Supply-Chain Security (Monitoring & Audit Trail)',
  };
}

const PILLARS = [
  'Firebase & Data Perimeter',
  'Identity & Workload Federation',
  'Cloud Workload & Database Hardening',
  'AI / Vertex & Runtime Threat Governance',
  'FinOps Cost Guardrails & Resilience',
] as const;

const PILLAR_JA: Record<string, string> = {
  'Firebase & Data Perimeter': 'Firebase・データ境界統制',
  'Identity & Workload Federation': 'ID・ワークロードフェデレーション (IAM/WIF)',
  'Cloud Workload & Database Hardening': 'クラウドワークロード・DB堅牢化',
  'AI / Vertex & Runtime Threat Governance': 'AI / Vertex・実行時脅威ガバナンス',
  'FinOps Cost Guardrails & Resilience': 'FinOps コスト統制・レジリエンス',
  'Scan Completeness & Input Safety': '走査完全性・入力安全性',
};

function scoreGrade(score: number, incomplete: boolean): string {
  if (incomplete) return 'INCOMPLETE';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

export function formatBlueprint(graph: GraphResult, prover?: DualProverVerdict, remediations: Remediation[] = [], lang: ReportLanguage = 'en', audience: ConsultingAudience = 'enterprise'): string {
  const counts: Record<Severity, number> = { blocker: 0, high: 0, medium: 0, low: 0, info: 0 };
  const pillarPenalties = new Map<string, number>(PILLARS.map(pillar => [pillar, 0]));
  const locusPenalties = new Map<string, { domain: string; penalty: number }>();
  const distinctRuleIds: string[] = [];
  for (const finding of graph.findings) {
    counts[finding.severity]++;
    if (!distinctRuleIds.includes(finding.ruleId)) distinctRuleIds.push(finding.ruleId);
    const domain = controlDomain(finding.ruleId);
    if (pillarPenalties.has(domain)) {
      const penalty = finding.severity === 'blocker' ? 35 : finding.severity === 'high' ? 18 : finding.severity === 'medium' ? 8 : 3;
      const scopeMatch = finding.ruleId.startsWith('firebase/')
        ? finding.message.match(/ (?:at|match) (\/[^\s.]*?)\.?$/)?.[1]
        : undefined;
      const locusKey = `${domain}:${finding.location.file}:${scopeMatch ?? finding.location.line}`;
      const prev = locusPenalties.get(locusKey);
      if (!prev || penalty > prev.penalty) {
        locusPenalties.set(locusKey, { domain, penalty });
      }
    }
  }
  for (const { domain, penalty } of locusPenalties.values()) {
    pillarPenalties.set(domain, (pillarPenalties.get(domain) ?? 0) + penalty);
  }
  const incomplete = graph.findings.some(finding => finding.ruleId.startsWith('scan/'));
  const pillarScores = PILLARS.map(pillar => ({
    pillar,
    score: Math.max(0, 100 - (pillarPenalties.get(pillar) ?? 0)),
  }));
  const rawAverage = Math.round(pillarScores.reduce((sum, item) => sum + item.score, 0) / PILLARS.length);
  const overallScore = incomplete ? 0 : rawAverage;
  const grade = scoreGrade(overallScore, incomplete);
  const estimatedHoursSaved = Math.max(40, graph.nodes.length * 4 + graph.findings.length * 6 + graph.paths.length * 8);
  const estimatedJpySaved = estimatedHoursSaved * 35_000;
  const estimatedUsdSaved = Math.round(estimatedJpySaved / 150);
  const intakeSummary = `audience=${audience} grade=${grade} score=${overallScore}/100 blocker=${counts.blocker} high=${counts.high} medium=${counts.medium} low=${counts.low} paths=${graph.paths.length} patches=${remediations.filter(item => item.diff).length}`;
  const destructionCert = executeEphemeralFernetDoDCycle(intakeSummary);

  if (lang === 'ja') {
    const audienceLabelJa = audience === 'municipal' ? '地方自治体・ガバメントクラウド向け（総務省三層の対策・デジタル庁基準・ISMAP対応）'
      : audience === 'sme' ? '中堅・中小企業・ひとり情シス向け（経産省サプライチェーン評価・IPA 5か条・個人情報保護法・FinOps対応）'
      : 'エンタープライズ・上場企業向け（SOC2・ISO27001・NIST CSF 2.0・全領域統合）';
    const lines = [
      '# Atlas Sovereign — 自律型クラウド・DX・AI コンサルティング＆セキュリティ設計書',
      '',
      '## 1. エグゼクティブリスク要約（社内専属コンサルAI — 外部コンサル不要）',
      `- 対象コンサルプロファイル: ${audienceLabelJa}`,
      `- 走査ステータス: ${incomplete ? '未完了（先に scan/* の入力診断エラーを解消してください）' : '完了 (COMPLETE)'}`,
      `- アーキテクチャ成熟度スコア: ${overallScore}/100 (Grade: ${grade})`,
      `- 検出件数: 合計 ${graph.findings.length} 件 (BLOCKER: ${counts.blocker}, HIGH: ${counts.high}, MEDIUM: ${counts.medium}, LOW: ${counts.low})`,
      `- 到達可能なクロス境界攻撃経路: ${graph.paths.length} 本`,
      `- 外部コンサル削減効果の試算: 約 ¥${estimatedJpySaved.toLocaleString('en-US')} 相当（約 ${estimatedHoursSaved} 時間分の外部コンサル工数を ¥0 で代替）`,
    ];
    if (prover) {
      lines.push(`- Sovereign Prover (${prover.mode}): ${prover.status}`);
      for (const [lane, verdict] of Object.entries(prover.lanes)) {
        lines.push(`  - ${lane} (${displayText(verdict.model)}): ${verdict.status} — ${displayText(verdict.rationale)}`);
      }
    }
    lines.push(
      '',
      '### 5領域アーキテクチャ成熟度スコアカード',
      '| コンサル評価領域 | スコア | グレード |',
      '| --- | --- | --- |',
      ...pillarScores.map(item => `| ${PILLAR_JA[item.pillar] ?? item.pillar} | ${item.score}/100 | ${scoreGrade(item.score, incomplete)} |`),
      '',
      '### 法規制・ガイドライン自動マッピング表（総務省・デジタル庁・ISMAP ／ 経産省・IPA・個情法 ／ SOC2・ISO27001）',
      '| ルールID | 地方自治体・公共（総務省・デジタル庁・ISMAP） | 中小企業・取引先提出（経産省・IPA・個人情報保護法） | グローバル・上場企業（SOC2 / ISO27001 / NIST） |',
      '| --- | --- | --- | --- |',
      ...(distinctRuleIds.length
        ? distinctRuleIds.map(ruleId => {
          const c = getCompliance(ruleId);
          return `| \`${ruleId}\` | ${c.municipalJa} | ${c.smeJa} | ${c.enterprise} |`;
        })
        : ['| `なし (全項目適合)` | 総務省三層の対策・ガバメントクラウド基準 適合 | 経産省サプライチェーン・個人情報保護法第23条 適合 | SOC2 / ISO27001 / NIST CSF 2.0 適合 |']),
      '',
      '## 2. 30 / 60 / 90日 自律改修ロードマップ',
      '- **フェーズ 1（1〜30日目 — 即時封じ込め＆AI Airlock 接続）**: BLOCKER および確定公開露出（Firebase Rules、0.0.0.0/0 の Cloud SQL、公開 BigQuery データセット、公開 Cloud Run invoker、ログ改ざん）を遮断し、`atlas-sovereign mcp-config --client gemini` で社内 AI の MCP サーバーを読み取り専用化する。',
      '- **フェーズ 2（31〜60日目 — ID・AI・データ主権・BCP・FinOps 堅牢化）**: 既定サービスアカウントの最小権限分離、GKE Workload Identity 有効化、Vertex AI 公開 IP 無効化、国内リージョン（東京・大阪）固定、Cloud SQL のマルチゾーン HA（`REGIONAL`）・TLS・削除保護・バックアップ強制、CMEK 鍵設定、Storage ライフサイクル設定、サーバーレス上限設定、および GitHub WIF / Actions 固定を実施する。',
      '- **フェーズ 3（61〜90日目 — 自走型 CI/CD 退行防止ゲート）**: GitHub Actions の Pull Request チェックに `atlas-sovereign audit` を組み込み、外部コンサルなしで今後の設定退行を自動ブロックする。',
      '',
      '## 3. 統制ドメイン別の優先指摘一覧',
    );
    if (!graph.findings.length) {
      lines.push('解析対象の入力で指摘は検出されませんでした（指摘なし・安全性の完全な保証ではありません）。');
    } else {
      for (const finding of [...graph.findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity])) {
        const domainJa = PILLAR_JA[controlDomain(finding.ruleId)] ?? controlDomain(finding.ruleId);
        const titleJa = RULE_TITLE_JA[finding.ruleId] ?? displayText(finding.title);
        const msgJa = RULE_MESSAGE_JA[finding.ruleId] ?? displayText(finding.message);
        const deepJa = RULE_DEEP_RATIONALE_JA[finding.ruleId];
        lines.push(`- **[${finding.severity.toUpperCase()}]** \`${displayText(finding.location.file)}:${finding.location.line}\` — **${titleJa}** (\`${finding.ruleId}\` · *${domainJa}*)`);
        lines.push(`  - ${msgJa}`);
        if (deepJa) lines.push(`  - ${deepJa}`);
      }
    }
    lines.push('', '## 4. 到達可能なクロス境界攻撃経路');
    if (!graph.paths.length) {
      lines.push('解析対象の入力で到達可能なクロス境界攻撃経路は検出されませんでした。');
    } else {
      for (const path of graph.paths) {
        lines.push(`- **攻撃経路 ${path.severity.toUpperCase()} (${path.confidence === 'confirmed' ? '確定' : '潜在'})**: ${localizePathJa(path.description)}`);
      }
    }
    if (remediations.length) {
      lines.push('', '## 5. レビュー専用の自動修正パッチ案');
      for (const remediation of remediations) {
        lines.push(`- **修正提案 ${remediation.findingId}** (\`${displayText(remediation.file)}\`): ${localizeRemediationJa(remediation.description)}`);
        if (remediation.diff) lines.push('```diff', remediation.diff.trimEnd(), '```');
      }
    }
    if (graph.limitations.length) {
      lines.push('', '## 6. 走査範囲と解析上の制約');
      for (const limitation of graph.limitations) lines.push(`- 制約事項: ${localizeLimitationJa(limitation)}`);
    }
    lines.push(
      '',
      '## 7. 組織別コンサル成果物＆自律実行モード（社内専属コンサルAI — Apache-2.0）',
      '- **社内専属コンサルAI即時構築（Apache-2.0、¥0／完全無料）**: `Atlas Sovereign` を自社の AI エージェントに読み込ませるだけで、外部コンサルティングファームを一切不要にする社内専属コンサルAIを即座に構築できます。',
      '- **🏛️ 地方自治体・公共機関向け（財政課・議会予算要求＆委託先SIer指示用）**: 上記マッピング表を「総務省ガイドライン（三層の対策・β\'モデル）・デジタル庁ガバメントクラウド利用基準・ISMAP」適合根拠および庁内稟議・SIer是正指示書としてそのまま転記可能です。',
      '- **🏢 中小企業・ひとり情シス向け（大手取引先・金融機関・補助金提出用）**: 上記マッピング表を「経済産業省サプライチェーン対策評価制度・IPA情報セキュリティ5か条・個人情報保護法第23条（安全管理措置）」の取引先提出用回答シートとしてそのまま活用可能です。',
      `- **Redacted Sprint Intake Summary**: \`${intakeSummary}\``,
      '',
      '## 8. 米国国防総省規格 DoD 5220.22-M 消去＆ECDSA P-256 暗号署名入りデータ破棄証明書',
      `- **証明書ID (Certificate ID)**: \`${destructionCert.certificateId}\` (${destructionCert.issuedAt})`,
      `- **対象リポジトリ保護モード**: \`${destructionCert.targetReadOnlyMode}\``,
      `- **一時領域隔離＆暗号化規格**: \`ACL ${destructionCert.ephemeralVaultAcl}\` + \`${destructionCert.encryptionStandard}\` (SHA-256: \`${destructionCert.fernetCiphertextSha256}\`)`,
      `- **完全消去規格 (Sanitization Standard)**: \`${destructionCert.sanitizationStandard}\` (${destructionCert.passesCompleted} パス上書き完了 · 計 ${destructionCert.totalBytesOverwritten} bytes 消去 · Pass-3 SHA-256: \`${destructionCert.pass3OverwriteSha256}\`)`,
      `- **暗号署名アルゴリズム**: \`${destructionCert.signatureAlgorithm}\` (検証ステータス: \`${destructionCert.verified ? 'VERIFIED' : 'FAILED'}\`)`,
      `- **公開鍵フィンガープリント (SPKI SHA-256)**: \`${destructionCert.publicKeyFingerprintSha256}\``,
      `- **ECDSA P-256 デジタル署名 (Base64URL)**: \`${destructionCert.signatureBase64Url}\``,
    );
    return lines.join('\n') + '\n';
  }

  const audienceLabelEn = audience === 'municipal' ? 'Municipal & Public Sector (GovCloud Data Residency, Disaster BCP & ISMAP)'
    : audience === 'sme' ? 'Small & Medium Enterprise / Lean IT (Supply-Chain Security, FinOps Cost Protection & Plain-Language Playbook)'
    : 'Enterprise & Public Company (SOC2, ISO/IEC 27001, NIST CSF 2.0 & Full-Spectrum Governance)';
  const lines = [
    '# Atlas Sovereign — Autonomous Cloud/DX/AI Consulting & Security Blueprint',
    '',
    '## 1. Executive Risk Summary (In-House Consulting AI — Zero External Consultants Needed)',
    `- Consulting Profile: ${audienceLabelEn}`,
    `- Scan Status: ${incomplete ? 'INCOMPLETE (resolve scan/* diagnostics first)' : 'COMPLETE'}`,
    `- Architecture Maturity Score: ${overallScore}/100 (Grade: ${grade})`,
    `- Findings: ${graph.findings.length} total (BLOCKER: ${counts.blocker}, HIGH: ${counts.high}, MEDIUM: ${counts.medium}, LOW: ${counts.low})`,
    `- Reachable Cross-Boundary Attack Paths: ${graph.paths.length}`,
    `- Estimated External Consulting Equivalent Saved: ~$${estimatedUsdSaved.toLocaleString('en-US')} (~${estimatedHoursSaved} consulting hours displaced for $0)`,
  ];
  if (prover) {
    lines.push(`- Sovereign Prover (${prover.mode}): ${prover.status}`);
    for (const [lane, verdict] of Object.entries(prover.lanes)) {
      lines.push(`  - ${lane} (${displayText(verdict.model)}): ${verdict.status} — ${displayText(verdict.rationale)}`);
    }
  }
  lines.push(
    '',
    '### 5-Pillar Architecture Maturity Scorecard',
    '| Consulting Pillar | Score | Grade |',
    '| --- | --- | --- |',
    ...pillarScores.map(item => `| ${item.pillar} | ${item.score}/100 | ${scoreGrade(item.score, incomplete)} |`),
    '',
    '### Regulatory & Framework Compliance Mapping (Enterprise SOC2/ISO27001, Municipal GovCloud/ISMAP & SME Supply-Chain)',
    '| Rule ID | Enterprise (SOC2 / ISO27001 / NIST CSF 2.0) | Municipal & Public Sector (GovCloud / ISMAP) | SME & Supply-Chain Partner Readiness |',
    '| --- | --- | --- | --- |',
    ...(distinctRuleIds.length
      ? distinctRuleIds.map(ruleId => {
        const c = getCompliance(ruleId);
        return `| \`${ruleId}\` | ${c.enterprise} | ${c.municipalEn} | ${c.smeEn} |`;
      })
      : ['| `None (All Controls Passing)` | SOC2 / ISO27001 / NIST CSF 2.0 Aligned | GovCloud & ISMAP Aligned | SME Supply-Chain & Data Privacy Aligned |']),
    '',
    '## 2. Autonomous 30 / 60 / 90-Day Remediation Roadmap',
    '- **Phase 1 (Day 1-30 — Immediate Containment & AI Airlock)**: Eliminate BLOCKER and confirmed public exposures (Firebase rules, 0.0.0.0/0 Cloud SQL, public BigQuery datasets, public invokers, logging tampering) and wrap internal AI MCP servers with `atlas-sovereign mcp-config --client gemini`.',
    '- **Phase 2 (Day 31-60 — Identity, AI, Data Sovereignty, BCP & FinOps Hardening)**: Replace default Compute/AppEngine/CloudBuild/GKE service accounts with least-privilege identities, enable GKE Workload Identity, disable public IP on Vertex AI Workbench, pin domestic data residency, enforce Cloud SQL REGIONAL HA, TLS & deletion/backup guardrails, configure CMEK keys and Storage lifecycle rules, cap serverless `max_instance_count`, and pin GitHub WIF / Actions.',
    '- **Phase 3 (Day 61-90 — Continuous Self-Driving CI/CD Gate)**: Enforce `atlas-sovereign audit` in GitHub Actions pull-request checks so posture drift is blocked automatically without external consultants.',
    '',
    '## 3. Prioritized Findings & Control Domains',
  );
  if (!graph.findings.length) {
    lines.push('No findings in the analyzed inputs; this is not a completeness guarantee.');
  } else {
    for (const finding of [...graph.findings].sort((a, b) => severityRank[a.severity] - severityRank[b.severity])) {
      const deepEn = RULE_DEEP_RATIONALE_EN[finding.ruleId];
      lines.push(`- **[${finding.severity.toUpperCase()}]** \`${displayText(finding.location.file)}:${finding.location.line}\` — **${displayText(finding.title)}** (\`${finding.ruleId}\` · *${controlDomain(finding.ruleId)}*)`);
      lines.push(`  - ${displayText(finding.message)}`);
      if (deepEn) lines.push(`  - ${deepEn}`);
    }
  }
  lines.push('', '## 4. Reachable Cross-Boundary Attack Paths');
  if (!graph.paths.length) {
    lines.push('No reachable cross-boundary attack paths were enumerated in the analyzed inputs.');
  } else {
    for (const path of graph.paths) {
      lines.push(`- **PATH ${path.severity.toUpperCase()} (${path.confidence})**: ${displayText(path.description)}`);
    }
  }
  if (remediations.length) {
    lines.push('', '## 5. Review-Only Remediation Proposals');
    for (const remediation of remediations) {
      lines.push(`- **PROPOSAL ${remediation.findingId}** (\`${displayText(remediation.file)}\`): ${displayText(remediation.description)}`);
      if (remediation.diff) lines.push('```diff', remediation.diff.trimEnd(), '```');
    }
  }
  if (graph.limitations.length) {
    lines.push('', '## 6. Scan Scope & Limitations');
    for (const limitation of graph.limitations) lines.push(`- LIMITATION: ${displayText(limitation)}`);
  }
  lines.push(
    '',
    '## 7. Execution Mode & Audience Deliverables (In-House Consulting AI — Apache-2.0)',
    '- **Instant In-House Consulting AI (Apache-2.0, $0 / Free)**: Load `Atlas Sovereign` into your company\'s AI agent to instantly build an enterprise, municipal, or SME Cloud/DX/AI consulting AI in-house, making external consulting firms completely unnecessary.',
    '- **Municipal & Public Sector Deliverable (`--audience municipal`)**: Directly maps findings to Government Cloud data residency, disaster BCP multi-zone HA, and ISMAP controls for budget proposals and vendor RFP verification.',
    '- **SME & Supply-Chain Deliverable (`--audience sme`)**: Provides a plain-language 3-step remediation prescription, FinOps monthly cloud bill protection, and partner security assessment evidence.',
    `- **Redacted Sprint Intake Summary**: \`${intakeSummary}\``,
    '',
    '## 8. DoD 5220.22-M 3-Pass Sanitization & ECDSA P-256 Signed Certificate of Data Destruction',
    `- **Certificate ID**: \`${destructionCert.certificateId}\` (${destructionCert.issuedAt})`,
    `- **Target Repository Protection**: \`${destructionCert.targetReadOnlyMode}\``,
    `- **Ephemeral Vault & Encryption**: \`ACL ${destructionCert.ephemeralVaultAcl}\` + \`${destructionCert.encryptionStandard}\` (SHA-256: \`${destructionCert.fernetCiphertextSha256}\`)`,
    `- **Sanitization Standard**: \`${destructionCert.sanitizationStandard}\` (${destructionCert.passesCompleted} passes completed · ${destructionCert.totalBytesOverwritten} total bytes overwritten · Pass-3 SHA-256: \`${destructionCert.pass3OverwriteSha256}\`)`,
    `- **Signature Algorithm**: \`${destructionCert.signatureAlgorithm}\` (Verification Status: \`${destructionCert.verified ? 'VERIFIED' : 'FAILED'}\`)`,
    `- **Public Key Fingerprint (SPKI SHA-256)**: \`${destructionCert.publicKeyFingerprintSha256}\``,
    `- **ECDSA P-256 Digital Signature (Base64URL)**: \`${destructionCert.signatureBase64Url}\``,
  );
  return lines.join('\n') + '\n';
}
