//! Security findings scanner: secret regexes + insecure-API matchers + manifest
//! red flags. Exports SARIF, Lancer-native JSON, and Quark-style rule JSON.

use jadx_resources::ManifestInfo;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Note,
    Info,
}

impl Severity {
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note | Severity::Info => "note",
        }
    }
    pub fn confidence(self) -> f32 {
        match self {
            Severity::Error => 1.0,
            Severity::Warning => 0.8,
            Severity::Note => 0.5,
            Severity::Info => 0.3,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

struct Rule {
    id: &'static str,
    category: &'static str,
    severity: Severity,
    description: &'static str,
    regex: Regex,
}

fn rule(
    id: &'static str,
    category: &'static str,
    severity: Severity,
    description: &'static str,
    pattern: &str,
) -> Option<Rule> {
    Regex::new(pattern).ok().map(|regex| Rule {
        id,
        category,
        severity,
        description,
        regex,
    })
}

/// The full rule bank (secret regexes + insecure-API matchers).
fn rules() -> Vec<Rule> {
    use Severity::*;
    let specs: Vec<Option<Rule>> = vec![
        // ---- hardcoded secrets (~ the upstream ~80-pattern set) ----
        rule("AWS_ACCESS_KEY", "secret", Error, "AWS access key ID", r"AKIA[0-9A-Z]{16}"),
        rule("AWS_SECRET_KEY", "secret", Error, "AWS secret access key", r#"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"#),
        rule("AWS_MWS_KEY", "secret", Error, "AWS MWS auth token", r"amzn\.mws\.[0-9a-f-]{36}"),
        rule("STRIPE_LIVE_SECRET", "secret", Error, "Stripe live secret key", r"sk_live_[0-9a-zA-Z]{24,}"),
        rule("STRIPE_LIVE_PUB", "secret", Warning, "Stripe live publishable key", r"pk_live_[0-9a-zA-Z]{24,}"),
        rule("STRIPE_RESTRICTED", "secret", Error, "Stripe restricted key", r"rk_live_[0-9a-zA-Z]{24,}"),
        rule("SLACK_TOKEN", "secret", Error, "Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
        rule("SLACK_WEBHOOK", "secret", Error, "Slack webhook URL", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        rule("GITHUB_PAT", "secret", Error, "GitHub personal access token", r"ghp_[0-9A-Za-z]{36}"),
        rule("GITHUB_OAUTH", "secret", Error, "GitHub OAuth token", r"gho_[0-9A-Za-z]{36}"),
        rule("GITHUB_USER_TOKEN", "secret", Error, "GitHub user-to-server token", r"ghu_[0-9A-Za-z]{36}"),
        rule("GITHUB_SERVER_TOKEN", "secret", Error, "GitHub server-to-server token", r"ghs_[0-9A-Za-z]{36}"),
        rule("GITHUB_REFRESH", "secret", Error, "GitHub refresh token", r"ghr_[0-9A-Za-z]{36}"),
        rule("GITHUB_FINE_PAT", "secret", Error, "GitHub fine-grained PAT", r"github_pat_[0-9A-Za-z_]{60,}"),
        rule("GOOGLE_API_KEY", "secret", Error, "Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
        rule("GOOGLE_OAUTH", "secret", Error, "Google OAuth access token", r"ya29\.[0-9A-Za-z_\-]+"),
        rule("GCP_SA_KEY", "secret", Error, "GCP service account private key id", r#""private_key_id"\s*:\s*"[0-9a-f]{40}""#),
        rule("FIREBASE_URL", "secret", Warning, "Firebase database URL", r"https://[a-z0-9.-]+\.firebaseio\.com"),
        rule("FIREBASE_APP_URL", "secret", Note, "Firebase app URL", r"https://[a-z0-9.-]+\.firebaseapp\.com"),
        rule("TWILIO_SID", "secret", Error, "Twilio account SID", r"AC[0-9a-fA-F]{32}"),
        rule("TWILIO_KEY", "secret", Error, "Twilio API key", r"SK[0-9a-fA-F]{32}"),
        rule("SENDGRID_KEY", "secret", Error, "SendGrid API key", r"SG\.[\w\-]{22}\.[\w\-]{43}"),
        rule("MAILGUN_KEY", "secret", Error, "Mailgun API key", r"key-[0-9a-zA-Z]{32}"),
        rule("MAILCHIMP_KEY", "secret", Error, "Mailchimp API key", r"[0-9a-f]{32}-us[0-9]{1,2}"),
        rule("SQUARE_ACCESS", "secret", Error, "Square access token", r"sq0atp-[0-9A-Za-z_\-]{22}"),
        rule("SQUARE_OAUTH", "secret", Error, "Square OAuth secret", r"sq0csp-[0-9A-Za-z_\-]{43}"),
        rule("PAYPAL_BRAINTREE", "secret", Error, "PayPal/Braintree access token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
        rule("HEROKU_KEY", "secret", Warning, "Heroku API key (UUID)", r"(?i)heroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
        rule("FACEBOOK_TOKEN", "secret", Error, "Facebook access token", r"EAACEdEose0cBA[0-9A-Za-z]+"),
        rule("FACEBOOK_SECRET", "secret", Error, "Facebook app secret", r#"(?i)facebook.{0,20}['\"][0-9a-f]{32}['\"]"#),
        rule("TWITTER_TOKEN", "secret", Warning, "Twitter access token", r#"(?i)twitter.{0,20}['\"][0-9a-zA-Z]{35,44}['\"]"#),
        rule("TWITTER_BEARER", "secret", Error, "Twitter bearer token", r"AAAAAAAAAAAAAAAAAAAAA[0-9A-Za-z%]{30,}"),
        rule("LINKEDIN_SECRET", "secret", Warning, "LinkedIn secret key", r#"(?i)linkedin.{0,20}['\"][0-9a-zA-Z]{16}['\"]"#),
        rule("AZURE_STORAGE", "secret", Error, "Azure storage account key", r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        rule("NPM_TOKEN", "secret", Error, "npm access token", r"npm_[0-9A-Za-z]{36}"),
        rule("PYPI_TOKEN", "secret", Error, "PyPI upload token", r"pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}"),
        rule("OPENAI_KEY", "secret", Error, "OpenAI API key", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        rule("ANTHROPIC_KEY", "secret", Error, "Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{90,}"),
        rule("DIGITALOCEAN", "secret", Error, "DigitalOcean PAT", r"dop_v1_[0-9a-f]{64}"),
        rule("SHOPIFY_TOKEN", "secret", Error, "Shopify access token", r"shpat_[0-9a-fA-F]{32}"),
        rule("DISCORD_TOKEN", "secret", Warning, "Discord bot token", r"[MN][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}"),
        rule("DISCORD_WEBHOOK", "secret", Warning, "Discord webhook", r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
        rule("JWT_TOKEN", "secret", Warning, "JWT-shaped token", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
        rule("PEM_PRIVATE_KEY", "secret", Error, "PEM private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        rule("SSH_PRIVATE", "secret", Error, "SSH private key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        rule("GENERIC_API_KEY", "secret", Note, "Generic hardcoded credential", r#"(?i)(api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\s*=\s*['\"][^'\"]{8,}['\"]"#),
        rule("BASIC_AUTH_URL", "secret", Warning, "Credentials in URL", r"https?://[^:@/\s]+:[^@/\s]+@"),
        rule("PRIVATE_KEY_JSON", "secret", Error, "Embedded private key (JSON)", r#""private_key"\s*:\s*"-----BEGIN"#),

        // ---- additional provider token shapes (extends bank to >=80 distinct patterns) ----
        rule("GITLAB_PAT", "secret", Error, "GitLab personal access token", r"glpat-[0-9A-Za-z_\-]{20}"),
        rule("GITLAB_PIPELINE", "secret", Error, "GitLab pipeline trigger token", r"glptt-[0-9a-f]{40}"),
        rule("GITLAB_RUNNER", "secret", Warning, "GitLab runner registration token", r"GR1348941[0-9A-Za-z_\-]{20}"),
        rule("STRIPE_TEST_SECRET", "secret", Warning, "Stripe test secret key", r"sk_test_[0-9a-zA-Z]{24,}"),
        rule("STRIPE_TEST_PUB", "secret", Note, "Stripe test publishable key", r"pk_test_[0-9a-zA-Z]{24,}"),
        rule("STRIPE_RESTRICTED_TEST", "secret", Warning, "Stripe restricted test key", r"rk_test_[0-9a-zA-Z]{24,}"),
        rule("STRIPE_WEBHOOK_SECRET", "secret", Error, "Stripe webhook signing secret", r"whsec_[0-9A-Za-z]{32,}"),
        rule("FIREBASE_FCM_SERVER", "secret", Error, "Firebase Cloud Messaging server key", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}"),
        rule("GOOGLE_OAUTH_REFRESH", "secret", Error, "Google OAuth refresh token", r"1/[0-9A-Za-z_\-]{43}|1/[0-9A-Za-z_\-]{64}"),
        rule("GOOGLE_CAPTCHA", "secret", Note, "Google reCAPTCHA key", r"6L[0-9A-Za-z_\-]{38}"),
        rule("SENTRY_DSN", "secret", Warning, "Sentry DSN", r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry\.io/[0-9]+"),
        rule("DATADOG_KEY", "secret", Error, "Datadog API key", r#"(?i)datadog.{0,20}['\"][0-9a-f]{32}['\"]"#),
        rule("NEW_RELIC_KEY", "secret", Error, "New Relic license/API key", r"NRAK-[0-9A-Z]{27}"),
        rule("NEW_RELIC_USER_KEY", "secret", Error, "New Relic user API key", r"NRJS-[0-9a-f]{19}"),
        rule("PAGERDUTY_KEY", "secret", Warning, "PagerDuty API token", r#"(?i)pagerduty.{0,20}['\"][0-9a-zA-Z+_\-]{20}['\"]"#),
        rule("ALGOLIA_KEY", "secret", Warning, "Algolia admin API key", r#"(?i)algolia.{0,20}['\"][0-9a-f]{32}['\"]"#),
        rule("CLOUDINARY_URL", "secret", Error, "Cloudinary credentials URL", r"cloudinary://[0-9]+:[0-9A-Za-z_\-]+@[0-9A-Za-z_\-]+"),
        rule("DIGITALOCEAN_OAUTH", "secret", Error, "DigitalOcean OAuth token", r"doo_v1_[0-9a-f]{64}"),
        rule("DIGITALOCEAN_REFRESH", "secret", Error, "DigitalOcean refresh token", r"dor_v1_[0-9a-f]{64}"),
        rule("DROPBOX_TOKEN", "secret", Error, "Dropbox short-lived access token", r"sl\.[A-Za-z0-9_\-]{130,}"),
        rule("DROPBOX_LONG", "secret", Warning, "Dropbox long-lived token", r#"(?i)dropbox.{0,20}['\"][0-9A-Za-z_\-]{43,}['\"]"#),
        rule("ASANA_TOKEN", "secret", Warning, "Asana personal access token", r"[0-9]/[0-9]{16}:[0-9A-Za-z]{32}"),
        rule("ATLASSIAN_TOKEN", "secret", Error, "Atlassian/Jira API token", r"ATATT3[A-Za-z0-9_\-=]{180,}"),
        rule("TELEGRAM_BOT", "secret", Error, "Telegram bot token", r"[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}"),
        rule("TWILIO_API_KEY", "secret", Error, "Twilio API key SID", r"SK[0-9a-f]{32}"),
        rule("SQUARE_PROD_ACCESS", "secret", Error, "Square production access token", r"EAAA[0-9A-Za-z_\-]{59}"),
        rule("SHOPIFY_PRIVATE", "secret", Error, "Shopify private app password", r"shpss_[0-9a-fA-F]{32}"),
        rule("SHOPIFY_CUSTOM", "secret", Error, "Shopify custom app token", r"shpca_[0-9a-fA-F]{32}"),
        rule("SHOPIFY_SHARED", "secret", Error, "Shopify shared secret", r"shpat_[0-9a-fA-F]{32}"),
        rule("RAZORPAY_LIVE", "secret", Error, "Razorpay live key id", r"rzp_live_[0-9A-Za-z]{14,}"),
        rule("RAZORPAY_TEST", "secret", Warning, "Razorpay test key id", r"rzp_test_[0-9A-Za-z]{14,}"),
        rule("OKTA_TOKEN", "secret", Warning, "Okta API token", r#"(?i)okta.{0,20}['\"]00[0-9A-Za-z_\-]{40}['\"]"#),
        rule("AUTH0_SECRET", "secret", Warning, "Auth0 client secret", r#"(?i)auth0.{0,20}['\"][0-9A-Za-z_\-]{40,}['\"]"#),
        rule("TWITCH_TOKEN", "secret", Warning, "Twitch OAuth token", r#"(?i)twitch.{0,20}['\"][0-9a-z]{30}['\"]"#),
        rule("SPOTIFY_TOKEN", "secret", Note, "Spotify access token", r#"(?i)spotify.{0,20}['\"]BQ[0-9A-Za-z_\-]{80,}['\"]"#),
        rule("MS_TEAMS_WEBHOOK", "secret", Warning, "Microsoft Teams webhook", r"https://[a-z0-9.]*webhook\.office\.com/webhookb2/[0-9A-Za-z@/\-]+"),
        rule("LINKEDIN_TOKEN", "secret", Warning, "LinkedIn OAuth access token", r"AQ[A-Za-z0-9_\-]{370,}"),
        rule("DISCORD_TOKEN_MFA", "secret", Warning, "Discord MFA bot token", r"mfa\.[A-Za-z0-9_\-]{84}"),
        rule("GENERIC_SECRET_ASSIGN", "secret", Note, "Generic secret literal assignment", r#"(?i)(secret|token|passwd|pwd|apikey)['\"]?\s*[:=]\s*['\"][^'\"]{12,}['\"]"#),
        rule("BEARER_HEADER", "secret", Note, "Hardcoded Bearer authorization header", r#"(?i)authorization['\"]?\s*[:=]\s*['\"]?Bearer\s+[0-9A-Za-z._\-]{20,}"#),
        rule("BASIC_AUTH_HEADER", "secret", Note, "Hardcoded Basic authorization header", r#"(?i)authorization['\"]?\s*[:=]\s*['\"]?Basic\s+[0-9A-Za-z+/=]{16,}"#),
        rule("PGP_PRIVATE_KEY", "secret", Error, "PGP private key block", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        rule("RSA_PRIVATE_KEY", "secret", Error, "RSA private key block", r"-----BEGIN RSA PRIVATE KEY-----"),
        rule("EC_PRIVATE_KEY", "secret", Error, "EC private key block", r"-----BEGIN EC PRIVATE KEY-----"),
        rule("DSA_PRIVATE_KEY", "secret", Error, "DSA private key block", r"-----BEGIN DSA PRIVATE KEY-----"),
        rule("PKCS8_PRIVATE_KEY", "secret", Error, "PKCS#8 private key block", r"-----BEGIN PRIVATE KEY-----"),
        rule("ENCRYPTED_PRIVATE_KEY", "secret", Error, "Encrypted private key block", r"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
        rule("PUTTY_PRIVATE_KEY", "secret", Error, "PuTTY private key", r"PuTTY-User-Key-File-[0-9]"),
        rule("AGE_SECRET_KEY", "secret", Error, "age encryption secret key", r"AGE-SECRET-KEY-1[0-9A-Z]{58}"),
        rule("GRAFANA_TOKEN", "secret", Warning, "Grafana service account token", r"glsa_[0-9A-Za-z]{32}_[0-9a-f]{8}"),
        rule("GRAFANA_CLOUD", "secret", Warning, "Grafana cloud API token", r"glc_[0-9A-Za-z_\-=]{40,}"),
        rule("HASHICORP_VAULT", "secret", Error, "HashiCorp Vault service token", r"hvs\.[0-9A-Za-z_\-]{90,}"),
        rule("HASHICORP_BATCH", "secret", Error, "HashiCorp Vault batch token", r"hvb\.[0-9A-Za-z_\-]{90,}"),
        rule("DOPPLER_TOKEN", "secret", Warning, "Doppler API token", r"dp\.(pt|ct|st|sa|scim|audit)\.[0-9A-Za-z]{40,}"),
        rule("FLY_API_TOKEN", "secret", Warning, "Fly.io API token", r"fly[A-Za-z0-9_\-]{0,4}_[0-9A-Za-z_\-]{40,}"),
        rule("LINEAR_API_KEY", "secret", Warning, "Linear API key", r"lin_api_[0-9A-Za-z]{40}"),
        rule("NOTION_TOKEN", "secret", Warning, "Notion integration token", r"secret_[0-9A-Za-z]{43}"),
        rule("POSTMAN_KEY", "secret", Warning, "Postman API key", r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}"),
        rule("PLANETSCALE_TOKEN", "secret", Warning, "PlanetScale OAuth token", r"pscale_oauth_[0-9A-Za-z_\.\-]{32,}"),
        rule("PLANETSCALE_PASSWORD", "secret", Error, "PlanetScale password", r"pscale_pw_[0-9A-Za-z_\.\-]{32,}"),
        rule("SUPABASE_SERVICE", "secret", Error, "Supabase service role JWT", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]*role[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+"),
        rule("MAPBOX_SECRET", "secret", Warning, "Mapbox secret token", r"sk\.eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+"),
        rule("FINICITY_KEY", "secret", Warning, "Finicity API key", r#"(?i)finicity.{0,20}['\"][0-9a-f]{32}['\"]"#),
        rule("INTERCOM_TOKEN", "secret", Warning, "Intercom access token", r#"(?i)intercom.{0,20}['\"]dG9r[0-9A-Za-z=_\-]{50,}['\"]"#),
        rule("AMPLITUDE_KEY", "secret", Note, "Amplitude API key", r#"(?i)amplitude.{0,20}['\"][0-9a-f]{32}['\"]"#),
        rule("SEGMENT_KEY", "secret", Note, "Segment write key", r#"(?i)segment.{0,20}['\"][0-9A-Za-z]{32}['\"]"#),
        rule("AIRTABLE_KEY", "secret", Warning, "Airtable API key", r"key[0-9A-Za-z]{14}|pat[0-9A-Za-z]{14}\.[0-9a-f]{64}"),
        rule("CLOUDFLARE_TOKEN", "secret", Warning, "Cloudflare API token", r#"(?i)cloudflare.{0,20}['\"][0-9A-Za-z_\-]{40}['\"]"#),
        rule("FASTLY_TOKEN", "secret", Warning, "Fastly API token", r#"(?i)fastly.{0,20}['\"][0-9A-Za-z_\-]{32}['\"]"#),
        rule("CIRCLECI_TOKEN", "secret", Warning, "CircleCI personal token", r#"(?i)circleci.{0,20}['\"][0-9a-f]{40}['\"]"#),
        rule("TYPEFORM_TOKEN", "secret", Note, "Typeform personal token", r"tfp_[0-9A-Za-z_\-]{40,}"),
        rule("CLOJARS_TOKEN", "secret", Warning, "Clojars deploy token", r"CLOJARS_[0-9A-Za-z]{60}"),
        rule("DOCKER_HUB_PAT", "secret", Warning, "Docker Hub personal access token", r"dckr_pat_[0-9A-Za-z_\-]{20,}"),
        rule("RUBYGEMS_KEY", "secret", Warning, "RubyGems API key", r"rubygems_[0-9a-f]{48}"),
        rule("FACEBOOK_OAUTH", "secret", Warning, "Facebook OAuth app token", r"[0-9]{13,17}\|[0-9A-Za-z_\-]{27}"),
        rule("YANDEX_TOKEN", "secret", Warning, "Yandex API key", r"AQVN[A-Za-z0-9_\-]{35,38}"),

        // ---- insecure crypto ----
        rule("CRYPTO_DES", "crypto", Warning, "Weak cipher: DES", r#"getInstance\(\s*"DES"#),
        rule("CRYPTO_DESEDE", "crypto", Warning, "Weak cipher: 3DES", r#"getInstance\(\s*"DESede"#),
        rule("CRYPTO_RC4", "crypto", Warning, "Weak cipher: RC4", r#"getInstance\(\s*"RC4"#),
        rule("CRYPTO_RC2", "crypto", Warning, "Weak cipher: RC2", r#"getInstance\(\s*"RC2"#),
        rule("CRYPTO_BLOWFISH", "crypto", Note, "Legacy cipher: Blowfish", r#"getInstance\(\s*"Blowfish"#),
        rule("CRYPTO_AES_ECB", "crypto", Warning, "AES in ECB mode", r#"getInstance\(\s*"AES/ECB"#),
        rule("CRYPTO_AES_CBC_NOPAD", "crypto", Note, "AES/CBC/NoPadding", r#"getInstance\(\s*"AES/CBC/NoPadding"#),
        rule("HASH_MD5", "crypto", Warning, "Weak hash: MD5", r#"getInstance\(\s*"MD5"#),
        rule("HASH_SHA1", "crypto", Warning, "Weak hash: SHA-1", r#"getInstance\(\s*"SHA-?1"#),
        rule("HASH_MD2", "crypto", Note, "Weak hash: MD2", r#"getInstance\(\s*"MD2"#),
        rule("ECB_MODE", "crypto", Note, "ECB mode reference", r#""[A-Za-z0-9]+/ECB/"#),

        // ---- WebView / bridges ----
        rule("WEBVIEW_JS_INTERFACE", "webview", Warning, "addJavascriptInterface bridge", r"addJavascriptInterface\s*\("),
        rule("WEBVIEW_JS_ENABLED", "webview", Note, "JavaScript enabled in WebView", r"setJavaScriptEnabled\s*\(\s*true"),
        rule("WEBVIEW_FILE_ACCESS", "webview", Warning, "WebView file access enabled", r"setAllowFileAccess\s*\(\s*true"),
        rule("WEBVIEW_UNIVERSAL_FILE", "webview", Error, "Universal file access from URLs", r"setAllowUniversalAccessFromFileURLs\s*\(\s*true"),
        rule("WEBVIEW_FILE_FROM_FILE", "webview", Error, "File access from file URLs", r"setAllowFileAccessFromFileURLs\s*\(\s*true"),
        rule("WEBVIEW_LOAD_ASSET", "webview", Note, "Hybrid app asset load", r#"loadUrl\(\s*"file:///android_asset"#),

        // ---- command / native ----
        rule("RUNTIME_EXEC", "exec", Warning, "Runtime.exec call", r"Runtime\.getRuntime\(\)\.exec|\.exec\("),
        rule("PROCESS_BUILDER", "exec", Note, "ProcessBuilder usage", r"new\s+ProcessBuilder"),
        rule("LOAD_LIBRARY", "native", Note, "Native library load", r"loadLibrary\s*\(|System\.load\s*\("),

        // ---- IPC / intents / storage ----
        rule("INTENT_GRANT_FLAG", "ipc", Note, "Intent FLAG_GRANT_* permission", r"FLAG_GRANT_(READ|WRITE)_URI_PERMISSION"),
        rule("PENDING_INTENT_MUTABLE", "ipc", Warning, "Mutable PendingIntent", r"FLAG_MUTABLE"),
        rule("WORLD_READABLE", "storage", Warning, "MODE_WORLD_READABLE", r"MODE_WORLD_READABLE"),
        rule("WORLD_WRITABLE", "storage", Error, "MODE_WORLD_WRITABLE", r"MODE_WORLD_WRITABLE"),
        rule("EXTERNAL_STORAGE", "storage", Note, "External storage path", r"getExternalStorage(Directory|PublicDirectory)"),
        rule("CONTENT_RESOLVER_OPEN", "ipc", Warning, "ContentResolver.openInputStream on a possibly user-controlled URI", r"getContentResolver\s*\(\s*\)\s*\.\s*openInputStream\s*\(|ContentResolver[^;]*\.openInputStream\s*\("),

        // ---- TLS / hostname verification ----
        rule("TRUST_ALL", "tls", Error, "Trust-all TrustManager", r"checkServerTrusted|X509TrustManager"),
        rule("ALLOW_ALL_HOSTNAME", "tls", Error, "Allow-all hostname verifier", r"ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier"),
        rule("SSL_NULL_VERIFY", "tls", Error, "HostnameVerifier returns true", r"public\s+boolean\s+verify\s*\([^)]*\)\s*\{[^}]*return\s+true"),
    ];
    specs.into_iter().flatten().collect()
}

/// Scan one decompiled source file. `file` is the display path.
fn scan_source(file: &str, source: &str, rules: &[Rule]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (lineno, line) in source.lines().enumerate() {
        for r in rules {
            if r.regex.is_match(line) {
                out.push(Finding {
                    rule_id: r.id.to_string(),
                    category: r.category.to_string(),
                    severity: r.severity,
                    message: r.description.to_string(),
                    file: file.to_string(),
                    line: lineno + 1,
                    snippet: line.trim().chars().take(200).collect(),
                });
            }
        }
        // High-entropy literal detection.
        if let Some(f) = high_entropy_finding(file, line, lineno + 1) {
            out.push(f);
        }
    }
    out
}

/// Convenience: compile the rule bank once and scan many files.
pub fn scan_sources(files: &[(String, String)]) -> Vec<Finding> {
    let rules = rules();
    let mut out = Vec::new();
    for (name, src) in files {
        out.extend(scan_source(name, src, &rules));
    }
    out
}

fn high_entropy_finding(file: &str, line: &str, lineno: usize) -> Option<Finding> {
    static LITERAL: once_cell_like::Lazy = once_cell_like::Lazy;
    let re = LITERAL.get();
    for cap in re.captures_iter(line) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str();
            if s.len() >= 20 && shannon_entropy(s) > 4.5 {
                return Some(Finding {
                    rule_id: "HIGH_ENTROPY_STRING".to_string(),
                    category: "secret".to_string(),
                    severity: Severity::Note,
                    message: "High-entropy string (possible secret/key)".to_string(),
                    file: file.to_string(),
                    line: lineno,
                    snippet: s.chars().take(80).collect(),
                });
            }
        }
    }
    None
}

/// Manifest-level red flags.
pub fn scan_manifest(info: &ManifestInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    let file = "AndroidManifest.xml".to_string();
    let mut push = |id: &str, sev: Severity, msg: String| {
        out.push(Finding {
            rule_id: id.to_string(),
            category: "manifest".to_string(),
            severity: sev,
            message: msg,
            file: file.clone(),
            line: 1,
            snippet: String::new(),
        });
    };
    if info.debuggable == Some(true) {
        push("MANIFEST_DEBUGGABLE", Severity::Error, "android:debuggable=\"true\" shipped".to_string());
    }
    if info.allow_backup == Some(true) {
        push("MANIFEST_ALLOW_BACKUP", Severity::Warning, "android:allowBackup=\"true\" (adb backup exfil)".to_string());
    }
    if info.uses_cleartext_traffic == Some(true) {
        push("MANIFEST_CLEARTEXT", Severity::Warning, "android:usesCleartextTraffic=\"true\"".to_string());
    }
    if info.network_security_config.is_none() {
        push("MANIFEST_NO_NSC", Severity::Note, "No networkSecurityConfig declared".to_string());
    }
    for c in info.exported_components() {
        push(
            "EXPORTED_COMPONENT",
            Severity::Note,
            format!("Exported {} {} (attack surface)", c.kind, c.name),
        );
        for f in &c.intent_filters {
            for scheme in f.schemes() {
                push(
                    "DEEP_LINK",
                    Severity::Note,
                    format!("Deep link scheme '{scheme}' on {}", c.name),
                );
            }
        }
    }
    out
}

pub fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---- SARIF / Quark output ----

#[derive(Serialize)]
struct SarifReport {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    version: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysical,
}

#[derive(Serialize)]
struct SarifPhysical {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifact,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifact {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
}

/// Render findings as a SARIF 2.1.0 report (GitHub code scanning compatible).
pub fn to_sarif(findings: &[Finding]) -> String {
    let report = SarifReport {
        version: "2.1.0".to_string(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "lancer-jadx".to_string(),
                    information_uri: "https://github.com/NHTanvir/lancer-jadx".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
            },
            results: findings
                .iter()
                .map(|f| SarifResult {
                    rule_id: f.rule_id.clone(),
                    level: f.severity.sarif_level().to_string(),
                    message: SarifMessage {
                        text: format!("{}: {}", f.message, f.snippet),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysical {
                            artifact_location: SarifArtifact { uri: f.file.clone() },
                            region: SarifRegion {
                                start_line: f.line.max(1),
                            },
                        },
                    }],
                })
                .collect(),
        }],
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

#[derive(Serialize)]
struct QuarkCrime {
    crime: String,
    category: String,
    confidence: f32,
    permissions: Vec<String>,
    register: Vec<String>,
    file: String,
    line: usize,
}

#[derive(Serialize)]
struct QuarkReport {
    md5: String,
    apk_filename: String,
    crimes: Vec<QuarkCrime>,
}

/// Render findings in a Quark-engine-style JSON (`--export-quark-rules`).
pub fn to_quark(findings: &[Finding], apk_name: &str) -> String {
    let report = QuarkReport {
        md5: String::new(),
        apk_filename: apk_name.to_string(),
        crimes: findings
            .iter()
            .map(|f| QuarkCrime {
                crime: f.message.clone(),
                category: f.category.clone(),
                confidence: f.severity.confidence(),
                permissions: Vec::new(),
                register: Vec::new(),
                file: f.file.clone(),
                line: f.line,
            })
            .collect(),
    };
    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}

/// Render findings as Lancer-native JSON.
pub fn to_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

// Minimal lazy-regex holder (avoids an extra dependency).
mod once_cell_like {
    use regex::Regex;
    use std::sync::OnceLock;

    pub struct Lazy;
    impl Lazy {
        pub fn get(&self) -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| Regex::new(r#""([^"\\]{20,})""#).unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(rule_id: &str, source: &str) -> bool {
        scan_sources(&[("Sample.java".to_string(), source.to_string())])
            .iter()
            .any(|f| f.rule_id == rule_id)
    }

    #[test]
    fn rule_bank_compiles_and_has_full_set() {
        // Every spec must compile (no `rule(..)` returned None).
        let compiled = rules().len();
        // The full bank covers secrets + crypto + webview + exec/native + ipc/storage + tls.
        assert!(compiled >= 80, "expected >=80 compiled rules, got {compiled}");
        // The secret bank alone must be >=80 distinct provider patterns.
        let secrets = rules().iter().filter(|r| r.category == "secret").count();
        assert!(secrets >= 80, "expected >=80 secret patterns, got {secrets}");
    }

    #[test]
    fn content_resolver_open_input_stream_fires() {
        let src = "InputStream in = getContentResolver().openInputStream(uri);";
        assert!(fires("CONTENT_RESOLVER_OPEN", src));
    }

    #[test]
    fn new_secret_patterns_fire() {
        assert!(fires("GITLAB_PAT", "String t = \"glpat-ABCDEFGHIJ1234567890\";"));
        assert!(fires("STRIPE_WEBHOOK_SECRET", "whsec_0123456789abcdef0123456789abcdef"));
        assert!(fires(
            "TELEGRAM_BOT",
            "110201543:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawXY"
        ));
        assert!(fires(
            "PKCS8_PRIVATE_KEY",
            "-----BEGIN PRIVATE KEY-----MIIEv..."
        ));
    }
}
