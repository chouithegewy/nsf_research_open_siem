use actix_files::{Files, NamedFile};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::http::header;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use duckdb::{params, Connection, OptionalExt};
use html_escape::encode_text;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::process::Command;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AppState {
    config: Config,
    sync_lock: Arc<Mutex<()>>,
    import_lock: Arc<StdMutex<()>>,
    import_running: Arc<AtomicBool>,
}

#[derive(Clone)]
struct Config {
    bind: String,
    db_path: PathBuf,
    export_db_path: PathBuf,
    report_dir: PathBuf,
    session_secret: String,
    admin_user: String,
    admin_password: String,
}

#[derive(Debug)]
struct AppError(String);

type AppResult<T> = Result<T, AppError>;

struct ReportPayload {
    event_count: i64,
    sessions: Vec<Value>,
    findings: Vec<Value>,
    actors: Vec<Value>,
    iocs: Vec<Value>,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

impl actix_web::ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        if self.0 == "unauthorized" {
            return redirect("/login");
        }
        HttpResponse::InternalServerError()
            .content_type("text/plain; charset=utf-8")
            .body(self.0.clone())
    }
}

impl From<duckdb::Error> for AppError {
    fn from(value: duckdb::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::from_env().map_err(std::io::Error::other)?;
    fs::create_dir_all(config.db_path.parent().unwrap_or_else(|| Path::new(".")))?;
    fs::create_dir_all(&config.report_dir)?;
    init_db(&config).map_err(std::io::Error::other)?;
    ensure_admin_user(&config).map_err(std::io::Error::other)?;

    let state = web::Data::new(AppState {
        config: config.clone(),
        sync_lock: Arc::new(Mutex::new(())),
        import_lock: Arc::new(StdMutex::new(())),
        import_running: Arc::new(AtomicBool::new(false)),
    });

    println!("honeypot-web listening on http://{}", config.bind);
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(Files::new("/static", "web/static"))
            .route("/login", web::get().to(login_page))
            .route("/login", web::post().to(login_submit))
            .route("/logout", web::post().to(logout))
            .route("/", web::get().to(dashboard))
            .route("/dashboard/live", web::get().to(dashboard_live))
            .route("/findings", web::get().to(findings))
            .route("/actors", web::get().to(actors))
            .route("/iocs", web::get().to(iocs))
            .route("/sessions", web::get().to(sessions))
            .route("/ml-alerts", web::get().to(ml_alerts))
            .route("/ebpf-events", web::get().to(ebpf_events))
            .route("/reports", web::get().to(reports))
            .route("/reports/list", web::get().to(reports_list))
            .route("/reports/{filename}/raw", web::get().to(report_raw))
            .route("/reports/{filename}", web::get().to(report_detail))
            .route("/sync", web::get().to(sync_page))
            .route("/sync/tpot", web::post().to(sync_tpot))
            .route("/sync/cowrie", web::post().to(sync_cowrie))
            .route("/sync/status", web::get().to(sync_status))
            .route("/analysis/sql", web::get().to(sql_shell))
            .route("/analysis/export.duckdb", web::get().to(analysis_export))
            .route("/admin/import-report", web::post().to(import_report))
            .route(
                "/admin/import-report/{filename}",
                web::post().to(import_named_report),
            )
    })
    .bind(&config.bind)?
    .run()
    .await
}

impl Config {
    fn from_env() -> AppResult<Self> {
        let admin_password = env::var("HONEYPOT_WEB_ADMIN_PASSWORD").map_err(|_| {
            AppError(
                "HONEYPOT_WEB_ADMIN_PASSWORD is required; copy .env.example to .env and set a local password"
                    .to_string(),
            )
        })?;

        Ok(Self {
            bind: env::var("HONEYPOT_WEB_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string()),
            db_path: env::var("HONEYPOT_WEB_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data/honeypot-web.duckdb")),
            export_db_path: env::var("HONEYPOT_WEB_EXPORT_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("data/honeypot-analysis-export.duckdb")),
            report_dir: env::var("HONEYPOT_WEB_REPORT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("logs/reports")),
            session_secret: env::var("HONEYPOT_WEB_SESSION_SECRET")
                .unwrap_or_else(|_| random_token(48)),
            admin_user: env::var("HONEYPOT_WEB_ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
            admin_password,
        })
    }
}

fn init_db(config: &Config) -> AppResult<()> {
    let conn = Connection::open(&config.db_path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions_auth (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_runs (
            id BIGINT PRIMARY KEY,
            sync_type TEXT NOT NULL,
            host TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            report_path TEXT,
            output_summary TEXT
        );
        CREATE SEQUENCE IF NOT EXISTS sync_runs_id_seq START 1;
        CREATE TABLE IF NOT EXISTS reports (
            id BIGINT PRIMARY KEY,
            source TEXT NOT NULL,
            report_path TEXT NOT NULL,
            report_modified_at TEXT,
            imported_at TEXT NOT NULL,
            event_count BIGINT NOT NULL,
            session_count BIGINT NOT NULL,
            finding_count BIGINT NOT NULL,
            actor_count BIGINT NOT NULL,
            ioc_count BIGINT NOT NULL
        );
        CREATE SEQUENCE IF NOT EXISTS reports_id_seq START 1;
        CREATE TABLE IF NOT EXISTS findings (
            report_id BIGINT,
            session_key TEXT,
            src_ip TEXT,
            severity TEXT,
            score DOUBLE,
            anomaly_score DOUBLE,
            reasons TEXT,
            techniques TEXT
        );
        CREATE TABLE IF NOT EXISTS actors (
            report_id BIGINT,
            ip TEXT,
            scope TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_events BIGINT,
            source_events BIGINT,
            destination_events BIGINT,
            sources TEXT,
            sessions TEXT,
            techniques TEXT,
            finding_score DOUBLE
        );
        CREATE TABLE IF NOT EXISTS iocs (
            report_id BIGINT,
            kind TEXT,
            value TEXT,
            source TEXT,
            context TEXT
        );
        CREATE TABLE IF NOT EXISTS analysis_sessions (
            report_id BIGINT,
            key TEXT,
            src_ip TEXT,
            first_seen TEXT,
            last_seen TEXT,
            total_events BIGINT,
            login_failures BIGINT,
            login_successes BIGINT,
            commands BIGINT,
            suricata_alerts BIGINT,
            bytes_in BIGINT,
            bytes_out BIGINT,
            event_types TEXT
        );
        CREATE TABLE IF NOT EXISTS ml_models (
            model_id TEXT PRIMARY KEY,
            kind TEXT,
            version TEXT,
            trained_at TEXT,
            feature_names TEXT,
            threshold DOUBLE,
            training_rows BIGINT,
            metrics TEXT,
            artifact_path TEXT
        );
        CREATE TABLE IF NOT EXISTS endpoint_windows (
            id TEXT PRIMARY KEY,
            model_id TEXT,
            endpoint TEXT,
            role TEXT,
            window_start TEXT,
            window_end TEXT,
            features TEXT,
            label TEXT,
            label_reasons TEXT,
            source_event_count BIGINT
        );
        CREATE TABLE IF NOT EXISTS ml_alerts (
            id TEXT PRIMARY KEY,
            model_id TEXT,
            endpoint TEXT,
            role TEXT,
            window_start TEXT,
            window_end TEXT,
            score DOUBLE,
            threshold DOUBLE,
            severity TEXT,
            reasons TEXT,
            features TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ebpf_events (
            id TEXT PRIMARY KEY,
            schema_version BIGINT,
            timestamp TEXT,
            host TEXT,
            event_type TEXT,
            pid BIGINT,
            ppid BIGINT,
            uid BIGINT,
            gid BIGINT,
            comm TEXT,
            "binary" TEXT,
            arguments_sample TEXT,
            argv_truncated BOOLEAN,
            cgroup_id TEXT,
            container_id TEXT,
            src_ip TEXT,
            src_port BIGINT,
            dest_ip TEXT,
            dest_port BIGINT,
            protocol TEXT,
            filename TEXT,
            access_type TEXT,
            severity_hint TEXT,
            raw TEXT
        );
        "#,
    )?;
    conn.execute_batch(
        r#"
        ALTER TABLE reports ADD COLUMN IF NOT EXISTS report_modified_at TEXT;
        ALTER TABLE ebpf_events ADD COLUMN IF NOT EXISTS raw TEXT;
        "#,
    )?;
    Ok(())
}

fn ensure_admin_user(config: &Config) -> AppResult<()> {
    let conn = Connection::open(&config.db_path)?;
    let exists: Option<String> = conn
        .query_row(
            "SELECT username FROM users WHERE username = ?1",
            params![config.admin_user],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_some() {
        return Ok(());
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(config.admin_password.as_bytes(), &salt)
        .map_err(|err| AppError(err.to_string()))?
        .to_string();
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        params![config.admin_user, hash, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

async fn login_page(req: HttpRequest) -> impl Responder {
    let error = req.query_string().contains("error=1");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(login_html(error))
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    state: web::Data<AppState>,
    form: web::Form<LoginForm>,
) -> AppResult<HttpResponse> {
    let config = state.config.clone();
    let username = form.username.clone();
    let password = form.password.clone();
    let valid = web::block(move || verify_login(&config, &username, &password))
        .await
        .map_err(|err| AppError(err.to_string()))??;
    if !valid {
        return Ok(redirect("/login?error=1"));
    }
    let token = create_session(&state.config, &form.username)?;
    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, "/"))
        .cookie(session_cookie(&state.config, token))
        .finish())
}

async fn logout(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    if let Some(cookie) = req.cookie("hp_session") {
        let conn = Connection::open(&state.config.db_path)?;
        conn.execute(
            "DELETE FROM sessions_auth WHERE token = ?1",
            params![cookie.value()],
        )?;
    }
    Ok(HttpResponse::SeeOther()
        .insert_header((header::LOCATION, "/login"))
        .cookie(
            Cookie::build("hp_session", "")
                .path("/")
                .http_only(true)
                .same_site(SameSite::Strict)
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        )
        .finish())
}

async fn dashboard(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let model = dashboard_model(&state.config)?;
    Ok(html_page("Dashboard", &nav(), &dashboard_html(&model)))
}

async fn dashboard_live(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let model = dashboard_model(&state.config)?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(dashboard_live_html(&model)))
}

async fn findings(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = findings_rows(&state.config, &query)?;
    let body = findings_html(&rows, &query);
    Ok(fragment_or_page(&req, "Findings", &body))
}

async fn actors(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = actors_rows(&state.config, &query)?;
    let body = actors_html(&rows, &query);
    Ok(fragment_or_page(&req, "Actors", &body))
}

async fn iocs(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = ioc_rows(&state.config, &query)?;
    let body = iocs_html(&rows, &query);
    Ok(fragment_or_page(&req, "IOCs", &body))
}

async fn sessions(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = session_rows(&state.config, &query)?;
    let body = sessions_html(&rows, &query);
    Ok(fragment_or_page(&req, "Sessions", &body))
}

async fn ml_alerts(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = ml_alert_rows(&state.config, &query)?;
    let body = ml_alerts_html(&rows, &query);
    Ok(fragment_or_page(&req, "ML Alerts", &body))
}

async fn ebpf_events(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TableQuery>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let rows = ebpf_event_rows(&state.config, &query)?;
    let body = ebpf_events_html(&rows, &query);
    Ok(fragment_or_page(&req, "eBPF Events", &body))
}

async fn reports(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let files = report_files(&state.config.report_dir)?;
    Ok(html_page(
        "Reports",
        &nav(),
        &reports_html(&state.config.report_dir, &files),
    ))
}

async fn reports_list(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    refresh_latest_report(&state)?;
    let files = report_files(&state.config.report_dir)?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(reports_table_html(&files)))
}

async fn report_detail(
    state: web::Data<AppState>,
    req: HttpRequest,
    filename: web::Path<String>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    let path = report_path(&state.config.report_dir, &filename)?;
    let body = report_detail_html(&state.config.report_dir, &path)?;
    Ok(html_page("Report", &nav(), &body))
}

async fn report_raw(
    state: web::Data<AppState>,
    req: HttpRequest,
    filename: web::Path<String>,
) -> AppResult<NamedFile> {
    require_auth(&state.config, &req)?;
    let path = report_path(&state.config.report_dir, &filename)?;
    Ok(NamedFile::open(path)?)
}

async fn sync_page(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    Ok(html_page("Sync", &nav(), &sync_html(&state.config)?))
}

async fn sync_status(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(sync_status_html(&state.config)?))
}

async fn sync_tpot(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    start_sync(state, "tpot").await
}

async fn sync_cowrie(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    start_sync(state, "cowrie").await
}

async fn sql_shell(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    Ok(html_page("SQL Shell", &nav(), &sql_shell_html()))
}

async fn analysis_export(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    regenerate_export(&state.config)?;
    let bytes = fs::read(&state.config.export_db_path)?;
    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .body(bytes))
}

async fn import_report(state: web::Data<AppState>, req: HttpRequest) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    let latest = latest_json_report(&state.config.report_dir)
        .ok_or_else(|| AppError("no JSON reports found in report directory".to_string()))?;
    queue_report_import(&state, latest, "manual");
    Ok(redirect("/"))
}

async fn import_named_report(
    state: web::Data<AppState>,
    req: HttpRequest,
    filename: web::Path<String>,
) -> AppResult<HttpResponse> {
    require_auth(&state.config, &req)?;
    let path = report_path(&state.config.report_dir, &filename)?;
    if path.extension().and_then(|s| s.to_str()) != Some("json") {
        return Err(AppError("only JSON reports can be imported".to_string()));
    }
    queue_report_import(&state, path, "manual");
    Ok(redirect("/reports"))
}

async fn start_sync(
    state: web::Data<AppState>,
    sync_type: &'static str,
) -> AppResult<HttpResponse> {
    if state.sync_lock.try_lock().is_err() {
        return Ok(HttpResponse::Conflict()
            .content_type("text/html; charset=utf-8")
            .body("<p class=\"notice\">A sync is already running.</p>"));
    }

    let state_for_task = state.get_ref().clone();
    tokio::spawn(async move {
        let _guard = state_for_task.sync_lock.lock().await;
        let _ = run_sync(state_for_task.config.clone(), sync_type).await;
    });

    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body("<p class=\"notice\">Sync started. Status will update automatically.</p>"))
}

async fn run_sync(config: Config, sync_type: &str) -> AppResult<()> {
    let started_at = Utc::now().to_rfc3339();
    let host = match sync_type {
        "tpot" => env::var("TPOT_HOST").ok(),
        "cowrie" => env::var("HONEYPOT_HOST").ok(),
        _ => None,
    };
    let run_id = create_sync_run(&config, sync_type, host.as_deref(), &started_at)?;
    let script = match sync_type {
        "tpot" => "scripts/collect-remote-tpot.sh",
        "cowrie" => "scripts/collect-remote-cowrie.sh",
        _ => return Err(AppError("unknown sync type".to_string())),
    };

    let output = Command::new(script)
        .env("ANALYZE_FORMAT", "both")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let summary = truncate(&format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr), 8000);
    let status = if output.status.success() {
        "success"
    } else {
        "failed"
    };
    let latest = latest_json_report(&config.report_dir);
    let report_path = latest.as_ref().map(|p| p.to_string_lossy().to_string());
    finish_sync_run(&config, run_id, status, report_path.as_deref(), &summary)?;

    if output.status.success() {
        if let Some(path) = latest {
            import_report_file(&config, &path, sync_type)?;
        }
    }
    Ok(())
}

fn create_sync_run(
    config: &Config,
    sync_type: &str,
    host: Option<&str>,
    started_at: &str,
) -> AppResult<i64> {
    let conn = Connection::open(&config.db_path)?;
    let id: i64 = conn.query_row("SELECT nextval('sync_runs_id_seq')", [], |row| row.get(0))?;
    conn.execute(
        "INSERT INTO sync_runs (id, sync_type, host, started_at, status) VALUES (?1, ?2, ?3, ?4, 'running')",
        params![id, sync_type, host, started_at],
    )?;
    Ok(id)
}

fn finish_sync_run(
    config: &Config,
    id: i64,
    status: &str,
    report_path: Option<&str>,
    output: &str,
) -> AppResult<()> {
    let conn = Connection::open(&config.db_path)?;
    conn.execute(
        "UPDATE sync_runs SET finished_at = ?1, status = ?2, report_path = ?3, output_summary = ?4 WHERE id = ?5",
        params![Utc::now().to_rfc3339(), status, report_path, output, id],
    )?;
    Ok(())
}

fn refresh_latest_report(state: &AppState) -> AppResult<bool> {
    let Some(path) = latest_json_report(&state.config.report_dir) else {
        return Ok(false);
    };
    if state.import_running.load(Ordering::SeqCst) {
        return Ok(false);
    }
    let modified_at = report_modified_at(&path)?;
    let path_text = path.to_string_lossy().to_string();
    let conn = Connection::open(&state.config.db_path)?;
    let imported_at: Option<String> = conn
        .query_row(
            "SELECT report_modified_at FROM reports WHERE report_path = ?1 ORDER BY imported_at DESC LIMIT 1",
            params![path_text],
            |row| row.get(0),
        )
        .optional()?;
    if imported_at.as_deref() == Some(modified_at.as_str()) {
        return Ok(false);
    }
    drop(conn);
    Ok(queue_report_import(state, path, "auto"))
}

fn import_report_file_locked(state: &AppState, path: &Path, source: &str) -> AppResult<()> {
    let _guard = state
        .import_lock
        .lock()
        .map_err(|_| AppError("report import lock poisoned".to_string()))?;
    import_report_file(&state.config, path, source)
}

fn queue_report_import(state: &AppState, path: PathBuf, source: &'static str) -> bool {
    if state.import_running.swap(true, Ordering::SeqCst) {
        return false;
    }
    let state_for_task = state.clone();
    std::thread::spawn(move || {
        eprintln!("importing report {}", path.display());
        let result = import_report_file_locked(&state_for_task, &path, source);
        match result {
            Ok(()) => eprintln!("finished importing report {}", path.display()),
            Err(err) => eprintln!("failed to import report {}: {}", path.display(), err),
        }
        state_for_task.import_running.store(false, Ordering::SeqCst);
    });
    true
}

fn import_report_file(config: &Config, path: &Path, source: &str) -> AppResult<()> {
    let report = parse_report_payload(path)?;
    let mut conn = Connection::open(&config.db_path)?;
    let path_text = path.to_string_lossy().to_string();
    let modified_at = report_modified_at(path)?;
    let tx = conn.transaction()?;

    let mut old_ids_stmt = tx.prepare("SELECT id FROM reports WHERE report_path = ?1")?;
    let old_ids = old_ids_stmt.query_map(params![path_text.clone()], |row| row.get::<_, i64>(0))?;
    let mut old_report_ids = Vec::new();
    for old_id in old_ids {
        old_report_ids.push(old_id?);
    }
    drop(old_ids_stmt);
    for old_id in old_report_ids {
        tx.execute("DELETE FROM findings WHERE report_id = ?1", params![old_id])?;
        tx.execute("DELETE FROM actors WHERE report_id = ?1", params![old_id])?;
        tx.execute("DELETE FROM iocs WHERE report_id = ?1", params![old_id])?;
        tx.execute(
            "DELETE FROM analysis_sessions WHERE report_id = ?1",
            params![old_id],
        )?;
        tx.execute("DELETE FROM reports WHERE id = ?1", params![old_id])?;
    }

    let report_id: i64 = tx.query_row("SELECT nextval('reports_id_seq')", [], |row| row.get(0))?;
    let event_count = report.event_count;
    let session_count = report.sessions.len() as i64;
    let finding_count = report.findings.len() as i64;
    let actor_count = report.actors.len() as i64;
    let ioc_count = report.iocs.len() as i64;

    tx.execute(
        "INSERT INTO reports (
            id, source, report_path, report_modified_at, imported_at,
            event_count, session_count, finding_count, actor_count, ioc_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            report_id,
            source,
            path_text,
            modified_at,
            Utc::now().to_rfc3339(),
            event_count,
            session_count,
            finding_count,
            actor_count,
            ioc_count
        ],
    )?;

    {
        let mut stmt =
            tx.prepare("INSERT INTO findings VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")?;
        for item in &report.findings {
            stmt.execute(params![
                report_id,
                str_field(item, "session_key"),
                str_field(item, "src_ip"),
                str_field(item, "severity"),
                num_field(item, "score"),
                num_field(item, "anomaly_score"),
                json_field(item, "reasons"),
                json_field(item, "mitre_techniques")
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare(
            "INSERT INTO actors VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        for item in &report.actors {
            stmt.execute(params![
                report_id,
                str_field(item, "ip"),
                str_field(item, "ip_scope"),
                str_field(item, "first_seen"),
                str_field(item, "last_seen"),
                int_field(item, "total_events"),
                int_field(item, "source_events"),
                int_field(item, "destination_events"),
                json_field(item, "sources"),
                json_field(item, "sessions"),
                json_field(item, "techniques"),
                num_field(item, "finding_score")
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare("INSERT INTO iocs VALUES (?1, ?2, ?3, ?4, ?5)")?;
        for item in &report.iocs {
            stmt.execute(params![
                report_id,
                str_field(item, "kind"),
                str_field(item, "value"),
                str_field(item, "source"),
                str_field(item, "context")
            ])?;
        }
    }

    {
        let mut stmt = tx.prepare(
            "INSERT INTO analysis_sessions VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        )?;
        for item in &report.sessions {
            stmt.execute(params![
                report_id,
                str_field(item, "key"),
                str_field(item, "src_ip"),
                str_field(item, "first_seen"),
                str_field(item, "last_seen"),
                int_field(item, "total_events"),
                int_field(item, "login_failures"),
                int_field(item, "login_successes"),
                int_field(item, "commands"),
                int_field(item, "suricata_alerts"),
                int_field(item, "bytes_in"),
                int_field(item, "bytes_out"),
                json_field(item, "event_types")
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn parse_report_payload(path: &Path) -> AppResult<ReportPayload> {
    let text = fs::read_to_string(path)?;
    Ok(ReportPayload {
        event_count: markdown_report_count(path, "Events parsed").unwrap_or(0),
        actors: parse_top_level_array(&text, "actors")?,
        findings: parse_top_level_array(&text, "findings")?,
        iocs: parse_top_level_array(&text, "iocs")?,
        sessions: parse_top_level_array(&text, "sessions")?,
    })
}

fn parse_top_level_array(text: &str, key: &str) -> AppResult<Vec<Value>> {
    let Some(array_start) = find_report_array_start(text, key) else {
        return Ok(Vec::new());
    };
    let array_end = find_json_array_end(text, array_start)
        .ok_or_else(|| AppError(format!("unterminated JSON array for {}", key)))?;
    Ok(serde_json::from_str(&text[array_start..array_end])?)
}

fn find_report_array_start(text: &str, key: &str) -> Option<usize> {
    for pattern in [
        format!("\"{}\": [", key),
        format!("\"{}\":\n[", key),
        format!("\"{}\":\n  [", key),
    ] {
        if let Some(position) = text.find(&pattern) {
            let bracket = text[position..].find('[')?;
            return Some(position + bracket);
        }
    }
    find_top_level_array_start(text, key)
}

fn find_top_level_array_start(text: &str, key: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut idx = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            idx += 1;
            continue;
        }
        match byte {
            b'"' if depth == 1 => {
                let (name, after_name) = read_json_string(bytes, idx)?;
                if name == key {
                    let mut cursor = skip_json_ws(bytes, after_name);
                    if bytes.get(cursor) != Some(&b':') {
                        return None;
                    }
                    cursor = skip_json_ws(bytes, cursor + 1);
                    if bytes.get(cursor) == Some(&b'[') {
                        return Some(cursor);
                    }
                    return None;
                }
                idx = after_name;
                continue;
            }
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        idx += 1;
    }
    None
}

fn read_json_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut idx = start + 1;
    let mut escaped = false;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            let value = std::str::from_utf8(&bytes[start + 1..idx])
                .ok()?
                .to_string();
            return Some((value, idx + 1));
        }
        idx += 1;
    }
    None
}

fn skip_json_ws(bytes: &[u8], mut idx: usize) -> usize {
    while matches!(bytes.get(idx), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        idx += 1;
    }
    idx
}

fn find_json_array_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut idx = start;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            idx += 1;
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn regenerate_export(config: &Config) -> AppResult<()> {
    if let Some(parent) = config.export_db_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if config.export_db_path.exists() {
        fs::remove_file(&config.export_db_path)?;
    }
    let conn = Connection::open(&config.export_db_path)?;
    let source = config.db_path.to_string_lossy().replace('\'', "''");
    conn.execute_batch(&format!(
        r#"
        ATTACH '{}' AS src (READ_ONLY);
        CREATE TABLE reports AS SELECT * FROM src.reports;
        CREATE TABLE findings AS SELECT * FROM src.findings;
        CREATE TABLE actors AS SELECT * FROM src.actors;
        CREATE TABLE iocs AS SELECT * FROM src.iocs;
        CREATE TABLE sessions AS SELECT * FROM src.analysis_sessions;
        CREATE TABLE ml_models AS SELECT * FROM src.ml_models;
        CREATE TABLE endpoint_windows AS SELECT * FROM src.endpoint_windows;
        CREATE TABLE ml_alerts AS SELECT * FROM src.ml_alerts;
        CREATE TABLE ebpf_events AS SELECT * FROM src.ebpf_events;
        DETACH src;
        "#,
        source
    ))?;
    Ok(())
}

fn dashboard_model(config: &Config) -> AppResult<BTreeMap<String, String>> {
    let conn = Connection::open(&config.db_path)?;
    let ml_alerts: i64 = conn
        .query_row("SELECT COUNT(*) FROM ml_alerts", [], |row| row.get(0))
        .unwrap_or(0);
    let ebpf_events: i64 = conn
        .query_row("SELECT COUNT(*) FROM ebpf_events", [], |row| row.get(0))
        .unwrap_or(0);
    let ebpf_high_signal: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ebpf_events WHERE severity_hint IN ('medium', 'high', 'critical')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let latest: Option<(i64, i64, i64, i64, i64, String)> = conn
        .query_row(
            "SELECT event_count, session_count, finding_count, actor_count, ioc_count, imported_at FROM reports ORDER BY imported_at DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()?;
    let mut model = BTreeMap::new();
    if let Some((events, sessions, findings, actors, iocs, imported_at)) = latest {
        model.insert("Events".to_string(), events.to_string());
        model.insert("Sessions".to_string(), sessions.to_string());
        model.insert("Findings".to_string(), findings.to_string());
        model.insert("Actors".to_string(), actors.to_string());
        model.insert("IOCs".to_string(), iocs.to_string());
        model.insert("ML Alerts".to_string(), ml_alerts.to_string());
        model.insert("eBPF Events".to_string(), ebpf_events.to_string());
        model.insert("eBPF Signals".to_string(), ebpf_high_signal.to_string());
        model.insert("Last import".to_string(), imported_at);
    } else {
        model.insert("Events".to_string(), "0".to_string());
        model.insert("Sessions".to_string(), "0".to_string());
        model.insert("Findings".to_string(), "0".to_string());
        model.insert("Actors".to_string(), "0".to_string());
        model.insert("IOCs".to_string(), "0".to_string());
        model.insert("ML Alerts".to_string(), ml_alerts.to_string());
        model.insert("eBPF Events".to_string(), ebpf_events.to_string());
        model.insert("eBPF Signals".to_string(), ebpf_high_signal.to_string());
        model.insert("Last import".to_string(), "never".to_string());
    }
    Ok(model)
}

#[derive(Deserialize, Default)]
struct TableQuery {
    q: Option<String>,
    limit: Option<i64>,
}

struct ReportFile {
    filename: String,
    extension: String,
    size: u64,
    modified: String,
}

fn query_like(query: &TableQuery) -> String {
    format!("%{}%", query.q.clone().unwrap_or_default())
}

fn limit(query: &TableQuery) -> i64 {
    query.limit.unwrap_or(100).clamp(10, 500)
}

fn findings_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(severity AS VARCHAR), CAST(score AS VARCHAR), CAST(src_ip AS VARCHAR),
                CAST(session_key AS VARCHAR), CAST(anomaly_score AS VARCHAR),
                CAST(techniques AS VARCHAR), CAST(reasons AS VARCHAR)
         FROM findings
         WHERE coalesce(src_ip, '') LIKE ?1 OR coalesce(session_key, '') LIKE ?1 OR coalesce(severity, '') LIKE ?1
         ORDER BY score DESC LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 7)
}

fn actors_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(ip AS VARCHAR), CAST(scope AS VARCHAR), CAST(total_events AS VARCHAR),
                CAST(source_events AS VARCHAR), CAST(destination_events AS VARCHAR),
                CAST(finding_score AS VARCHAR), CAST(sources AS VARCHAR), CAST(techniques AS VARCHAR)
         FROM actors
         WHERE coalesce(ip, '') LIKE ?1 OR coalesce(scope, '') LIKE ?1
         ORDER BY finding_score DESC, total_events DESC LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 8)
}

fn ioc_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(kind AS VARCHAR), CAST(value AS VARCHAR), CAST(source AS VARCHAR), CAST(context AS VARCHAR)
         FROM iocs
         WHERE coalesce(kind, '') LIKE ?1 OR coalesce(value, '') LIKE ?1 OR coalesce(source, '') LIKE ?1
         LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 4)
}

fn session_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(key AS VARCHAR), CAST(src_ip AS VARCHAR), CAST(first_seen AS VARCHAR),
                CAST(last_seen AS VARCHAR), CAST(total_events AS VARCHAR),
                CAST(login_failures AS VARCHAR), CAST(login_successes AS VARCHAR),
                CAST(commands AS VARCHAR), CAST(suricata_alerts AS VARCHAR)
         FROM analysis_sessions
         WHERE coalesce(key, '') LIKE ?1 OR coalesce(src_ip, '') LIKE ?1
         ORDER BY total_events DESC LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 9)
}

fn ml_alert_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(severity AS VARCHAR), CAST(score AS VARCHAR), CAST(threshold AS VARCHAR),
                CAST(endpoint AS VARCHAR), CAST(role AS VARCHAR), CAST(window_start AS VARCHAR),
                CAST(model_id AS VARCHAR), CAST(reasons AS VARCHAR)
         FROM ml_alerts
         WHERE coalesce(endpoint, '') LIKE ?1 OR coalesce(severity, '') LIKE ?1 OR coalesce(model_id, '') LIKE ?1
         ORDER BY created_at DESC, score DESC LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 8)
}

fn ebpf_event_rows(config: &Config, query: &TableQuery) -> AppResult<Vec<Vec<String>>> {
    let conn = Connection::open(&config.db_path)?;
    let like = query_like(query);
    let mut stmt = conn.prepare(
        "SELECT CAST(timestamp AS VARCHAR), CAST(host AS VARCHAR), CAST(event_type AS VARCHAR),
                CAST(pid AS VARCHAR), CAST(uid AS VARCHAR), CAST(\"binary\" AS VARCHAR),
                CAST(arguments_sample AS VARCHAR), CAST(dest_ip AS VARCHAR),
                CAST(filename AS VARCHAR), CAST(access_type AS VARCHAR), CAST(severity_hint AS VARCHAR)
         FROM ebpf_events
         WHERE coalesce(host, '') LIKE ?1 OR coalesce(event_type, '') LIKE ?1 OR
               coalesce(\"binary\", '') LIKE ?1 OR coalesce(filename, '') LIKE ?1 OR
               coalesce(dest_ip, '') LIKE ?1 OR coalesce(severity_hint, '') LIKE ?1
         ORDER BY timestamp DESC LIMIT ?2",
    )?;
    collect_rows(&mut stmt, params![like, limit(query)], 11)
}

fn collect_rows<P: duckdb::Params>(
    stmt: &mut duckdb::Statement<'_>,
    params: P,
    cols: usize,
) -> AppResult<Vec<Vec<String>>> {
    let mapped = stmt.query_map(params, |row| {
        let mut values = Vec::with_capacity(cols);
        for idx in 0..cols {
            let value: Option<String> = row.get(idx)?;
            values.push(value.unwrap_or_default());
        }
        Ok(values)
    })?;
    let mut rows = Vec::new();
    for row in mapped {
        rows.push(row?);
    }
    Ok(rows)
}

fn report_files(report_dir: &Path) -> AppResult<Vec<ReportFile>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(report_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || !is_report_file(&path) {
            continue;
        }
        let metadata = entry.metadata()?;
        let modified = metadata
            .modified()
            .ok()
            .map(DateTime::<Utc>::from)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();
        files.push(ReportFile {
            filename: entry.file_name().to_string_lossy().to_string(),
            extension: path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string(),
            size: metadata.len(),
            modified,
        });
    }
    files.sort_by(|a, b| {
        b.modified
            .cmp(&a.modified)
            .then_with(|| a.filename.cmp(&b.filename))
    });
    Ok(files)
}

fn report_path(report_dir: &Path, filename: &str) -> AppResult<PathBuf> {
    let requested = Path::new(filename);
    if requested.components().count() != 1 {
        return Err(AppError("invalid report filename".to_string()));
    }
    let path = report_dir.join(requested);
    if !path.is_file() || !is_report_file(&path) {
        return Err(AppError("report not found".to_string()));
    }
    Ok(path)
}

fn is_report_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|s| s.to_str()),
        Some("json" | "md")
    )
}

fn read_report_preview(path: &Path) -> AppResult<(String, bool)> {
    let max_preview_bytes = if path.extension().and_then(|s| s.to_str()) == Some("md") {
        5 * 1024 * 1024
    } else {
        512 * 1024
    };
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    let read = file
        .by_ref()
        .take(max_preview_bytes + 1)
        .read_to_end(&mut bytes)?;
    let truncated = read > max_preview_bytes as usize;
    if truncated {
        bytes.truncate(max_preview_bytes as usize);
    }
    let buffer = String::from_utf8_lossy(&bytes).to_string();
    Ok((buffer, truncated))
}

fn require_auth(config: &Config, req: &HttpRequest) -> AppResult<String> {
    let Some(cookie) = req.cookie("hp_session") else {
        return Err(AppError("unauthorized".to_string()));
    };
    let conn = Connection::open(&config.db_path)?;
    let username: Option<String> = conn
        .query_row(
            "SELECT username FROM sessions_auth WHERE token = ?1 AND expires_at > ?2",
            params![cookie.value(), Utc::now().to_rfc3339()],
            |row| row.get(0),
        )
        .optional()?;
    username.ok_or_else(|| AppError("unauthorized".to_string()))
}

fn verify_login(config: &Config, username: &str, password: &str) -> AppResult<bool> {
    let conn = Connection::open(&config.db_path)?;
    let hash: Option<String> = conn
        .query_row(
            "SELECT password_hash FROM users WHERE username = ?1",
            params![username],
            |row| row.get(0),
        )
        .optional()?;
    let Some(hash) = hash else {
        return Ok(false);
    };
    let parsed = PasswordHash::new(&hash).map_err(|err| AppError(err.to_string()))?;
    let valid = Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    if valid {
        conn.execute(
            "UPDATE users SET last_login_at = ?1 WHERE username = ?2",
            params![Utc::now().to_rfc3339(), username],
        )?;
    }
    Ok(valid)
}

fn create_session(config: &Config, username: &str) -> AppResult<String> {
    let token = format!("{}.{}", random_token(32), config.session_secret.len());
    let conn = Connection::open(&config.db_path)?;
    conn.execute(
        "INSERT INTO sessions_auth VALUES (?1, ?2, ?3, ?4)",
        params![
            token,
            username,
            Utc::now().to_rfc3339(),
            (Utc::now() + chrono::Duration::hours(12)).to_rfc3339()
        ],
    )?;
    Ok(token)
}

fn session_cookie(config: &Config, token: String) -> Cookie<'static> {
    Cookie::build("hp_session", token)
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(
            config.bind.starts_with("0.0.0.0")
                && env::var("HONEYPOT_WEB_COOKIE_SECURE").as_deref() != Ok("false"),
        )
        .finish()
}

fn random_token(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn redirect(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, location))
        .finish()
}

fn fragment_or_page(req: &HttpRequest, title: &str, body: &str) -> HttpResponse {
    if req.headers().contains_key("HX-Request") {
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(body.to_string())
    } else {
        html_page(title, &nav(), body)
    }
}

fn html_page(title: &str, nav: &str, body: &str) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(format!(
            r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  {}
  <main>{}</main>
</body>
</html>"#,
            encode_text(title),
            nav,
            body
        ))
}

fn nav() -> String {
    r#"<header class="topbar">
  <a href="/" class="brand">Honeypot Research</a>
  <nav>
    <a href="/findings">Findings</a>
    <a href="/ml-alerts">ML Alerts</a>
    <a href="/ebpf-events">eBPF</a>
    <a href="/actors">Actors</a>
    <a href="/iocs">IOCs</a>
    <a href="/sessions">Sessions</a>
    <a href="/reports">Reports</a>
    <a href="/sync">Sync</a>
    <a href="/analysis/sql">SQL</a>
  </nav>
  <form method="post" action="/logout"><button>Log out</button></form>
</header>"#
        .to_string()
}

fn login_html(error: bool) -> String {
    let error_html = if error {
        "<p class=\"error\">Invalid username or password.</p>"
    } else {
        ""
    };
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Login</title><link rel="stylesheet" href="/static/site.css"></head>
<body class="login"><form class="login-panel" method="post" action="/login">
<h1>Honeypot Research</h1>{}
<label>Username<input name="username" autocomplete="username" required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Log in</button>
</form></body></html>"#,
        error_html
    )
}

fn dashboard_html(model: &BTreeMap<String, String>) -> String {
    format!(
        r#"<section class="hero"><h1>Honeypot results</h1><form method="post" action="/admin/import-report"><button>Import latest report</button></form></section>
<section id="dashboard-live" hx-get="/dashboard/live" hx-trigger="every 5s" hx-swap="innerHTML">{}</section>"#,
        dashboard_live_html(model)
    )
}

fn dashboard_live_html(model: &BTreeMap<String, String>) -> String {
    let cards = model
        .iter()
        .map(|(key, value)| {
            format!(
                "<article><span>{}</span><strong>{}</strong></article>",
                encode_text(key),
                encode_text(value)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"<section class="metric-grid">{}</section>
<section class="panel"><h2>Next sync</h2><p>Use the Sync page to pull T-Pot or Cowrie logs with rsync and import the generated JSON report.</p></section>"#,
        cards
    )
}

fn reports_html(report_dir: &Path, files: &[ReportFile]) -> String {
    format!(
        r#"<section class="hero"><h1>CLI reports</h1><form method="post" action="/admin/import-report"><button>Import latest JSON</button></form></section>
<section class="panel"><p>Showing report files from <code>{}</code>.</p></section>
<section id="reports-list" hx-get="/reports/list" hx-trigger="every 5s" hx-swap="innerHTML">{}</section>"#,
        encode_text(&report_dir.to_string_lossy()),
        reports_table_html(files)
    )
}

fn reports_table_html(files: &[ReportFile]) -> String {
    let rows = files
        .iter()
        .map(|file| {
            let encoded_name = url_path_segment(&file.filename);
            let import = if file.extension == "json" {
                format!(
                    r#"<form method="post" action="/admin/import-report/{}"><button>Import</button></form>"#,
                    encoded_name
                )
            } else {
                String::new()
            };
            format!(
                r#"<tr>
<td><a href="/reports/{}">{}</a></td>
<td>{}</td>
<td>{}</td>
<td>{}</td>
<td>{}</td>
</tr>"#,
                encoded_name,
                encode_text(&file.filename),
                encode_text(&file.extension),
                encode_text(&format_size(file.size)),
                encode_text(&file.modified),
                import
            )
        })
        .collect::<Vec<_>>()
        .join("");
    if files.is_empty() {
        "<p class=\"notice\">No Markdown or JSON reports found in the configured report directory.</p>".to_string()
    } else {
        format!(
            r#"<table><thead><tr><th>Report</th><th>Format</th><th>Size</th><th>Modified</th><th>Action</th></tr></thead><tbody>{}</tbody></table>"#,
            rows
        )
    }
}

fn report_detail_html(report_dir: &Path, path: &Path) -> AppResult<String> {
    let filename = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    let encoded_name = url_path_segment(&filename);
    let metadata = fs::metadata(path)?;
    let modified = metadata
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();
    let import = if path.extension().and_then(|s| s.to_str()) == Some("json") {
        format!(
            r#"<form method="post" action="/admin/import-report/{}"><button>Import JSON</button></form>"#,
            encoded_name
        )
    } else {
        String::new()
    };
    let (preview, truncated) = read_report_preview(path)?;
    let truncated_html = if truncated {
        "<p class=\"notice\">Preview is truncated. Open the raw file to view the full report.</p>"
    } else {
        ""
    };
    Ok(format!(
        r#"<section class="hero"><h1>{}</h1><div class="actions"><a class="button" href="/reports/{}/raw">Raw</a>{}</div></section>
<section class="panel report-meta">
  <span><strong>Directory</strong>{}</span>
  <span><strong>Size</strong>{}</span>
  <span><strong>Modified</strong>{}</span>
</section>
{}
<pre class="report-preview">{}</pre>"#,
        encode_text(&filename),
        encoded_name,
        import,
        encode_text(&report_dir.to_string_lossy()),
        encode_text(&format_size(metadata.len())),
        encode_text(&modified),
        truncated_html,
        encode_text(&preview)
    ))
}

fn table_filter(path: &str, query: &TableQuery) -> String {
    format!(
        r##"<form class="filters" hx-get="{}" hx-target="#table-region" hx-push-url="true">
<input name="q" value="{}" placeholder="Filter">
<select name="limit"><option>100</option><option>250</option><option>500</option></select>
<button>Apply</button>
</form>"##,
        path,
        encode_text(query.q.as_deref().unwrap_or(""))
    )
}

fn findings_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/findings", query),
        table(
            &[
                "Severity",
                "Score",
                "Source IP",
                "Session",
                "Anomaly",
                "MITRE",
                "Reasons"
            ],
            rows
        )
    )
}

fn actors_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/actors", query),
        table(
            &[
                "IP",
                "Scope",
                "Events",
                "Source",
                "Destination",
                "Score",
                "Sources",
                "Techniques"
            ],
            rows
        )
    )
}

fn iocs_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/iocs", query),
        table(&["Kind", "Value", "Source", "Context"], rows)
    )
}

fn sessions_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/sessions", query),
        table(
            &[
                "Key",
                "Source IP",
                "First",
                "Last",
                "Events",
                "Failures",
                "Successes",
                "Commands",
                "Alerts"
            ],
            rows
        )
    )
}

fn ml_alerts_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/ml-alerts", query),
        table(
            &[
                "Severity",
                "Score",
                "Threshold",
                "Endpoint",
                "Role",
                "Window",
                "Model",
                "Reasons",
            ],
            rows
        )
    )
}

fn ebpf_events_html(rows: &[Vec<String>], query: &TableQuery) -> String {
    format!(
        "{}<div id=\"table-region\">{}</div>",
        table_filter("/ebpf-events", query),
        table(
            &[
                "Time",
                "Host",
                "Type",
                "PID",
                "UID",
                "Binary",
                "Arguments",
                "Destination",
                "File",
                "Access",
                "Severity",
            ],
            rows
        )
    )
}

fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let head = headers
        .iter()
        .map(|h| format!("<th>{}</th>", encode_text(h)))
        .collect::<Vec<_>>()
        .join("");
    let body = rows
        .iter()
        .map(|row| {
            let cells = row
                .iter()
                .map(|cell| format!("<td>{}</td>", encode_text(cell)))
                .collect::<Vec<_>>()
                .join("");
            format!("<tr>{}</tr>", cells)
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>",
        head, body
    )
}

fn sync_html(config: &Config) -> AppResult<String> {
    Ok(format!(
        r##"<section class="hero"><h1>Sync honeypot data</h1></section>
<section class="actions">
  <form hx-post="/sync/tpot" hx-target="#sync-message"><button>T-Pot rsync</button></form>
  <form hx-post="/sync/cowrie" hx-target="#sync-message"><button>Cowrie rsync</button></form>
</section>
<div id="sync-message"></div>
<section id="sync-status" hx-get="/sync/status" hx-trigger="load, every 5s">{}</section>"##,
        sync_status_html(config)?
    ))
}

fn sync_status_html(config: &Config) -> AppResult<String> {
    let conn = Connection::open(&config.db_path)?;
    let mut stmt = conn.prepare(
        "SELECT sync_type, coalesce(host, ''), started_at, coalesce(finished_at, ''), status, coalesce(report_path, '')
         FROM sync_runs ORDER BY started_at DESC LIMIT 20",
    )?;
    let rows = collect_rows(&mut stmt, [], 6)?;
    Ok(format!(
        "<h2>Sync history</h2>{}",
        table(
            &["Type", "Host", "Started", "Finished", "Status", "Report"],
            &rows
        )
    ))
}

fn sql_shell_html() -> String {
    r#"<section class="hero"><h1>DuckDB WASM SQL shell</h1><button id="load-db">Load analysis export</button></section>
<section class="sql-layout">
  <aside><h2>Schema</h2><pre id="schema">Load the export to inspect tables.</pre></aside>
  <section>
    <textarea id="sql">select * from findings limit 10;</textarea>
    <div class="actions"><button id="run-sql">Run SQL</button></div>
    <pre id="sql-error"></pre>
    <div id="sql-results"></div>
  </section>
</section>
<script type="module" src="/static/duckdb-shell.js"></script>"#
        .to_string()
}

fn str_field(item: &Value, key: &str) -> Option<String> {
    item.get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn num_field(item: &Value, key: &str) -> Option<f64> {
    item.get(key).and_then(Value::as_f64)
}

fn int_field(item: &Value, key: &str) -> Option<i64> {
    item.get(key).and_then(Value::as_i64)
}

fn json_field(item: &Value, key: &str) -> Option<String> {
    item.get(key).map(Value::to_string)
}

fn latest_json_report(report_dir: &Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(report_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .filter_map(|path| {
            let modified = fs::metadata(&path).ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(modified, _)| *modified);
    candidates.pop().map(|(_, path)| path)
}

fn report_modified_at(path: &Path) -> AppResult<String> {
    let modified = fs::metadata(path)?.modified()?;
    Ok(DateTime::<Utc>::from(modified).to_rfc3339())
}

fn markdown_report_count(json_path: &Path, label: &str) -> Option<i64> {
    let markdown_path = json_path.with_extension("md");
    let text = fs::read_to_string(markdown_path).ok()?;
    let prefix = format!("- {}: ", label);
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse::<i64>().ok())
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = UNITS[0];
    for next in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    if unit == "B" {
        format!("{} {}", bytes, unit)
    } else {
        format!("{:.1} {}", value, unit)
    }
}

fn url_path_segment(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{:02X}", byte),
        })
        .collect()
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}...", &value[..max])
    }
}
