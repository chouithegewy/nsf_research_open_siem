import * as duckdb from "https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.29.0/+esm";

let db;
let conn;

const loadButton = document.getElementById("load-db");
const runButton = document.getElementById("run-sql");
const schema = document.getElementById("schema");
const errorBox = document.getElementById("sql-error");
const results = document.getElementById("sql-results");
const sql = document.getElementById("sql");

loadButton.addEventListener("click", async () => {
  errorBox.textContent = "";
  results.textContent = "";
  loadButton.disabled = true;
  loadButton.textContent = "Loading...";
  try {
    const bundles = duckdb.getJsDelivrBundles();
    const bundle = await duckdb.selectBundle(bundles);
    const workerUrl = URL.createObjectURL(new Blob([`importScripts("${bundle.mainWorker}");`], { type: "text/javascript" }));
    const worker = new Worker(workerUrl);
    const logger = new duckdb.ConsoleLogger();
    db = new duckdb.AsyncDuckDB(logger, worker);
    await db.instantiate(bundle.mainModule, bundle.pthreadWorker);

    const response = await fetch("/analysis/export.duckdb", { cache: "no-store" });
    if (!response.ok) throw new Error(`Export download failed: ${response.status}`);
    const buffer = new Uint8Array(await response.arrayBuffer());
    await db.registerFileBuffer("analysis.duckdb", buffer);
    conn = await db.connect();
    await conn.query("ATTACH 'analysis.duckdb' AS analysis_db (READ_ONLY); USE analysis_db;");
    await refreshSchema();
    loadButton.textContent = "Loaded";
  } catch (err) {
    errorBox.textContent = String(err);
    loadButton.disabled = false;
    loadButton.textContent = "Load analysis export";
  }
});

runButton.addEventListener("click", async () => {
  errorBox.textContent = "";
  results.textContent = "";
  if (!conn) {
    errorBox.textContent = "Load the analysis export first.";
    return;
  }
  try {
    const result = await conn.query(sql.value);
    renderTable(result);
  } catch (err) {
    errorBox.textContent = String(err);
  }
});

async function refreshSchema() {
  const tables = await conn.query("show tables;");
  const names = tables.toArray().map((row) => row.name || row[0]);
  const lines = [];
  for (const name of names) {
    lines.push(name);
    const columns = await conn.query(`describe ${quoteIdent(name)};`);
    for (const column of columns.toArray()) {
      lines.push(`  ${column.column_name} ${column.column_type}`);
    }
  }
  schema.textContent = lines.join("\n");
}

function renderTable(result) {
  const rows = result.toArray();
  if (!rows.length) {
    results.innerHTML = "<p>No rows returned.</p>";
    return;
  }
  const columns = Object.keys(rows[0]);
  const thead = columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("");
  const tbody = rows
    .map((row) => `<tr>${columns.map((column) => `<td>${escapeHtml(String(row[column] ?? ""))}</td>`).join("")}</tr>`)
    .join("");
  results.innerHTML = `<table><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table>`;
}

function quoteIdent(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
}
