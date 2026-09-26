//! Selective Rust acceleration for Web3Guard.
//!
//! Three hot, safety-trivial loops are served natively; everything else
//! stays in Python (the orchestrator). Each function mirrors a pure
//! Python fallback in `web3guard/accel/__init__.py` — identical shapes,
//! so callers cannot tell which ran (except via the `kind` tag).
//!
//! Build: `maturin develop --release` (or `pip install .` via maturin
//! build backend). The scanner degrades to Python automatically when
//! this module is absent.

use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use rayon::prelude::*;
use regex::Regex;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// 1. Content hashing for the incremental dependency graph
// ---------------------------------------------------------------------------

/// Hash one file's bytes; returns the first 24 hex chars (matches
/// `web3guard.graph.analyzer.hash_content`, which hashes text with the
/// same SHA-256 and truncation).
fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        .chars()
        .take(24)
        .collect()
}

/// Parallel content hashing: `{"path": "hash24"}`.
///
/// Accepts a list of path strings. Missing/unreadable files map to the
/// empty string so callers can skip them (same contract as the Python
/// fallback's error handling).
#[pyfunction]
fn hash_files(paths: Vec<String>) -> PyResult<Py<PyDict>> {
    Python::with_gil(|py| {
        let results: Vec<(String, String)> = paths
            .par_iter()
            .map(|p| {
                let hash = std::fs::read(p)
                    .map(|data| hash_bytes(&data))
                    .unwrap_or_default();
                (p.clone(), hash)
            })
            .collect();
        let dict = PyDict::new(py);
        for (path, hash) in results {
            dict.set_item(path, hash).map_err(|e| {
                PyValueError::new_err(format!("dict build failed: {e}"))
            })?;
        }
        Ok(dict.unbind())
    })
}

// ---------------------------------------------------------------------------
// 2. Secret-pattern scanning (mirrors web3guard.utils.secrets patterns)
// ---------------------------------------------------------------------------

struct SecretRule {
    kind: &'static str,
    re: Regex,
}

static SECRET_RULES: Lazy<Vec<SecretRule>> = Lazy::new(|| {
    vec![
        SecretRule {
            kind: "private_key",
            re: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            )
            .unwrap(),
        },
        SecretRule {
            kind: "aws_access_key",
            re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        },
        SecretRule {
            kind: "alchemy_rpc",
            re: Regex::new(
                r"https://[a-zA-Z0-9._-]*alchemy[a-zA-Z0-9._-]*/v2/[A-Za-z0-9_-]{20,}",
            )
            .unwrap(),
        },
        SecretRule {
            kind: "infura_rpc",
            re: Regex::new(
                r"https://[a-zA-Z0-9._-]*infura[a-zA-Z0-9._-]*/v3/[A-Za-z0-9_-]{20,}",
            )
            .unwrap(),
        },
        SecretRule {
            kind: "github_token",
            re: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        },
        SecretRule {
            kind: "openai_key",
            re: Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        },
        SecretRule {
            kind: "google_api_key",
            re: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
        },
        // Note: the mnemonic rule is validated by Python-side heuristics
        // (BIP39 lengths + context), so the Rust path deliberately skips
        // it and the caller can run the Python validator over results if
        // mnemonic coverage matters (see fallback in web3guard/accel).
    ]
});

/// Scan text for secret-shaped matches. Returns a list of dicts:
/// `{"rule": str, "match": str, "line": int}`.
#[pyfunction]
fn scan_secrets(content: &str) -> PyResult<Py<PyList>> {
    let mut out: Vec<PyObject> = Vec::new();
    for rule in SECRET_RULES.iter() {
        for m in rule.re.find_iter(content) {
            let line = content[..m.start()].matches('\n').count() + 1;
            out.push(Python::with_gil(|py| {
                let d = PyDict::new(py);
                let _ = d.set_item("rule", rule.kind);
                let _ = d.set_item("match", m.as_str());
                let _ = d.set_item("line", line);
                d.into()
            }));
        }
    }
    Python::with_gil(|py| {
        let list = PyList::new(py, out);
        Ok(list.unbind())
    })
}

// ---------------------------------------------------------------------------
// 3. Rust/Cargo import-edge extraction (graph builder hot path)
// ---------------------------------------------------------------------------

static USE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*use\s+([\w:]+)").unwrap());
static MOD_DECL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\s*(?:pub\s+)?mod\s+(\w+)\s*;").unwrap());

/// Extract import/module edges from Rust source text: `use` targets and
/// `mod` declarations (module files resolve to `<mod>.rs` on disk by the
/// Python graph builder). Returns unique strings in first-seen order.
#[pyfunction]
fn extract_imports(content: &str) -> PyResult<Py<PyList>> {
    let mut seen: Vec<String> = Vec::new();
    for caps in USE_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let s = m.as_str().to_string();
            if !seen.contains(&s) {
                seen.push(s);
            }
        }
    }
    for caps in MOD_DECL_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            let s = m.as_str().to_string();
            if !seen.contains(&s) {
                seen.push(s);
            }
        }
    }
    Python::with_gil(|py| {
        let list = PyList::new(py, seen);
        Ok(list.unbind())
    })
}

// ---------------------------------------------------------------------------
// Module wiring
// ---------------------------------------------------------------------------

/// Read a file's bytes (helper exposed for tests / parity checks).
#[pyfunction]
fn file_digest(path: &str) -> PyResult<Py<PyBytes>> {
    let data = std::fs::read(path)
        .map_err(|e| PyValueError::new_err(format!("read {path}: {e}")))?;
    Ok(PyBytes::new(Python::with_gil(|py| py), &data))
}

#[pymodule]
fn web3guard_accel(m: &PyModule) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(hash_files, m)?)?;
    m.add_function(wrap_pyfunction!(scan_secrets, m)?)?;
    m.add_function(wrap_pyfunction!(extract_imports, m)?)?;
    m.add_function(wrap_pyfunction!(file_digest, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_sha256_truncated() {
        // sha256("x") = 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
        let mut h = Sha256::new();
        h.update(b"x");
        let expect: String = h
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .chars()
            .take(24)
            .collect();
        assert_eq!(hash_bytes(b"x"), expect);
    }

    #[test]
    fn secrets_match_python_patterns() {
        let text = "key = \"AKIAIOSFODNN7EXAMPLE\"";
        let hits = scan_secrets_text(text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "aws_access_key");
    }

    fn scan_secrets_text(text: &str) -> Vec<(String, String, usize)> {
        SECRET_RULES
            .iter()
            .flat_map(|rule| {
                rule.re
                    .find_iter(text)
                    .map(move |m| (rule.kind.to_string(), m.as_str().to_string(),
                                   text[..m.start()].matches('\n').count() + 1))
            })
            .collect()
    }

    #[test]
    fn imports_dedupe_and_keep_order() {
        let src = "use std::collections;\nuse std::io;\nuse std::collections;\nmod config;\n";
        let mut got: Vec<String> = Vec::new();
        for caps in USE_RE.captures_iter(src) {
            let s = caps.get(1).unwrap().as_str().to_string();
            if !got.contains(&s) {
                got.push(s);
            }
        }
        for caps in MOD_DECL_RE.captures_iter(src) {
            let s = caps.get(1).unwrap().as_str().to_string();
            if !got.contains(&s) {
                got.push(s);
            }
        }
        assert_eq!(got, vec!["std::collections", "std::io", "config"]);
    }
}
