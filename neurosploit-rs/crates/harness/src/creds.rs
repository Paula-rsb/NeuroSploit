//! Credential loading for authenticated testing (`creds.yaml`).
//!
//! Dependency-free parser for a small YAML subset: flat `key: value` pairs plus
//! one nested `login:` block (2-space indent). Lets the operator hand the
//! harness a JWT / header / cookie, or a login flow the agents should perform so
//! they test the target as an authenticated user.
//!
//! Example `creds.yaml`:
//! ```yaml
//! jwt: eyJhbGciOi...                 # → Authorization: Bearer <jwt>
//! # header: "X-Api-Key: abc123"      # raw header (alternative)
//! # cookie: "session=deadbeef"       # → Cookie: session=deadbeef
//! login:
//!   url: http://app/login
//!   method: POST
//!   username_field: uid
//!   password_field: passw
//!   username: admin
//!   password: admin
//!   success: Logout
//! ```

#[derive(Default, Debug, Clone)]
pub struct Login {
    pub url: String,
    pub method: String,
    pub username_field: String,
    pub password_field: String,
    pub username: String,
    pub password: String,
    pub success: String,
}

#[derive(Default, Debug, Clone)]
pub struct Creds {
    pub jwt: Option<String>,
    pub header: Option<String>,
    pub cookie: Option<String>,
    pub login: Option<Login>,
}

impl Creds {
    pub fn load(path: &std::path::Path) -> Option<Creds> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut c = Creds::default();
        let mut login = Login { method: "POST".into(), ..Default::default() };
        let mut in_login = false;
        let mut have_login = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("");
            if line.trim().is_empty() {
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let (k, v) = match line.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), unquote(v.trim())),
                None => continue,
            };
            if k == "login" && v.is_empty() {
                in_login = true;
                have_login = true;
                continue;
            }
            if in_login && indented {
                match k.as_str() {
                    "url" => login.url = v,
                    "method" => login.method = v.to_uppercase(),
                    "username_field" => login.username_field = v,
                    "password_field" => login.password_field = v,
                    "username" | "user" => login.username = v,
                    "password" | "pass" => login.password = v,
                    "success" => login.success = v,
                    _ => {}
                }
                continue;
            }
            in_login = false;
            match k.as_str() {
                "jwt" | "token" => c.jwt = Some(v),
                "header" => c.header = Some(v),
                "cookie" => c.cookie = Some(v),
                _ => {}
            }
        }
        if have_login && !login.url.is_empty() {
            c.login = Some(login);
        }
        if c.jwt.is_none() && c.header.is_none() && c.cookie.is_none() && c.login.is_none() {
            return None;
        }
        Some(c)
    }

    /// The auth material to send with each request, as a header line.
    pub fn auth_header(&self) -> Option<String> {
        if let Some(h) = &self.header {
            return Some(h.clone());
        }
        if let Some(j) = &self.jwt {
            return Some(format!("Authorization: Bearer {j}"));
        }
        if let Some(ck) = &self.cookie {
            return Some(format!("Cookie: {ck}"));
        }
        None
    }

    /// A directive instructing the agent to authenticate first via curl.
    pub fn login_instruction(&self) -> Option<String> {
        let l = self.login.as_ref()?;
        Some(format!(
            "AUTHENTICATE FIRST: {} {} with {}={} and {}={}; capture the session cookie/token \
             from the response (success indicator: \"{}\") and reuse it on every subsequent request.",
            l.method, l.url, l.username_field, l.username, l.password_field, l.password, l.success
        ))
    }
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}
