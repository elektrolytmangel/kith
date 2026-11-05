//! Azure Table Storage as a [`StateStore`], over plain REST (no SDK).
//!
//! Table `allowedorgs`: `PartitionKey = "org"`, `RowKey = <org ID>`. Add a row to approve an
//! org, delete it to withdraw. The relay re-reads the table every few seconds.
//!
//! Authentication, chosen by environment (see [`AzureTables::from_env`]):
//! - `KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING`: account name + key (SharedKeyLite). For
//!   local use and CI (Azurite).
//! - `KITH_RELAY_AZURE_STORAGE_ACCOUNT`: a storage account reached with the Container Apps
//!   managed identity (`IDENTITY_ENDPOINT` / `IDENTITY_HEADER`, optional `AZURE_CLIENT_ID`
//!   for a user-assigned identity). No keys in the app.

use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{BoxFuture, StateStore};

const API_VERSION: &str = "2020-12-06";
const PARTITION: &str = "org";
/// A token is renewed this long before it expires.
const TOKEN_SLACK: Duration = Duration::from_secs(300);

enum Auth {
    /// Storage account key (SharedKeyLite).
    Key(Vec<u8>),
    /// Managed identity bearer token, cached until shortly before it expires.
    Identity {
        endpoint: String,
        header: String,
        client_id: Option<String>,
        cached: Mutex<Option<(String, SystemTime)>>,
    },
}

/// A table client for one storage account.
pub struct AzureTables {
    http: reqwest::Client,
    /// Table service endpoint without a trailing slash (includes `/<account>` for Azurite).
    endpoint: String,
    account: String,
    auth: Auth,
    table: String,
}

impl AzureTables {
    /// Build from the environment. `None` if neither variable is set.
    pub fn from_env() -> Result<Option<Self>, String> {
        let table = std::env::var("KITH_RELAY_AZURE_ALLOWED_ORGS_TABLE")
            .unwrap_or_else(|_| "allowedorgs".into());
        if let Ok(cs) = std::env::var("KITH_RELAY_AZURE_STORAGE_CONNECTION_STRING") {
            return Self::from_connection_string(&cs, &table).map(Some);
        }
        let Ok(account) = std::env::var("KITH_RELAY_AZURE_STORAGE_ACCOUNT") else {
            return Ok(None);
        };
        let endpoint = std::env::var("IDENTITY_ENDPOINT").map_err(
            |_| "IDENTITY_ENDPOINT is not set (not on Container Apps with a managed identity?)",
        )?;
        let header = std::env::var("IDENTITY_HEADER").map_err(|_| "IDENTITY_HEADER is not set")?;
        Ok(Some(Self {
            http: reqwest::Client::new(),
            endpoint: format!("https://{account}.table.core.windows.net"),
            account,
            auth: Auth::Identity {
                endpoint,
                header,
                client_id: std::env::var("AZURE_CLIENT_ID")
                    .ok()
                    .filter(|s| !s.is_empty()),
                cached: Mutex::new(None),
            },
            table,
        }))
    }

    /// Build from an Azure storage connection string (`AccountName`, `AccountKey`, and
    /// `TableEndpoint` or `EndpointSuffix`).
    pub fn from_connection_string(cs: &str, table: &str) -> Result<Self, String> {
        let get = |k: &str| {
            cs.split(';')
                .filter_map(|p| p.split_once('='))
                .find(|(key, _)| key.trim().eq_ignore_ascii_case(k))
                .map(|(_, v)| v.trim().to_string())
        };
        let account = get("AccountName").ok_or("connection string has no AccountName")?;
        let key = get("AccountKey").ok_or("connection string has no AccountKey")?;
        let key = B64
            .decode(key)
            .map_err(|e| format!("AccountKey is not base64: {e}"))?;
        let endpoint = match get("TableEndpoint") {
            Some(e) => e,
            None => format!(
                "{}://{account}.table.{}",
                get("DefaultEndpointsProtocol").unwrap_or_else(|| "https".into()),
                get("EndpointSuffix").unwrap_or_else(|| "core.windows.net".into())
            ),
        };
        Ok(Self {
            http: reqwest::Client::new(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            account,
            auth: Auth::Key(key),
            table: table.to_string(),
        })
    }

    /// Create the table if it does not exist (Bicep creates it in Azure; this is for Azurite).
    pub async fn ensure_table(&self) -> Result<(), String> {
        let body = serde_json::json!({ "TableName": self.table });
        let url = format!("{}/Tables", self.endpoint);
        let resp = self
            .request(self.http.post(&url).json(&body))
            .await?
            .header("Prefer", "return-no-content")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        match resp.status().as_u16() {
            200..=299 | 409 => Ok(()),
            s => Err(format!(
                "create table: HTTP {s}: {}",
                resp.text().await.unwrap_or_default()
            )),
        }
    }

    /// Approve `org` (idempotent).
    pub async fn allow(&self, org: &str) -> Result<(), String> {
        let body =
            serde_json::json!({ "PartitionKey": PARTITION, "RowKey": org.to_ascii_lowercase() });
        let url = format!("{}/{}", self.endpoint, self.table);
        let resp = self
            .request(self.http.post(&url).json(&body))
            .await?
            .header("Prefer", "return-no-content")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        match resp.status().as_u16() {
            200..=299 | 409 => Ok(()),
            s => Err(format!(
                "add org: HTTP {s}: {}",
                resp.text().await.unwrap_or_default()
            )),
        }
    }

    /// Withdraw `org` (idempotent).
    pub async fn disallow(&self, org: &str) -> Result<(), String> {
        let url = format!(
            "{}/{}(PartitionKey='{PARTITION}',RowKey='{}')",
            self.endpoint,
            self.table,
            org.to_ascii_lowercase().replace('\'', "''")
        );
        let resp = self
            .request(self.http.delete(&url))
            .await?
            .header("If-Match", "*")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        match resp.status().as_u16() {
            200..=299 | 404 => Ok(()),
            s => Err(format!(
                "remove org: HTTP {s}: {}",
                resp.text().await.unwrap_or_default()
            )),
        }
    }

    /// Every approved org (follows continuation tokens).
    pub async fn list(&self) -> Result<HashSet<String>, String> {
        let mut orgs = HashSet::new();
        let mut next: Option<(String, String)> = None;
        loop {
            let mut url = reqwest::Url::parse(&format!("{}/{}()", self.endpoint, self.table))
                .map_err(|e| e.to_string())?;
            {
                let mut q = url.query_pairs_mut();
                q.append_pair("$filter", &format!("PartitionKey eq '{PARTITION}'"));
                q.append_pair("$select", "RowKey");
                if let Some((p, r)) = &next {
                    q.append_pair("NextPartitionKey", p);
                    q.append_pair("NextRowKey", r);
                }
            }
            let resp = self
                .request(self.http.get(url))
                .await?
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status();
            if status.as_u16() == 404 {
                return Err(format!("table {} does not exist", self.table));
            }
            if !status.is_success() {
                return Err(format!(
                    "list orgs: HTTP {status}: {}",
                    resp.text().await.unwrap_or_default()
                ));
            }
            let header = |n: &str| {
                resp.headers()
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let cont = header("x-ms-continuation-NextPartitionKey").map(|p| {
                (
                    p,
                    header("x-ms-continuation-NextRowKey").unwrap_or_default(),
                )
            });
            let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
            for row in json["value"].as_array().into_iter().flatten() {
                if let Some(id) = row["RowKey"].as_str() {
                    orgs.insert(id.to_ascii_lowercase());
                }
            }
            match cont {
                Some(c) => next = Some(c),
                None => return Ok(orgs),
            }
        }
    }

    /// Add the standard headers and the authorization to a request.
    async fn request(
        &self,
        rb: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, String> {
        let req = rb.build().map_err(|e| e.to_string())?;
        let path = req.url().path().to_string();
        let date = http_date(SystemTime::now());
        let rb = reqwest::RequestBuilder::from_parts(self.http.clone(), req)
            .header("x-ms-date", &date)
            .header("x-ms-version", API_VERSION)
            .header("Accept", "application/json;odata=nometadata");
        let authorization = match &self.auth {
            Auth::Key(key) => {
                // SharedKeyLite for tables: date + canonicalized resource (account + path).
                let string = format!("{date}\n/{}{}", self.account, path);
                let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|e| e.to_string())?;
                mac.update(string.as_bytes());
                format!(
                    "SharedKeyLite {}:{}",
                    self.account,
                    B64.encode(mac.finalize().into_bytes())
                )
            }
            Auth::Identity { .. } => format!("Bearer {}", self.token().await?),
        };
        Ok(rb.header("Authorization", authorization))
    }

    async fn token(&self) -> Result<String, String> {
        let Auth::Identity {
            endpoint,
            header,
            client_id,
            cached,
        } = &self.auth
        else {
            return Err("not a managed identity".into());
        };
        if let Some((t, exp)) = cached.lock().unwrap().as_ref()
            && SystemTime::now() + TOKEN_SLACK < *exp
        {
            return Ok(t.clone());
        }
        let mut q = vec![
            ("api-version", "2019-08-01".to_string()),
            ("resource", "https://storage.azure.com/".to_string()),
        ];
        if let Some(id) = client_id {
            q.push(("client_id", id.clone()));
        }
        let resp = self
            .http
            .get(endpoint)
            .query(&q)
            .header("X-IDENTITY-HEADER", header)
            .send()
            .await
            .map_err(|e| format!("managed identity: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("managed identity: HTTP {}", resp.status()));
        }
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let token = json["access_token"]
            .as_str()
            .ok_or("managed identity: no access_token")?
            .to_string();
        let expires = json["expires_on"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| json["expires_on"].as_u64())
            .map_or(SystemTime::now() + Duration::from_secs(600), |s| {
                UNIX_EPOCH + Duration::from_secs(s)
            });
        *cached.lock().unwrap() = Some((token.clone(), expires));
        Ok(token)
    }
}

impl StateStore for AzureTables {
    fn allowed_orgs(&self) -> BoxFuture<'_, Result<Option<HashSet<String>>, String>> {
        // An empty table approves nobody (fail closed), unlike an unset env list.
        Box::pin(async move { self.list().await.map(Some) })
    }
}

/// RFC 1123 date (`Sun, 06 Nov 1994 08:49:37 GMT`) for the `x-ms-date` header.
fn http_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates_are_rfc_1123() {
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    #[test]
    fn connection_strings_parse() {
        let cs = "DefaultEndpointsProtocol=http;AccountName=dev;AccountKey=AAAA;TableEndpoint=http://127.0.0.1:10002/dev/;";
        let t = AzureTables::from_connection_string(cs, "t").unwrap();
        assert_eq!(t.endpoint, "http://127.0.0.1:10002/dev");
        assert_eq!(t.account, "dev");
        let cs = "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=AAAA;EndpointSuffix=core.windows.net";
        let t = AzureTables::from_connection_string(cs, "t").unwrap();
        assert_eq!(t.endpoint, "https://acme.table.core.windows.net");
        assert!(AzureTables::from_connection_string("AccountName=x", "t").is_err());
    }
}
