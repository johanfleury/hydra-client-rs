// Copyright 2020 Johan Fleury <jfleury@arcaik.net>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;
use url::{self, Url};

// Common Types

#[derive(Debug, Error, Deserialize)]
#[error("{description}")]
pub struct ApiError {
    pub error: String,

    #[serde(rename = "error_description")]
    pub description: String,

    #[serde(rename = "error_debug")]
    pub debug: String,

    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct CompletedRequest {
    pub redirect_to: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuth2Client {
    pub metadata: HashMap<String, String>,
}

// Login Types

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub client: OAuth2Client,

    #[serde(default)]
    pub context: HashMap<String, Value>,

    pub skip: bool,

    pub subject: String,
}

#[derive(Debug, Serialize)]
struct AcceptLoginRequest {
    acr: Option<String>,
    context: Option<HashMap<String, Value>>,
    force_subject_identifier: Option<String>,
    remember: Option<bool>,
    remember_for: Option<u64>,
    subject: String,
}

// Consent Types

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
    #[serde(default)]
    pub context: HashMap<String, Value>,

    pub requested_access_token_audience: Vec<String>,

    pub requested_scope: Vec<String>,

    pub skip: bool,

    pub subject: String,
}

#[derive(Debug, Serialize)]
struct AcceptConsentRequest {
    grant_access_token_audience: Vec<String>,
    grant_scope: Vec<String>,
    handled_at: DateTime<Utc>,
    remember: Option<bool>,
    remember_for: Option<u64>,
    session: Option<ConsentRequestSession>,
}

#[derive(Debug, Serialize)]
struct ConsentRequestSession {
    id_token: Option<HashMap<String, Value>>,
}

// Logout Types

#[derive(Debug, Serialize)]
pub struct AcceptLogoutRequest;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    #[error(transparent)]
    URLParseError(#[from] url::ParseError),

    #[error("API error: {}", .0.description)]
    ApiError(#[from] ApiError),

    #[error("Unknown error: {0}")]
    UnknownError(String),
}

#[derive(Debug, Clone)]
pub struct Hydra {
    url: Url,
    client: reqwest::blocking::Client,
}

impl Hydra {
    pub fn new(url: Url) -> Hydra {
        Hydra {
            url,
            client: reqwest::blocking::Client::new(),
        }
    }

    // Login

    pub fn get_login_request(&self, login_challenge: String) -> Result<LoginRequest, Error> {
        self.get(
            self.endpoint("/oauth2/auth/requests/login")?,
            Some(format!("login_challenge={}", login_challenge).as_str()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_login_request(
        &self,
        login_challenge: String,
        subject: String,
        acr: Option<String>,
        context: Option<HashMap<String, Value>>,
        force_subject_identifier: Option<String>,
        remember: Option<bool>,
        remember_for: Option<u64>,
    ) -> Result<CompletedRequest, Error> {
        let body = AcceptLoginRequest {
            acr,
            context,
            force_subject_identifier,
            remember,
            remember_for,
            subject,
        };

        self.put(
            self.endpoint("/oauth2/auth/requests/login/accept")?,
            Some(format!("login_challenge={}", login_challenge).as_str()),
            Some(body),
        )
    }

    // Consent

    pub fn get_consent_request(&self, consent_challenge: String) -> Result<ConsentRequest, Error> {
        self.get(
            self.endpoint("/oauth2/auth/requests/consent")?,
            Some(format!("consent_challenge={}", consent_challenge).as_str()),
        )
    }

    pub fn accept_consent_request(
        &self,
        consent_challenge: String,
        grant_access_token_audience: Vec<String>,
        grant_scope: Vec<String>,
        remember: Option<bool>,
        remember_for: Option<u64>,
        claims: Option<HashMap<String, Value>>,
    ) -> Result<CompletedRequest, Error> {
        let session = match claims.is_some() {
            true => Some(ConsentRequestSession { id_token: claims }),
            false => None,
        };

        let body = AcceptConsentRequest {
            grant_access_token_audience,
            grant_scope,
            handled_at: Utc::now(),
            remember,
            remember_for,
            session,
        };

        self.put(
            self.endpoint("/oauth2/auth/requests/consent/accept")?,
            Some(format!("consent_challenge={}", consent_challenge).as_str()),
            Some(body),
        )
    }

    // Logout

    pub fn accept_logout_request(
        &self,
        logout_challenge: String,
    ) -> Result<CompletedRequest, Error> {
        self.put(
            self.endpoint("/oauth2/auth/requests/logout/accept")?,
            Some(format!("logout_challenge={}", logout_challenge).as_str()),
            AcceptLogoutRequest,
        )
    }

    // Internal

    fn endpoint(&self, endpoint: &str) -> Result<Url, Error> {
        self.url
            .clone()
            .join(endpoint)
            .map_err(Error::URLParseError)
    }

    fn deserialize<R: for<'de> Deserialize<'de>>(
        r: reqwest::blocking::Response,
    ) -> Result<R, Error> {
        let status = r.status();

        if status.is_success() {
            r.json().map_err(Error::RequestError)
        } else {
            match r.json::<ApiError>() {
                Ok(api_error) => Err(Error::ApiError(api_error)),
                Err(_) => Err(Error::UnknownError(format!(
                    "unable to parse reply from Hydra API (status: {})",
                    status.clone()
                ))),
            }
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, url: Url, query: Option<&str>) -> Result<T, Error> {
        let mut url = url;
        url.set_query(query);

        let r = self.client.get(url).send()?;

        Hydra::deserialize(r)
    }

    fn put<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        query: Option<&str>,
        body: T,
    ) -> Result<R, Error> {
        let mut url = url;
        url.set_query(query);

        let r = self.client.put(url).json(&body).send()?;

        Hydra::deserialize(r)
    }
}
