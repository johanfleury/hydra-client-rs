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
use reqwest;
use serde::{Deserialize, Serialize};
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
    pub skip: bool,
    pub subject: String,
}

#[derive(Debug, Serialize)]
struct AcceptLoginRequest {
    acr: Option<String>,
    force_subject_identifier: Option<String>,
    remember: Option<bool>,
    remember_for: Option<u64>,
    subject: String,
}

// Consent Types

#[derive(Debug, Deserialize)]
pub struct ConsentRequest {
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
    remember: bool,
    remember_for: u64,
    session: ConsentRequestSession,
}

#[derive(Debug, Serialize)]
struct ConsentRequestSession {
    id_token: HashMap<String, String>,
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
}

impl Hydra {
    pub fn new(url: Url) -> Hydra {
        return Hydra { url };
    }

    // Login

    pub fn get_login_request(&self, login_challenge: String) -> Result<LoginRequest, Error> {
        return self.get(
            self.endpoint("/oauth2/auth/requests/login")?,
            Some(format!("login_challenge={}", login_challenge).as_str()),
        );
    }

    pub fn accept_login_request(
        &self,
        login_challenge: String,
        subject: String,
        acr: Option<String>,
        force_subject_identifier: Option<String>,
        remember: Option<bool>,
        remember_for: Option<u64>,
    ) -> Result<CompletedRequest, Error> {
        let body = AcceptLoginRequest {
            acr: acr,
            force_subject_identifier: force_subject_identifier,
            remember: remember,
            remember_for: remember_for,
            subject,
        };

        return self.put(
            self.endpoint("/oauth2/auth/requests/login/accept")?,
            Some(format!("login_challenge={}", login_challenge).as_str()),
            Some(body),
        );
    }

    // Consent

    pub fn get_consent_request(&self, consent_challenge: String) -> Result<ConsentRequest, Error> {
        return self.get(
            self.endpoint("/oauth2/auth/requests/consent")?,
            Some(format!("consent_challenge={}", consent_challenge).as_str()),
        );
    }

    pub fn accept_consent_request(
        &self,
        consent_challenge: String,
        grant_access_token_audience: Vec<String>,
        grant_scope: Vec<String>,
        remember: bool,
        remember_for: u64,
        claims: HashMap<String, String>,
    ) -> Result<CompletedRequest, Error> {
        let session = ConsentRequestSession { id_token: claims };

        let body = AcceptConsentRequest {
            grant_access_token_audience,
            grant_scope,
            handled_at: Utc::now(),
            remember,
            remember_for,
            session: session,
        };

        return self.put(
            self.endpoint("/oauth2/auth/requests/consent/accept")?,
            Some(format!("consent_challenge={}", consent_challenge).as_str()),
            Some(body),
        );
    }

    // Logout

    pub fn accept_logout_request(
        &self,
        logout_challenge: String,
    ) -> Result<CompletedRequest, Error> {
        return self.put(
            self.endpoint("/oauth2/auth/requests/logout/accept")?,
            Some(format!("logout_challenge={}", logout_challenge).as_str()),
            AcceptLogoutRequest,
        );
    }

    // Internal

    fn endpoint(&self, endpoint: &str) -> Result<Url, Error> {
        return self
            .url
            .clone()
            .join(endpoint)
            .map_err(|e| Error::URLParseError(e));
    }

    fn deserialize<R: for<'de> Deserialize<'de>>(
        r: reqwest::blocking::Response,
    ) -> Result<R, Error> {
        let status = r.status().clone();

        if status.is_success() {
            return r.json().map_err(|e| Error::RequestError(e));
        } else {
            return match r.json::<ApiError>() {
                Ok(api_error) => Err(Error::ApiError(api_error)),
                Err(_) => Err(Error::UnknownError(format!(
                    "unable to parse reply from Hydra API (status: {})",
                    status.clone()
                ))),
            };
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, url: Url, query: Option<&str>) -> Result<T, Error> {
        let mut url = url;
        url.set_query(query);

        let r = reqwest::blocking::Client::new().get(url).send()?;

        return Hydra::deserialize(r);
    }

    fn put<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        query: Option<&str>,
        body: T,
    ) -> Result<R, Error> {
        let mut url = url;
        url.set_query(query);

        let r = reqwest::blocking::Client::new()
            .put(url)
            .json(&body)
            .send()?;

        return Hydra::deserialize(r);
    }
}
