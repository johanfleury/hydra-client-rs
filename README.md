# hydra-rs

hydra-rs is a client implementation for the [ORY Hydra
API](https://www.ory.sh/hydra/) written in Rust.

It is fairly incomplete, and mainly developed for the needs of
[hydra-idp-ldap](https://gitlab.com/Arcaik/hydra-idp-ldap).

At the moment, only a few response types and the folowing endpoints are
implemented:

* Getting login request informations (`GET /oauth2/auth/requests/login`)
* Accepting a login request (`PUT /oauth2/auth/requests/login/accept`)
* Getting consent request informations (`GET /oauth2/auth/requests/consent`)
* Accepting a consent request (`PUT /oauth2/auth/requests/consent/accept`)
* Accepting a logout request (`PUT /oauth2/auth/requests/logout/accept`)

## Usage

Using this library is pretty simple:

```
use hydra_client::Hydra;
use url::Url;

fn main() {
    let hydra = Hydra::new(Url::parse("http://127.0.0.1:4445").unwrap());
    ...
}
```

## Contributing

This library is [Free Software](LICENCE.md) and every contributions are
welcome.

Please note that this project is released with a [Contributor Code of
Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to
abide by its terms.
