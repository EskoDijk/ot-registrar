# `credentials/` — test & development certificate fixtures

All material here is **for testing and local development only**. Every private
key is committed in clear text — never deploy these credentials in production.

## Naming scheme

The PEM files in a vendor directory and the aliases inside the keystores both use
the role name directly:

| Role / alias   | Certificate file   | Private-key file           |
|----------------|--------------------|----------------------------|
| `domain_ca`    | `domain_ca.pem`    | `privkey_domain_ca.pem`    |
| `registrar`    | `registrar.pem`    | `privkey_registrar.pem`    |
| `masa_ca`      | `masa_ca.pem`      | `privkey_masa_ca.pem`      |
| `masa`         | `masa.pem`         | `privkey_masa.pem`         |
| `pledge`       | `pledge.pem`       | `privkey_pledge.pem`       |
| `commissioner` | `commissioner.pem` | `privkey_commissioner.pem` |

Keystore password is `OpenThread` (`Constants.KEY_STORE_PASSWORD`). The aliases
are defined in `com.google.openthread.CredentialsSet` and generation/packaging in
`com.google.openthread.tools.CredentialGenerator` — treat those as the source of
truth if this README file says otherwise.

## Per-role keystores: `<vendor>_<role>.p12`

Each keystore holds only what its role loads at runtime; `CredentialsSet(vendor,
role)` loads `credentials/<vendor>_<role>.p12`:

| Keystore                 | Aliases inside                                    |
|--------------------------|---------------------------------------------------|
| `<vendor>_pledge.p12`    | `pledge` (+chain), `masa_ca` (trust cert)         |
| `<vendor>_registrar.p12` | `registrar` (+chain), `domain_ca` (LDevID signer) |
| `<vendor>_masa.p12`      | `masa` (+chain), `masa_ca` (Voucher signer)       |

- **`default_*.p12`** — runtime defaults (for `OtRegistrarConfig`, `run-servers.sh`)
  and the default test fixtures.
- **`TestVendor_*.p12`** — the same files, used by the "loaded credentials"
  tests.

## Vendor PEM directories

A `<vendor>/` directory holds one vendor's PEM set, in the naming scheme above:

- **`TestVendor/`** — a full topology (domain CA → registrar; MASA CA → MASA,
  pledge; commissioner); the source for `TestVendor_*.p12`.
  Used as the default MASA and Pledge's vendor.
- **`ietf-cbrski/`** — PEMs for the constrained-BRSKI IETF draft appendix examples.
  Its Registrar/Domain CA are used as the default Registrar/Domain CA.
- **`honeydukes/`** — Sandelman "Honeydukes" third-party pledge IDevID + MASA CA
  (pledge + masa_ca only). Cannot currently be packaged into a keystore on JDK 17+:
  its IDevID issuing CA certificate is not part of the fixture, so the `pledge`
  chain does not validate. TODO: to be updated to newer certs.

## Scripts

```bash
# generate a fresh PEM set for a new vendor into credentials/<vendor>/
./script/create-credentials-pem.sh <vendor>

# package a vendor's PEMs into per-role keystores credentials/<vendor>_<role>.p12
./script/create-credentials-p12.sh <vendor>

# adopt a keystore as a runtime default, for a particular roles
cp credentials/<vendor>_pledge.p12 credentials/default_pledge.p12
```

Generation refuses to overwrite an existing `<vendor>/` directory. Generated
certificate DNs use `<vendor>` for the organization and common name; the location
(`C=NL,L=Utrecht`) is fixed currently.
