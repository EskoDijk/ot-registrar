# `credentials/` — Test and development certificate fixtures

This directory contains the certificate / private-key material used by
OT-Registrar's tests and `./script/run-*` helpers. **Everything in this
directory is for testing or local development. Do not deploy these
credentials in production — every private key is committed in clear text
in the public repository.**

## Layout

```
credentials/
├── default_masa.p12          ← runtime defaults for the role-named
├── default_pledge.p12          *Main classes and run-servers.sh
├── default_registrar.p12
├── local-masa/               ← local development fixture (PEM + .p12)
├── ietf-draft-constrained-brski/  ← IETF-draft demo / interop fixture
├── iotconsultancy-masa/      ← third-party MASA interop fixture
└── honeydukes/               ← third-party MASA interop fixture
```

### Root keystores: `default_{masa,pledge,registrar}.p12`

The three `default_*.p12` files are the keystores loaded when an
`OtRegistrarConfig.default*()` builder is used (see
`com.google.openthread.main.OtRegistrarConfig`). They are also the
`run-servers.sh` defaults.

The Java code expects these aliases inside each keystore (see
`com.google.openthread.tools.CredentialGenerator`):

| Alias        | Role                                             |
|--------------|--------------------------------------------------|
| `domainca`   | Domain CA (cert + private key)                   |
| `registrar`  | Registrar RA (cert + chain to domain CA + key)   |
| `masaca`     | MASA CA                                          |
| `masa`       | MASA server (cert + chain to MASA CA + key)      |
| `pledge`     | Pledge / IDevID (cert + chain to MASA CA + key)  |
| `commissioner` | Commissioner (optional, for some flows)        |

Keystore password is `OpenThread` (`CredentialGenerator.PASSWORD`).

There is no regeneration script for the three `default_*.p12` files. If
they need to be refreshed, run `CredentialGenerator` directly (see
`./script/create-test-credentials-p12.sh` for a template) and copy the
resulting keystore into place — or build per-role keystores with
`./script/create-credentials-p12.sh` (below) and copy them into place.

## Building per-role keystores: `create-credentials-p12.sh`

`./script/create-credentials-p12.sh <vendor>` builds per-role PKCS#12
keystores from a vendor's PEM files and writes them to
`credentials/<vendor>_<role>.p12`. Copy a result onto a runtime default to
use it, e.g.:

```bash
./script/create-credentials-p12.sh local-masa
cp credentials/local-masa_pledge.p12 credentials/default_pledge.p12
```

**Uniform file naming** in `credentials/<vendor>/`: each certificate is
`<name>.pem` and its private key is `privkey_<name>.pem`, where `<name>` is
the keystore alias / role — `pledge`, `masaca`, `masa`, `domainca`,
`registrar`.

**What each role keystore contains** (only the aliases that role loads at
runtime):

| Output `.p12`            | Aliases                                       | Required files in vendor dir |
|--------------------------|-----------------------------------------------|------------------------------|
| `<vendor>_pledge.p12`    | `pledge` (key+chain), `masaca` (trust cert)   | `pledge.pem`, `privkey_pledge.pem`, `masaca.pem` |
| `<vendor>_registrar.p12` | `registrar` (key+chain), `domainca` (key)     | `registrar.pem`, `privkey_registrar.pem`, `domainca.pem`, `privkey_domainca.pem` |
| `<vendor>_masa.p12`      | `masa` (key+chain), `masaca` (key)            | `masa.pem`, `privkey_masa.pem`, `masaca.pem`, `privkey_masaca.pem` |

The script builds a keystore for each role whose files are present, so a
pledge-only vendor directory yields only `<vendor>_pledge.p12`. For the
`pledge` role the MASA CA is stored as a trusted-certificate entry (no
private key needed), so third-party MASA trust anchors can be used.
Implemented by `CredentialGenerator -role <role> ...`.

Only `honeydukes/` has been migrated to this scheme so far; the other
vendor directories below still use their older per-directory naming and
scripts and can be migrated over time.

### `local-masa/`

Standalone PEM cert + private-key files for a complete BRSKI topology
(DomainCA → Registrar; MASA-CA → MASA; MASA-CA → Pledge; commissioner).
Used by:

- `./script/create-pledge-credentials-p12.sh` — packages a pledge .p12.
- `./script/create-test-credentials-p12.sh` — packages the full
  Registrar/MASA/DomainCA keystore.
- `./script/create-ot-registrar-cert.sh` — re-issues only the
  Registrar EE cert (random serial via `-CAcreateserial`).
- `x509v3_registrar.ext` — OpenSSL extension config used by the script
  above.

### `ietf-draft-constrained-brski/`

Fixture used by `IETFConstrainedBrskiTest` and by the appendix examples
in the constrained-BRSKI IETF draft. PEMs + per-role private keys with
the `privkey_<role>.pem` naming. Packaged into `.p12` via
`./script/create-keystore-ietf-draft-constrained-brski.sh`, which writes
`credentials/keystore_ietf-draft-constrained-brski.p12` (gitignored).

A `domain_ca.srl` may appear here when OpenSSL is used to re-sign certs
manually (gitignored via `*.srl`).

### `iotconsultancy-masa/`

Third-party MASA interop fixture (TestVendor IoT device + TestVendor
MASA CA + TestVendor MASA server). Loaded by `CoseTest`, `FunctionalTest`
(in the loaded-credentials test) and by
`./script/run-pledge-iotconsultancy.sh`. The `.p12` is regenerable via
`./script/create-pledge-credentials-p12-iotconsultancy.sh`.

### `honeydukes/`

Third-party Pledge IDevID fixture (Sandelman's Honeydukes test MASA),
migrated to the uniform naming scheme: `pledge.pem` (IDevID) +
`privkey_pledge.pem`, `masaca.pem` (the "Unstrung Highway CA" trust
anchor), and `masa.pem` (MASA server cert), plus the alternate IDevIDs
`device_2021.crt` / `device_2022.crt`. Used by
`./script/run-pledge-honeydukes.sh` via the pre-built `credentials.p12`.

**Limitation:** this `.p12` cannot currently be regenerated with
`./script/create-credentials-p12.sh honeydukes` on JDK 17+. The honeydukes
IDevID is issued by "highway-test.example.com IDevID CA", whose certificate
is not part of the fixture, so the `pledge`→`masaca` chain does not validly
chain and the JDK refuses to store it (`Certificate chain is not valid`).
The committed `credentials.p12` was produced on an older, lenient JDK. To
regenerate it, the missing IDevID CA certificate would need to be added so
the pledge chain validates.

## Regenerating

For the in-repo fixtures (`local-masa/`, `ietf-draft-constrained-brski/`,
`iotconsultancy-masa/`), the regen pattern is:

1. Re-issue the PEM with OpenSSL (or with `CredentialGenerator`, for
   `local-masa/`).
2. Rerun the matching `script/create-*-p12.sh` to repack the keystore.
3. Commit the updated PEMs and `.p12`.

The Java code path (`SecurityUtils.allocateSerialNumber`) and the
`-CAcreateserial` flag in `create-ot-registrar-cert.sh` both produce
random 160-bit serial numbers (matching RFC 5280 §4.1.2.2).
