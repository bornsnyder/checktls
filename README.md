# checktls

A simple website that checks whether a domain's **mail server (MX record)** presents a TLS
**root CA** that is accepted by Mimecast.

For each MX host it:
1. Resolves the domain's MX records (all of them).
2. Connects to the mail server over SMTP/TLS (port 25 STARTTLS, falling back to port 465 implicit TLS) and captures the certificate chain.
3. Identifies the **root CA** at the top of the chain (if the server doesn't send the root, it is derived from the chain's issuer).
4. Compares that root against Mimecast's **"Supported SSL Certificates"** list using normalized matching with a family-level fallback.

The result per MX host is shown as:
- 🟢 **Root CA PRESENT on mimecast** (green) — the root CA fully matches a Mimecast entry.
- 🟡 **Root CA PARTIALLY MATCHED on mimecast** (yellow) — no exact match, but the CA shares meaningful brand words with one or more Mimecast entries (e.g. Mimecast lists `deutsche telekom root ca 1` while the server presents `Telekom Security ServerID OV Class 2 CA (Deutsche Telekom Security GmbH)`). This is "found in parts" — likely valid, but not a 100% match.
- 🔴 **Root CA NOT PRESENT on mimecast** (red) — no exact or partial match.
- or an error card if DNS/TLS fails.

Each successful host also shows a collapsed **Certificate chain details** block. Click it to expand the full presented chain in text form, e.g.:

```
Cert VALIDATED: ok
Cert Hostname VERIFIED (smtpin.rzone.de = smtpin.rzone.de | DNS:smtpin.rzone.de)
cert not revoked by OCSP
Not Valid Before: Jan 13 08:55:10 2026 GMT
Not Valid After: Jan 17 23:59:59 2027 GMT
Seconds Until Expired: 12406439
subject: /C=DE/ST=Berlin/L=Berlin/O=Strato GmbH/CN=smtpin.rzone.de
issuer: /C=DE/O=Deutsche Telekom Security GmbH/CN=Telekom Security ServerID OV Class 2 CA
Certificate #2 of 3 (sent by MX):
...
```

The OCSP line is a best-effort revocation check; if the server does not configure an OCSP responder (common for mail), it reads `OCSP status unknown`.

## Run locally

```bash
py -m pip install -r requirements.txt
py app.py
# open http://localhost:5000
```

(On systems where `python` works, `python app.py` is equivalent.)

The bind address and port are configurable via environment variables:
`CHECKTLS_HOST` (default `0.0.0.0`) and `CHECKTLS_PORT` (default `5000`).

## Run in Docker

A production-ready image is provided (gunicorn WSGI server, non-root user):

```bash
docker build -t checktls .
docker run --rm -p 5000:5000 checktls
# open http://localhost:5000
```

Or with Docker Compose:

```bash
docker compose up --build
```

To expose it on a different host port, change the left side of the mapping in
`docker-compose.yml` (e.g. `"8080:5000"`). For public hosting, put a reverse proxy
(Caddy/Nginx) with TLS in front and point it at the container's port 5000.

> **Network requirement:** the container needs outbound internet access for DNS,
> the Mimecast fetch (HTTPS/443), and direct SMTP to mail servers (**ports 25 + 465**).
> On a corporate network that blocks outbound SMTP (e.g. Zscaler), checks will fail
> with connection timeouts.

## How the Mimecast list is obtained

The supported-certificate names are fetched live from the Mimecast support article
with a browser User-Agent (to bypass Cloudflare's bot challenge), parsed into ~250+ CA
names, and cached in memory for ~6 hours. If the live fetch fails, the last good cache is used.

## Notes / limitations

- Many mail servers do **not** send the root certificate; in that case the root name is derived from the topmost presented cert's issuer (shown with a note).
- Matching is normalized + family-based: e.g. a DigiCert leaf/intermediate matches the DigiCert entries in Mimecast's list.
- Running `py app.py` uses Flask's development server, which is fine for local use. For hosting, run under **gunicorn** (used by the Docker image): `gunicorn -w 2 -b 0.0.0.0:5000 app:app`. The bind address/port can be set via `CHECKTLS_HOST` / `CHECKTLS_PORT`.
