# Local TLS Certificate for Development

When running the proxy locally in TLS mode, you need a certificate that
covers the hostnames the proxy will serve. This guide generates a
self-signed CA and leaf certificate for local development.

## Subjects

The certificate covers:

| SAN | Purpose |
|-----|---------|
| `localhost` | Direct access to the local proxy |
| `api.github.com` | Proxied GitHub API traffic |
| `github.com` | Proxied GitHub web traffic |
| `raw.githubusercontent.com` | Proxied raw file content |

## Generate the certificate

```bash
# 1. Create a self-signed CA (valid 10 years)
openssl req -x509 -new -nodes \
  -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout local-ca.key -out local-ca.crt \
  -days 3650 -subj "/CN=GHP Local Dev CA"

# 2. Create a private key for the leaf certificate
openssl ecparam -genkey -name prime256v1 -out local.key

# 3. Create a CSR with the required SANs
openssl req -new -key local.key -out local.csr \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:api.github.com,DNS:github.com,DNS:raw.githubusercontent.com"

# 4. Sign the CSR with the CA (valid 1 year)
openssl x509 -req -in local.csr \
  -CA local-ca.crt -CAkey local-ca.key -CAcreateserial \
  -out local.crt -days 365 \
  -copy_extensions copyall

# 5. Clean up intermediate files
rm -f local.csr local-ca.srl
```

This produces four files:

| File | Description |
|------|-------------|
| `local-ca.crt` | CA certificate — add this to your system/browser trust store |
| `local-ca.key` | CA private key — keep safe, used to re-sign if needed |
| `local.crt` | Leaf certificate for the proxy |
| `local.key` | Leaf private key for the proxy |

## Configure the proxy

### Via YAML

```yaml
server:
  https_listen: ":443"

tls:
  certificates:
    - cert_file: "./local.crt"
      key_file: "./local.key"
```

### Via environment variables

```bash
export GHP_SERVER_HTTPS_LISTEN=":443"
export GHP_TLS_CERT_FILE="./local.crt"
export GHP_TLS_KEY_FILE="./local.key"
```

> **Note:** These convenience env vars populate `tls.certificates[0]`
> when no certificates are configured via YAML. Both must be set.

## Trust the CA (macOS)

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain local-ca.crt
```

To remove later:

```bash
sudo security delete-certificate -c "GHP Local Dev CA" \
  /Library/Keychains/System.keychain
```

## Verify

```bash
# Inspect the certificate SANs
openssl x509 -in local.crt -noout -text | grep -A1 "Subject Alternative Name"

# Test a TLS handshake against the running proxy
openssl s_client -connect localhost:443 -servername localhost \
  -CAfile local-ca.crt </dev/null
```
