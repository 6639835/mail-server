# mail-server

Windows mail stack installer + web admin UI + API (built around **hMailServer**).

## What this repo sets up

- **IIS + PHP (FastCGI)**: hosts Roundcube webmail, the admin panel, and the API
- **MariaDB**: Roundcube database
- **Roundcube**: webmail UI at `/`
- **hMailServer**: SMTP/IMAP/POP3 server (Windows)
- **Admin panel**: manage accounts at `/admin/`
- **REST API**: create accounts at `POST /api/v1/accounts`

## Quick start (Windows Server)

### Prerequisites

- **Windows Server** (run the installer as Administrator)
- **A domain name** you control (DNS access)
- **A public static IP** (strongly recommended for real internet email)
- **Firewall/NAT** ready to allow inbound:
  - SMTP: **25** (server-to-server)
  - Submission: **587** (recommended) / **465** (optional SMTPS)
  - IMAP: **143** / **993** (recommended)
  - POP3: **110** / **995** (optional)

### Install

1. Edit the `$Config` block in `Install-MailStack-Windows.ps1`:
   - **Passwords**: `MariaDbRootPass`, `RoundcubeDBPass`, `HmailAdminPass`, `AdminPassword`
   - **API key**: `ApiKey` (if left empty, the installer auto-generates a strong key)
   - **Offline artifacts (optional)**:
     - Place `mariadb-12.1.2-winx64.msi` and/or `hMailServer-5.6.8-B2574.exe` **next to the script**, or set `MariaDbMsiPath` / `HmailExePath` to local file paths
2. Run from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install-MailStack-Windows.ps1
```

### Finish hMailServer setup (required)

The installer **installs** hMailServer but you still must configure it:

- Open **hMailServer Administrator**
- Set the Administrator password to match `HmailAdminPass`
- Add your domain(s) under **Domains**
- Configure **TCP/IP ports** (SMTP/IMAP/POP3 + TLS settings)
- Configure **SSL certificates** and enable **STARTTLS/SSL** where appropriate

## URLs after install

- **Roundcube Webmail**: `http://<YourIP>/`
- **Admin panel**: `http://<YourIP>/admin/`
- **Account API**: `POST http://<YourIP>/api/v1/accounts`

## API usage

The installer writes `api/config.php` with an `api_key`. Use the `X-API-Key` header:

```bash
curl -X POST "http://<IP>/api/v1/accounts" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <API_KEY>" \
  -d '{"email":"user@example.com","password":"pass123"}'
```

## Making this a real internet mail server (DNS + deliverability checklist)

To reliably send/receive mail on the public internet, you typically need:

- **A record**: `mail.example.com` → your server IP
- **MX record**: `example.com` → `mail.example.com`
- **PTR / rDNS**: your server IP → `mail.example.com` (**critical** for deliverability)
- **SPF**: `v=spf1 mx -all` (or include your outbound relays)
- **DKIM**: publish DKIM TXT record(s) + sign outgoing mail (often requires an additional DKIM signer with hMailServer)
- **DMARC**: start with monitoring, e.g. `v=DMARC1; p=none; rua=mailto:dmarc@example.com`

Also check that your ISP/cloud provider **does not block outbound port 25** (many do).

## Troubleshooting

- **Admin/API shows “Unable to connect to hMailServer”**
  - hMailServer service is running
  - hMailServer Administrator password matches `HmailAdminPass`
  - COM from IIS requires **32-bit PHP (x86)** (the installer defaults to x86 for this reason)
  - If you see “Access denied” COM errors, you may need to grant DCOM permissions to the IIS app pool identity
- **Roundcube shows 403.14 (no default document)**
  - Ensure IIS includes `index.php` as a default document (the installer attempts to add this)
- **Roundcube temp/logs not writable**
  - Ensure NTFS permissions allow `IIS_IUSRS` modify access to `temp\` and `logs\`

## Security notes

- Change all placeholder secrets (`ChangeMe_*`) before exposing anything to the internet.
- Put the web UIs behind **HTTPS** (and consider restricting `/admin` + `/api` by IP).