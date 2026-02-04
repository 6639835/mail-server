<# ===========================================================
Windows Mail Stack Installer
- IIS + PHP (FastCGI)
- MariaDB (MSI silent with properties)
- Roundcube (download + config + DB init)
- hMailServer (silent install)

Run as Administrator.
=========================================================== #>

# ---------------------------
# 0) Configuration (modify here only)
# ---------------------------
$Config = @{
    # Your domain (for documentation; Roundcube login still uses email address)
    Domain = "example.com"
  
    # Roundcube installed as IIS site root: http://<IP>/
    WebRoot      = "C:\inetpub\wwwroot"
    RoundcubeDir = "C:\inetpub\wwwroot"

    # Roundcube connects to local IMAP/SMTP (provided by hMailServer after installation)
    ImapHost = "ssl://127.0.0.1:993"
    SmtpHost = "tls://127.0.0.1:587"
  
    # MariaDB
    MariaDbMsiUrl     = "https://mirrors.accretive-networks.net/mariadb///mariadb-12.1.2/winx64-packages/mariadb-12.1.2-winx64.msi"
    MariaDbService    = "MariaDB"
    MariaDbPort       = 3306
    MariaDbRootPass   = "ChangeMe_Strong_RootPass!"
    RoundcubeDBName   = "roundcube"
    RoundcubeDBUser   = "roundcube_user"
    RoundcubeDBPass   = "ChangeMe_Strong_RC_DBPass!"
  
    # Roundcube
    RoundcubeVersion  = "1.6.12"
    RoundcubeUrl      = "https://github.com/roundcube/roundcubemail/releases/download/1.6.12/roundcubemail-1.6.12-complete.tar.gz"
  
    # PHP (Windows NTS zip; you can also use your own internal mirror/version)
    PhpZipUrl = "https://windows.php.net/downloads/releases/php-8.2.14-nts-Win32-vs16-x64.zip"
    PhpDir    = "C:\PHP"
  
    # hMailServer
    HmailExeUrl = "https://www.hmailserver.com/files/hMailServer-5.6.8-B2574.exe"
    HmailInstallDir = "C:\Program Files (x86)\hMailServer"
    HmailAdminPass = "ChangeMe_HMailAdmin!"

    # Mail API (for programmatic account registration)
    ApiDir = "C:\inetpub\wwwroot\api"
  }
  
  # ---------------------------
  # 1) Administrator privilege check
  # ---------------------------
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator"
  }
  
  # ---------------------------
  # Utility function: Download
  # ---------------------------
  function Download-File($Url, $OutFile) {
    Write-Host "Downloading: $Url"
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
    if (-not (Test-Path $OutFile)) { throw "Download failed: $OutFile" }
  }
  
  # Utility function: Find mysql.exe under Program Files
  function Find-MySqlExe {
    $candidates = @(
      "C:\Program Files\MariaDB*\bin\mysql.exe",
      "C:\Program Files (x86)\MariaDB*\bin\mysql.exe"
    )
    foreach ($pat in $candidates) {
      $hit = Get-ChildItem -Path $pat -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
    return $null
  }
  
  # ---------------------------
  # 2) Install IIS (including FastCGI)
  # ---------------------------
  Write-Host "Installing IIS..."
  Install-WindowsFeature Web-Server, Web-Common-Http, Web-Default-Doc, Web-Static-Content, `
    Web-Http-Errors, Web-Http-Redirect, Web-Http-Logging, Web-Request-Monitor, `
    Web-Filtering, Web-App-Dev, Web-CGI, Web-Mgmt-Tools | Out-Null
  
  # ---------------------------
  # 3) Install PHP (zip) and configure FastCGI
  # ---------------------------
  Write-Host "Installing PHP..."
  New-Item -ItemType Directory -Force -Path $Config.PhpDir | Out-Null
  $phpZip = Join-Path $env:TEMP "php.zip"
  Download-File $Config.PhpZipUrl $phpZip
  Expand-Archive -Path $phpZip -DestinationPath $Config.PhpDir -Force
  
  $phpIniProd = Join-Path $Config.PhpDir "php.ini-production"
  $phpIni     = Join-Path $Config.PhpDir "php.ini"
  Copy-Item $phpIniProd $phpIni -Force
  
  # Common extensions for Roundcube + COM for hMailServer API
  Add-Content $phpIni "`r`nextension_dir=`"$($Config.PhpDir)\ext`""
  foreach ($ext in @("openssl","mbstring","intl","gd","curl","mysqli","pdo_mysql","zip","fileinfo","com_dotnet")) {
    Add-Content $phpIni "extension=$ext"
  }
  Add-Content $phpIni "date.timezone=Asia/Shanghai"
  
  Import-Module WebAdministration
  $phpCgi = Join-Path $Config.PhpDir "php-cgi.exe"
  
  # Register FastCGI application
  if (-not (Get-WebConfiguration "//system.webServer/fastCgi/application[@fullPath='$phpCgi']" -ErrorAction SilentlyContinue)) {
    Add-WebConfiguration -Filter "system.webServer/fastCgi" -PSPath "IIS:\" -Value @{fullPath=$phpCgi; arguments="";}
  }
  
  # Map .php to FastCGI
  New-WebHandler -Name "PHP_via_FastCGI" -Path "*.php" -Verb "*" -Modules "FastCgiModule" `
    -ScriptProcessor $phpCgi -ResourceType "Either" -ErrorAction SilentlyContinue | Out-Null
  
  iisreset | Out-Null
  
  # ---------------------------
  # 4) Install MariaDB (MSI silent + properties)
  #   - PASSWORD / SERVICENAME / PORT etc. are officially supported MSI properties
  # ---------------------------
  Write-Host "Installing MariaDB..."
  $mariadbMsi = Join-Path $env:TEMP "mariadb.msi"
  Download-File $Config.MariaDbMsiUrl $mariadbMsi
  
  $msiArgs = @(
    "/i `"$mariadbMsi`"",
    "/qn",
    "SERVICENAME=$($Config.MariaDbService)",
    "PASSWORD=$($Config.MariaDbRootPass)",
    "PORT=$($Config.MariaDbPort)"
  ) -join " "
  
  Start-Process msiexec.exe -ArgumentList $msiArgs -Wait
  
  Start-Sleep -Seconds 3
  
  # ---------------------------
  # 5) Install Roundcube (download + extract + generate config.inc.php)
  # ---------------------------
  Write-Host "Installing Roundcube..."
  New-Item -ItemType Directory -Force -Path $Config.RoundcubeDir | Out-Null
  
  $rcTgz = Join-Path $env:TEMP "roundcube.tar.gz"
  Download-File $Config.RoundcubeUrl $rcTgz
  
  # Windows built-in tar
  $tmpExtractRoot = Join-Path $env:TEMP "roundcube_extract"
  Remove-Item $tmpExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $tmpExtractRoot | Out-Null
  
  tar -xzf $rcTgz -C $tmpExtractRoot
  
  $extracted = Join-Path $tmpExtractRoot "roundcubemail-$($Config.RoundcubeVersion)"
  if (-not (Test-Path $extracted)) {
    throw "Roundcube extract directory not found: $extracted (please check if version number matches download package)"
  }
  
  # Deploy to IIS directory (overwrite)
  Remove-Item $Config.RoundcubeDir -Recurse -Force -ErrorAction SilentlyContinue
  Copy-Item $extracted $Config.RoundcubeDir -Recurse -Force
  
  # Generate Roundcube config (separate config: DB/IMAP/SMTP all here)
  $rcConfigDir = Join-Path $Config.RoundcubeDir "config"
  New-Item -ItemType Directory -Force -Path $rcConfigDir | Out-Null
  $rcConfig = Join-Path $rcConfigDir "config.inc.php"
  
  $desKey = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
  
  $configPhp = @"
  <?php
  \$config['db_dsnw'] = 'mysql://$($Config.RoundcubeDBUser):$($Config.RoundcubeDBPass)@localhost:$($Config.MariaDbPort)/$($Config.RoundcubeDBName)';
  \$config['default_host'] = '$($Config.ImapHost)';
  \$config['smtp_server']  = '$($Config.SmtpHost)';
  \$config['smtp_user']    = '%u';
  \$config['smtp_pass']    = '%p';
  \$config['product_name'] = 'Webmail';
  \$config['des_key'] = '$desKey';
  \$config['plugins'] = ['archive','zipdownload'];
  \$config['language'] = 'en_US';
  \$config['enable_installer'] = false;
  "@
  Set-Content -Path $rcConfig -Value $configPhp -Encoding UTF8
  
  # ---------------------------
  # 6) Initialize Roundcube database (create DB/user + import schema)
  # ---------------------------
  Write-Host "Initializing Roundcube database..."
  $mysqlExe = Find-MySqlExe
  if (-not $mysqlExe) { throw "mysql.exe not found (MariaDB installation may have failed or path differs)" }
  
  # Create DB + user
  $sql = @"
  CREATE DATABASE IF NOT EXISTS `$($Config.RoundcubeDBName)` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE USER IF NOT EXISTS '$($Config.RoundcubeDBUser)'@'localhost' IDENTIFIED BY '$($Config.RoundcubeDBPass)';
  GRANT ALL PRIVILEGES ON `$($Config.RoundcubeDBName)`.* TO '$($Config.RoundcubeDBUser)'@'localhost';
  FLUSH PRIVILEGES;
  "@
  $sqlFile = Join-Path $env:TEMP "roundcube_bootstrap.sql"
  Set-Content -Path $sqlFile -Value $sql -Encoding UTF8
  
  & $mysqlExe -uroot -p$($Config.MariaDbRootPass) -e "source $sqlFile"
  
  # Import Roundcube schema (MySQL/MariaDB)
  $schema = Join-Path $Config.RoundcubeDir "SQL\mysql.initial.sql"
  if (-not (Test-Path $schema)) { throw "Roundcube schema not found: $schema" }
  
  & $mysqlExe -uroot -p$($Config.MariaDbRootPass) $Config.RoundcubeDBName < $schema
  
  # ---------------------------
  # 7) Install hMailServer (silent)
  #   Inno Setup common silent parameters: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  # ---------------------------
  Write-Host "Installing hMailServer..."
  $hmailExe = Join-Path $env:TEMP "hmailserver.exe"
  Download-File $Config.HmailExeUrl $hmailExe
  
  Start-Process $hmailExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" -Wait
  
  # ---------------------------
  # 8) Deploy Mail API for account registration
  # ---------------------------
  Write-Host "Deploying Mail API..."
  
  # Create API directory structure
  New-Item -ItemType Directory -Force -Path $Config.ApiDir | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $Config.ApiDir "v1") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $Config.ApiDir "logs") | Out-Null
  
  # Grant IIS write access to logs directory
  $logsDir = Join-Path $Config.ApiDir "logs"
  $acl = Get-Acl $logsDir
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
  $acl.SetAccessRule($rule)
  Set-Acl $logsDir $acl
  
  # Generate API config with hMailServer admin password
  $apiConfig = @"
<?php
/**
 * hMailServer API Configuration
 * Generated by Install-MailStack-Windows.ps1
 */

declare(strict_types=1);

return [
    'hmailserver_admin_password' => '$($Config.HmailAdminPass)',
    'api_key' => '',
    'allowed_domains' => [],
    'rate_limit' => 0,
    'debug' => false,
    'log_enabled' => true,
    'log_file' => __DIR__ . '/logs/api.log',
];
"@
  Set-Content -Path (Join-Path $Config.ApiDir "config.php") -Value $apiConfig -Encoding UTF8
  
  # Deploy accounts API endpoint
  $accountsApi = @"
<?php
/**
 * hMailServer Account Management API
 * 
 * RESTful API endpoint for managing email accounts.
 * 
 * Endpoints:
 *   POST /api/v1/accounts - Create a new email account
 * 
 * Request Format (JSON):
 *   { "email": "user@example.com", "password": "securepassword" }
 * 
 * Response Format (JSON):
 *   Success: { "success": true, "message": "...", "data": {...} }
 *   Error:   { "success": false, "error": { "code": "...", "message": "..." } }
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

`$configPath = dirname(__DIR__) . '/config.php';
if (!file_exists(`$configPath)) {
    sendError('CONFIG_MISSING', 'Server configuration not found', 500);
}
`$config = require `$configPath;

function sendSuccess(string `$message, array `$data = []): void {
    http_response_code(200);
    echo json_encode(['success' => true, 'message' => `$message, 'data' => `$data], JSON_UNESCAPED_UNICODE);
    exit;
}

function sendError(string `$code, string `$message, int `$httpCode = 400): void {
    http_response_code(`$httpCode);
    echo json_encode(['success' => false, 'error' => ['code' => `$code, 'message' => `$message]], JSON_UNESCAPED_UNICODE);
    exit;
}

function writeLog(string `$level, string `$message, array `$context = []): void {
    global `$config;
    if (empty(`$config['log_enabled'])) return;
    `$logFile = `$config['log_file'] ?? __DIR__ . '/../logs/api.log';
    `$logDir = dirname(`$logFile);
    if (!is_dir(`$logDir)) @mkdir(`$logDir, 0755, true);
    `$timestamp = date('Y-m-d H:i:s');
    `$contextStr = `$context ? ' ' . json_encode(`$context, JSON_UNESCAPED_UNICODE) : '';
    @file_put_contents(`$logFile, "[{`$timestamp}] [{`$level}] {`$message}{`$contextStr}\n", FILE_APPEND | LOCK_EX);
}

function validateEmail(string `$email): bool {
    return filter_var(`$email, FILTER_VALIDATE_EMAIL) !== false;
}

function extractDomain(string `$email): string {
    `$parts = explode('@', `$email);
    return strtolower(`$parts[1] ?? '');
}

function authenticateRequest(array `$config): void {
    `$apiKey = `$config['api_key'] ?? '';
    if (empty(`$apiKey)) return;
    `$authHeader = `$_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+(.+)$/i', `$authHeader, `$matches)) {
        if (hash_equals(`$apiKey, `$matches[1])) return;
    }
    `$headerKey = `$_SERVER['HTTP_X_API_KEY'] ?? '';
    if (!empty(`$headerKey) && hash_equals(`$apiKey, `$headerKey)) return;
    sendError('UNAUTHORIZED', 'Invalid or missing API key', 401);
}

function connectHMailServer(string `$adminPassword): ?object {
    if (!class_exists('COM')) return null;
    try {
        `$app = new COM('hMailServer.Application');
        `$app->Authenticate('Administrator', `$adminPassword);
        return `$app;
    } catch (Exception `$e) {
        writeLog('ERROR', 'hMailServer connection failed', ['error' => `$e->getMessage()]);
        return null;
    }
}

function findDomain(object `$app, string `$domainName): ?object {
    try {
        `$domains = `$app->Domains;
        for (`$i = 0; `$i < `$domains->Count; `$i++) {
            `$domain = `$domains->Item(`$i);
            if (strtolower(`$domain->Name) === strtolower(`$domainName)) return `$domain;
        }
    } catch (Exception `$e) {
        writeLog('ERROR', 'Domain lookup failed', ['domain' => `$domainName, 'error' => `$e->getMessage()]);
    }
    return null;
}

function accountExists(object `$domain, string `$email): bool {
    try {
        `$accounts = `$domain->Accounts;
        for (`$i = 0; `$i < `$accounts->Count; `$i++) {
            if (strtolower(`$accounts->Item(`$i)->Address) === strtolower(`$email)) return true;
        }
    } catch (Exception `$e) {}
    return false;
}

function createAccount(object `$domain, string `$email, string `$password): bool {
    try {
        `$account = `$domain->Accounts->Add();
        `$account->Address = `$email;
        `$account->Password = `$password;
        `$account->Active = true;
        `$account->MaxSize = 0;
        `$account->Save();
        return true;
    } catch (Exception `$e) {
        writeLog('ERROR', 'Account creation failed', ['email' => `$email, 'error' => `$e->getMessage()]);
        return false;
    }
}

// Request handling
if (`$_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError('METHOD_NOT_ALLOWED', 'Only POST method is allowed', 405);
}

authenticateRequest(`$config);

`$rawInput = file_get_contents('php://input');
`$input = json_decode(`$rawInput, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    sendError('INVALID_JSON', 'Request body must be valid JSON', 400);
}

`$email = trim(`$input['email'] ?? '');
`$password = `$input['password'] ?? '';

if (empty(`$email)) sendError('EMAIL_REQUIRED', 'Email address is required', 400);
if (!validateEmail(`$email)) sendError('EMAIL_INVALID', 'Invalid email address format', 400);
if (empty(`$password)) sendError('PASSWORD_REQUIRED', 'Password is required', 400);
if (strlen(`$password) < 4) sendError('PASSWORD_WEAK', 'Password must be at least 4 characters', 400);

`$domain = extractDomain(`$email);
if (empty(`$domain)) sendError('DOMAIN_INVALID', 'Could not extract domain from email', 400);

`$allowedDomains = `$config['allowed_domains'] ?? [];
if (!empty(`$allowedDomains)) {
    `$normalizedAllowed = array_map('strtolower', `$allowedDomains);
    if (!in_array(strtolower(`$domain), `$normalizedAllowed, true)) {
        sendError('DOMAIN_NOT_ALLOWED', "Domain '{`$domain}' is not allowed", 403);
    }
}

writeLog('INFO', 'Account creation request', ['email' => `$email]);

if (!class_exists('COM')) {
    writeLog('ERROR', 'COM extension not available');
    sendError('SERVER_ERROR', 'Mail server integration not available', 500);
}

`$adminPassword = `$config['hmailserver_admin_password'] ?? '';
`$hmailApp = connectHMailServer(`$adminPassword);
if (`$hmailApp === null) sendError('SERVER_ERROR', 'Failed to connect to mail server', 500);

`$hmailDomain = findDomain(`$hmailApp, `$domain);
if (`$hmailDomain === null) sendError('DOMAIN_NOT_FOUND', "Domain '{`$domain}' is not configured on this server", 404);

if (accountExists(`$hmailDomain, `$email)) {
    writeLog('INFO', 'Account already exists', ['email' => `$email]);
    sendError('ACCOUNT_EXISTS', 'An account with this email address already exists', 409);
}

if (!createAccount(`$hmailDomain, `$email, `$password)) {
    sendError('CREATION_FAILED', 'Failed to create account', 500);
}

writeLog('INFO', 'Account created successfully', ['email' => `$email]);
sendSuccess('Account created successfully', ['email' => `$email, 'domain' => `$domain]);
"@
  Set-Content -Path (Join-Path $Config.ApiDir "v1\accounts.php") -Value $accountsApi -Encoding UTF8
  
  Write-Host "Mail API deployed to: $($Config.ApiDir)"
  
  # ---------------------------
  # 9) Output next steps
  # ---------------------------
  Write-Host ""
  Write-Host "==================== DONE ===================="
  Write-Host "Roundcube URL: http://<YourIP>/roundcube"
  Write-Host "Account API:   POST http://<YourIP>/api/v1/accounts"
  Write-Host ""
  Write-Host "Next steps:"
  Write-Host "1) Open hMailServer Administrator -> set admin password to: $($Config.HmailAdminPass)"
  Write-Host "2) In hMailServer Administrator -> add your domain(s) and enable needed protocols"
  Write-Host "3) (Optional) Enable SSL on IMAP/SMTP, open firewall ports, configure DNS"
  Write-Host ""
  Write-Host "API Usage (JSON):"
  Write-Host '  curl -X POST http://<IP>/api/v1/accounts -H "Content-Type: application/json" -d "{\"email\":\"user@example.com\",\"password\":\"pass123\"}"'
  Write-Host "============================================="
  