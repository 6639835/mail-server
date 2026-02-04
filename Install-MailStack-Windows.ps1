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
  
    # Roundcube installed under IIS default site: http://<IP>/roundcube
    WebRoot      = "C:\inetpub\wwwroot"
    RoundcubeDir = "C:\inetpub\wwwroot\roundcube"
  
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
  
  # Common extensions for Roundcube
  Add-Content $phpIni "`r`nextension_dir=`"$($Config.PhpDir)\ext`""
  foreach ($ext in @("openssl","mbstring","intl","gd","curl","mysqli","pdo_mysql","zip","fileinfo")) {
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
  # 8) Output next steps
  # ---------------------------
  Write-Host ""
  Write-Host "==================== DONE ===================="
  Write-Host "Roundcube URL: http://<YourPublicIP>/roundcube"
  Write-Host "Next steps are in SETUP-WINDOWS.md:"
  Write-Host "1) Open hMailServer Administrator -> set admin password + choose DB + add domain/accounts"
  Write-Host "2) Enable SSL on IMAP/SMTP, open firewall ports, configure DNS"
  Write-Host "============================================="
  