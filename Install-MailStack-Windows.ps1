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
    ImapHost = "127.0.0.1"
    SmtpHost = "127.0.0.1"
  
    # MariaDB
    MariaDbMsiUrl     = "https://mirrors.accretive-networks.net/mariadb///mariadb-12.1.2/winx64-packages/mariadb-12.1.2-winx64.msi"
    # Optional: if set, use this local MSI instead of downloading
    MariaDbMsiPath    = ""
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
    # IMPORTANT: hMailServer's COM API is 32-bit only, so PHP must be x86 for COM integration to work.
    PhpZipUrl = "https://windows.php.net/downloads/releases/php-8.2.30-nts-Win32-vs16-x86.zip"
    PhpDir    = "C:\PHP"
  
    # hMailServer
    HmailExeUrl = "https://www.hmailserver.com/files/hMailServer-5.6.8-B2574.exe"
    # Optional: if set, use this local EXE instead of downloading
    HmailExePath = ""
    HmailInstallDir = "C:\Program Files (x86)\hMailServer"
    HmailAdminPass = "ChangeMe_HMailAdmin!"

    # Mail API (for programmatic account registration)
    ApiDir = "C:\inetpub\wwwroot\api"
    ApiKey = ""  # leave empty to auto-generate a strong key

    # Admin Panel
    AdminDir = "C:\inetpub\wwwroot\admin"
    AdminUsername = "admin"
    AdminPassword = "ChangeMe_Admin123!"
  }
  
  # ---------------------------
  # 1) Administrator privilege check
  # ---------------------------
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator"
  }

  # Generate a strong API key if not provided (prevents unauthenticated account creation)
  if ([string]::IsNullOrWhiteSpace($Config.ApiKey)) {
    $Config.ApiKey = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))
  }
  
  # ---------------------------
  # Force TLS 1.2 for HTTPS downloads (required for modern servers)
  # ---------------------------
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

  # ---------------------------
  # Utility function: Download
  # ---------------------------
  function Download-File($Url, $OutFile) {
    Write-Host "Downloading: $Url"
    try {
      $iwrParams = @{
        Uri         = $Url
        OutFile     = $OutFile
        ErrorAction = 'Stop'
      }
      # -UseBasicParsing is removed in PowerShell 6+
      if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) {
        $iwrParams.UseBasicParsing = $true
      }
      Invoke-WebRequest @iwrParams
    } catch {
      Write-Host "Invoke-WebRequest failed, trying WebClient..." -ForegroundColor Yellow
      $webClient = New-Object System.Net.WebClient
      $webClient.DownloadFile($Url, $OutFile)
    }
    if (-not (Test-Path $OutFile)) { throw "Download failed: $OutFile" }
  }

  # Utility function: Write UTF-8 without BOM (prevents PHP "headers already sent" issues)
  function Write-TextFileUtf8NoBom([string]$Path, [string]$Content) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
  }

  # Utility function: Extract .tar.gz (works on Windows without built-in tar)
  function Extract-TarGz($TarGzPath, $DestDir) {
    Add-Type -AssemblyName System.IO.Compression
    
    # Step 1: Decompress .gz to .tar
    $tarPath = $TarGzPath -replace '\.gz$', ''
    $gzStream = [System.IO.File]::OpenRead($TarGzPath)
    $gzipStream = New-Object System.IO.Compression.GZipStream($gzStream, [System.IO.Compression.CompressionMode]::Decompress)
    $tarStream = [System.IO.File]::Create($tarPath)
    $gzipStream.CopyTo($tarStream)
    $tarStream.Close()
    $gzipStream.Close()
    $gzStream.Close()
    
    # Step 2: Extract .tar (simple TAR parser for POSIX/ustar format)
    $tarBytes = [System.IO.File]::ReadAllBytes($tarPath)
    $pos = 0
    while ($pos -lt $tarBytes.Length - 512) {
      # Read 512-byte header
      $header = $tarBytes[$pos..($pos + 511)]
      $pos += 512
      
      # Check for empty block (end of archive)
      $allZero = $true
      for ($i = 0; $i -lt 100; $i++) { if ($header[$i] -ne 0) { $allZero = $false; break } }
      if ($allZero) { break }
      
      # Extract filename (bytes 0-99)
      $nameBytes = $header[0..99]
      $nameEnd = [Array]::IndexOf($nameBytes, [byte]0)
      if ($nameEnd -lt 0) { $nameEnd = 100 }
      $name = [System.Text.Encoding]::UTF8.GetString($nameBytes, 0, $nameEnd)
      
      # Check for prefix (bytes 345-499) for long paths
      $prefixBytes = $header[345..499]
      $prefixEnd = [Array]::IndexOf($prefixBytes, [byte]0)
      if ($prefixEnd -lt 0) { $prefixEnd = 155 }
      $prefix = [System.Text.Encoding]::UTF8.GetString($prefixBytes, 0, $prefixEnd)
      if ($prefix) { $name = "$prefix/$name" }
      
      # Extract size (bytes 124-135, octal)
      $sizeStr = [System.Text.Encoding]::ASCII.GetString($header[124..135]).Trim([char]0, ' ')
      $size = 0
      if ($sizeStr) { $size = [Convert]::ToInt64($sizeStr, 8) }
      
      # Extract type (byte 156): '0' or null = file, '5' = directory
      $type = [char]$header[156]
      
      # Build full path
      $fullPath = Join-Path $DestDir $name.TrimStart('/')
      
      if ($type -eq '5' -or $name.EndsWith('/')) {
        # Directory
        New-Item -ItemType Directory -Force -Path $fullPath -ErrorAction SilentlyContinue | Out-Null
      }
      elseif ($type -eq '0' -or $type -eq [char]0) {
        # Regular file
        $parentDir = Split-Path $fullPath -Parent
        if ($parentDir -and -not (Test-Path $parentDir)) {
          New-Item -ItemType Directory -Force -Path $parentDir | Out-Null
        }
        if ($size -gt 0) {
          $fileBytes = $tarBytes[$pos..($pos + $size - 1)]
          [System.IO.File]::WriteAllBytes($fullPath, $fileBytes)
        } else {
          [System.IO.File]::WriteAllBytes($fullPath, @())
        }
      }
      
      # Move to next header (size rounded up to 512-byte block)
      $blocks = [Math]::Ceiling($size / 512)
      $pos += $blocks * 512
    }
    
    # Cleanup temp .tar file
    Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
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
  Add-Content -Path $phpIni -Value "`r`nextension_dir=`"$($Config.PhpDir)\ext`"" -Encoding ASCII
  foreach ($ext in @("mbstring","intl","gd","curl","mysqli","pdo_mysql","zip","fileinfo","exif","openssl","sockets","com_dotnet")) {
    Add-Content -Path $phpIni -Value "extension=$ext" -Encoding ASCII
  }
  Add-Content -Path $phpIni -Value "date.timezone=Asia/Shanghai" -Encoding ASCII
  Add-Content -Path $phpIni -Value "com.allow_dcom = true" -Encoding ASCII
  Add-Content -Path $phpIni -Value "com.autoregister_typelib = true" -Encoding ASCII
  
  Import-Module WebAdministration
  $phpCgi = Join-Path $Config.PhpDir "php-cgi.exe"
  
  # Register FastCGI application
  if (-not (Get-WebConfiguration "//system.webServer/fastCgi/application[@fullPath='$phpCgi']" -ErrorAction SilentlyContinue)) {
    Add-WebConfiguration -Filter "system.webServer/fastCgi" -PSPath "IIS:\" -Value @{fullPath=$phpCgi; arguments="";}
  }
  
  # Map .php to FastCGI
  New-WebHandler -Name "PHP_via_FastCGI" -Path "*.php" -Verb "*" -Modules "FastCgiModule" `
    -ScriptProcessor $phpCgi -ResourceType "Either" -ErrorAction SilentlyContinue | Out-Null

  # Ensure index.php is a default document (so http://<IP>/ loads Roundcube)
  Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/defaultDocument/files" -Name "." -Value @{value="index.php"} -ErrorAction SilentlyContinue | Out-Null

  # Roundcube Elastic skin fonts (IIS may not include these MIME types by default)
  Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/staticContent" -Name "." -Value @{fileExtension=".woff"; mimeType="application/font-woff"} -ErrorAction SilentlyContinue | Out-Null
  Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/staticContent" -Name "." -Value @{fileExtension=".woff2"; mimeType="application/font-woff2"} -ErrorAction SilentlyContinue | Out-Null
  
  iisreset | Out-Null
  
  # ---------------------------
  # 4) Install MariaDB (MSI silent + properties)
  #   - PASSWORD / SERVICENAME / PORT etc. are officially supported MSI properties
  # ---------------------------
  Write-Host "Installing MariaDB..."
  $mariadbMsiName = "mariadb-12.1.2-winx64.msi"
  $mariadbMsi = $null

  if (-not [string]::IsNullOrWhiteSpace($Config.MariaDbMsiPath) -and (Test-Path $Config.MariaDbMsiPath)) {
    $mariadbMsi = $Config.MariaDbMsiPath
    Write-Host "  Using local MariaDB MSI: $mariadbMsi"
  } else {
    $localMsi = Join-Path $PSScriptRoot $mariadbMsiName
    if (Test-Path $localMsi) {
      $mariadbMsi = $localMsi
      Write-Host "  Using MariaDB MSI next to script: $mariadbMsi"
    } else {
      $mariadbMsi = Join-Path $env:TEMP $mariadbMsiName
      Download-File $Config.MariaDbMsiUrl $mariadbMsi
    }
  }
  
  $msiArgs = @(
    "/i `"$mariadbMsi`"",
    "/qn",
    "SERVICENAME=$($Config.MariaDbService)",
    "PASSWORD=$($Config.MariaDbRootPass)",
    "PORT=$($Config.MariaDbPort)"
  ) -join " "
  
  $mariaInstall = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
  if ($mariaInstall.ExitCode -ne 0) {
    throw "MariaDB installer failed (exit code: $($mariaInstall.ExitCode))"
  }
  
  Start-Sleep -Seconds 3
  
  # ---------------------------
  # 5) Install Roundcube (download + extract + generate config.inc.php)
  # ---------------------------
  Write-Host "Installing Roundcube..."
  New-Item -ItemType Directory -Force -Path $Config.RoundcubeDir | Out-Null
  
  $rcTgz = Join-Path $env:TEMP "roundcube.tar.gz"
  Download-File $Config.RoundcubeUrl $rcTgz
  
  # Extract .tar.gz (using PowerShell function for compatibility with older Windows)
  $tmpExtractRoot = Join-Path $env:TEMP "roundcube_extract"
  Remove-Item $tmpExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $tmpExtractRoot | Out-Null
  
  Write-Host "Extracting Roundcube (this may take a moment)..."
  Extract-TarGz $rcTgz $tmpExtractRoot
  
  $extracted = Join-Path $tmpExtractRoot "roundcubemail-$($Config.RoundcubeVersion)"
  if (-not (Test-Path $extracted)) {
    throw "Roundcube extract directory not found: $extracted (please check if version number matches download package)"
  }
  
  # Deploy to IIS directory (overwrite)
  Remove-Item $Config.RoundcubeDir -Recurse -Force -ErrorAction SilentlyContinue
  Copy-Item $extracted $Config.RoundcubeDir -Recurse -Force

  # Roundcube requires temp/ and logs/ to be writable by the web server user (IIS)
  foreach ($dirName in @("temp", "logs")) {
    $dirPath = Join-Path $Config.RoundcubeDir $dirName
    New-Item -ItemType Directory -Force -Path $dirPath | Out-Null
    $acl = Get-Acl $dirPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $dirPath $acl
  }

  # IIS doesn't process Roundcube's .htaccess, so block HTTP access to private folders
  $denyWebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <authorization>
        <deny users="*" />
      </authorization>
    </security>
  </system.webServer>
</configuration>
"@

  foreach ($subDir in @("config", "temp", "logs", "SQL")) {
    $dir = Join-Path $Config.RoundcubeDir $subDir
    if (Test-Path $dir) {
      Write-TextFileUtf8NoBom (Join-Path $dir "web.config") $denyWebConfig
    }
  }
  
  # Generate Roundcube config (separate config: DB/IMAP/SMTP all here)
  $rcConfigDir = Join-Path $Config.RoundcubeDir "config"
  New-Item -ItemType Directory -Force -Path $rcConfigDir | Out-Null
  $rcConfig = Join-Path $rcConfigDir "config.inc.php"
  
  $desKey = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
  
  $configPhp = @"
<?php
`$config['db_dsnw'] = 'mysql://$($Config.RoundcubeDBUser):$($Config.RoundcubeDBPass)@localhost:$($Config.MariaDbPort)/$($Config.RoundcubeDBName)';
`$config['default_host'] = '$($Config.ImapHost)';
`$config['smtp_server']  = '$($Config.SmtpHost)';
`$config['smtp_user']    = '%u';
`$config['smtp_pass']    = '%p';
`$config['product_name'] = 'Webmail';
`$config['des_key'] = '$desKey';
`$config['plugins'] = ['archive','zipdownload'];
`$config['language'] = 'en_US';
`$config['log_dir']  = __DIR__ . '/../logs';
`$config['temp_dir'] = __DIR__ . '/../temp';
`$config['enable_installer'] = false;
"@
  Write-TextFileUtf8NoBom $rcConfig $configPhp

  # Defense-in-depth: remove installer directory entirely
  Remove-Item (Join-Path $Config.RoundcubeDir "installer") -Recurse -Force -ErrorAction SilentlyContinue
  
  # ---------------------------
  # 6) Initialize Roundcube database (create DB/user + import schema)
  # ---------------------------
  Write-Host "Initializing Roundcube database..."

  # Ensure MariaDB service is running before connecting
  $mariaSvc = Get-Service -Name $Config.MariaDbService -ErrorAction SilentlyContinue
  if ($mariaSvc -and $mariaSvc.Status -ne "Running") {
    Write-Host "  Starting MariaDB service..."
    Start-Service -Name $Config.MariaDbService -ErrorAction Stop
    $mariaSvc.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
  }

  $mysqlExe = Find-MySqlExe
  if (-not $mysqlExe) { throw "mysql.exe not found (MariaDB installation may have failed or path differs)" }
  
  function Escape-MySqlString([string]$value) {
    if ($null -eq $value) { return '' }
    return $value.Replace('\', '\\').Replace("'", "''")
  }

  function Quote-MySqlIdentifier([string]$value) {
    if ($null -eq $value) { return '``' }
    return ('`' + $value.Replace('`', '``') + '`')
  }

  $dbName = $Config.RoundcubeDBName
  $dbNameQuoted = Quote-MySqlIdentifier $dbName
  $dbUserEsc = Escape-MySqlString $Config.RoundcubeDBUser
  $dbPassEsc = Escape-MySqlString $Config.RoundcubeDBPass

  # Create DB + user (no temp SQL files; avoids UTF-8 BOM and quoting issues)
  $bootstrapSql = @"
CREATE DATABASE IF NOT EXISTS $dbNameQuoted DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$dbUserEsc'@'localhost' IDENTIFIED BY '$dbPassEsc';
GRANT ALL PRIVILEGES ON $dbNameQuoted.* TO '$dbUserEsc'@'localhost';
FLUSH PRIVILEGES;
"@

  $mysqlRootArgs = @(
    "-uroot",
    "-p$($Config.MariaDbRootPass)",
    "-h", "127.0.0.1",
    "-P", "$($Config.MariaDbPort)"
  )

  & $mysqlExe @mysqlRootArgs -e $bootstrapSql
  if ($LASTEXITCODE -ne 0) { throw "Roundcube DB bootstrap failed (mysql exit code: $LASTEXITCODE)" }
  
  # Import Roundcube schema (MySQL/MariaDB)
  $schema = Join-Path $Config.RoundcubeDir "SQL\mysql.initial.sql"
  if (-not (Test-Path $schema)) { throw "Roundcube schema not found: $schema" }

  $schemaPath = $schema.Replace('\', '/')
  $sourceStmt = "source `"$schemaPath`""
  & $mysqlExe @mysqlRootArgs $dbName -e $sourceStmt
  if ($LASTEXITCODE -ne 0) { throw "Roundcube schema import failed (mysql exit code: $LASTEXITCODE)" }
  
  # ---------------------------
  # 7) Install hMailServer (silent)
  #   Inno Setup common silent parameters: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  # ---------------------------
  $hmailServerExe = Join-Path $Config.HmailInstallDir "Bin\hMailServer.exe"
  if (Test-Path $hmailServerExe) {
    Write-Host "hMailServer already installed, skipping..."
  } else {
    Write-Host "Installing hMailServer..."
    $hmailInstallerName = "hMailServer-5.6.8-B2574.exe"
    $hmailExe = $null
    
    if (-not [string]::IsNullOrWhiteSpace($Config.HmailExePath) -and (Test-Path $Config.HmailExePath)) {
      $hmailExe = $Config.HmailExePath
      Write-Host "  Using local hMailServer installer: $hmailExe"
    } else {
      $localHmail = Join-Path $PSScriptRoot $hmailInstallerName
      if (Test-Path $localHmail) {
        $hmailExe = $localHmail
        Write-Host "  Using hMailServer installer next to script: $hmailExe"
      } else {
        $hmailExe = Join-Path $env:TEMP $hmailInstallerName
        # Download hMailServer installer
        Download-File $Config.HmailExeUrl $hmailExe
      }
    }
    
    # Run silent installation
    Write-Host "  Running hMailServer installer (this may take a few minutes)..."
    $installProcess = Start-Process $hmailExe -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" -Wait -PassThru
    
    # Check installation result
    if ($installProcess.ExitCode -ne 0) {
      Write-Host "  WARNING: hMailServer installer returned exit code: $($installProcess.ExitCode)" -ForegroundColor Yellow
    }
    
    # Verify installation
    Start-Sleep -Seconds 3
    if (Test-Path $hmailServerExe) {
      Write-Host "  hMailServer installed successfully to: $($Config.HmailInstallDir)" -ForegroundColor Green
    } else {
      Write-Host "  WARNING: hMailServer installation may have failed. Please check manually." -ForegroundColor Yellow
      Write-Host "  Expected path: $hmailServerExe" -ForegroundColor Yellow
    }
    
    # Clean up installer (only if we downloaded it to TEMP)
    if ($hmailExe -like (Join-Path $env:TEMP '*')) {
      Remove-Item $hmailExe -ErrorAction SilentlyContinue
    }
  }
  
  # Ensure hMailServer service is running
  $hmailService = Get-Service -Name "hMailServer" -ErrorAction SilentlyContinue
  if ($hmailService) {
    if ($hmailService.Status -ne "Running") {
      Write-Host "  Starting hMailServer service..."
      Start-Service -Name "hMailServer" -ErrorAction SilentlyContinue
    }
    Write-Host "  hMailServer service status: $($hmailService.Status)"
  } else {
    Write-Host "  WARNING: hMailServer service not found. You may need to configure it manually." -ForegroundColor Yellow
  }
  
  # ---------------------------
  # 8) Deploy Mail API for account registration
  # ---------------------------
  Write-Host "Deploying Mail API..."
  
  # Create API directory structure
  if (-not (Test-Path $Config.ApiDir)) {
    New-Item -ItemType Directory -Force -Path $Config.ApiDir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $($Config.ApiDir)"
  }
  $apiV1Dir = Join-Path $Config.ApiDir "v1"
  if (-not (Test-Path $apiV1Dir)) {
    New-Item -ItemType Directory -Force -Path $apiV1Dir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $apiV1Dir"
  }
  $apiLogsDir = Join-Path $Config.ApiDir "logs"
  if (-not (Test-Path $apiLogsDir)) {
    New-Item -ItemType Directory -Force -Path $apiLogsDir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $apiLogsDir"
  }
  
  # Grant IIS write access to logs directory
  $acl = Get-Acl $apiLogsDir
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
  $acl.SetAccessRule($rule)
  Set-Acl $apiLogsDir $acl
  
  # Copy API PHP files from the script's directory
  $scriptDir = $PSScriptRoot
  $sourceApiDir = Join-Path $scriptDir "api"
  
  if (Test-Path $sourceApiDir) {
    Write-Host "  Copying API files from: $sourceApiDir"
    
    # Copy all files except config.php (we generate that with correct credentials)
    Get-ChildItem -Path $sourceApiDir -Recurse | ForEach-Object {
      $relativePath = $_.FullName.Substring($sourceApiDir.Length + 1)
      $destPath = Join-Path $Config.ApiDir $relativePath
      
      if ($_.PSIsContainer) {
        # Create directory if it doesn't exist
        if (-not (Test-Path $destPath)) {
          New-Item -ItemType Directory -Force -Path $destPath | Out-Null
        }
      } else {
        # Skip config.php - we generate it with correct credentials
        if ($_.Name -ne "config.php") {
          Copy-Item -Path $_.FullName -Destination $destPath -Force
        }
      }
    }
    Write-Host "  API files copied successfully" -ForegroundColor Green
  } else {
    Write-Host "  WARNING: API source folder not found at: $sourceApiDir" -ForegroundColor Yellow
    Write-Host "  Please ensure the 'api' folder is in the same directory as this script."
  }
  
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
    'api_key' => '$($Config.ApiKey)',
    'allowed_domains' => [],
    'rate_limit' => 0,
    'debug' => false,
    'log_enabled' => true,
    'log_file' => __DIR__ . '/logs/api.log',
];
"@
  Write-TextFileUtf8NoBom (Join-Path $Config.ApiDir "config.php") $apiConfig
  
  Write-Host "Mail API deployed to: $($Config.ApiDir)"

  # ---------------------------
  # 9) Deploy Admin Panel
  # ---------------------------
  Write-Host "Deploying Admin Panel..."
  
  # Create admin directory structure
  if (-not (Test-Path $Config.AdminDir)) {
    New-Item -ItemType Directory -Force -Path $Config.AdminDir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $($Config.AdminDir)"
  }
  $adminIncludesDir = Join-Path $Config.AdminDir "includes"
  if (-not (Test-Path $adminIncludesDir)) {
    New-Item -ItemType Directory -Force -Path $adminIncludesDir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $adminIncludesDir"
  }
  $adminLogsDir = Join-Path $Config.AdminDir "logs"
  if (-not (Test-Path $adminLogsDir)) {
    New-Item -ItemType Directory -Force -Path $adminLogsDir -ErrorAction Stop | Out-Null
    Write-Host "  Created: $adminLogsDir"
  }
  
  # Grant IIS write access to logs directory
  $acl = Get-Acl $adminLogsDir
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
  $acl.SetAccessRule($rule)
  Set-Acl $adminLogsDir $acl
  
  # Copy admin panel PHP files from the script's directory
  $scriptDir = $PSScriptRoot
  $sourceAdminDir = Join-Path $scriptDir "admin"
  
  if (Test-Path $sourceAdminDir) {
    Write-Host "  Copying admin panel files from: $sourceAdminDir"
    
    # Copy all files except config.php (we generate that with correct credentials)
    Get-ChildItem -Path $sourceAdminDir -Recurse | ForEach-Object {
      $relativePath = $_.FullName.Substring($sourceAdminDir.Length + 1)
      $destPath = Join-Path $Config.AdminDir $relativePath
      
      if ($_.PSIsContainer) {
        # Create directory if it doesn't exist
        if (-not (Test-Path $destPath)) {
          New-Item -ItemType Directory -Force -Path $destPath | Out-Null
        }
      } else {
        # Skip config.php - we generate it with correct credentials
        if ($_.Name -ne "config.php") {
          Copy-Item -Path $_.FullName -Destination $destPath -Force
        }
      }
    }
    Write-Host "  Admin panel files copied successfully" -ForegroundColor Green
  } else {
    Write-Host "  WARNING: Admin source folder not found at: $sourceAdminDir" -ForegroundColor Yellow
    Write-Host "  Please ensure the 'admin' folder is in the same directory as this script."
  }
  
  # Generate config file with correct credentials
  $adminConfigPhp = @"
<?php
/**
 * Admin Panel Configuration
 * Generated by Install-MailStack-Windows.ps1
 */
declare(strict_types=1);

return [
    'admin_username' => '$($Config.AdminUsername)',
    'admin_password' => '$($Config.AdminPassword)',
    'hmailserver_admin_password' => '$($Config.HmailAdminPass)',
    'session_name' => 'MAILSERVER_ADMIN',
    'session_lifetime' => 3600,
    'app_name' => 'Mail Server Admin',
    'items_per_page' => 25,
    'max_login_attempts' => 5,
    'lockout_duration' => 900,
    'max_bulk_accounts' => 1000,
    'default_bulk_count' => 10,
    'min_password_length' => 4,
    'log_enabled' => true,
    'log_file' => __DIR__ . '/logs/admin.log',
];
"@
  Write-TextFileUtf8NoBom (Join-Path $Config.AdminDir "config.php") $adminConfigPhp
  
  Write-Host "Admin Panel deployed to: $($Config.AdminDir)"
  
  # ---------------------------
  # 10) Output next steps
  # ---------------------------
  Write-Host ""
  Write-Host "==================== INSTALLATION COMPLETE ===================="
  Write-Host ""
  Write-Host "URLs:"
  Write-Host "  Roundcube Webmail: http://<YourIP>/"
  Write-Host "  Admin Panel:       http://<YourIP>/admin/"
  Write-Host "  Account API:       POST http://<YourIP>/api/v1/accounts"
  Write-Host ""
  Write-Host "Admin Panel Credentials:"
  Write-Host "  Username: $($Config.AdminUsername)"
  Write-Host "  Password: $($Config.AdminPassword)"
  Write-Host ""
  Write-Host "hMailServer Configuration (REQUIRED):"
  Write-Host "  1) Open hMailServer Administrator (Start Menu -> hMailServer)"
  Write-Host "  2) Connect and set admin password to: $($Config.HmailAdminPass)"
  Write-Host "  3) Add your domain(s) under 'Domains'"
  Write-Host "  4) Enable SMTP, IMAP, POP3 protocols as needed"
  Write-Host ""
  Write-Host "Optional:"
  Write-Host "  - Open firewall ports (25, 110, 143, 587, 993, 995)"
  Write-Host "  - Configure DNS MX records for your domain"
  Write-Host ""
  Write-Host "API Usage (JSON):"
  Write-Host "  X-API-Key: $($Config.ApiKey)"
  Write-Host '  curl -X POST http://<IP>/api/v1/accounts -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" -d "{\"email\":\"user@example.com\",\"password\":\"pass123\"}"'
  Write-Host "=============================================================="
  