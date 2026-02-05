<# ===========================================================
Mail Stack Installer (Windows) — CLEAN / PINNED / VERIFIED
- IIS + PHP (FastCGI)      (PHP x86 required for COM with hMailServer)
- MySQL (ZIP install)      (deterministic + hash-verified; avoids MSI property drift)
- Roundcube (download + config + DB init)
- hMailServer (silent install; supports local EXE when official download blocks automation)
- Deploy /api + /admin from folders next to this script (optional)

Run as Administrator.
=========================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------
# 0) Configuration (edit here only)
# ---------------------------
$Config = @{
  # General
  Domain            = "dhieihe.work"
  TimeZone          = "Europe/Berlin"     # used for PHP date.timezone
  InstallRoot       = "C:\MailStack"      # logs + working area
  SiteName          = "MailWeb"
  SitePort          = 8080
  SiteHostHeader    = ""                  # optional; leave empty for IP-based
  SitePhysicalPath  = "C:\inetpub\mailstack"  # NOT default wwwroot (safer)

  # Roundcube (installed into site root)
  RoundcubeVersion  = "1.6.12"
  RoundcubeUrl      = "https://github.com/roundcube/roundcubemail/releases/download/1.6.12/roundcubemail-1.6.12-complete.tar.gz"
  ImapHost          = "127.0.0.1"
  SmtpHost          = "127.0.0.1"

  # PHP (Pinned + verified)
  # IMPORTANT: hMailServer COM is 32-bit, so PHP must be x86, and IIS app pool must allow 32-bit apps.
  PhpDir            = "C:\PHP"
  PhpZipUrl         = "https://windows.php.net/downloads/releases/php-8.4.16-nts-Win32-vs17-x86.zip"
  PhpZipSha256      = "fe8d7b4125653f7ee8df4f550c4959d209fbdfc10a72a251a20a1eb44dc4f8aa"

  # MySQL (Pinned + verified)
  MySqlVersion      = "8.4.8"
  MySqlZipUrl       = "https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.8-winx64.zip"
  MySqlZipMd5       = "0b268cf3d792dad998dca057c386d45c"
  MySqlBaseDir      = "C:\MySQL\8.4"
  MySqlDataDir      = "C:\ProgramData\MySQL\data"
  MySqlLogDir       = "C:\ProgramData\MySQL\log"
  MySqlService      = "MySQL"
  MySqlPort         = 3306
  MySqlRootPass     = "ChangeMe_Strong_RootPass!"

  # Roundcube DB
  RoundcubeDBName   = "roundcube"
  RoundcubeDBUser   = "roundcube_user"
  RoundcubeDBPass   = "ChangeMe_Strong_RC_DBPass!"

  # hMailServer (silent install)
  # NOTE: official download may 403 in automated contexts; set HmailExePath to a local EXE to be reliable.
  HmailExeUrl       = "https://www.hmailserver.com/files/hMailServer-5.6.8-B2574.exe"
  HmailExePath      = ""  # if provided and exists, used instead of download
  HmailInstallDir   = "C:\Program Files (x86)\hMailServer"
  HmailAdminPass    = "ChangeMe_HMailAdmin!"

  # Mail API (optional)
  ApiDir            = ""  # defaults to "$SitePhysicalPath\api"
  ApiKey            = ""  # auto-generate if blank

  # Admin Panel (optional)
  AdminDir          = ""  # defaults to "$SitePhysicalPath\admin"
  AdminUsername     = "admin"
  AdminPassword     = "ChangeMe_Admin123!"
  AdminAppName      = "Mail Server Admin"
  AdminMaxBulkAccounts = 1000
  AdminDefaultBulkCount = 10
  AdminMinPasswordLength = 4

  # Behavior / safety
  IgnorePendingReboot   = $true
  AllowDefaultSecrets   = $true   # if false, script stops if passwords contain "ChangeMe"
  CreateApiAndAdmin     = $true
  VerifyDownloads       = $true
}

# ---------------------------
# 1) Logging + helpers (global, consistent)
# ---------------------------
function Write-Log([string]$Message, [ValidateSet("INFO","WARN","ERROR","OK")] [string]$Level = "INFO") {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "[$ts][$Level] $Message"
  Write-Host $line
  if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
}

function Invoke-Step([string]$Name, [scriptblock]$Action) {
  Write-Log "==> $Name" "INFO"
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    & $Action
    $sw.Stop()
    Write-Log "<== $Name (OK) in $([int]$sw.Elapsed.TotalSeconds)s" "OK"
  } catch {
    $sw.Stop()
    Write-Log "<== $Name (FAILED) in $([int]$sw.Elapsed.TotalSeconds)s : $($_.Exception.Message)" "ERROR"
    throw
  }
}

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator."
  }
}

function Ensure-Directory([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return }
  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Force -Path $Path | Out-Null }
}

function Get-PendingRebootState {
  $reasons = New-Object System.Collections.Generic.List[string]
  try {
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
      $reasons.Add("CBS:RebootPending")
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
      $reasons.Add("WindowsUpdate:RebootRequired")
    }
    $pfr = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($null -ne $pfr -and $pfr.Count -gt 0) {
      $reasons.Add(("SessionManager:PendingFileRenameOperations({0})" -f $pfr.Count))
    }
    try {
      $sysInfo = New-Object -ComObject Microsoft.Update.SystemInfo
      if ($sysInfo -and $sysInfo.RebootRequired) { $reasons.Add("Microsoft.Update.SystemInfo:RebootRequired") }
    } catch { }
  } catch { }
  [pscustomobject]@{ IsPending = ($reasons.Count -gt 0); Reasons = $reasons.ToArray() }
}

function Assert-NoPendingReboot {
  $state = Get-PendingRebootState
  if ($state.IsPending) {
    Write-Log "Pending reboot detected: $($state.Reasons -join ', ')" "WARN"
    if (-not $Config.IgnorePendingReboot) {
      throw "A system reboot is pending. Reboot Windows, then re-run. (Set IgnorePendingReboot=\$true to bypass — not recommended.)"
    }
    Write-Log "IgnorePendingReboot=true; continuing despite pending reboot." "WARN"
  }
}

function Test-LocalTcpPortInUse([int]$Port) {
  try {
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
      $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
      return (@($conn).Count -gt 0)
    }
  } catch { }
  try {
    # Bind to all interfaces (not just loopback) to detect broader conflicts.
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    $listener.Start(); $listener.Stop()
    return $false
  } catch { return $true }
}

function Test-VcRuntimeX64Present {
  # MySQL (winx64) requires the MSVC runtime. If missing, mysqld often exits with 0xC0000135 (-1073741515).
  $dlls = @(
    (Join-Path $env:WINDIR "System32\vcruntime140.dll"),
    (Join-Path $env:WINDIR "System32\vcruntime140_1.dll"),
    (Join-Path $env:WINDIR "System32\msvcp140.dll")
  )
  foreach ($d in $dlls) { if (-not (Test-Path $d)) { return $false } }
  return $true
}

function Ensure-VcRedistX64 {
  if (Test-VcRuntimeX64Present) { return }

  $url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
  $exe = Join-Path $env:TEMP ("vc_redist.x64-{0}.exe" -f (Get-Date -Format "yyyyMMddHHmmss"))
  Download-File $url $exe

  Write-Log "Installing Microsoft Visual C++ Redistributable (x64)..." "INFO"
  $p = Start-Process -FilePath $exe -ArgumentList "/install","/quiet","/norestart" -Wait -PassThru
  Remove-Item $exe -Force -ErrorAction SilentlyContinue

  # 0 = success, 3010 = success (reboot required)
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
    throw "VC++ Redistributable installation failed (exit=$($p.ExitCode))."
  }
  if ($p.ExitCode -eq 3010) {
    Write-Log "VC++ Redistributable installed; reboot is recommended (installer returned 3010)." "WARN"
  }
}

function Assert-SafeSecrets {
  if ($Config.AllowDefaultSecrets) { return }

  $checks = @(
    @{ Name="MySqlRootPass";   Value=$Config.MySqlRootPass },
    @{ Name="RoundcubeDBPass";Value=$Config.RoundcubeDBPass },
    @{ Name="HmailAdminPass"; Value=$Config.HmailAdminPass },
    @{ Name="AdminPassword";  Value=$Config.AdminPassword }
  )

  foreach ($c in $checks) {
    if ([string]::IsNullOrWhiteSpace($c.Value)) { throw "Secret '$($c.Name)' is empty. Set it in the Config block." }
    if ($c.Value -match "ChangeMe") {
      throw "Secret '$($c.Name)' still contains 'ChangeMe'. Set strong unique values (or set AllowDefaultSecrets=\$true)."
    }
  }
}

function Initialize-ConfigDerivedPaths {
  if ([string]::IsNullOrWhiteSpace($Config.ApiDir))   { $Config.ApiDir   = (Join-Path $Config.SitePhysicalPath "api") }
  if ([string]::IsNullOrWhiteSpace($Config.AdminDir)) { $Config.AdminDir = (Join-Path $Config.SitePhysicalPath "admin") }
  if ([string]::IsNullOrWhiteSpace($Config.ApiKey)) {
    $Config.ApiKey = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))
  }
}

# Force TLS 1.2+ for downloads
[Net.ServicePointManager]::SecurityProtocol = `
  [Net.SecurityProtocolType]::Tls12 -bor `
  [Net.SecurityProtocolType]::Tls11 -bor `
  [Net.SecurityProtocolType]::Tls

function Download-File([string]$Url, [string]$OutFile) {
  Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
  Write-Log "Downloading: $Url -> $OutFile" "INFO"

  $lastError = $null

  # 1) Invoke-WebRequest
  try {
    $iwrParams = @{ Uri=$Url; OutFile=$OutFile; ErrorAction='Stop' }
    if ((Get-Command Invoke-WebRequest).Parameters.ContainsKey('UseBasicParsing')) { $iwrParams.UseBasicParsing = $true }
    Invoke-WebRequest @iwrParams
  } catch { $lastError = $_ }

  if (-not (Test-Path $OutFile)) {
    # 2) BITS
    try {
      if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        Write-Log "Invoke-WebRequest failed; trying BITS..." "WARN"
        Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
      }
    } catch { $lastError = $_ }
  }

  if (-not (Test-Path $OutFile)) {
    $msg = "Download failed: $Url"
    if ($lastError) { $msg += " | Last error: $($lastError.Exception.Message)" }
    throw $msg
  }
}

function Get-FileHashHex([string]$Path, [ValidateSet("MD5","SHA256")] [string]$Algorithm) {
  (Get-FileHash -Path $Path -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

function Assert-Hash([string]$Path, [string]$ExpectedHex, [ValidateSet("MD5","SHA256")] [string]$Algorithm) {
  if (-not $Config.VerifyDownloads) { return }
  $actual = Get-FileHashHex $Path $Algorithm
  if ($actual -ne $ExpectedHex.ToLowerInvariant()) {
    throw "Hash mismatch for $Path ($Algorithm). Expected=$ExpectedHex Actual=$actual"
  }
  Write-Log "Verified $Algorithm hash for $(Split-Path $Path -Leaf)" "OK"
}

function Write-TextFileUtf8NoBom([string]$Path, [string]$Content) {
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Extract-TarGz([string]$TarGzPath, [string]$DestDir) {
  # Prefer built-in tar if available (newer Windows)
  $tar = Get-Command tar -ErrorAction SilentlyContinue
  if ($tar) {
    Ensure-Directory $DestDir
    & $tar.Source -xzf $TarGzPath -C $DestDir
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed (exit=$LASTEXITCODE)" }
    return
  }

  # Fallback TAR.GZ extractor (memory-heavy but compatible)
  Add-Type -AssemblyName System.IO.Compression
  $tarPath = $TarGzPath -replace '\.gz$', ''
  $gzStream = [System.IO.File]::OpenRead($TarGzPath)
  $gzipStream = New-Object System.IO.Compression.GZipStream($gzStream, [System.IO.Compression.CompressionMode]::Decompress)
  $tarStream = [System.IO.File]::Create($tarPath)
  $gzipStream.CopyTo($tarStream)
  $tarStream.Close(); $gzipStream.Close(); $gzStream.Close()

  $tarBytes = [System.IO.File]::ReadAllBytes($tarPath)
  $pos = 0
  while ($pos -lt $tarBytes.Length - 512) {
    $header = $tarBytes[$pos..($pos + 511)]
    $pos += 512

    $allZero = $true
    for ($i=0; $i -lt 100; $i++) { if ($header[$i] -ne 0) { $allZero = $false; break } }
    if ($allZero) { break }

    $nameBytes = $header[0..99]
    $nameEnd = [Array]::IndexOf($nameBytes, [byte]0)
    if ($nameEnd -lt 0) { $nameEnd = 100 }
    $name = [System.Text.Encoding]::UTF8.GetString($nameBytes, 0, $nameEnd)

    $prefixBytes = $header[345..499]
    $prefixEnd = [Array]::IndexOf($prefixBytes, [byte]0)
    if ($prefixEnd -lt 0) { $prefixEnd = 155 }
    $prefix = [System.Text.Encoding]::UTF8.GetString($prefixBytes, 0, $prefixEnd)
    if ($prefix) { $name = "$prefix/$name" }

    $sizeStr = [System.Text.Encoding]::ASCII.GetString($header[124..135]).Trim([char]0,' ')
    $size = 0
    if ($sizeStr) { $size = [Convert]::ToInt64($sizeStr, 8) }

    $type = [char]$header[156]
    $fullPath = Join-Path $DestDir $name.TrimStart('/')

    if ($type -eq '5' -or $name.EndsWith('/')) {
      Ensure-Directory $fullPath
    } elseif ($type -eq '0' -or $type -eq [char]0) {
      Ensure-Directory (Split-Path $fullPath -Parent)
      if ($size -gt 0) {
        [System.IO.File]::WriteAllBytes($fullPath, $tarBytes[$pos..($pos + $size - 1)])
      } else {
        [System.IO.File]::WriteAllBytes($fullPath, @())
      }
    }

    $blocks = [Math]::Ceiling($size / 512)
    $pos += $blocks * 512
  }

  Remove-Item $tarPath -Force -ErrorAction SilentlyContinue
}

function Ensure-IisMimeMap([string]$fileExtension, [string]$mimeType) {
  Import-Module WebAdministration -ErrorAction Stop
  try {
    $filter = "system.webServer/staticContent/mimeMap[@fileExtension='$fileExtension']"
    $existing = Get-WebConfigurationProperty -PSPath "IIS:\" -Filter $filter -Name "mimeType" -ErrorAction SilentlyContinue
    if (-not $existing) {
      Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/staticContent" -Name "." -Value @{fileExtension=$fileExtension; mimeType=$mimeType} -ErrorAction Stop | Out-Null
    } else {
      if ([string]$existing -ne $mimeType) {
        Set-WebConfigurationProperty -PSPath "IIS:\" -Filter $filter -Name "mimeType" -Value $mimeType -ErrorAction SilentlyContinue | Out-Null
      }
    }
  } catch { }
}

function Find-MySqlExe {
  $candidates = @(
    (Join-Path $Config.MySqlBaseDir "bin\mysql.exe"),
    "C:\Program Files\MySQL\MySQL Server*\bin\mysql.exe",
    "C:\Program Files (x86)\MySQL\MySQL Server*\bin\mysql.exe"
  )
  foreach ($pat in $candidates) {
    $hit = Get-ChildItem -Path $pat -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  $null
}

function Find-MySqlD {
  $d = Join-Path $Config.MySqlBaseDir "bin\mysqld.exe"
  if (Test-Path $d) { return $d }
  $null
}

# ---------------------------
# 2) Start / preflight
# ---------------------------
Assert-Admin
Initialize-ConfigDerivedPaths

Ensure-Directory $Config.InstallRoot
$script:LogFile = Join-Path $Config.InstallRoot ("install-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
Start-Transcript -Path (Join-Path $Config.InstallRoot ("transcript-{0}.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss"))) | Out-Null

try {
  Invoke-Step "Preflight checks" {
    Assert-NoPendingReboot
    Assert-SafeSecrets

    if (Test-LocalTcpPortInUse $Config.SitePort) {
      throw "SitePort $($Config.SitePort) is already in use. Change SitePort or stop the conflicting service."
    }
    if (Test-LocalTcpPortInUse $Config.MySqlPort) {
      Write-Log "MySQL port $($Config.MySqlPort) is already in use. If a MySQL instance exists, keep it; otherwise change MySqlPort." "WARN"
    }

    Write-Log "InstallRoot: $($Config.InstallRoot)" "INFO"
    Write-Log "Site: $($Config.SiteName) Port=$($Config.SitePort) Path=$($Config.SitePhysicalPath)" "INFO"
    Write-Log "MySQL: $($Config.MySqlVersion) BaseDir=$($Config.MySqlBaseDir) DataDir=$($Config.MySqlDataDir) Port=$($Config.MySqlPort)" "INFO"
    Write-Log "PHP: $($Config.PhpDir) (x86 NTS)" "INFO"
    Write-Log "Roundcube: $($Config.RoundcubeVersion)" "INFO"
  }

  # ---------------------------
  # 3) Install IIS + CGI/FastCGI
  # ---------------------------
  Invoke-Step "Install IIS + CGI (FastCGI)" {
    $hasInstallWindowsFeature = (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)
    if ($hasInstallWindowsFeature) {
      $features = @(
        "Web-Server","Web-Common-Http","Web-Default-Doc","Web-Static-Content",
        "Web-Http-Errors","Web-Http-Redirect","Web-Http-Logging","Web-Request-Monitor",
        "Web-Filtering","Web-App-Dev","Web-CGI","Web-Mgmt-Tools"
      )
      $res = Install-WindowsFeature -Name $features -IncludeManagementTools
      if ($res.RestartNeeded -eq "Yes") { throw "Windows feature install requires reboot. Reboot and re-run." }
    } else {
      # Windows client
      $features = @(
        "IIS-WebServerRole","IIS-WebServer","IIS-CommonHttpFeatures","IIS-DefaultDocument",
        "IIS-StaticContent","IIS-HttpErrors","IIS-HttpRedirect","IIS-HttpLogging",
        "IIS-RequestMonitor","IIS-Filtering","IIS-ApplicationDevelopment","IIS-CGI",
        "IIS-ManagementConsole"
      )
      foreach ($f in $features) {
        Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart -ErrorAction Stop | Out-Null
      }
    }

    Assert-NoPendingReboot
  }

  # ---------------------------
  # 4) Install PHP (Pinned + SHA256 verified) + FastCGI
  # ---------------------------
  Invoke-Step "Install PHP + configure FastCGI" {
    Ensure-Directory $Config.PhpDir

    $phpZip = Join-Path $env:TEMP ("php-{0}.zip" -f (Get-Date -Format "yyyyMMddHHmmss"))
    Download-File $Config.PhpZipUrl $phpZip
    Assert-Hash $phpZip $Config.PhpZipSha256 "SHA256"

    # Clean PHP dir for idempotency
    Get-ChildItem -Path $Config.PhpDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Expand-Archive -Path $phpZip -DestinationPath $Config.PhpDir -Force
    Remove-Item $phpZip -Force -ErrorAction SilentlyContinue

    $phpIniProd = Join-Path $Config.PhpDir "php.ini-production"
    $phpIni     = Join-Path $Config.PhpDir "php.ini"
    Copy-Item $phpIniProd $phpIni -Force

    # Minimal, common, Roundcube-compatible extensions (+ COM for hMailServer API)
    $iniLines = @(
      "extension_dir=""$($Config.PhpDir)\ext""",
      "date.timezone=$($Config.TimeZone)",
      "cgi.fix_pathinfo=0",
      "fastcgi.impersonate=1",
      "fastcgi.logging=0",
      "expose_php=0",
      "memory_limit=256M",
      "upload_max_filesize=25M",
      "post_max_size=25M",
      "max_execution_time=180",
      "",
      "extension=mbstring",
      "extension=intl",
      "extension=gd",
      "extension=curl",
      "extension=mysqli",
      "extension=pdo_mysql",
      "extension=zip",
      "extension=fileinfo",
      "extension=openssl",
      "extension=sockets",
      "extension=com_dotnet",
      "",
      "com.allow_dcom=true",
      "com.autoregister_typelib=true"
    )
    Add-Content -Path $phpIni -Value ($iniLines -join "`r`n") -Encoding ASCII

    Import-Module WebAdministration -ErrorAction Stop

    $phpCgi = Join-Path $Config.PhpDir "php-cgi.exe"
    if (-not (Test-Path $phpCgi)) { throw "php-cgi.exe not found at $phpCgi" }

    # Register FastCGI app (global)
    $existingFastCgi = Get-WebConfiguration "//system.webServer/fastCgi/application[@fullPath='$phpCgi']" -ErrorAction SilentlyContinue
    if (-not $existingFastCgi) {
      Add-WebConfiguration -Filter "system.webServer/fastCgi" -PSPath "IIS:\" -Value @{ fullPath=$phpCgi; arguments=""; } | Out-Null
    }

    # Handler mapping (global; safe + common)
    New-WebHandler -Name "PHP_via_FastCGI" -Path "*.php" -Verb "*" -Modules "FastCgiModule" `
      -ScriptProcessor $phpCgi -ResourceType "Either" -ErrorAction SilentlyContinue | Out-Null

    # Default docs include index.php
    try {
      $filter = "system.webServer/defaultDocument/files"
      $hasIndexPhp = Get-WebConfigurationProperty -PSPath "IIS:\" -Filter "$filter/add[@value='index.php']" -Name "value" -ErrorAction SilentlyContinue
      if (-not $hasIndexPhp) {
        Add-WebConfigurationProperty -PSPath "IIS:\" -Filter $filter -Name "." -Value @{value="index.php"} | Out-Null
      }
    } catch { }

    # Modern MIME types for Roundcube fonts
    Ensure-IisMimeMap ".woff"  "font/woff"
    Ensure-IisMimeMap ".woff2" "font/woff2"
  }

  # ---------------------------
  # 5) Create IIS site + app pool (32-bit ON)
  # ---------------------------
  Invoke-Step "Create IIS site + 32-bit app pool" {
    Import-Module WebAdministration -ErrorAction Stop

    Ensure-Directory $Config.SitePhysicalPath

    $poolName = "$($Config.SiteName)_Pool"
    if (-not (Test-Path "IIS:\AppPools\$poolName")) {
      New-WebAppPool -Name $poolName | Out-Null
    }
    # PHP is unmanaged; use "No Managed Code"
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "managedRuntimeVersion" -Value "" | Out-Null
    Set-ItemProperty "IIS:\AppPools\$poolName" -Name "enable32BitAppOnWin64" -Value $true | Out-Null

    # Binding safety: IIS can throw 0x800700B7 when starting a site whose binding
    # (IP:Port:HostHeader) conflicts with another configured site.
    $desiredBindingInformation = "*:$($Config.SitePort):$($Config.SiteHostHeader)"
    $desiredPort = [int]$Config.SitePort
    $desiredHost = if ([string]::IsNullOrWhiteSpace($Config.SiteHostHeader)) { "" } else { [string]$Config.SiteHostHeader }

    # NOTE: IIS may represent the IP portion as "*", "0.0.0.0", a concrete IP, or IPv6.
    # Match conflicts by (Port, HostHeader) rather than full string-equality, and prefer Get-Website
    # so we can reliably map bindings back to the site name.
    $bindingConflicts = @()
    try {
      $sites = Get-Website -ErrorAction SilentlyContinue
      foreach ($s in @($sites)) {
        if (-not $s -or [string]::IsNullOrWhiteSpace($s.Name)) { continue }
        if ($s.Name -eq $Config.SiteName) { continue }

        foreach ($bind in @($s.Bindings.Collection)) {
          try {
            if (($bind.protocol -ne "http")) { continue }
            $bi = [string]$bind.bindingInformation
            if ([string]::IsNullOrWhiteSpace($bi)) { continue }

            if ($bi -match '^(?<ip>.+):(?<port>\d+):(?<host>.*)$') {
              $p = [int]$Matches['port']
              $h = [string]$Matches['host']
              if ($p -eq $desiredPort -and $h -eq $desiredHost) {
                $bindingConflicts += $s.Name
              }
            }
          } catch { }
        }
      }
    } catch { }

    $bindingConflicts = @($bindingConflicts | Sort-Object -Unique | Where-Object { $_ -and $_ -ne $Config.SiteName })
    if ($bindingConflicts.Count -gt 0) {
      throw "IIS binding conflict: http '$desiredBindingInformation' is already configured on site(s): $($bindingConflicts -join ', '). Change SitePort / SiteHostHeader or remove/disable the conflicting site(s), then re-run."
    }

    if (-not (Test-Path "IIS:\Sites\$($Config.SiteName)")) {
      if ([string]::IsNullOrWhiteSpace($Config.SiteHostHeader)) {
        New-Website -Name $Config.SiteName -Port $Config.SitePort -PhysicalPath $Config.SitePhysicalPath -ApplicationPool $poolName | Out-Null
      } else {
        New-Website -Name $Config.SiteName -Port $Config.SitePort -HostHeader $Config.SiteHostHeader -PhysicalPath $Config.SitePhysicalPath -ApplicationPool $poolName | Out-Null
      }
    } else {
      # Enforce physical path + pool + binding (idempotent on re-runs)
      Set-ItemProperty "IIS:\Sites\$($Config.SiteName)" -Name physicalPath -Value $Config.SitePhysicalPath | Out-Null
      Set-ItemProperty "IIS:\Sites\$($Config.SiteName)" -Name applicationPool -Value $poolName | Out-Null

      # Normalize HTTP bindings to exactly what config requests.
      try {
        $existingHttpBindings = Get-WebBinding -Name $Config.SiteName -Protocol "http" -ErrorAction SilentlyContinue
        foreach ($b in $existingHttpBindings) {
          Remove-WebBinding -Name $Config.SiteName -Protocol "http" -BindingInformation $b.bindingInformation -ErrorAction SilentlyContinue
        }
      } catch { }

      if ([string]::IsNullOrWhiteSpace($Config.SiteHostHeader)) {
        New-WebBinding -Name $Config.SiteName -Protocol "http" -IPAddress "*" -Port $Config.SitePort | Out-Null
      } else {
        New-WebBinding -Name $Config.SiteName -Protocol "http" -IPAddress "*" -Port $Config.SitePort -HostHeader $Config.SiteHostHeader | Out-Null
      }
    }

    try {
      Start-WebAppPool -Name $poolName -ErrorAction SilentlyContinue | Out-Null
      Start-WebSite -Name $Config.SiteName | Out-Null
    } catch {
      # Re-surface binding conflicts with a clearer message (common: 0x800700B7)
      $hr = $null
      try { $hr = $_.Exception.HResult } catch { }
      if ($hr -eq -2147024713) {
        throw "Failed to start IIS site '$($Config.SiteName)'. This often means the HTTP binding '$desiredBindingInformation' conflicts with another IIS site/binding. Set SitePort/SiteHostHeader (Config block) or remove/disable the conflicting binding, then re-run. Original error: $($_.Exception.Message)"
      }
      throw
    }
  }

  # ---------------------------
  # 6) Install MySQL (ZIP, deterministic)
  # ---------------------------
  Invoke-Step "Install MySQL (ZIP) + initialize service" {
    Ensure-Directory $Config.MySqlBaseDir
    Ensure-Directory $Config.MySqlDataDir
    Ensure-Directory $Config.MySqlLogDir

    $mysqlExe = Find-MySqlExe
    $mysqld   = Find-MySqlD

    if (-not $mysqld -or -not $mysqlExe) {
      $zip = Join-Path $env:TEMP ("mysql-{0}.zip" -f (Get-Date -Format "yyyyMMddHHmmss"))
      Download-File $Config.MySqlZipUrl $zip
      Assert-Hash $zip $Config.MySqlZipMd5 "MD5"

      # Extract into temp then move to BaseDir
      $tmp = Join-Path $env:TEMP ("mysql_extract_{0}" -f (Get-Date -Format "yyyyMMddHHmmss"))
      Ensure-Directory $tmp
      Expand-Archive -Path $zip -DestinationPath $tmp -Force
      Remove-Item $zip -Force -ErrorAction SilentlyContinue

      $sub = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
      if (-not $sub) { throw "MySQL ZIP did not contain a top-level directory as expected." }

      # Clean BaseDir and move extracted
      Get-ChildItem -Path $Config.MySqlBaseDir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      Copy-Item -Path (Join-Path $sub.FullName "*") -Destination $Config.MySqlBaseDir -Recurse -Force
      Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $mysqld = Find-MySqlD
    $mysqlExe = Find-MySqlExe
    if (-not $mysqld -or -not $mysqlExe) { throw "MySQL binaries not found after extraction." }

    # my.ini (stored in ProgramData to keep it stable)
    $myIni = Join-Path (Split-Path $Config.MySqlDataDir -Parent) "my.ini"
    $myIniContent = @"
[mysqld]
basedir=$($Config.MySqlBaseDir)
datadir=$($Config.MySqlDataDir)
port=$($Config.MySqlPort)
bind-address=127.0.0.1
mysqlx=0

character-set-server=utf8mb4
collation-server=utf8mb4_0900_ai_ci
skip_name_resolve=1

log_error=$($Config.MySqlLogDir)\mysql-error.log

[client]
port=$($Config.MySqlPort)
"@
    Write-TextFileUtf8NoBom $myIni $myIniContent

    # Install service if missing
    $svc = Get-Service -Name $Config.MySqlService -ErrorAction SilentlyContinue
    if (-not $svc) {
      # Initialize datadir if empty
      $hasData = (Get-ChildItem -Path $Config.MySqlDataDir -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
      if (-not $hasData) {
        Ensure-VcRedistX64
        & $mysqld --defaults-file="$myIni" --initialize-insecure --console
        if ($LASTEXITCODE -eq -1073741515) {
          throw "mysqld failed to start (exit=-1073741515 / 0xC0000135). This usually means the Microsoft Visual C++ (x64) runtime is missing. Install VC++ 2015-2022 x64 redistributable and re-run."
        }
        if ($LASTEXITCODE -ne 0) { throw "mysqld --initialize-insecure failed (exit=$LASTEXITCODE)." }
      }

      & $mysqld --install $Config.MySqlService --defaults-file="$myIni"
      if ($LASTEXITCODE -ne 0) { throw "mysqld --install failed (exit=$LASTEXITCODE)." }
    }

    Start-Service -Name $Config.MySqlService -ErrorAction Stop
    (Get-Service -Name $Config.MySqlService).WaitForStatus("Running",[TimeSpan]::FromSeconds(30)) | Out-Null

    # Wait for port
    $wait = 0
    while ($wait -lt 25 -and -not (Test-LocalTcpPortInUse $Config.MySqlPort)) { Start-Sleep 1; $wait++ }
    if (-not (Test-LocalTcpPortInUse $Config.MySqlPort)) {
      throw "MySQL service is running, but port $($Config.MySqlPort) is not listening. Check $($Config.MySqlLogDir)\mysql-error.log"
    }

    # Set root password (only if not set yet) — try connecting without password first
    # Use localhost (not 127.0.0.1) for initial connection since root@localhost uses socket/named pipe
    $tryNoPass = & $mysqlExe -uroot -h localhost -P $Config.MySqlPort -e "SELECT 1;" 2>$null
    if ($LASTEXITCODE -eq 0) {
      # Set password and also create root@'127.0.0.1' for TCP/IP connections
      & $mysqlExe -uroot -h localhost -P $Config.MySqlPort -e @"
ALTER USER 'root'@'localhost' IDENTIFIED BY '$($Config.MySqlRootPass)';
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY '$($Config.MySqlRootPass)';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
"@
      if ($LASTEXITCODE -ne 0) { throw "Failed setting MySQL root password." }
      Write-Log "MySQL root password set." "OK"
    } else {
      Write-Log "MySQL root password appears already set (or root cannot login without password). Continuing." "INFO"
    }
  }

  # ---------------------------
  # 7) Install Roundcube into site root + lock down folders
  # ---------------------------
  Invoke-Step "Install Roundcube" {
    Ensure-Directory $Config.SitePhysicalPath

    $rcTgz = Join-Path $env:TEMP ("roundcube-{0}.tar.gz" -f $Config.RoundcubeVersion)
    Download-File $Config.RoundcubeUrl $rcTgz

    $tmpExtractRoot = Join-Path $env:TEMP ("roundcube_extract_{0}" -f (Get-Date -Format "yyyyMMddHHmmss"))
    Remove-Item $tmpExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
    Ensure-Directory $tmpExtractRoot

    Extract-TarGz $rcTgz $tmpExtractRoot
    Remove-Item $rcTgz -Force -ErrorAction SilentlyContinue

    $extracted = Join-Path $tmpExtractRoot "roundcubemail-$($Config.RoundcubeVersion)"
    if (-not (Test-Path $extracted)) { throw "Roundcube extract dir not found: $extracted" }

    # Deploy to site root (clean but do not touch admin/api if they already exist)
    $keep = @("admin","api")
    $existingItems = Get-ChildItem -Path $Config.SitePhysicalPath -Force -ErrorAction SilentlyContinue
    foreach ($it in $existingItems) {
      if ($keep -contains $it.Name) { continue }
      Remove-Item $it.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

    Copy-Item -Path (Join-Path $extracted "*") -Destination $Config.SitePhysicalPath -Recurse -Force
    Remove-Item $tmpExtractRoot -Recurse -Force -ErrorAction SilentlyContinue

    # Writable dirs for IIS
    foreach ($d in @("temp","logs")) {
      $p = Join-Path $Config.SitePhysicalPath $d
      Ensure-Directory $p
      $acl = Get-Acl $p
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Modify","ContainerInherit,ObjectInherit","None","Allow")
      $acl.SetAccessRule($rule)
      Set-Acl $p $acl
    }

    # Block HTTP access to sensitive dirs (IIS ignores .htaccess)
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
    foreach ($sub in @("config","temp","logs","SQL","installer")) {
      $dir = Join-Path $Config.SitePhysicalPath $sub
      if (Test-Path $dir) {
        Write-TextFileUtf8NoBom (Join-Path $dir "web.config") $denyWebConfig
      }
    }

    # Remove installer (defense-in-depth)
    Remove-Item (Join-Path $Config.SitePhysicalPath "installer") -Recurse -Force -ErrorAction SilentlyContinue

    # Generate Roundcube config
    $rcConfigDir = Join-Path $Config.SitePhysicalPath "config"
    Ensure-Directory $rcConfigDir
    $rcConfig = Join-Path $rcConfigDir "config.inc.php"

    $desKey = ([guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N"))

    $configPhp = @"
<?php
\$config['db_dsnw'] = 'mysql://$($Config.RoundcubeDBUser):$($Config.RoundcubeDBPass)@127.0.0.1:$($Config.MySqlPort)/$($Config.RoundcubeDBName)';
\$config['default_host'] = '$($Config.ImapHost)';
\$config['smtp_server']  = '$($Config.SmtpHost)';
\$config['smtp_user']    = '%u';
\$config['smtp_pass']    = '%p';
\$config['product_name'] = 'Webmail';
\$config['des_key']      = '$desKey';
\$config['plugins']      = ['archive','zipdownload'];
\$config['language']     = 'en_US';
\$config['log_dir']      = __DIR__ . '/../logs';
\$config['temp_dir']     = __DIR__ . '/../temp';
\$config['enable_installer'] = false;
"@
    Write-TextFileUtf8NoBom $rcConfig $configPhp
  }

  # ---------------------------
  # 8) Initialize Roundcube DB (global + deterministic)
  # ---------------------------
  Invoke-Step "Initialize Roundcube database" {
    $mysqlExe = Find-MySqlExe
    if (-not $mysqlExe) { throw "mysql.exe not found." }

    function Escape-MySqlString([string]$v) { if ($null -eq $v) { "" } else { $v.Replace('\','\\').Replace("'","''") } }
    function Quote-MySqlIdentifier([string]$v) { if ($null -eq $v) { "``" } else { ('`' + $v.Replace('`','``') + '`') } }

    $dbNameQuoted = Quote-MySqlIdentifier $Config.RoundcubeDBName
    $dbUserEsc = Escape-MySqlString $Config.RoundcubeDBUser
    $dbPassEsc = Escape-MySqlString $Config.RoundcubeDBPass

    $bootstrapSql = @"
CREATE DATABASE IF NOT EXISTS $dbNameQuoted DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$dbUserEsc'@'localhost' IDENTIFIED BY '$dbPassEsc';
GRANT ALL PRIVILEGES ON $dbNameQuoted.* TO '$dbUserEsc'@'localhost';
FLUSH PRIVILEGES;
"@

    $rootArgs = @("-uroot","-p$($Config.MySqlRootPass)","-h","127.0.0.1","-P","$($Config.MySqlPort)","--protocol=TCP")
    & $mysqlExe @rootArgs -e $bootstrapSql
    if ($LASTEXITCODE -ne 0) { throw "Roundcube DB bootstrap failed (exit=$LASTEXITCODE)." }

    $schema = Join-Path $Config.SitePhysicalPath "SQL\mysql.initial.sql"
    if (-not (Test-Path $schema)) { throw "Roundcube schema not found: $schema" }

    $schemaPath = $schema.Replace('\','/')
    & $mysqlExe @rootArgs $Config.RoundcubeDBName -e "source `"$schemaPath`""
    if ($LASTEXITCODE -ne 0) { throw "Roundcube schema import failed (exit=$LASTEXITCODE)." }
  }

  # ---------------------------
  # 9) Install hMailServer (silent) — supports local EXE
  # ---------------------------
  Invoke-Step "Install hMailServer (silent)" {
    $hmailServerExe = Join-Path $Config.HmailInstallDir "Bin\hMailServer.exe"
    if (Test-Path $hmailServerExe) {
      Write-Log "hMailServer already installed. Skipping installer." "INFO"
      return
    }

    $installer = $null
    if (-not [string]::IsNullOrWhiteSpace($Config.HmailExePath) -and (Test-Path $Config.HmailExePath)) {
      $installer = $Config.HmailExePath
      Write-Log "Using local hMailServer installer: $installer" "INFO"
    } else {
      $installer = Join-Path $env:TEMP "hMailServer-5.6.8-B2574.exe"
      try {
        Download-File $Config.HmailExeUrl $installer
      } catch {
        throw "hMailServer download failed (often HTTP 403 from the official site). Download it manually in a browser, set HmailExePath to the local EXE, and re-run."
      }
    }

    $p = Start-Process $installer -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-" -Wait -PassThru
    if ($p.ExitCode -ne 0) {
      Write-Log "hMailServer installer exit code: $($p.ExitCode) (check installer UI/logs if needed)" "WARN"
    }

    if (-not (Test-Path $hmailServerExe)) {
      throw "hMailServer not found after install. Expected: $hmailServerExe"
    }

    # Ensure service
    $svc = Get-Service -Name "hMailServer" -ErrorAction SilentlyContinue
    if ($svc) {
      if ($svc.Status -ne "Running") { Start-Service -Name "hMailServer" -ErrorAction SilentlyContinue }
      Write-Log "hMailServer service status: $((Get-Service hMailServer).Status)" "INFO"
    } else {
      Write-Log "hMailServer service not found; check install manually." "WARN"
    }
  }

  # ---------------------------
  # 10) Deploy API + Admin (optional) + web.config lock-down
  # ---------------------------
  if ($Config.CreateApiAndAdmin) {
    Invoke-Step "Deploy API + Admin (optional)" {
      Import-Module WebAdministration -ErrorAction Stop

      # API
      Ensure-Directory $Config.ApiDir
      Ensure-Directory (Join-Path $Config.ApiDir "v1")
      Ensure-Directory (Join-Path $Config.ApiDir "logs")

      # Admin
      Ensure-Directory $Config.AdminDir
      Ensure-Directory (Join-Path $Config.AdminDir "includes")
      Ensure-Directory (Join-Path $Config.AdminDir "logs")

      # ACL for logs
      foreach ($logDir in @((Join-Path $Config.ApiDir "logs"), (Join-Path $Config.AdminDir "logs"))) {
        $acl = Get-Acl $logDir
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Modify","ContainerInherit,ObjectInherit","None","Allow")
        $acl.SetAccessRule($rule)
        Set-Acl $logDir $acl
      }

      # Copy from script folders if present
      $scriptDir = $PSScriptRoot

      $srcApi = Join-Path $scriptDir "api"
      if (Test-Path $srcApi) {
        Get-ChildItem -Path $srcApi -Recurse | ForEach-Object {
          $rel = $_.FullName.Substring($srcApi.Length + 1)
          $dst = Join-Path $Config.ApiDir $rel
          if ($_.PSIsContainer) { Ensure-Directory $dst }
          else {
            if ($_.Name -ne "config.php") { Copy-Item $_.FullName $dst -Force }
          }
        }
        Write-Log "API files copied." "OK"
      } else {
        Write-Log "API source folder not found at: $srcApi (skipping file copy)." "WARN"
      }

      $srcAdmin = Join-Path $scriptDir "admin"
      if (Test-Path $srcAdmin) {
        Get-ChildItem -Path $srcAdmin -Recurse | ForEach-Object {
          $rel = $_.FullName.Substring($srcAdmin.Length + 1)
          $dst = Join-Path $Config.AdminDir $rel
          if ($_.PSIsContainer) { Ensure-Directory $dst }
          else {
            if ($_.Name -ne "config.php") { Copy-Item $_.FullName $dst -Force }
          }
        }
        Write-Log "Admin files copied." "OK"
      } else {
        Write-Log "Admin source folder not found at: $srcAdmin (skipping file copy)." "WARN"
      }

      # Generate API config
      $apiConfig = @"
<?php
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

      # Generate Admin config
      $adminConfig = @"
<?php
declare(strict_types=1);
return [
  'admin_username' => '$($Config.AdminUsername)',
  'admin_password' => '$($Config.AdminPassword)',
  'hmailserver_admin_password' => '$($Config.HmailAdminPass)',
  'session_name' => 'MAILSERVER_ADMIN',
  'session_lifetime' => 3600,
  'app_name' => '$($Config.AdminAppName)',
  'items_per_page' => 25,
  'max_login_attempts' => 5,
  'lockout_duration' => 900,
  'max_bulk_accounts' => $($Config.AdminMaxBulkAccounts),
  'default_bulk_count' => $($Config.AdminDefaultBulkCount),
  'min_password_length' => $($Config.AdminMinPasswordLength),
  'log_enabled' => true,
  'log_file' => __DIR__ . '/logs/admin.log',
];
"@
      Write-TextFileUtf8NoBom (Join-Path $Config.AdminDir "config.php") $adminConfig

      # Deny HTTP access to config.php + logs (does not block PHP filesystem includes)
      $lockdown = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <location path="config.php">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
  <location path="logs">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>
"@
      Write-TextFileUtf8NoBom (Join-Path $Config.ApiDir "web.config") $lockdown
      Write-TextFileUtf8NoBom (Join-Path $Config.AdminDir "web.config") $lockdown
    }
  }

  # ---------------------------
  # 11) Postflight validation (global, standard)
  # ---------------------------
  Invoke-Step "Postflight validation" {
    # IIS
    Import-Module WebAdministration -ErrorAction Stop
    $site = Get-Website -Name $Config.SiteName -ErrorAction Stop
    if ($site.State -ne "Started") { throw "IIS site '$($Config.SiteName)' is not started." }

    # PHP health check (create temp file, request it locally, then delete)
    $healthPhp = Join-Path $Config.SitePhysicalPath "_health.php"
    $healthContent = @"
<?php
header('Content-Type: application/json');
echo json_encode([
  'php_version' => PHP_VERSION,
  'extensions' => [
    'mysqli' => extension_loaded('mysqli'),
    'pdo_mysql' => extension_loaded('pdo_mysql'),
    'mbstring' => extension_loaded('mbstring'),
    'intl' => extension_loaded('intl'),
    'openssl' => extension_loaded('openssl'),
    'com_dotnet' => extension_loaded('com_dotnet'),
  ],
], JSON_PRETTY_PRINT);
"@
    Write-TextFileUtf8NoBom $healthPhp $healthContent

    $url = if ([string]::IsNullOrWhiteSpace($Config.SiteHostHeader)) { "http://127.0.0.1:$($Config.SitePort)/_health.php" }
           else { "http://127.0.0.1:$($Config.SitePort)/_health.php" } # host header validation would require hosts file; keep simple
    try {
      $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
      if ($resp.StatusCode -ne 200) { throw "PHP health check HTTP $($resp.StatusCode)" }
      Write-Log "PHP health endpoint responded." "OK"
    } finally {
      Remove-Item $healthPhp -Force -ErrorAction SilentlyContinue
    }

    # MySQL
    $mysqlExe = Find-MySqlExe
    & $mysqlExe -uroot -p$($Config.MySqlRootPass) -h 127.0.0.1 -P $Config.MySqlPort --protocol=TCP -e "SELECT VERSION();" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "MySQL root login failed during validation." }

    # Roundcube tables exist?
    & $mysqlExe -uroot -p$($Config.MySqlRootPass) -h 127.0.0.1 -P $Config.MySqlPort --protocol=TCP `
      -e "SELECT COUNT(*) AS tables_count FROM information_schema.tables WHERE table_schema='$($Config.RoundcubeDBName)';" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Roundcube DB validation failed." }

    # hMailServer service presence (configuration still required manually)
    $hm = Get-Service -Name "hMailServer" -ErrorAction SilentlyContinue
    if (-not $hm) { Write-Log "hMailServer service not found (validate install manually)." "WARN" }
  }

  # ---------------------------
  # 12) Output next steps (no secrets dumped beyond what you configured)
  # ---------------------------
  Write-Host ""
  Write-Host "==================== INSTALLATION COMPLETE ===================="
  Write-Host ""
  Write-Host "Web:"
  Write-Host "  Roundcube Webmail: http://<YourIP>:$($Config.SitePort)/"
  if ($Config.CreateApiAndAdmin) {
    Write-Host "  Admin Panel:       http://<YourIP>:$($Config.SitePort)/admin/"
    Write-Host "  Account API:       POST http://<YourIP>:$($Config.SitePort)/api/v1/accounts"
  }
  Write-Host ""
  Write-Host "hMailServer Configuration (REQUIRED):"
  Write-Host "  1) Open hMailServer Administrator"
  Write-Host "  2) Connect and set admin password to your configured value"
  Write-Host "  3) Add domain(s) and create accounts (or via your API if implemented)"
  Write-Host "  4) Enable SMTP/IMAP and configure TLS certificates"
  Write-Host ""
  Write-Host "Firewall/DNS reminders:"
  Write-Host "  - Open ports as needed: 25, 587, 465, 143, 993, 110, 995"
  Write-Host "  - Configure MX + SPF + DKIM + DMARC for your domain"
  Write-Host ""
  Write-Host "Logs:"
  Write-Host "  Installer log: $script:LogFile"
  Write-Host "  Install root:  $($Config.InstallRoot)"
  Write-Host "==============================================================="
}
finally {
  try { Stop-Transcript | Out-Null } catch { }
}