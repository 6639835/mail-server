<?php
/**
 * Authentication Functions
 * 
 * Handles admin login, logout, and session management.
 */

declare(strict_types=1);

/**
 * Initialize session with secure settings
 */
function initSession(array $config): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_name($config['session_name'] ?? 'MAILSERVER_ADMIN');
        $secure = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off');
        if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
            $proto = strtolower(trim(explode(',', (string)$_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
            if ($proto === 'https') {
                $secure = true;
            }
        }
        session_set_cookie_params([
            'lifetime' => 0, // Session cookie (expires when browser closes)
            'path' => '/',
            'secure' => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }
}

/**
 * Check if user is logged in
 */
function isLoggedIn(): bool
{
    return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true;
}

/**
 * Require authentication - redirect to login if not authenticated
 */
function requireAuth(array $config): void
{
    initSession($config);
    
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit;
    }
    
    // Check session timeout
    $lifetime = $config['session_lifetime'] ?? 3600;
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $lifetime) {
        logout();
        header('Location: index.php?timeout=1');
        exit;
    }
    
    $_SESSION['last_activity'] = time();
}

/**
 * Attempt to login with credentials
 */
function attemptLogin(string $username, string $password, array $config): bool
{
    $validUsername = $config['admin_username'] ?? 'admin';
    $validPassword = $config['admin_password'] ?? '';
    
    // Check lockout
    if (isLockedOut($config)) {
        return false;
    }
    
    if ($username === $validUsername && $password === $validPassword) {
        session_regenerate_id(true);
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_username'] = $username;
        $_SESSION['last_activity'] = time();
        $_SESSION['login_time'] = time();
        
        // Clear failed attempts
        unset($_SESSION['failed_attempts']);
        unset($_SESSION['lockout_until']);
        
        writeLog('INFO', "Admin login successful: {$username}");
        return true;
    }
    
    // Record failed attempt
    recordFailedAttempt($config);
    writeLog('WARNING', "Failed login attempt for: {$username}");
    return false;
}

/**
 * Record a failed login attempt
 */
function recordFailedAttempt(array $config): void
{
    if (!isset($_SESSION['failed_attempts'])) {
        $_SESSION['failed_attempts'] = 0;
    }
    
    $_SESSION['failed_attempts']++;
    
    $maxAttempts = $config['max_login_attempts'] ?? 5;
    if ($_SESSION['failed_attempts'] >= $maxAttempts) {
        $lockoutDuration = $config['lockout_duration'] ?? 900;
        $_SESSION['lockout_until'] = time() + $lockoutDuration;
    }
}

/**
 * Check if account is locked out
 */
function isLockedOut(array $config): bool
{
    if (isset($_SESSION['lockout_until'])) {
        if (time() < $_SESSION['lockout_until']) {
            return true;
        }
        // Lockout expired
        unset($_SESSION['lockout_until']);
        unset($_SESSION['failed_attempts']);
    }
    return false;
}

/**
 * Get remaining lockout time in seconds
 */
function getLockoutRemaining(): int
{
    if (isset($_SESSION['lockout_until'])) {
        return max(0, $_SESSION['lockout_until'] - time());
    }
    return 0;
}

/**
 * Logout and destroy session
 */
function logout(): void
{
    $_SESSION = [];
    
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    
    session_destroy();
}

/**
 * Write log entry
 */
function writeLog(string $level, string $message, array $context = []): void
{
    global $adminConfig;
    
    if (empty($adminConfig['log_enabled'])) {
        return;
    }
    
    $logFile = $adminConfig['log_file'] ?? __DIR__ . '/../logs/admin.log';
    $logDir = dirname($logFile);
    
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $contextStr = $context ? ' ' . json_encode($context, JSON_UNESCAPED_UNICODE) : '';
    $entry = "[{$timestamp}] [{$level}] [{$ip}] {$message}{$contextStr}\n";
    
    @file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

/**
 * Generate CSRF token
 */
function generateCsrfToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 */
function verifyCsrfToken(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Get CSRF token input field HTML
 */
function csrfField(): string
{
    $token = generateCsrfToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}
