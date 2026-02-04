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
 *   {
 *     "email": "user@example.com",
 *     "password": "securepassword"
 *   }
 * 
 * Response Format (JSON):
 *   Success: { "success": true, "message": "...", "data": {...} }
 *   Error:   { "success": false, "error": { "code": "...", "message": "..." } }
 * 
 * @author Mail Server API
 * @version 1.0.0
 */

declare(strict_types=1);

// ===========================================================================
// Configuration & Setup
// ===========================================================================

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

// Load configuration
$configPath = dirname(__DIR__) . '/config.php';
if (!file_exists($configPath)) {
    sendError('CONFIG_MISSING', 'Server configuration not found', 500);
}
$config = require $configPath;

// ===========================================================================
// Helper Functions
// ===========================================================================

/**
 * Send a JSON success response and exit
 */
function sendSuccess(string $message, array $data = []): void
{
    http_response_code(200);
    echo json_encode([
        'success' => true,
        'message' => $message,
        'data' => $data,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Send a JSON error response and exit
 */
function sendError(string $code, string $message, int $httpCode = 400): void
{
    http_response_code($httpCode);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => $code,
            'message' => $message,
        ],
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Write a log entry
 */
function writeLog(string $level, string $message, array $context = []): void
{
    global $config;
    
    if (empty($config['log_enabled'])) {
        return;
    }
    
    $logFile = $config['log_file'] ?? __DIR__ . '/../logs/api.log';
    $logDir = dirname($logFile);
    
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = $context ? ' ' . json_encode($context, JSON_UNESCAPED_UNICODE) : '';
    $entry = "[{$timestamp}] [{$level}] {$message}{$contextStr}\n";
    
    @file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}

/**
 * Validate email address format
 */
function validateEmail(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Extract domain from email address
 */
function extractDomain(string $email): string
{
    $parts = explode('@', $email);
    return strtolower($parts[1] ?? '');
}

/**
 * Validate password meets requirements
 */
function validatePassword(string $password): bool
{
    // Minimum 4 characters for basic intranet use
    // Adjust as needed for your security requirements
    return strlen($password) >= 4;
}

// ===========================================================================
// Authentication
// ===========================================================================

/**
 * Verify API key if configured
 */
function authenticateRequest(array $config): void
{
    $apiKey = $config['api_key'] ?? '';
    
    if (empty($apiKey)) {
        return; // No authentication required
    }
    
    // Check Authorization header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
        if (hash_equals($apiKey, $matches[1])) {
            return;
        }
    }
    
    // Check X-API-Key header
    $headerKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
    if (!empty($headerKey) && hash_equals($apiKey, $headerKey)) {
        return;
    }
    
    sendError('UNAUTHORIZED', 'Invalid or missing API key', 401);
}

// ===========================================================================
// hMailServer Integration
// ===========================================================================

/**
 * Connect to hMailServer via COM
 */
function connectHMailServer(string $adminPassword): ?object
{
    if (!class_exists('COM')) {
        return null;
    }
    
    try {
        $app = new COM('hMailServer.Application');
        $app->Authenticate('Administrator', $adminPassword);
        return $app;
    } catch (Exception $e) {
        writeLog('ERROR', 'hMailServer connection failed', ['error' => $e->getMessage()]);
        return null;
    }
}

/**
 * Find domain in hMailServer
 */
function findDomain(object $app, string $domainName): ?object
{
    try {
        $domains = $app->Domains;
        $count = $domains->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $domain = $domains->Item($i);
            if (strtolower($domain->Name) === strtolower($domainName)) {
                return $domain;
            }
        }
    } catch (Exception $e) {
        writeLog('ERROR', 'Domain lookup failed', ['domain' => $domainName, 'error' => $e->getMessage()]);
    }
    
    return null;
}

/**
 * Check if account already exists
 */
function accountExists(object $domain, string $email): bool
{
    try {
        $accounts = $domain->Accounts;
        $count = $accounts->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $account = $accounts->Item($i);
            if (strtolower($account->Address) === strtolower($email)) {
                return true;
            }
        }
    } catch (Exception $e) {
        writeLog('ERROR', 'Account existence check failed', ['email' => $email, 'error' => $e->getMessage()]);
    }
    
    return false;
}

/**
 * Create a new email account
 */
function createAccount(object $domain, string $email, string $password): bool
{
    try {
        $account = $domain->Accounts->Add();
        $account->Address = $email;
        $account->Password = $password;
        $account->Active = true;
        $account->MaxSize = 0; // Unlimited
        $account->Save();
        
        return true;
    } catch (Exception $e) {
        writeLog('ERROR', 'Account creation failed', ['email' => $email, 'error' => $e->getMessage()]);
        return false;
    }
}

// ===========================================================================
// Request Handler
// ===========================================================================

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError('METHOD_NOT_ALLOWED', 'Only POST method is allowed', 405);
}

// Authenticate request
authenticateRequest($config);

// Parse JSON body
$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    sendError('INVALID_JSON', 'Request body must be valid JSON', 400);
}

// ===========================================================================
// Input Validation
// ===========================================================================

$email = trim($input['email'] ?? '');
$password = $input['password'] ?? '';

// Validate email
if (empty($email)) {
    sendError('EMAIL_REQUIRED', 'Email address is required', 400);
}

if (!validateEmail($email)) {
    sendError('EMAIL_INVALID', 'Invalid email address format', 400);
}

// Validate password
if (empty($password)) {
    sendError('PASSWORD_REQUIRED', 'Password is required', 400);
}

if (!validatePassword($password)) {
    sendError('PASSWORD_WEAK', 'Password must be at least 4 characters', 400);
}

// Extract and validate domain
$domain = extractDomain($email);

if (empty($domain)) {
    sendError('DOMAIN_INVALID', 'Could not extract domain from email', 400);
}

// Check allowed domains
$allowedDomains = $config['allowed_domains'] ?? [];
if (!empty($allowedDomains)) {
    $normalizedAllowed = array_map('strtolower', $allowedDomains);
    if (!in_array(strtolower($domain), $normalizedAllowed, true)) {
        sendError('DOMAIN_NOT_ALLOWED', "Domain '{$domain}' is not allowed", 403);
    }
}

// ===========================================================================
// Account Creation
// ===========================================================================

writeLog('INFO', 'Account creation request', ['email' => $email]);

// Check COM extension
if (!class_exists('COM')) {
    writeLog('ERROR', 'COM extension not available');
    sendError('SERVER_ERROR', 'Mail server integration not available', 500);
}

// Connect to hMailServer
$adminPassword = $config['hmailserver_admin_password'] ?? '';
$hmailApp = connectHMailServer($adminPassword);

if ($hmailApp === null) {
    sendError('SERVER_ERROR', 'Failed to connect to mail server', 500);
}

// Find domain
$hmailDomain = findDomain($hmailApp, $domain);

if ($hmailDomain === null) {
    sendError('DOMAIN_NOT_FOUND', "Domain '{$domain}' is not configured on this server", 404);
}

// Check if account already exists
if (accountExists($hmailDomain, $email)) {
    writeLog('INFO', 'Account already exists', ['email' => $email]);
    sendError('ACCOUNT_EXISTS', 'An account with this email address already exists', 409);
}

// Create account
if (!createAccount($hmailDomain, $email, $password)) {
    sendError('CREATION_FAILED', 'Failed to create account', 500);
}

// Success
writeLog('INFO', 'Account created successfully', ['email' => $email]);
sendSuccess('Account created successfully', [
    'email' => $email,
    'domain' => $domain,
]);
