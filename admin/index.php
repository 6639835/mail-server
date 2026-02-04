<?php
/**
 * Admin Login Page
 * 
 * Entry point for the admin panel. Requires authentication.
 */

declare(strict_types=1);

// Load configuration
$adminConfig = require __DIR__ . '/config.php';

// Load includes
require_once __DIR__ . '/includes/auth.php';

// Initialize session
initSession($adminConfig);

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$info = '';

// Check for timeout message
if (isset($_GET['timeout'])) {
    $info = 'Your session has expired. Please login again.';
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (isLockedOut($adminConfig)) {
        $remaining = getLockoutRemaining();
        $minutes = ceil($remaining / 60);
        $error = "Too many failed attempts. Please try again in {$minutes} minute(s).";
    } elseif (empty($username) || empty($password)) {
        $error = 'Please enter both username and password.';
    } elseif (attemptLogin($username, $password, $adminConfig)) {
        header('Location: dashboard.php');
        exit;
    } else {
        $maxAttempts = $adminConfig['max_login_attempts'] ?? 5;
        $attempts = $_SESSION['failed_attempts'] ?? 0;
        $remaining = $maxAttempts - $attempts;
        
        if ($remaining > 0) {
            $error = "Invalid username or password. {$remaining} attempt(s) remaining.";
        } else {
            $lockoutMinutes = ceil(($adminConfig['lockout_duration'] ?? 900) / 60);
            $error = "Too many failed attempts. Account locked for {$lockoutMinutes} minutes.";
        }
    }
}

$appName = $adminConfig['app_name'] ?? 'Mail Server Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?= htmlspecialchars($appName) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            max-width: 420px;
            width: 100%;
            border: none;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        .login-header {
            background: linear-gradient(135deg, #0d6efd 0%, #0056b3 100%);
            border-radius: 16px 16px 0 0;
            padding: 2rem;
            text-align: center;
            color: white;
        }
        .login-header i {
            font-size: 3rem;
            margin-bottom: 0.5rem;
        }
        .login-body {
            padding: 2rem;
        }
        .form-control {
            border-radius: 8px;
            padding: 12px 16px;
        }
        .form-control:focus {
            box-shadow: 0 0 0 3px rgba(13, 110, 253, 0.15);
        }
        .btn-login {
            border-radius: 8px;
            padding: 12px;
            font-weight: 600;
        }
        .input-group-text {
            background: #f8f9fa;
            border-right: none;
        }
        .form-control.with-icon {
            border-left: none;
        }
    </style>
</head>
<body>
    <div class="login-card card">
        <div class="login-header">
            <i class="bi bi-envelope-fill d-block"></i>
            <h4 class="mb-0"><?= htmlspecialchars($appName) ?></h4>
        </div>
        <div class="login-body">
            <?php if ($error): ?>
                <div class="alert alert-danger d-flex align-items-center" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    <div><?= htmlspecialchars($error) ?></div>
                </div>
            <?php endif; ?>
            
            <?php if ($info): ?>
                <div class="alert alert-info d-flex align-items-center" role="alert">
                    <i class="bi bi-info-circle-fill me-2"></i>
                    <div><?= htmlspecialchars($info) ?></div>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="bi bi-person"></i></span>
                        <input type="text" class="form-control with-icon" id="username" name="username" 
                               placeholder="Enter username" required autofocus
                               value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                    </div>
                </div>
                
                <div class="mb-4">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-group">
                        <span class="input-group-text"><i class="bi bi-lock"></i></span>
                        <input type="password" class="form-control with-icon" id="password" name="password" 
                               placeholder="Enter password" required>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary btn-login w-100">
                    <i class="bi bi-box-arrow-in-right me-2"></i>Login
                </button>
            </form>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
