<?php
/**
 * Create Single Account Page
 * 
 * Form for creating individual email accounts.
 */

declare(strict_types=1);

// Load configuration and includes
$adminConfig = require __DIR__ . '/config.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/hmailserver.php';
require_once __DIR__ . '/includes/layout.php';

// Require authentication
requireAuth($adminConfig);

// Connect to hMailServer
$hmailApp = connectHMailServer($adminConfig['hmailserver_admin_password'] ?? '');
$domains = $hmailApp ? getDomains($hmailApp) : [];
$connectionError = $hmailApp === null;

$message = '';
$messageType = '';
$formData = [
    'username' => $_POST['username'] ?? '',
    'domain' => $_POST['domain'] ?? $_GET['domain'] ?? '',
    'password' => '',
];

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$connectionError) {
    // Verify CSRF token
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please try again.';
        $messageType = 'danger';
    } else {
        $username = trim($_POST['username'] ?? '');
        $domain = trim($_POST['domain'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        $formData['username'] = $username;
        $formData['domain'] = $domain;
        
        // Validation
        $minPasswordLength = $adminConfig['min_password_length'] ?? 4;
        
        if (empty($username)) {
            $message = 'Username is required.';
            $messageType = 'danger';
        } elseif (!preg_match('/^[a-zA-Z0-9._-]+$/', $username)) {
            $message = 'Username can only contain letters, numbers, dots, underscores, and hyphens.';
            $messageType = 'danger';
        } elseif (empty($domain)) {
            $message = 'Domain is required.';
            $messageType = 'danger';
        } elseif (empty($password)) {
            $message = 'Password is required.';
            $messageType = 'danger';
        } elseif (strlen($password) < $minPasswordLength) {
            $message = "Password must be at least {$minPasswordLength} characters.";
            $messageType = 'danger';
        } elseif ($password !== $confirmPassword) {
            $message = 'Passwords do not match.';
            $messageType = 'danger';
        } else {
            // Find domain in hMailServer
            $hmailDomain = findDomain($hmailApp, $domain);
            
            if (!$hmailDomain) {
                $message = "Domain '{$domain}' is not configured on this server.";
                $messageType = 'danger';
            } else {
                $email = $username . '@' . $domain;
                $result = createAccount($hmailDomain, $email, $password);
                
                if ($result['success']) {
                    $message = "Account '{$email}' created successfully!";
                    $messageType = 'success';
                    // Clear form on success
                    $formData = ['username' => '', 'domain' => $domain, 'password' => ''];
                } else {
                    $message = $result['error'] ?? 'Failed to create account.';
                    $messageType = 'danger';
                }
            }
        }
    }
}

// Generate password helper
function generateRandomPassword(int $length = 12): string
{
    $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $password;
}

// Render page
renderHeader('Create Account', 'create');

if ($connectionError):
?>
    <div class="alert alert-danger d-flex align-items-center">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <div>
            <strong>Connection Error:</strong> Unable to connect to hMailServer. 
            Please verify that hMailServer is running and the admin password is correct.
        </div>
    </div>
<?php else: ?>
    <?php if ($message): ?>
        <?php renderAlert($messageType, $message); ?>
    <?php endif; ?>

    <div class="row">
        <div class="col-lg-6">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-person-plus me-2"></i>New Email Account
                </div>
                <div class="card-body">
                    <form method="POST" action="" id="createForm">
                        <?= csrfField() ?>
                        
                        <div class="mb-3">
                            <label for="username" class="form-label">Username <span class="text-danger">*</span></label>
                            <div class="input-group">
                                <input type="text" class="form-control" id="username" name="username" 
                                       placeholder="username" required
                                       pattern="[a-zA-Z0-9._-]+"
                                       value="<?= htmlspecialchars($formData['username']) ?>">
                                <span class="input-group-text">@</span>
                                <input type="text" class="form-control" id="domain" name="domain" 
                                       placeholder="example.com" required
                                       value="<?= htmlspecialchars($formData['domain']) ?>"
                                       list="domainList">
                                <datalist id="domainList">
                                    <?php foreach ($domains as $d): ?>
                                        <option value="<?= htmlspecialchars($d['name']) ?>">
                                    <?php endforeach; ?>
                                </datalist>
                            </div>
                            <div class="form-text">
                                Letters, numbers, dots, underscores, and hyphens only.
                                <?php if (!empty($domains)): ?>
                                    Available domains: <?= implode(', ', array_column($domains, 'name')) ?>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Password <span class="text-danger">*</span></label>
                            <div class="input-group">
                                <input type="password" class="form-control" id="password" name="password" 
                                       placeholder="Enter password" required
                                       minlength="<?= $adminConfig['min_password_length'] ?? 4 ?>">
                                <button class="btn btn-outline-secondary" type="button" id="togglePassword">
                                    <i class="bi bi-eye"></i>
                                </button>
                                <button class="btn btn-outline-primary" type="button" id="generatePassword">
                                    <i class="bi bi-magic"></i> Generate
                                </button>
                            </div>
                        </div>
                        
                        <div class="mb-4">
                            <label for="confirm_password" class="form-label">Confirm Password <span class="text-danger">*</span></label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" 
                                   placeholder="Confirm password" required>
                        </div>
                        
                        <div class="d-flex gap-2">
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-check-lg me-1"></i> Create Account
                            </button>
                            <a href="dashboard.php" class="btn btn-outline-secondary">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-lg-6">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-info-circle me-2"></i>Instructions
                </div>
                <div class="card-body">
                    <h6>Creating an Email Account</h6>
                    <ol class="mb-4">
                        <li>Enter a username (the part before @)</li>
                        <li>Enter or select a domain (must be configured in hMailServer)</li>
                        <li>Set a password (minimum <?= $adminConfig['min_password_length'] ?? 4 ?> characters)</li>
                        <li>Click "Create Account"</li>
                    </ol>
                    
                    <h6>Tips</h6>
                    <ul class="mb-0">
                        <li>Use the <strong>Generate</strong> button to create a secure random password</li>
                        <li>Usernames are not case-sensitive</li>
                        <li>The domain must already exist in hMailServer</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Toggle password visibility
        document.getElementById('togglePassword').addEventListener('click', function() {
            const password = document.getElementById('password');
            const confirm = document.getElementById('confirm_password');
            const icon = this.querySelector('i');
            
            if (password.type === 'password') {
                password.type = 'text';
                confirm.type = 'text';
                icon.classList.replace('bi-eye', 'bi-eye-slash');
            } else {
                password.type = 'password';
                confirm.type = 'password';
                icon.classList.replace('bi-eye-slash', 'bi-eye');
            }
        });
        
        // Generate random password
        document.getElementById('generatePassword').addEventListener('click', function() {
            const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';
            let password = '';
            for (let i = 0; i < 12; i++) {
                password += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            document.getElementById('password').value = password;
            document.getElementById('confirm_password').value = password;
            document.getElementById('password').type = 'text';
            document.getElementById('confirm_password').type = 'text';
            document.querySelector('#togglePassword i').classList.replace('bi-eye', 'bi-eye-slash');
        });
    </script>
<?php endif;

renderFooter();
