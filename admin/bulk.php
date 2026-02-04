<?php
/**
 * Bulk Account Creation Page
 * 
 * Create multiple email accounts at once with various generation options.
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

$results = null;
$formData = [
    'domain' => $_POST['domain'] ?? '',
    'count' => $_POST['count'] ?? $adminConfig['default_bulk_count'] ?? 10,
    'username_mode' => $_POST['username_mode'] ?? 'random',
    'prefix' => $_POST['prefix'] ?? 'user',
    'password_mode' => $_POST['password_mode'] ?? 'random',
    'fixed_password' => $_POST['fixed_password'] ?? '',
];

// Username generation functions
function generateRandomUsername(int $length = 8): string
{
    $chars = 'abcdefghijkmnpqrstuvwxyz23456789';
    $username = '';
    // First char must be letter
    $username .= $chars[random_int(0, 23)];
    for ($i = 1; $i < $length; $i++) {
        $username .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $username;
}

function generateSequentialUsername(string $prefix, int $index): string
{
    return $prefix . str_pad((string)$index, 4, '0', STR_PAD_LEFT);
}

function generateRandomPassword(int $length = 10): string
{
    $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= $chars[random_int(0, strlen($chars) - 1)];
    }
    return $password;
}

function generateNumericPassword(int $length = 6): string
{
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= random_int(0, 9);
    }
    return $password;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$connectionError) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $results = ['error' => 'Invalid security token. Please try again.'];
    } else {
        $domain = trim($_POST['domain'] ?? '');
        $count = (int)($_POST['count'] ?? 10);
        $usernameMode = $_POST['username_mode'] ?? 'random';
        $prefix = trim($_POST['prefix'] ?? 'user');
        $passwordMode = $_POST['password_mode'] ?? 'random';
        $fixedPassword = $_POST['fixed_password'] ?? '';
        
        $maxCount = $adminConfig['max_bulk_accounts'] ?? 1000;
        $minPasswordLength = $adminConfig['min_password_length'] ?? 4;
        
        // Validation
        if (empty($domain)) {
            $results = ['error' => 'Domain is required.'];
        } elseif ($count < 1 || $count > $maxCount) {
            $results = ['error' => "Count must be between 1 and {$maxCount}."];
        } elseif ($passwordMode === 'fixed' && strlen($fixedPassword) < $minPasswordLength) {
            $results = ['error' => "Fixed password must be at least {$minPasswordLength} characters."];
        } else {
            $hmailDomain = findDomain($hmailApp, $domain);
            
            if (!$hmailDomain) {
                $results = ['error' => "Domain '{$domain}' is not configured on this server."];
            } else {
                $results = [
                    'success' => [],
                    'failed' => [],
                    'domain' => $domain,
                ];
                
                $existingCount = $hmailDomain->Accounts->Count;
                $startIndex = $existingCount + 1;
                
                for ($i = 0; $i < $count; $i++) {
                    // Generate username
                    switch ($usernameMode) {
                        case 'sequential':
                            $username = generateSequentialUsername($prefix, $startIndex + $i);
                            break;
                        case 'random':
                        default:
                            $username = generateRandomUsername(8);
                            break;
                    }
                    
                    $email = $username . '@' . $domain;
                    
                    // Generate password
                    switch ($passwordMode) {
                        case 'fixed':
                            $password = $fixedPassword;
                            break;
                        case 'numeric':
                            $password = generateNumericPassword(6);
                            break;
                        case 'random':
                        default:
                            $password = generateRandomPassword(10);
                            break;
                    }
                    
                    // Try to create account
                    $result = createAccount($hmailDomain, $email, $password);
                    
                    if ($result['success']) {
                        $results['success'][] = [
                            'email' => $email,
                            'password' => $password,
                        ];
                    } else {
                        $results['failed'][] = [
                            'email' => $email,
                            'error' => $result['error'] ?? 'Unknown error',
                        ];
                        
                        // If duplicate, try with different username (for random mode)
                        if ($usernameMode === 'random' && strpos($result['error'] ?? '', 'exists') !== false) {
                            // Retry with new random username
                            $username = generateRandomUsername(8);
                            $email = $username . '@' . $domain;
                            $result = createAccount($hmailDomain, $email, $password);
                            
                            if ($result['success']) {
                                array_pop($results['failed']);
                                $results['success'][] = [
                                    'email' => $email,
                                    'password' => $password,
                                ];
                            }
                        }
                    }
                }
                
                writeLog('INFO', 'Bulk creation completed', [
                    'domain' => $domain,
                    'requested' => $count,
                    'success' => count($results['success']),
                    'failed' => count($results['failed']),
                ]);
            }
        }
    }
}

// Render page
renderHeader('Bulk Create Accounts', 'bulk');

if ($connectionError):
?>
    <div class="alert alert-danger d-flex align-items-center">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <div><strong>Connection Error:</strong> Unable to connect to hMailServer.</div>
    </div>
<?php else: ?>

    <?php if ($results && isset($results['error'])): ?>
        <?php renderAlert('danger', $results['error']); ?>
    <?php endif; ?>

    <div class="row">
        <!-- Form Panel -->
        <div class="col-lg-5 mb-4">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-people me-2"></i>Bulk Account Creation
                </div>
                <div class="card-body">
                    <form method="POST" action="" id="bulkForm">
                        <?= csrfField() ?>
                        
                        <div class="mb-3">
                            <label for="domain" class="form-label">Domain <span class="text-danger">*</span></label>
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
                        
                        <div class="mb-3">
                            <label for="count" class="form-label">Number of Accounts <span class="text-danger">*</span></label>
                            <input type="number" class="form-control" id="count" name="count" 
                                   min="1" max="<?= $adminConfig['max_bulk_accounts'] ?? 1000 ?>" 
                                   value="<?= htmlspecialchars((string)$formData['count']) ?>" required>
                            <div class="form-text">Maximum: <?= $adminConfig['max_bulk_accounts'] ?? 1000 ?></div>
                        </div>
                        
                        <hr>
                        
                        <div class="mb-3">
                            <label class="form-label">Username Generation</label>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="username_mode" 
                                       id="username_random" value="random" 
                                       <?= $formData['username_mode'] === 'random' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="username_random">
                                    Random (8 characters, e.g., <code>ab3kx9pm</code>)
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="username_mode" 
                                       id="username_sequential" value="sequential"
                                       <?= $formData['username_mode'] === 'sequential' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="username_sequential">
                                    Sequential (prefix + number)
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-3" id="prefixGroup" style="<?= $formData['username_mode'] !== 'sequential' ? 'display:none;' : '' ?>">
                            <label for="prefix" class="form-label">Username Prefix</label>
                            <input type="text" class="form-control" id="prefix" name="prefix" 
                                   value="<?= htmlspecialchars($formData['prefix']) ?>" 
                                   placeholder="user">
                            <div class="form-text">e.g., "user" → user0001, user0002, ...</div>
                        </div>
                        
                        <hr>
                        
                        <div class="mb-3">
                            <label class="form-label">Password Generation</label>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="password_mode" 
                                       id="password_random" value="random"
                                       <?= $formData['password_mode'] === 'random' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="password_random">
                                    Random Strong (10 chars, mixed)
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="password_mode" 
                                       id="password_numeric" value="numeric"
                                       <?= $formData['password_mode'] === 'numeric' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="password_numeric">
                                    Random Numeric (6 digits)
                                </label>
                            </div>
                            <div class="form-check">
                                <input class="form-check-input" type="radio" name="password_mode" 
                                       id="password_fixed" value="fixed"
                                       <?= $formData['password_mode'] === 'fixed' ? 'checked' : '' ?>>
                                <label class="form-check-label" for="password_fixed">
                                    Fixed Password (same for all)
                                </label>
                            </div>
                        </div>
                        
                        <div class="mb-4" id="fixedPasswordGroup" style="<?= $formData['password_mode'] !== 'fixed' ? 'display:none;' : '' ?>">
                            <label for="fixed_password" class="form-label">Fixed Password</label>
                            <input type="text" class="form-control" id="fixed_password" name="fixed_password" 
                                   value="<?= htmlspecialchars($formData['fixed_password']) ?>">
                        </div>
                        
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-lightning me-1"></i> Create Accounts
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <!-- Results Panel -->
        <div class="col-lg-7">
            <?php if ($results && !isset($results['error'])): ?>
                <!-- Summary -->
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card border-success">
                            <div class="card-body text-center">
                                <h2 class="text-success mb-0"><?= count($results['success']) ?></h2>
                                <small class="text-muted">Successfully Created</small>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card border-danger">
                            <div class="card-body text-center">
                                <h2 class="text-danger mb-0"><?= count($results['failed']) ?></h2>
                                <small class="text-muted">Failed</small>
                            </div>
                        </div>
                    </div>
                </div>
                
                <?php if (!empty($results['success'])): ?>
                    <!-- Success Table -->
                    <div class="card mb-4">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span><i class="bi bi-check-circle text-success me-2"></i>Created Accounts</span>
                            <button type="button" class="btn btn-sm btn-outline-primary" onclick="copyToClipboard()">
                                <i class="bi bi-clipboard me-1"></i> Copy All
                            </button>
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive" style="max-height: 400px; overflow-y: auto;">
                                <table class="table table-sm table-hover mb-0">
                                    <thead class="sticky-top bg-light">
                                        <tr>
                                            <th>#</th>
                                            <th>Email</th>
                                            <th>Password</th>
                                        </tr>
                                    </thead>
                                    <tbody id="successTable">
                                        <?php foreach ($results['success'] as $i => $account): ?>
                                            <tr>
                                                <td><?= $i + 1 ?></td>
                                                <td><code><?= htmlspecialchars($account['email']) ?></code></td>
                                                <td><code><?= htmlspecialchars($account['password']) ?></code></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Hidden textarea for copy -->
                    <textarea id="copyData" style="position: absolute; left: -9999px;"><?php
                        foreach ($results['success'] as $account) {
                            echo $account['email'] . "\t" . $account['password'] . "\n";
                        }
                    ?></textarea>
                <?php endif; ?>
                
                <?php if (!empty($results['failed'])): ?>
                    <!-- Failed Table -->
                    <div class="card">
                        <div class="card-header">
                            <i class="bi bi-x-circle text-danger me-2"></i>Failed Accounts
                        </div>
                        <div class="card-body p-0">
                            <div class="table-responsive" style="max-height: 200px; overflow-y: auto;">
                                <table class="table table-sm table-hover mb-0">
                                    <thead class="sticky-top bg-light">
                                        <tr>
                                            <th>Email</th>
                                            <th>Error</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($results['failed'] as $account): ?>
                                            <tr>
                                                <td><code><?= htmlspecialchars($account['email']) ?></code></td>
                                                <td class="text-danger"><?= htmlspecialchars($account['error']) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
                
            <?php else: ?>
                <!-- Instructions -->
                <div class="card">
                    <div class="card-header">
                        <i class="bi bi-info-circle me-2"></i>Instructions
                    </div>
                    <div class="card-body">
                        <h6>Bulk Account Creation</h6>
                        <p>Create multiple email accounts at once with customizable options.</p>
                        
                        <h6 class="mt-4">Username Modes</h6>
                        <ul>
                            <li><strong>Random:</strong> 8-character random usernames (letters and numbers)</li>
                            <li><strong>Sequential:</strong> Prefix followed by incrementing numbers (e.g., user0001, user0002)</li>
                        </ul>
                        
                        <h6 class="mt-4">Password Modes</h6>
                        <ul>
                            <li><strong>Random Strong:</strong> 10-character passwords with letters, numbers, and symbols</li>
                            <li><strong>Random Numeric:</strong> 6-digit numeric passwords</li>
                            <li><strong>Fixed:</strong> Same password for all accounts</li>
                        </ul>
                        
                        <div class="alert alert-info mt-4 mb-0">
                            <i class="bi bi-lightbulb me-2"></i>
                            <strong>Tip:</strong> After creation, use the "Copy All" button to export all credentials to clipboard in tab-separated format.
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Show/hide prefix field
        document.querySelectorAll('input[name="username_mode"]').forEach(function(radio) {
            radio.addEventListener('change', function() {
                document.getElementById('prefixGroup').style.display = 
                    this.value === 'sequential' ? 'block' : 'none';
            });
        });
        
        // Show/hide fixed password field
        document.querySelectorAll('input[name="password_mode"]').forEach(function(radio) {
            radio.addEventListener('change', function() {
                document.getElementById('fixedPasswordGroup').style.display = 
                    this.value === 'fixed' ? 'block' : 'none';
            });
        });
        
        // Copy to clipboard
        function copyToClipboard() {
            const copyData = document.getElementById('copyData');
            copyData.select();
            document.execCommand('copy');
            
            // Show feedback
            const btn = event.target.closest('button');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check me-1"></i> Copied!';
            btn.classList.replace('btn-outline-primary', 'btn-success');
            
            setTimeout(function() {
                btn.innerHTML = originalHtml;
                btn.classList.replace('btn-success', 'btn-outline-primary');
            }, 2000);
        }
    </script>
<?php endif;

renderFooter();
