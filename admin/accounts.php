<?php
/**
 * Account Management Page
 * 
 * List, search, and manage email accounts.
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
$allDomains = $hmailApp ? getDomains($hmailApp) : [];
$connectionError = $hmailApp === null;

$message = '';
$messageType = '';

// Get filter parameters
$selectedDomain = trim($_GET['domain'] ?? '');
$search = trim($_GET['search'] ?? '');
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = $adminConfig['items_per_page'] ?? 25;
$offset = ($page - 1) * $perPage;

// Handle actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$connectionError) {
    if (!verifyCsrfToken($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid security token. Please try again.';
        $messageType = 'danger';
    } else {
        $action = $_POST['action'] ?? '';
        $email = $_POST['email'] ?? '';
        $domain = $_POST['domain'] ?? '';
        
        if ($email && $domain) {
            $hmailDomain = findDomain($hmailApp, $domain);
            
            if ($hmailDomain) {
                switch ($action) {
                    case 'delete':
                        $result = deleteAccount($hmailDomain, $email);
                        $message = $result['success'] ? "Account '{$email}' deleted." : $result['error'];
                        $messageType = $result['success'] ? 'success' : 'danger';
                        break;
                        
                    case 'toggle':
                        $result = toggleAccountStatus($hmailDomain, $email);
                        $message = $result['success'] ? $result['message'] : $result['error'];
                        $messageType = $result['success'] ? 'success' : 'danger';
                        break;
                        
                    case 'change_password':
                        $newPassword = $_POST['new_password'] ?? '';
                        $minLength = $adminConfig['min_password_length'] ?? 4;
                        
                        if (strlen($newPassword) < $minLength) {
                            $message = "Password must be at least {$minLength} characters.";
                            $messageType = 'danger';
                        } else {
                            $result = changeAccountPassword($hmailDomain, $email, $newPassword);
                            $message = $result['success'] ? $result['message'] : $result['error'];
                            $messageType = $result['success'] ? 'success' : 'danger';
                        }
                        break;
                }
            } else {
                $message = "Domain not found.";
                $messageType = 'danger';
            }
        }
    }
}

// Get accounts for selected domain
$accounts = [];
$totalAccounts = 0;
$hmailDomain = null;

if (!$connectionError && $selectedDomain) {
    $hmailDomain = findDomain($hmailApp, $selectedDomain);
    if ($hmailDomain) {
        $accounts = getAccounts($hmailDomain, $offset, $perPage, $search);
        $totalAccounts = countAccounts($hmailDomain, $search);
    }
}

$totalPages = ceil($totalAccounts / $perPage);

// Render page
renderHeader('Manage Accounts', 'accounts');

if ($connectionError):
?>
    <div class="alert alert-danger d-flex align-items-center">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <div><strong>Connection Error:</strong> Unable to connect to hMailServer.</div>
    </div>
<?php else: ?>
    <?php if ($message): ?>
        <?php renderAlert($messageType, $message); ?>
    <?php endif; ?>

    <!-- Filters -->
    <div class="card mb-4">
        <div class="card-body">
            <form method="GET" action="" class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="domain" class="form-label">Domain</label>
                    <select class="form-select" id="domain" name="domain" onchange="this.form.submit()">
                        <option value="">-- Select Domain --</option>
                        <?php foreach ($allDomains as $d): ?>
                            <option value="<?= htmlspecialchars($d['name']) ?>" 
                                    <?= $selectedDomain === $d['name'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($d['name']) ?> (<?= $d['account_count'] ?> accounts)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-4">
                    <label for="search" class="form-label">Search</label>
                    <input type="text" class="form-control" id="search" name="search" 
                           placeholder="Search by email..." value="<?= htmlspecialchars($search) ?>">
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-primary">
                        <i class="bi bi-search me-1"></i> Search
                    </button>
                    <?php if ($selectedDomain || $search): ?>
                        <a href="accounts.php" class="btn btn-outline-secondary">Clear</a>
                    <?php endif; ?>
                </div>
            </form>
        </div>
    </div>

    <?php if (!$selectedDomain): ?>
        <div class="card">
            <div class="card-body text-center py-5">
                <i class="bi bi-inbox text-muted" style="font-size: 4rem;"></i>
                <p class="mt-3 mb-0 text-muted">Please select a domain to view accounts.</p>
            </div>
        </div>
    <?php elseif (empty($accounts)): ?>
        <div class="card">
            <div class="card-body text-center py-5">
                <i class="bi bi-person-x text-muted" style="font-size: 4rem;"></i>
                <p class="mt-3 mb-0 text-muted">
                    <?= $search ? 'No accounts found matching your search.' : 'No accounts in this domain.' ?>
                </p>
                <a href="create.php?domain=<?= urlencode($selectedDomain) ?>" class="btn btn-primary mt-3">
                    <i class="bi bi-plus me-1"></i> Create First Account
                </a>
            </div>
        </div>
    <?php else: ?>
        <!-- Accounts Table -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <span>
                    <i class="bi bi-people me-2"></i>
                    Accounts in <?= htmlspecialchars($selectedDomain) ?>
                    <span class="badge bg-secondary ms-2"><?= number_format($totalAccounts) ?></span>
                </span>
                <a href="create.php?domain=<?= urlencode($selectedDomain) ?>" class="btn btn-sm btn-primary">
                    <i class="bi bi-plus"></i> Add Account
                </a>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead>
                            <tr>
                                <th>Email Address</th>
                                <th>Status</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($accounts as $account): ?>
                                <tr>
                                    <td>
                                        <i class="bi bi-envelope me-2 text-primary"></i>
                                        <strong><?= htmlspecialchars($account['address']) ?></strong>
                                    </td>
                                    <td>
                                        <?php if ($account['active']): ?>
                                            <span class="badge badge-active">Active</span>
                                        <?php else: ?>
                                            <span class="badge badge-inactive">Inactive</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="text-end">
                                        <!-- Toggle Status -->
                                        <form method="POST" action="" class="d-inline">
                                            <?= csrfField() ?>
                                            <input type="hidden" name="action" value="toggle">
                                            <input type="hidden" name="email" value="<?= htmlspecialchars($account['address']) ?>">
                                            <input type="hidden" name="domain" value="<?= htmlspecialchars($selectedDomain) ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-warning btn-action" 
                                                    title="<?= $account['active'] ? 'Deactivate' : 'Activate' ?>">
                                                <i class="bi bi-<?= $account['active'] ? 'pause' : 'play' ?>"></i>
                                            </button>
                                        </form>
                                        
                                        <!-- Change Password -->
                                        <button type="button" class="btn btn-sm btn-outline-info btn-action" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#passwordModal"
                                                data-email="<?= htmlspecialchars($account['address']) ?>"
                                                data-domain="<?= htmlspecialchars($selectedDomain) ?>"
                                                title="Change Password">
                                            <i class="bi bi-key"></i>
                                        </button>
                                        
                                        <!-- Delete -->
                                        <button type="button" class="btn btn-sm btn-outline-danger btn-action" 
                                                data-bs-toggle="modal" 
                                                data-bs-target="#deleteModal"
                                                data-email="<?= htmlspecialchars($account['address']) ?>"
                                                data-domain="<?= htmlspecialchars($selectedDomain) ?>"
                                                title="Delete Account">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <?php if ($totalPages > 1): ?>
                <div class="card-footer">
                    <nav>
                        <ul class="pagination justify-content-center mb-0">
                            <?php if ($page > 1): ?>
                                <li class="page-item">
                                    <a class="page-link" href="?domain=<?= urlencode($selectedDomain) ?>&search=<?= urlencode($search) ?>&page=<?= $page - 1 ?>">
                                        <i class="bi bi-chevron-left"></i>
                                    </a>
                                </li>
                            <?php endif; ?>
                            
                            <?php for ($p = max(1, $page - 2); $p <= min($totalPages, $page + 2); $p++): ?>
                                <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                                    <a class="page-link" href="?domain=<?= urlencode($selectedDomain) ?>&search=<?= urlencode($search) ?>&page=<?= $p ?>">
                                        <?= $p ?>
                                    </a>
                                </li>
                            <?php endfor; ?>
                            
                            <?php if ($page < $totalPages): ?>
                                <li class="page-item">
                                    <a class="page-link" href="?domain=<?= urlencode($selectedDomain) ?>&search=<?= urlencode($search) ?>&page=<?= $page + 1 ?>">
                                        <i class="bi bi-chevron-right"></i>
                                    </a>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </nav>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Delete Confirmation Modal -->
    <div class="modal fade" id="deleteModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="POST" action="">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="email" id="deleteEmail">
                    <input type="hidden" name="domain" id="deleteDomain">
                    
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-exclamation-triangle text-danger me-2"></i>Delete Account</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>Are you sure you want to delete this account?</p>
                        <p class="fw-bold text-danger" id="deleteEmailDisplay"></p>
                        <p class="text-muted small mb-0">This action cannot be undone. All emails will be permanently deleted.</p>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-danger">
                            <i class="bi bi-trash me-1"></i> Delete Account
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Change Password Modal -->
    <div class="modal fade" id="passwordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <form method="POST" action="">
                    <?= csrfField() ?>
                    <input type="hidden" name="action" value="change_password">
                    <input type="hidden" name="email" id="passwordEmail">
                    <input type="hidden" name="domain" id="passwordDomain">
                    
                    <div class="modal-header">
                        <h5 class="modal-title"><i class="bi bi-key me-2"></i>Change Password</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <p>Change password for: <strong id="passwordEmailDisplay"></strong></p>
                        <div class="mb-3">
                            <label for="new_password" class="form-label">New Password</label>
                            <div class="input-group">
                                <input type="password" class="form-control" id="new_password" name="new_password" 
                                       required minlength="<?= $adminConfig['min_password_length'] ?? 4 ?>">
                                <button class="btn btn-outline-secondary" type="button" onclick="toggleModalPassword()">
                                    <i class="bi bi-eye" id="modalPasswordIcon"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-check-lg me-1"></i> Change Password
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        // Delete modal
        document.getElementById('deleteModal').addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            document.getElementById('deleteEmail').value = button.dataset.email;
            document.getElementById('deleteDomain').value = button.dataset.domain;
            document.getElementById('deleteEmailDisplay').textContent = button.dataset.email;
        });
        
        // Password modal
        document.getElementById('passwordModal').addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            document.getElementById('passwordEmail').value = button.dataset.email;
            document.getElementById('passwordDomain').value = button.dataset.domain;
            document.getElementById('passwordEmailDisplay').textContent = button.dataset.email;
            document.getElementById('new_password').value = '';
        });
        
        function toggleModalPassword() {
            const input = document.getElementById('new_password');
            const icon = document.getElementById('modalPasswordIcon');
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('bi-eye', 'bi-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.replace('bi-eye-slash', 'bi-eye');
            }
        }
    </script>
<?php endif;

renderFooter();
