<?php
/**
 * Layout Helper Functions
 * 
 * Provides common HTML structure and components.
 */

declare(strict_types=1);

/**
 * Render the page header with navigation
 */
function renderHeader(string $title, string $activePage = ''): void
{
    global $adminConfig;
    $appName = $adminConfig['app_name'] ?? 'Mail Server Admin';
    $username = $_SESSION['admin_username'] ?? 'Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($title) ?> - <?= htmlspecialchars($appName) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --sidebar-width: 250px;
        }
        body {
            min-height: 100vh;
        }
        .sidebar {
            width: var(--sidebar-width);
            min-height: 100vh;
            background: linear-gradient(135deg, #1e3a5f 0%, #0d1b2a 100%);
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 12px 20px;
            border-radius: 8px;
            margin: 4px 12px;
            transition: all 0.2s;
        }
        .sidebar .nav-link:hover {
            color: #fff;
            background: rgba(255,255,255,0.1);
        }
        .sidebar .nav-link.active {
            color: #fff;
            background: rgba(255,255,255,0.15);
        }
        .sidebar .nav-link i {
            width: 24px;
            margin-right: 8px;
        }
        .main-content {
            margin-left: var(--sidebar-width);
            min-height: 100vh;
            background: #f8f9fa;
        }
        .card {
            border: none;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
            border-radius: 12px;
        }
        .card-header {
            background: #fff;
            border-bottom: 1px solid #eee;
            font-weight: 600;
        }
        .stat-card {
            border-left: 4px solid;
        }
        .stat-card.primary { border-left-color: #0d6efd; }
        .stat-card.success { border-left-color: #198754; }
        .stat-card.warning { border-left-color: #ffc107; }
        .stat-card.danger { border-left-color: #dc3545; }
        .btn-action {
            padding: 4px 8px;
            font-size: 0.875rem;
        }
        .table th {
            font-weight: 600;
            background: #f8f9fa;
        }
        .badge-active { background: #198754; }
        .badge-inactive { background: #6c757d; }
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                min-height: auto;
                position: relative;
            }
            .main-content {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <div class="d-flex">
        <!-- Sidebar -->
        <nav class="sidebar d-flex flex-column">
            <div class="p-4">
                <h4 class="text-white mb-0">
                    <i class="bi bi-envelope-fill me-2"></i>
                    <?= htmlspecialchars($appName) ?>
                </h4>
            </div>
            <ul class="nav flex-column flex-grow-1">
                <li class="nav-item">
                    <a class="nav-link <?= $activePage === 'dashboard' ? 'active' : '' ?>" href="dashboard.php">
                        <i class="bi bi-speedometer2"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?= $activePage === 'create' ? 'active' : '' ?>" href="create.php">
                        <i class="bi bi-person-plus"></i> Create Account
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?= $activePage === 'bulk' ? 'active' : '' ?>" href="bulk.php">
                        <i class="bi bi-people"></i> Bulk Create
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?= $activePage === 'accounts' ? 'active' : '' ?>" href="accounts.php">
                        <i class="bi bi-list-ul"></i> Manage Accounts
                    </a>
                </li>
            </ul>
            <div class="p-3 border-top border-secondary">
                <div class="d-flex align-items-center text-white-50 mb-2">
                    <i class="bi bi-person-circle me-2"></i>
                    <span><?= htmlspecialchars($username) ?></span>
                </div>
                <a href="logout.php" class="btn btn-outline-light btn-sm w-100">
                    <i class="bi bi-box-arrow-right me-1"></i> Logout
                </a>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="main-content flex-grow-1">
            <div class="p-4">
                <h2 class="mb-4"><?= htmlspecialchars($title) ?></h2>
<?php
}

/**
 * Render the page footer
 */
function renderFooter(): void
{
?>
            </div>
        </main>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Auto-dismiss alerts after 5 seconds
        document.querySelectorAll('.alert-dismissible').forEach(function(alert) {
            setTimeout(function() {
                var bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        });
    </script>
</body>
</html>
<?php
}

/**
 * Render an alert message
 */
function renderAlert(string $type, string $message): void
{
    $icon = match($type) {
        'success' => 'check-circle-fill',
        'danger', 'error' => 'exclamation-triangle-fill',
        'warning' => 'exclamation-circle-fill',
        'info' => 'info-circle-fill',
        default => 'info-circle-fill',
    };
    $type = $type === 'error' ? 'danger' : $type;
?>
    <div class="alert alert-<?= $type ?> alert-dismissible fade show d-flex align-items-center" role="alert">
        <i class="bi bi-<?= $icon ?> me-2"></i>
        <div><?= htmlspecialchars($message) ?></div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
<?php
}

/**
 * Render a stat card
 */
function renderStatCard(string $title, $value, string $icon, string $color = 'primary'): void
{
?>
    <div class="col-md-3 col-sm-6 mb-4">
        <div class="card stat-card <?= $color ?>">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="text-muted mb-1"><?= htmlspecialchars($title) ?></h6>
                        <h3 class="mb-0"><?= htmlspecialchars((string)$value) ?></h3>
                    </div>
                    <div class="text-<?= $color ?> opacity-50">
                        <i class="bi bi-<?= $icon ?>" style="font-size: 2.5rem;"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
<?php
}
