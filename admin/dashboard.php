<?php
/**
 * Admin Dashboard
 * 
 * Overview of mail server statistics and quick actions.
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
$stats = $hmailApp ? getServerStats($hmailApp) : null;
$connectionError = $hmailApp === null;

// Render page
renderHeader('Dashboard', 'dashboard');

if ($connectionError):
?>
    <div class="alert alert-danger d-flex align-items-center">
        <i class="bi bi-exclamation-triangle-fill me-2"></i>
        <div>
            <strong>Connection Error:</strong> Unable to connect to hMailServer. 
            Please verify that hMailServer is running and the admin password is correct in config.php.
        </div>
    </div>
<?php else: ?>
    <!-- Statistics Cards -->
    <div class="row">
        <?php renderStatCard('Total Domains', $stats['total_domains'], 'globe', 'primary'); ?>
        <?php renderStatCard('Total Accounts', $stats['total_accounts'], 'people-fill', 'success'); ?>
        <?php renderStatCard('Active Accounts', $stats['active_accounts'], 'person-check-fill', 'warning'); ?>
        <?php renderStatCard('Inactive', $stats['total_accounts'] - $stats['active_accounts'], 'person-x-fill', 'danger'); ?>
    </div>

    <!-- Quick Actions -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="card">
                <div class="card-header">
                    <i class="bi bi-lightning-fill me-2"></i>Quick Actions
                </div>
                <div class="card-body">
                    <a href="create.php" class="btn btn-primary me-2">
                        <i class="bi bi-person-plus me-1"></i> Create Account
                    </a>
                    <a href="bulk.php" class="btn btn-success me-2">
                        <i class="bi bi-people me-1"></i> Bulk Create
                    </a>
                    <a href="accounts.php" class="btn btn-outline-secondary">
                        <i class="bi bi-list-ul me-1"></i> Manage Accounts
                    </a>
                </div>
            </div>
        </div>
    </div>

    <!-- Domains Overview -->
    <div class="row">
        <div class="col-12">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-globe me-2"></i>Domains Overview</span>
                </div>
                <div class="card-body">
                    <?php if (empty($stats['domains'])): ?>
                        <div class="text-center text-muted py-4">
                            <i class="bi bi-inbox" style="font-size: 3rem;"></i>
                            <p class="mt-2 mb-0">No domains configured. Add domains in hMailServer Administrator.</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th>Domain</th>
                                        <th>Accounts</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($stats['domains'] as $domain): ?>
                                        <tr>
                                            <td>
                                                <i class="bi bi-globe2 me-2 text-primary"></i>
                                                <strong><?= htmlspecialchars($domain['name']) ?></strong>
                                            </td>
                                            <td><?= number_format($domain['accounts']) ?></td>
                                            <td>
                                                <?php if ($domain['active']): ?>
                                                    <span class="badge badge-active">Active</span>
                                                <?php else: ?>
                                                    <span class="badge badge-inactive">Inactive</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <a href="accounts.php?domain=<?= urlencode($domain['name']) ?>" 
                                                   class="btn btn-sm btn-outline-primary">
                                                    <i class="bi bi-eye"></i> View Accounts
                                                </a>
                                                <a href="create.php?domain=<?= urlencode($domain['name']) ?>" 
                                                   class="btn btn-sm btn-outline-success">
                                                    <i class="bi bi-plus"></i> Add Account
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
<?php endif;

renderFooter();
