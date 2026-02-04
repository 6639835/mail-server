<?php
/**
 * Admin Panel Configuration
 * 
 * Contains authentication credentials and panel settings.
 * SECURITY: Change default credentials before deployment!
 */

declare(strict_types=1);

return [
    /**
     * Admin Authentication
     * Simple username/password authentication
     */
    'admin_username' => 'admin',
    'admin_password' => 'ChangeMe_Admin123!',

    /**
     * hMailServer Configuration
     * Must match the password set in hMailServer Administrator
     */
    'hmailserver_admin_password' => 'ChangeMe_HMailAdmin!',

    /**
     * Session Settings
     */
    'session_name' => 'MAILSERVER_ADMIN',
    'session_lifetime' => 3600, // 1 hour

    /**
     * UI Settings
     */
    'app_name' => 'Mail Server Admin',
    'items_per_page' => 25,

    /**
     * Security Settings
     */
    'max_login_attempts' => 5,
    'lockout_duration' => 900, // 15 minutes

    /**
     * Bulk Creation Limits
     */
    'max_bulk_accounts' => 1000,
    'default_bulk_count' => 10,

    /**
     * Password Requirements for New Accounts
     */
    'min_password_length' => 4,

    /**
     * Logging
     */
    'log_enabled' => true,
    'log_file' => __DIR__ . '/logs/admin.log',
];
