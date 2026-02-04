<?php
/**
 * hMailServer API Configuration
 * 
 * This file contains configuration settings for the mail server API.
 * Modify these values according to your hMailServer installation.
 * 
 * SECURITY NOTE: In production, consider moving sensitive credentials
 * outside the web root or using environment variables.
 */

declare(strict_types=1);

return [
    /**
     * hMailServer Administrator Password
     * Set during hMailServer installation
     */
    'hmailserver_admin_password' => 'ChangeMe_HMailAdmin!',

    /**
     * API Authentication
     * Simple API key for intranet environments
     * Set to empty string to disable authentication
     */
    'api_key' => '',

    /**
     * Allowed domains for account creation
     * Leave empty array to allow any domain configured in hMailServer
     * Example: ['example.com', 'mail.local']
     */
    'allowed_domains' => [],

    /**
     * Rate limiting (requests per minute per IP)
     * Set to 0 to disable rate limiting
     */
    'rate_limit' => 0,

    /**
     * Enable debug mode
     * WARNING: Disable in production - exposes detailed error messages
     */
    'debug' => false,

    /**
     * Logging
     */
    'log_enabled' => true,
    'log_file' => __DIR__ . '/logs/api.log',
];
