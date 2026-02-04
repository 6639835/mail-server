<?php
/**
 * Logout Handler
 */

declare(strict_types=1);

$adminConfig = require __DIR__ . '/config.php';
require_once __DIR__ . '/includes/auth.php';

initSession($adminConfig);
logout();

header('Location: index.php');
exit;
