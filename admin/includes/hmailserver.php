<?php
/**
 * hMailServer Integration Functions
 * 
 * Provides functions for interacting with hMailServer via COM.
 */

declare(strict_types=1);

/**
 * Connect to hMailServer
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
 * Get all domains from hMailServer
 */
function getDomains(object $app): array
{
    $result = [];
    
    try {
        $domains = $app->Domains;
        $count = $domains->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $domain = $domains->Item($i);
            $result[] = [
                'id' => $domain->ID,
                'name' => $domain->Name,
                'active' => $domain->Active,
                'account_count' => $domain->Accounts->Count,
            ];
        }
    } catch (Exception $e) {
        writeLog('ERROR', 'Failed to get domains', ['error' => $e->getMessage()]);
    }
    
    return $result;
}

/**
 * Find a domain by name
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
 * Get all accounts for a domain
 */
function getAccounts(object $domain, int $offset = 0, int $limit = 100, string $search = ''): array
{
    $result = [];
    
    try {
        $accounts = $domain->Accounts;
        $count = $accounts->Count;
        
        $matched = 0;
        $added = 0;
        
        for ($i = 0; $i < $count && $added < $limit; $i++) {
            $account = $accounts->Item($i);
            $address = $account->Address;
            
            // Apply search filter
            if ($search && stripos($address, $search) === false) {
                continue;
            }
            
            $matched++;
            
            // Apply offset
            if ($matched <= $offset) {
                continue;
            }
            
            $result[] = [
                'id' => $account->ID,
                'address' => $address,
                'active' => $account->Active,
                'max_size' => $account->MaxSize,
                'size' => $account->Size ?? 0,
                'last_logon' => '', // Not available via COM
            ];
            
            $added++;
        }
    } catch (Exception $e) {
        writeLog('ERROR', 'Failed to get accounts', ['error' => $e->getMessage()]);
    }
    
    return $result;
}

/**
 * Count accounts in a domain (with optional search)
 */
function countAccounts(object $domain, string $search = ''): int
{
    if (empty($search)) {
        return $domain->Accounts->Count;
    }
    
    $count = 0;
    try {
        $accounts = $domain->Accounts;
        $total = $accounts->Count;
        
        for ($i = 0; $i < $total; $i++) {
            $account = $accounts->Item($i);
            if (stripos($account->Address, $search) !== false) {
                $count++;
            }
        }
    } catch (Exception $e) {
        // Ignore
    }
    
    return $count;
}

/**
 * Check if an account exists
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
        // Ignore
    }
    
    return false;
}

/**
 * Create a new email account
 */
function createAccount(object $domain, string $email, string $password): array
{
    try {
        // Check if exists
        if (accountExists($domain, $email)) {
            return ['success' => false, 'error' => 'Account already exists'];
        }
        
        $account = $domain->Accounts->Add();
        $account->Address = $email;
        $account->Password = $password;
        $account->Active = true;
        $account->MaxSize = 0; // Unlimited
        $account->Save();
        
        writeLog('INFO', 'Account created', ['email' => $email]);
        return ['success' => true, 'message' => 'Account created successfully'];
    } catch (Exception $e) {
        writeLog('ERROR', 'Account creation failed', ['email' => $email, 'error' => $e->getMessage()]);
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Delete an email account
 */
function deleteAccount(object $domain, string $email): array
{
    try {
        $accounts = $domain->Accounts;
        $count = $accounts->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $account = $accounts->Item($i);
            if (strtolower($account->Address) === strtolower($email)) {
                $account->Delete();
                writeLog('INFO', 'Account deleted', ['email' => $email]);
                return ['success' => true, 'message' => 'Account deleted successfully'];
            }
        }
        
        return ['success' => false, 'error' => 'Account not found'];
    } catch (Exception $e) {
        writeLog('ERROR', 'Account deletion failed', ['email' => $email, 'error' => $e->getMessage()]);
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Toggle account active status
 */
function toggleAccountStatus(object $domain, string $email): array
{
    try {
        $accounts = $domain->Accounts;
        $count = $accounts->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $account = $accounts->Item($i);
            if (strtolower($account->Address) === strtolower($email)) {
                $account->Active = !$account->Active;
                $account->Save();
                $status = $account->Active ? 'activated' : 'deactivated';
                writeLog('INFO', "Account {$status}", ['email' => $email]);
                return ['success' => true, 'message' => "Account {$status} successfully", 'active' => $account->Active];
            }
        }
        
        return ['success' => false, 'error' => 'Account not found'];
    } catch (Exception $e) {
        writeLog('ERROR', 'Toggle status failed', ['email' => $email, 'error' => $e->getMessage()]);
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Change account password
 */
function changeAccountPassword(object $domain, string $email, string $newPassword): array
{
    try {
        $accounts = $domain->Accounts;
        $count = $accounts->Count;
        
        for ($i = 0; $i < $count; $i++) {
            $account = $accounts->Item($i);
            if (strtolower($account->Address) === strtolower($email)) {
                $account->Password = $newPassword;
                $account->Save();
                writeLog('INFO', 'Password changed', ['email' => $email]);
                return ['success' => true, 'message' => 'Password changed successfully'];
            }
        }
        
        return ['success' => false, 'error' => 'Account not found'];
    } catch (Exception $e) {
        writeLog('ERROR', 'Password change failed', ['email' => $email, 'error' => $e->getMessage()]);
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Get server statistics
 */
function getServerStats(object $app): array
{
    $stats = [
        'total_domains' => 0,
        'total_accounts' => 0,
        'active_accounts' => 0,
        'domains' => [],
    ];
    
    try {
        $domains = $app->Domains;
        $stats['total_domains'] = $domains->Count;
        
        for ($i = 0; $i < $domains->Count; $i++) {
            $domain = $domains->Item($i);
            $accountCount = $domain->Accounts->Count;
            $stats['total_accounts'] += $accountCount;
            
            // Count active accounts
            for ($j = 0; $j < $accountCount; $j++) {
                if ($domain->Accounts->Item($j)->Active) {
                    $stats['active_accounts']++;
                }
            }
            
            $stats['domains'][] = [
                'name' => $domain->Name,
                'accounts' => $accountCount,
                'active' => $domain->Active,
            ];
        }
    } catch (Exception $e) {
        writeLog('ERROR', 'Failed to get server stats', ['error' => $e->getMessage()]);
    }
    
    return $stats;
}
