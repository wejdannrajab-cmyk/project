<?php
/**
 * Health Monitoring System - Authentication Functions
 * Handles login, logout, session management, and access control
 */

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/db_connect.php';
require_once __DIR__ . '/audit.php';

/**
 * Authenticate user across all roles
 * @param string $username
 * @param string $password
 * @param string $role (admin, caregiver, patient, family)
 * @return array|false User data on success, false on failure
 */
function login($username, $password, $role) {
    global $pdo;
    
    $user = false;
    $user_id = null;
    $user_data = [];
    
    try {
        switch ($role) {
            case 'admin':
            case 'caregiver':
                // Check users table
                $stmt = $pdo->prepare("
                    SELECT user_id, username, password_hash, full_name, email, role, is_active 
                    FROM users 
                    WHERE username = ? AND role = ? AND is_active = 1
                ");
                $stmt->execute([$username, $role]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password_hash'])) {
                    $user_id = $user['user_id'];
                    $user_data = [
                        'user_id' => $user['user_id'],
                        'username' => $user['username'],
                        'full_name' => $user['full_name'],
                        'email' => $user['email'],
                        'role' => $user['role']
                    ];
                } else {
                    return false;
                }
                break;
                
            case 'patient':
                // Check patient_users table
                $stmt = $pdo->prepare("
                    SELECT pu.patient_user_id, pu.patient_id, pu.username, pu.password_hash, 
                           p.first_name, p.last_name, p.is_active
                    FROM patient_users pu
                    JOIN patients p ON pu.patient_id = p.patient_id
                    WHERE pu.username = ? AND pu.is_active = 1 AND p.is_active = 1
                ");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password_hash'])) {
                    $user_id = $user['patient_user_id'];
                    $user_data = [
                        'user_id' => $user['patient_user_id'],
                        'patient_id' => $user['patient_id'],
                        'username' => $user['username'],
                        'full_name' => $user['first_name'] . ' ' . $user['last_name'],
                        'role' => 'patient'
                    ];
                } else {
                    return false;
                }
                break;
                
            case 'family':
                // Check family_users table
                $stmt = $pdo->prepare("
                    SELECT fu.family_user_id, fu.patient_id, fu.username, fu.password_hash, 
                           fu.full_name, fu.relationship, fu.is_active
                    FROM family_users fu
                    WHERE fu.username = ? AND fu.is_active = 1
                ");
                $stmt->execute([$username]);
                $user = $stmt->fetch();
                
                if ($user && password_verify($password, $user['password_hash'])) {
                    $user_id = $user['family_user_id'];
                    $user_data = [
                        'user_id' => $user['family_user_id'],
                        'patient_id' => $user['patient_id'],
                        'username' => $user['username'],
                        'full_name' => $user['full_name'],
                        'relationship' => $user['relationship'],
                        'role' => 'family'
                    ];
                } else {
                    return false;
                }
                break;
                
            default:
                return false;
        }
        
        // If authentication successful, create session
        if ($user_data) {
            // Regenerate session ID for security
            session_regenerate_id(true);
            
            // Store user data in session
            $_SESSION['user_id'] = $user_data['user_id'];
            $_SESSION['username'] = $user_data['username'];
            $_SESSION['full_name'] = $user_data['full_name'];
            $_SESSION['role'] = $role;
            $_SESSION['logged_in'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            
            // Store patient_id for patient and family roles
            if (isset($user_data['patient_id'])) {
                $_SESSION['patient_id'] = $user_data['patient_id'];
            }
            
            // Log successful login
            log_audit($user_id, $role, 'LOGIN', "User {$username} logged in successfully", get_client_ip());
            
            return $user_data;
        }
        
    } catch (PDOException $e) {
        error_log("Login Error: " . $e->getMessage());
        return false;
    }
    
    return false;
}

/**
 * Logout user and destroy session
 */
function logout() {
    if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
        // Log logout
        log_audit($_SESSION['user_id'], $_SESSION['role'], 'LOGOUT', "User {$_SESSION['username']} logged out", get_client_ip());
    }
    
    // Destroy session
    $_SESSION = [];
    session_destroy();
    
    // Start new session
    session_start();
}

/**
 * Check if user is authenticated
 * @return bool
 */
function is_authenticated() {
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

/**
 * Check if user has specific role
 * @param string|array $allowed_roles
 * @return bool
 */
function has_role($allowed_roles) {
    if (!is_authenticated()) {
        return false;
    }
    
    if (is_array($allowed_roles)) {
        return in_array($_SESSION['role'], $allowed_roles);
    }
    
    return $_SESSION['role'] === $allowed_roles;
}

/**
 * Require authentication - redirect to login if not authenticated
 */
function require_auth() {
    if (!is_authenticated()) {
        header('Location: ' . APP_URL . '/login.php');
        exit;
    }
}

/**
 * Require specific role - redirect if user doesn't have permission
 * @param string|array $allowed_roles
 */
function require_role($allowed_roles) {
    require_auth();
    
    if (!has_role($allowed_roles)) {
        header('Location: ' . APP_URL . '/access_denied.php');
        exit;
    }
}

/**
 * Get current user ID
 * @return int|null
 */
function get_current_user_id() {
    return $_SESSION['user_id'] ?? null;
}

/**
 * Get current user role
 * @return string|null
 */
function get_current_user_role() {
    return $_SESSION['role'] ?? null;
}

/**
 * Get current user full name
 * @return string|null
 */
function get_current_user_name() {
    return $_SESSION['full_name'] ?? null;
}

/**
 * Get current patient ID (for patient and family roles)
 * @return int|null
 */
function get_current_patient_id() {
    return $_SESSION['patient_id'] ?? null;
}

/**
 * Get client IP address
 * @return string
 */
function get_client_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    }
}

/**
 * Get dashboard URL for current user role
 * @return string
 */
function get_dashboard_url() {
    $role = get_current_user_role();
    
    switch ($role) {
        case 'admin':
            return APP_URL . '/admin/dashboard.php';
        case 'caregiver':
            return APP_URL . '/caregiver/dashboard.php';
        case 'patient':
            return APP_URL . '/patient/dashboard.php';
        case 'family':
            return APP_URL . '/family/dashboard.php';
        default:
            return APP_URL . '/login.php';
    }
}
?>

