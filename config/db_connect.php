<?php
/**
 * Health Monitoring System - Database Connection
 * Uses PDO for secure database operations
 */

require_once __DIR__ . '/config.php';

try {
    // Create PDO connection
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
    
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    
} catch (PDOException $e) {
    // Log error (in production, log to file instead of displaying)
    error_log("Database Connection Error: " . $e->getMessage());
    
    // Display user-friendly error
    die("Database connection failed. Please contact system administrator.");
}

/**
 * Helper function to execute queries with error handling
 */
function executeQuery($pdo, $sql, $params = []) {
    try {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    } catch (PDOException $e) {
        error_log("Query Error: " . $e->getMessage());
        return false;
    }
}

/**
 * Helper function to get single row
 */
function fetchOne($pdo, $sql, $params = []) {
    $stmt = executeQuery($pdo, $sql, $params);
    return $stmt ? $stmt->fetch() : false;
}

/**
 * Helper function to get all rows
 */
function fetchAll($pdo, $sql, $params = []) {
    $stmt = executeQuery($pdo, $sql, $params);
    return $stmt ? $stmt->fetchAll() : false;
}
?>
