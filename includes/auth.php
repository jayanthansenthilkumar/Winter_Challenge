<?php
function checkUserAccess($isPublic = false)
{
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.gc_maxlifetime', 3600);
        session_set_cookie_params(0);
        session_start();
    }

    // If public page and NOT logged in, just return (allow access)
    if ($isPublic && !isset($_SESSION['user_id'])) {
        return;
    }

    // If protected page and NOT logged in, redirect to login
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit();
    }

    // Check session timeout (30 minutes = 1800 seconds)
    // Using sliding expiration: Update time on every activity
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 1800)) {
        // Session has expired
        session_unset();
        session_destroy();
        header('Location: login.php?timeout=1');
        exit();
    }
    // Update last activity time to current time to keep session alive
    $_SESSION['last_activity'] = time();

    // Get current page and user info
    $current_page = basename($_SERVER['PHP_SELF']);
    $user_role = $_SESSION['role'] ?? '';

    // Define allowed pages for each role
    $allowed_pages = [
        'admin' => [
            'adminDashboard.php', 'users.php', 'accounts.php', 'transactions.php',
            'alerts.php', 'analytics.php', 'fraudRules.php', 'auditLog.php',
            'messages.php', 'profile.php', 'settings.php', 'database.php'
        ],
        'analyst' => [
            'analystDashboard.php', 'transactions.php', 'alerts.php',
            'analytics.php', 'fraudRules.php', 'messages.php', 'profile.php'
        ],
        'customer' => [
            'customerDashboard.php', 'transactions.php', 'accounts.php',
            'messages.php', 'profile.php'
        ]
    ];

    // Determine Dashboard for redirect
    $dashboards = [
        'admin' => 'adminDashboard.php',
        'analyst' => 'analystDashboard.php',
        'customer' => 'customerDashboard.php'
    ];

    // Check access rights
    if (array_key_exists($user_role, $allowed_pages)) {
        if (!in_array($current_page, $allowed_pages[$user_role])) {
            // Unauthorized page for this role -> destroy session
            session_unset();
            session_destroy();
            header('Location: login.php');
            exit();
        }
    } else {
        // Invalid role
        session_unset();
        session_destroy();
        header('Location: login.php');
        exit();
    }

    // Verify sessionStorage data exists (Frontend Check)
    echo "<script>
        if (!sessionStorage.getItem('userData')) {
            // sessionStorage missing - optional: redirect to logout
        }
    </script>";
}

// Prevent caching for all authenticated pages
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
?>
