<?php
/** Front controller: matches the per-instance generated paths to handlers. */
require '/var/www/app/core.php';
require '/var/www/app/pages.php';
require '/var/www/app/modules/lookup.php';
require '/var/www/app/modules/netcheck.php';

$path = rtrim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
if ($path === '') { $path = '/'; }
$r = cfg('routes');

// Routes requiring an authenticated session.
$protected = [$r['lookup'] => 'handle_lookup', $r['netcheck'] => 'handle_netcheck'];
$public    = [
    '/'            => 'handle_home',
    '/index.php'   => 'handle_home',
    $r['signin']   => 'handle_signin',
    $r['handbook'] => 'handle_handbook',
    $r['signout']  => 'handle_signout',
];

if (isset($public[$path])) {
    $public[$path]();
} elseif (isset($protected[$path])) {
    if (!logged_in()) {
        header('Location: ' . $r['signin']);
        exit;
    }
    $protected[$path]();
} else {
    http_response_code(404);
    render('Not found', '<div class="card"><h2>404</h2><p class="muted">No such page.</p></div>');
}
