<?php
/** Shared runtime helpers. Reads the per-instance config written by bootstrap.php. */

$DATA = getenv('APP_DATA') ?: '/var/www/data';
$CFG = require $DATA . '/instance.php';

session_name($CFG['sess_cookie']);          // renamed from PHPSESSID
session_start();

function cfg($k) { global $CFG; return $CFG[$k]; }

function db() {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . cfg('db'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    return $pdo;
}

function logged_in() { return !empty($_SESSION['uid']); }

function csrf_token() {
    if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); }
    return $_SESSION['csrf'];
}
function csrf_field() {
    return '<input type="hidden" name="' . htmlspecialchars(cfg('csrf_field')) .
           '" value="' . csrf_token() . '">';
}
function csrf_ok() {
    $f = cfg('csrf_field');
    return isset($_POST[$f]) && hash_equals($_SESSION['csrf'] ?? '', $_POST[$f]);
}

function e($s) { return htmlspecialchars((string)$s, ENT_QUOTES); }

/** Minimal neutral chrome. Deliberately carries no DVWA/version/footer fingerprint. */
function render($title, $body) {
    $app = e(cfg('app_name'));
    $nav = '<a href="/">Home</a>';
    if (logged_in()) {
        $nav .= ' &middot; <a href="' . e(cfg('routes')['lookup']) . '">Records</a>' .
                ' &middot; <a href="' . e(cfg('routes')['netcheck']) . '">Diagnostics</a>' .
                ' &middot; <a href="' . e(cfg('routes')['fileview']) . '">Documents</a>' .
                ' &middot; <a href="' . e(cfg('routes')['search']) . '">Directory</a>' .
                ' &middot; <a href="' . e(cfg('routes')['signout']) . '">Sign out</a>';
    } else {
        $nav .= ' &middot; <a href="' . e(cfg('routes')['signin']) . '">Sign in</a>' .
                ' &middot; <a href="' . e(cfg('routes')['handbook']) . '">Handbook</a>';
    }
    echo "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" .
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" .
         "<title>" . e($title) . " &ndash; $app</title><style>" .
         "body{font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#1d2733;background:#f4f6f9}" .
         "header{background:#2b3a4a;color:#fff;padding:14px 22px}header h1{margin:0;font-size:18px;font-weight:600}" .
         "nav{padding:9px 22px;background:#e7ecf2;font-size:13px}nav a{color:#2b3a4a;text-decoration:none}" .
         "main{max-width:760px;margin:22px auto;padding:0 18px}" .
         ".card{background:#fff;border:1px solid #d9e0e8;border-radius:8px;padding:20px;margin-bottom:18px}" .
         "label{display:block;font-size:13px;color:#56636f;margin:10px 0 4px}" .
         "input[type=text],input[type=password]{width:100%;max-width:320px;padding:8px;border:1px solid #c2ccd6;border-radius:5px}" .
         "button{margin-top:14px;background:#2f6db0;color:#fff;border:0;padding:9px 18px;border-radius:5px;cursor:pointer}" .
         ".res{background:#f1f5f9;border-left:3px solid #2f6db0;padding:10px 14px;margin-top:14px;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;font-size:13px}" .
         ".err{color:#9b2226}.muted{color:#56636f;font-size:13px}" .
         "</style></head><body><header><h1>$app</h1></header><nav>$nav</nav><main>$body</main></body></html>";
}
