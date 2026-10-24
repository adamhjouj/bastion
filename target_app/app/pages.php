<?php
/** Public + auth pages: landing, sign-in (CSRF-protected), handbook, sign-out. */

function handle_home() {
    $r = cfg('routes');
    if (logged_in()) {
        $body = '<div class="card"><h2>Welcome back</h2>' .
            '<p>Signed in as <strong>' . e($_SESSION['uname']) . '</strong>.</p>' .
            '<p>Internal tools:</p><ul>' .
            '<li><a href="' . e($r['lookup']) . '">Record lookup</a></li>' .
            '<li><a href="' . e($r['netcheck']) . '">Network diagnostics</a></li>' .
            '</ul></div>';
    } else {
        $body = '<div class="card"><h2>Operations portal</h2>' .
            '<p class="muted">Internal tooling for support and operations staff. ' .
            'Access requires an operator account.</p>' .
            '<p><a href="' . e($r['signin']) . '">Sign in</a> &middot; ' .
            'New here? See the <a href="' . e($r['handbook']) . '">operator handbook</a>.</p></div>';
    }
    render('Home', $body);
}

function handle_signin() {
    $r = cfg('routes');
    $msg = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!csrf_ok()) {
            $msg = '<p class="err">Session expired, please retry.</p>';
        } else {
            $u = $_POST[cfg('field_user')] ?? '';
            $p = $_POST[cfg('field_pass')] ?? '';
            $stmt = db()->prepare(sprintf('SELECT %s,%s FROM %s WHERE %s = ?',
                cfg('c_id'), cfg('c_user'), cfg('tbl'), cfg('c_user')));
            $stmt->execute([$u]);
            $row = $stmt->fetch(PDO::FETCH_NUM);
            $hash = null;
            if ($row) {
                $h = db()->prepare(sprintf('SELECT %s FROM %s WHERE %s = ?',
                    cfg('c_pass'), cfg('tbl'), cfg('c_user')));
                $h->execute([$u]);
                $hash = $h->fetchColumn();
            }
            if ($hash !== null && hash_equals($hash, md5($p))) {
                $_SESSION['uid'] = $row[0];
                $_SESSION['uname'] = $row[1];
                header('Location: /');
                return;
            }
            $msg = '<p class="err">Invalid credentials.</p>';
        }
    }
    $body = '<div class="card"><h2>Sign in</h2>' . $msg .
        '<form method="post" action="' . e($r['signin']) . '">' . csrf_field() .
        '<label>Operator ID</label>' .
        '<input type="text" name="' . e(cfg('field_user')) . '" autocomplete="off">' .
        '<label>Passphrase</label>' .
        '<input type="password" name="' . e(cfg('field_pass')) . '">' .
        '<input type="hidden" name="' . e(cfg('field_submit')) . '" value="1">' .
        '<button type="submit">Sign in</button></form>' .
        '<p class="muted">Lost your credentials? They are listed in the ' .
        '<a href="' . e($r['handbook']) . '">operator handbook</a>.</p></div>';
    render('Sign in', $body);
}

/** Discoverable (by recon) non-default credentials — realistic "onboarding note". */
function handle_handbook() {
    $body = '<div class="card"><h2>Operator handbook</h2>' .
        '<p class="muted">Evaluation build. A demo operator account is pre-provisioned so ' .
        'reviewers can sign in without IT.</p>' .
        '<p>Operator ID: <strong>' . e(cfg('operator_user')) . '</strong><br>' .
        'Passphrase: <strong>' . e(cfg('operator_pass')) . '</strong></p>' .
        '<p class="muted">Rotate these before any non-evaluation use.</p></div>';
    render('Operator handbook', $body);
}

function handle_signout() {
    $_SESSION = [];
    session_destroy();
    header('Location: /');
}
