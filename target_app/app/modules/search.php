<?php
/**
 * Staff directory search — reflected XSS module (forked from DVWA XSS reflected).
 *
 * Echoes the user's query back into the page. Vulnerable pattern is DVWA's reflected
 * XSS medium, faithful:
 *   low    : query echoed with no filtering -> any payload reflects and executes.
 *   medium : DVWA medium strips a literal '<script>' (case-sensitive, single pass), so
 *            case variation (<ScRiPt>) or a non-<script> vector (<img onerror>) bypasses it.
 *   patched: htmlspecialchars-encode the reflection -> inert. In this lab the blue team
 *            instead virtual-patches the exploit at the proxy (a real server-side fix a
 *            reverse proxy can author without editing the app), so this branch is unused
 *            on the red eval path.
 */

function handle_search() {
    $param = cfg('param_q');
    $q = $_REQUEST[$param] ?? '';
    $echo = '';
    if ($q !== '') {
        $out = $q;
        if (cfg('level') === 'low') {
            // no filtering -> reflected XSS
        } elseif (cfg('level') === 'medium') {
            $out = str_replace('<script>', '', $out);   // DVWA medium: literal, case-sensitive, single pass
        } else {
            $out = e($out);                               // patched: output-encoded (inert)
        }
        // The reflection is the sink: $out is echoed unescaped at low/medium.
        $echo = '<p class="muted">No staff member matches &ldquo;' . $out . '&rdquo;.</p>';
    }
    $f = e($param);
    $body = '<div class="card"><h2>Staff directory</h2>' .
        '<p class="muted">Search the internal staff directory by name.</p>' .
        '<form method="get" action="' . e(cfg('routes')['search']) . '">' .
        '<label for="q">Name</label>' .
        '<input type="text" id="q" name="' . $f . '" value="' . e($q) . '">' .
        '<input type="hidden" name="' . e(cfg('param_submit')) . '" value="1">' .
        '<button type="submit">Search</button></form>' . $echo . '</div>';
    render('Staff directory', $body);
}
