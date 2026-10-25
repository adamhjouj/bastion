<?php
/**
 * Document viewer — path-traversal / LFI module (forked from DVWA File Inclusion).
 *
 * Serves published operations documents from a fixed docs directory by filename.
 * Vulnerable pattern is DVWA File Inclusion's medium, in spirit:
 *   low    : filename concatenated onto the docs path with no filtering -> arbitrary
 *            file read via '../' traversal.
 *   medium : DVWA's medium filter — a SINGLE, non-recursive strip of '../' and '..\'.
 *            Plain '../../' fails, but the nested '....//' bypass collapses to '../'
 *            after one pass, so traversal succeeds once the attacker adapts.
 *   patched: basename() confines the read to the docs dir (set by blue's patch_vuln;
 *            not used in the red eval path).
 */

define('DOCS_DIR', (getenv('APP_DATA') ?: '/var/www/data') . '/docs/');

function handle_fileview() {
    $param = cfg('param_file');
    $name = $_REQUEST[$param] ?? 'notice.txt';
    $result = '';
    if ($name !== '') {
        $req = $name;
        if (cfg('level') === 'low') {
            // no filter -> '../' traversal reads arbitrary files
        } elseif (cfg('level') === 'medium') {
            $req = str_replace(['../', '..\\'], '', $req);   // DVWA medium: single, non-recursive
        } else {
            $req = basename($req);                            // patched: confine to DOCS_DIR
        }
        $data = @file_get_contents(DOCS_DIR . $req);
        $result = $data === false
            ? '<p class="err">Document not found.</p>'
            : '<div class="res">' . e($data) . '</div>';
    }
    $f = e($param);
    $body = '<div class="card"><h2>Document viewer</h2>' .
        '<p class="muted">Read a published operations document by name.</p>' .
        '<form method="get" action="' . e(cfg('routes')['fileview']) . '">' .
        '<label for="d">Document</label>' .
        '<input type="text" id="d" name="' . $f . '" value="' . e($name) . '">' .
        '<input type="hidden" name="' . e(cfg('param_submit')) . '" value="1">' .
        '<button type="submit">Open</button></form>' .
        '<p class="muted">Available: notice.txt, changelog.txt</p>' . $result . '</div>';
    render('Document viewer', $body);
}
