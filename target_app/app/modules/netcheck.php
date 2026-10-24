<?php
/**
 * Network diagnostics — command injection module (forked from DVWA vulnerabilities/exec).
 *
 * Vulnerable pattern is DVWA's, verbatim in spirit:
 *   low    : user input concatenated straight into a shell command.
 *   medium : blacklist strips '&&' and ';' only -> '|', '&', backticks, '$()'
 *            still get through, so injection succeeds after the attacker adapts.
 */

function handle_netcheck() {
    $param = cfg('param_host');
    $result = '';
    if (isset($_REQUEST[$param]) && $_REQUEST[$param] !== '') {
        $target = $_REQUEST[$param];
        if (cfg('level') === 'low') {
            // no filter -> straight shell injection
        } elseif (cfg('level') === 'medium') {
            // medium blacklist (identical to DVWA medium)
            $target = str_replace(['&&', ';'], '', $target);
        } else {
            // patched (high/impossible): pass as ONE shell-escaped argument -> no injection.
            // Set by the blue-team patch_vuln remediation; not used in the red eval path.
            $target = escapeshellarg($target);
        }
        $out = shell_exec('ping -c 3 ' . $target . ' 2>&1');
        $result = '<div class="res">' . e($out) . '</div>';
    }
    $f = e($param);
    $body = '<div class="card"><h2>Network diagnostics</h2>' .
        '<p class="muted">Check reachability of an internal host (sends 3 ICMP echoes).</p>' .
        '<form method="get" action="' . e(cfg('routes')['netcheck']) . '">' .
        '<label for="h">Host / address</label>' .
        '<input type="text" id="h" name="' . $f . '" value="' . e($_REQUEST[$param] ?? '') . '">' .
        '<input type="hidden" name="' . e(cfg('param_submit')) . '" value="1">' .
        '<button type="submit">Run check</button></form>' . $result . '</div>';
    render('Network diagnostics', $body);
}
