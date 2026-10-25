#!/bin/sh
# Re-mutate the instance on every boot (Option C: per-deploy randomization),
# then hand off to Apache. Set BASTION_SEED to reproduce a fixed instance.
set -e
php /var/www/bootstrap.php
chown -R www-data:www-data /var/www/data
exec "$@"
