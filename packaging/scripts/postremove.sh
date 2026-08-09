#!/bin/sh
# Postremove hook (#412 req 11): a clean uninstall leaves no orphan files outside the documented state
# directory.
#
# Removing the package deletes the files it owns, but neither rpm nor dpkg removes a DIRECTORY that
# once held a config file — so /etc/synapse-agent survives an erase as an empty orphan. The matrix job
# caught this on the rpm row: `dpkg --purge` happens to clean it, `rpm -e` does not, and a difference
# between package formats in what uninstall leaves behind is exactly the kind of thing nobody notices
# until an auditor asks.
#
# It is removed ONLY when it is empty and ONLY on a final removal. An operator who left something in
# /etc/synapse-agent — a site config, a token file — keeps it; deleting an operator's file during an
# uninstall would be worse than leaving an empty directory. On upgrade nothing is removed at all.
set -eu

# rpm passes the remaining-instance count ("0" on final erase, >=1 on upgrade).
# dpkg passes an action word ("remove", "purge", "upgrade", ...).
case "${1:-}" in
0 | remove | purge) ;;
*) exit 0 ;;
esac

if [ -d /etc/synapse-agent ] && [ -z "$(ls -A /etc/synapse-agent 2>/dev/null)" ]; then
    rmdir /etc/synapse-agent
fi

exit 0
