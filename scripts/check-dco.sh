#!/usr/bin/env sh
# Fails if any non-merge commit in BASE..HEAD lacks a Signed-off-by trailer
# matching its author (Developer Certificate of Origin, see CONTRIBUTING.md).
#   scripts/check-dco.sh origin/main HEAD
set -eu
base="$1"
head="$2"
status=0
for commit in $(git rev-list --no-merges "$base..$head"); do
    author="$(git log -1 --format='%an <%ae>' "$commit")"
    if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" | grep -Fqx "$author"; then
        echo "missing 'Signed-off-by: $author' on $(git log -1 --format='%h %s' "$commit")"
        status=1
    fi
done
[ "$status" -eq 0 ] && echo "all commits in $base..$head are signed off"
exit "$status"
