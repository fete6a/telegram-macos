#/bin/sh
set -e

export PATH="$PATH:$HOME/.credentials"
. "$HOME/.credentials/variables.sh"
MAIN_REPOSITORY=$PWD
deploy_revision="$(sh "$MAIN_REPOSITORY/buildbox/verify-toolbox.sh" --revision)"
deploy_parent="$MAIN_REPOSITORY/.."
deploy_directory="$MAIN_REPOSITORY/../deploy"

if [ -z "${deploy_repository:-}" ]; then
    echo "deploy_repository must be set" >&2
    exit 1
fi

staged_directory="$(mktemp -d "$deploy_parent/deploy.staged.XXXXXX")"
cleanup_staged_directory() {
    if [ -n "${staged_directory:-}" ] && [ -d "$staged_directory" ]; then
        rm -rf "$staged_directory"
    fi
}
trap cleanup_staged_directory 0 1 2 15

git init "$staged_directory"
git -C "$staged_directory" remote add origin "$deploy_repository"
git -C "$staged_directory" fetch --no-tags origin "$deploy_revision"
fetched_revision="$(git -C "$staged_directory" rev-parse --verify 'FETCH_HEAD^{commit}')"
if [ "$fetched_revision" != "$deploy_revision" ]; then
    echo "Fetched deployment toolbox revision $fetched_revision does not match approved revision $deploy_revision" >&2
    exit 1
fi

git -C "$staged_directory" checkout --detach --force "$deploy_revision"
git -C "$staged_directory" clean -ffdx
sh "$MAIN_REPOSITORY/buildbox/verify-toolbox.sh" "$staged_directory"

previous_directory=""
if [ -e "$deploy_directory" ]; then
    previous_directory="$(mktemp -d "$deploy_parent/deploy.previous.XXXXXX")"
    rmdir "$previous_directory"
    mv "$deploy_directory" "$previous_directory"
fi

if ! mv "$staged_directory" "$deploy_directory"; then
    if [ -n "$previous_directory" ]; then
        mv "$previous_directory" "$deploy_directory"
    fi
    exit 1
fi
staged_directory=""

if [ -n "$previous_directory" ]; then
    rm -rf "$previous_directory"
fi
trap - 0 1 2 15
