#!/bin/sh
set -e

export PATH="$PATH:$HOME/.credentials"
. "$HOME/.credentials/variables.sh"

if [ -z "${deploy_revision:-}" ]; then
    echo "deploy_revision must be set to an approved deployment toolbox commit" >&2
    exit 1
fi

case "$deploy_revision" in
    *[!0-9a-f]*)
        echo "deploy_revision must be a lowercase hexadecimal commit object ID" >&2
        exit 1
        ;;
esac

case "${#deploy_revision}" in
    40|64)
        ;;
    *)
        echo "deploy_revision must be a full 40- or 64-character commit object ID" >&2
        exit 1
        ;;
esac

if [ "${1:-}" = "--revision" ]; then
    printf '%s\n' "$deploy_revision"
    exit 0
fi

toolbox_directory="${1:-$PWD/../deploy}"
checked_out_revision="$(git -C "$toolbox_directory" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" || {
    echo "Deployment toolbox is not a valid Git checkout: $toolbox_directory" >&2
    exit 1
}

if [ "$checked_out_revision" != "$deploy_revision" ]; then
    echo "Deployment toolbox revision $checked_out_revision does not match approved revision $deploy_revision" >&2
    exit 1
fi

if ! git -C "$toolbox_directory" diff-index --quiet "$deploy_revision" --; then
    echo "Deployment toolbox has tracked changes" >&2
    exit 1
fi

untracked_files="$(git -C "$toolbox_directory" ls-files --others --exclude-standard)"
ignored_files="$(git -C "$toolbox_directory" ls-files --others --ignored --exclude-standard)"
if [ -n "$untracked_files$ignored_files" ]; then
    echo "Deployment toolbox has untracked or ignored files" >&2
    exit 1
fi

printf 'Using deployment toolbox revision %s\n' "$checked_out_revision"

