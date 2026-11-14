#/bin/sh
set -e

TOOLBOX_DIRECTORY="$PWD/../deploy"
sh ./buildbox/verify-toolbox.sh "$TOOLBOX_DIRECTORY"
export PATH="$PATH:$TOOLBOX_DIRECTORY"
export PATH="$PATH:$HOME/.fastlane/bin"
export PATH="$PATH:/opt/homebrew/bin"



tag="$1"
BUILD_OUTPUT="${TELEGRAM_BUILD_ROOT:-$HOME}/build-$tag"

lock="$HOME/telegram-build.lock"
if [ -z "$TELEGRAM_BUILD_LOCK_HELD" ]; then
    if ! lockf -k -t 0 "$lock" true 2>/dev/null; then
        echo "Another Telegram build is running on this machine, waiting for it: $(cat "$lock.owner" 2>/dev/null)"
    fi
    export TELEGRAM_BUILD_LOCK_HELD=1
    exec lockf -k -t 10800 "$lock" sh "$0" "$@"
fi
echo "job ${CI_JOB_ID:-manual} $tag $(git rev-parse --short HEAD) since $(date -u '+%Y-%m-%d %H:%M:%S UTC')" > "$lock.owner"

export CI_BUILD_LOG_DIR="$PWD/.ci-build-logs/${CI_JOB_ID:-manual}"
mkdir -p "$CI_BUILD_LOG_DIR"
export BUILD_TIMING_LOG="$CI_BUILD_LOG_DIR/timings.tsv"
printf 'stage\tseconds\texit_code\n' > "$BUILD_TIMING_LOG"

sh ./buildbox/stop-leftover-builds.sh

sh ./scripts/time-step.sh build sh ./buildbox/build-mac.sh "$tag"
sh ./scripts/time-step.sh verify sh ./buildbox/verify-build.sh "$BUILD_OUTPUT" "$PWD"
sh ./buildbox/verify-toolbox.sh "$TOOLBOX_DIRECTORY"
sh ./scripts/time-step.sh deploy sh "$TOOLBOX_DIRECTORY/deploy-$tag.sh" "$BUILD_OUTPUT" "$PWD" Telegram.app ~/.credentials/dsa-$tag
mv "$BUILD_OUTPUT.app-size.pending" "$BUILD_OUTPUT.app-size"
