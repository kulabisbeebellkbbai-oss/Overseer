#!/bin/sh
set -eu

EXPECTED_ARCHIVE_SHA3_256=454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338
EXPECTED_BINARY_SHA256=ca4c66d9a6b3d24b27e05f8d1cfd7ae620e5862df39c96164910885797d6fc2e

if [ "$#" -ne 2 ]; then
    echo "usage: $0 SQLITE_AUTOCONF_ARCHIVE NEW_OUTPUT_DIRECTORY" >&2
    exit 2
fi

archive=$1
output_directory=$2
case "$archive" in
    /*) ;;
    *) echo "archive must be an absolute path" >&2; exit 2 ;;
esac
case "$output_directory" in
    /*) ;;
    *) echo "output directory must be an absolute path" >&2; exit 2 ;;
esac
if [ ! -f "$archive" ] || [ -L "$archive" ]; then
    echo "archive must be a regular non-symlink file" >&2
    exit 2
fi
if [ -e "$output_directory" ] || [ -L "$output_directory" ]; then
    echo "output directory must not already exist" >&2
    exit 2
fi

archive_digest=$(/usr/bin/openssl dgst -sha3-256 "$archive" | /usr/bin/awk '{print $NF}')
if [ "$archive_digest" != "$EXPECTED_ARCHIVE_SHA3_256" ]; then
    echo "SQLite source archive digest is not approved" >&2
    exit 1
fi

build_directory=$(/usr/bin/mktemp -d /tmp/overseer-sqlite-build.XXXXXX)
cleanup() {
    /usr/bin/find "$build_directory" -depth -delete
}
trap cleanup EXIT HUP INT TERM

/usr/bin/tar -xzf "$archive" -C "$build_directory"
source_file=$build_directory/sqlite-autoconf-3530400/sqlite3.c
candidate=$build_directory/libsqlite3.so.0
if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    echo "approved SQLite amalgamation is missing" >&2
    exit 1
fi

/usr/bin/gcc \
    -O2 \
    -fPIC \
    -shared \
    -Wl,-soname,libsqlite3.so.0 \
    -DSQLITE_THREADSAFE=1 \
    -DSQLITE_DEFAULT_AUTOVACUUM=1 \
    -DSQLITE_DEFAULT_CACHE_SIZE=-2000 \
    -DSQLITE_DEFAULT_RECURSIVE_TRIGGERS=1 \
    -DSQLITE_DEFAULT_SYNCHRONOUS=2 \
    -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=2 \
    -DSQLITE_DEFAULT_WORKER_THREADS=0 \
    -DSQLITE_DIRECT_OVERFLOW_READ \
    -DSQLITE_ENABLE_COLUMN_METADATA \
    -DSQLITE_ENABLE_DBPAGE_VTAB \
    -DSQLITE_ENABLE_DBSTAT_VTAB \
    -DSQLITE_ENABLE_FTS3 \
    -DSQLITE_ENABLE_FTS3_PARENTHESIS \
    -DSQLITE_ENABLE_FTS3_TOKENIZER \
    -DSQLITE_ENABLE_FTS4 \
    -DSQLITE_ENABLE_FTS5 \
    -DSQLITE_ENABLE_LOAD_EXTENSION \
    -DSQLITE_ENABLE_MATH_FUNCTIONS \
    -DSQLITE_ENABLE_PREUPDATE_HOOK \
    -DSQLITE_ENABLE_RTREE \
    -DSQLITE_ENABLE_SESSION \
    -DSQLITE_ENABLE_STMTVTAB \
    -DSQLITE_ENABLE_UNLOCK_NOTIFY \
    -DSQLITE_ENABLE_UPDATE_DELETE_LIMIT \
    -DSQLITE_SECURE_DELETE \
    -DSQLITE_SOUNDEX \
    -DSQLITE_USE_URI \
    -DSQLITE_MAX_VARIABLE_NUMBER=250000 \
    "$source_file" \
    -o "$candidate" \
    -lm \
    -ldl \
    -lpthread

binary_digest=$(/usr/bin/sha256sum "$candidate" | /usr/bin/awk '{print $1}')
if [ "$binary_digest" != "$EXPECTED_BINARY_SHA256" ]; then
    echo "reproduced SQLite binary digest is not approved" >&2
    exit 1
fi

/usr/bin/install -d -m 0700 "$output_directory"
/usr/bin/install -m 0555 "$candidate" "$output_directory/libsqlite3.so.0"
/usr/bin/printf '%s  %s\n' "$binary_digest" "$output_directory/libsqlite3.so.0"
