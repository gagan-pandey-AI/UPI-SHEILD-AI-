#!/bin/sh
set -eu

data_dir="${DATA_DIRECTORY:-/var/data}"
upload_dir="${UPLOAD_FOLDER:-${data_dir}/uploads}"
backup_dir="${BACKUP_DIRECTORY:-${data_dir}/backups}"
database_path="${DATABASE_PATH:-${data_dir}/database.db}"

export DATA_DIRECTORY="$data_dir"
export UPLOAD_FOLDER="$upload_dir"
export BACKUP_DIRECTORY="$backup_dir"
export DATABASE_PATH="$database_path"

mkdir -p "$data_dir" "$upload_dir" "$backup_dir" "$(dirname "$database_path")"
chown -R app:app "$data_dir"
if [ ! -e "$database_path" ]; then
    DATABASE_PATH="$database_path" gosu app python /app/initialize_empty_database.py
fi
exec gosu app "$@"
