#!/bin/sh
cmd64=''; pass=0
while [ $# -gt 0 ]; do
  case "$1" in
    --command-b64) cmd64=$2; shift 2;;
    --password-stdin) pass=1; shift;;
    --host|--port|--user|--known-hosts|--key) shift 2;;
    --accept-new) shift;;
    *) shift;;
  esac
done
[ "$pass" -eq 1 ] && IFS= read -r _pw
cmd=$(printf '%s' "$cmd64" | base64 -d 2>/dev/null)
case "$cmd" in
  *'printf PGSEC_SSH_OK'*) printf 'PGSEC_SSH_OK\n';;
  *'docker ps -a --no-trunc'*) printf 'abc123456789|pg-prod|postgres:16.15|Up 5 days|127.0.0.1:5432->5432/tcp\n';;
  *'docker inspect'*) printf '%s\n' '[{"Id":"abc123456789","Name":"/pg-prod","Config":{"Image":"postgres:16.15","User":"999:999","Env":["POSTGRES_DB=app","POSTGRES_PASSWORD=hidden"]},"HostConfig":{"Privileged":false,"CapAdd":[],"SecurityOpt":["no-new-privileges:true"],"ReadonlyRootfs":false,"PortBindings":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]},"NetworkMode":"bridge","PidMode":""},"Mounts":[{"Source":"/srv/pgdata","Destination":"/var/lib/postgresql/data","RW":true,"Type":"bind"}]}]';;
  *'SHOW server_version;'*) printf '16.15\n';;
  *'SHOW data_directory;'*) printf '/var/lib/postgresql/data\n';;
  *'SHOW config_file;'*) printf '/var/lib/postgresql/data/postgresql.conf\n';;
  *'SHOW hba_file;'*) printf '/var/lib/postgresql/data/pg_hba.conf\n';;
  *'command -v postgres'*) printf '/usr/local/bin/postgres\n';;
  *'command -v psql'*) printf '/usr/local/bin/psql\n';;
  *'postgres --version'*) printf 'postgres (PostgreSQL) 16.15\n';;
  *'psql --version'*) printf 'psql (PostgreSQL) 16.15\n';;
  *'ps -eo pid,args'*) printf '101 postgres -D /var/lib/postgresql/data\n';;
  *'find /etc /var/lib'*) printf '/var/lib/postgresql/data/postgresql.conf\n/var/lib/postgresql/data/pg_hba.conf\n';;
  *'cat /etc/os-release'*) printf 'NAME=RemoteSimulation\nID=sim\n';;
  *'uname -r'*) printf '6.8.0-sim\n';;
  *'uname -m'*) printf 'x86_64\n';;
  *'id -un'*) printf 'audit\n';;
  *'hostname'*) printf 'remote-sim\n';;
  *'docker version'*) :;;
  *'podman version'*) exit 1;;
  *) :;;
esac
exit 0
