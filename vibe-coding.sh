#!/usr/bin/env bash

set -e

HERE="$(dirname "$(readlink -f "${0}")")"



export AGENT_HOME="$HERE/.agent"
export OPENHANDS_HOME="$HOME/.openhands"
export PROJECTS_PATH="$OPENHANDS_HOME/projects"
export PROJECT_NAME="$(basename $HERE)"


declare -a MOUNTS=(
    "$AGENT_HOME/.local:/home/openhands/.local"
    "$AGENT_HOME/.cache:/home/openhands/.cache"
    "$AGENT_HOME/.cargo:/home/openhands/.cargo"
    "$AGENT_HOME/.rustup:/home/openhands/.rustup"
    "$AGENT_HOME/.nvm:/home/openhands/.nvm"
    "$OPENHANDS_HOME:/home/openhands/.openhands"
    "$PROJECTS_PATH:/projects"
)


mkdir -p ${MOUNTS[@]%%:*}

declare -a VOLUME_ARGS=()
for m in "${MOUNTS[@]}"; do VOLUME_ARGS+=("-v" "${m}:Z"); done


podman run -it --rm \
  -p 8000:8000 \
  --name "openhands-$PROJECT_NAME"\
  --userns=keep-id:uid=10001,gid=10001 \
  --cap-add=NET_RAW \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  -v /etc/ca-certificates:/etc/ca-certificates:ro \
  "${VOLUME_ARGS[@]}" \
  -v "$HERE:/projects/$PROJECT_NAME" \
  ghcr.io/openhands/agent-canvas:1.0.0-rc.11