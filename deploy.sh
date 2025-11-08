#!/usr/bin/env bash
set -euo pipefail
action=${1:-deploy}
if [ "$action" = "deploy" ]; then
  cdk deploy --all --require-approval never
elif [ "$action" = "destroy" ]; then
  cdk destroy --all --force
else
  echo "Usage: $0 [deploy|destroy]"
  exit 1
fi
