#!/bin/bash
#
if [[ -f /tmp/healthcheck.inc ]]
then
  source /tmp/healthcheck.inc
  healthy=true
  for p in "${!PIDS[@]}"
  do
    if ! kill -0 "${PIDS[$p]}" 2>/dev/null
    then
      echo "$p FAIL"
      healthy=false
    fi
  done
  if $healthy
  then
    echo "OK"
    exit 0
  else
    exit 1
  fi
else
  echo "MISSING PID FILE"
  exit 1
fi
