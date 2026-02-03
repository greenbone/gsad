#!/bin/sh

[ -z "$GSAD_ARGS" ] && GSAD_ARGS="-f --http-only"

echo "starting gsad with args ${GSAD_ARGS}"
gsad $GSAD_ARGS 2>&1 | tee /var/log/gvm/gsad.log
