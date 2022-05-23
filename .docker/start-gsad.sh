#!/bin/sh

[ -z "$GSAD_ARGS" ] && GSAD_ARGS="--http-only"

echo "starting gsad"
gsad $GSAD_ARGS ||
	(cat /var/log/gvm/gsad.log && exit 1)

tail -f /var/log/gvm/gsad.log
