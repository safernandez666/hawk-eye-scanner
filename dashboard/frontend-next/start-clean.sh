#!/bin/bash
# Inicia Next.js silenciando warnings de desarrollo

NEXT_TELEMETRY_DISABLED=1 node --no-deprecation node_modules/.bin/next dev 2>&1 | grep -v "DEP0060\|hot-update.json\|Fast Refresh"
