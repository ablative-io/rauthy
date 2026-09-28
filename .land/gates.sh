#!/bin/sh
# Run every declared fork gate in the owned PostgreSQL test environment.
set -eu
exec sh .land/test.sh
