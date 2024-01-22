#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2024  The DOSBox Staging Team

# Repackages the Windows ZIP release package generated by the CI workflow
# under a parent directory.
#
# Prerequisites: zip & unzip commands

set -e

if [ $# -ne 1 ]; then
	echo "Usage: repackage-windows-zip.sh MSYS2_ZIP_NAME"
	exit 1
fi

IN_ZIP=$1
IN_ZIP_PREFIX=dosbox-staging-windows-msys2-x86_64-

if [[ $IN_ZIP != $IN_ZIP_PREFIX* ]]; then
	echo "Input filename must start with '$IN_ZIP_PREFIX'"
	exit 1
fi

function strip {
	local STRING=${1#$"$2"}
	echo "${STRING%$"$2"}"
}

VERSION=$(strip "$IN_ZIP" $IN_ZIP_PREFIX)
ROOT_DIR=dosbox-staging-$VERSION
OUT_ZIP=dosbox-staging-windows-$VERSION

RMDIR_CMD="rm -rf $ROOT_DIR"
MKDIR_CMD="mkdir $ROOT_DIR"
EXTRACT_CMD="unzip $IN_ZIP -d $ROOT_DIR"
ZIP_CMD="zip -r $OUT_ZIP $ROOT_DIR"

$RMDIR_CMD
$MKDIR_CMD
$EXTRACT_CMD
$ZIP_CMD
$RMDIR_CMD

