#!/bin/bash -ex

SRC_DIR=$1
pushd $SRC_DIR
PKG_VERSION=$(python -c "import icontrol; print(icontrol.__version__)")

PKG_NAME="f5-icontrol-rest"

TMP_DIST="/var/deb_dist"
OS_VERSION="1404"
DIST_DIR="f5-icontrol-rest-dist/deb_dist"

echo "Building ${PKG_NAME} debian packages..."

cp -R "${SRC_DIR}/${DIST_DIR}" ${TMP_DIST}
pwd
python setup.py --command-packages=stdeb.command sdist_dsc  --dist-dir=${TMP_DIST}
pushd "${TMP_DIST}/${PKG_NAME}-${PKG_VERSION}"
dpkg-buildpackage -rfakeroot -uc -us
popd; popd

pkg="python-${PKG_NAME}_${PKG_VERSION}-1_all.deb"
cp "${TMP_DIST}/${pkg}" "${SRC_DIR}/${DIST_DIR}/${pkg%%_all.deb}_${OS_VERSION}_all.deb"
