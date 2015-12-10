#!/usr/bin/env python

# Copyright 2015 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import sys

from distutils.core import setup

if 'PROJECT_DIR' in os.environ:
    project_dir = os.environ['PROJECT_DIR']
else:
    project_dir = os.path.curdir

if 'bdist_deb' in sys.argv:
    stdebcfg = open('stdeb.cfg', 'w')
    stdebcfg.write('[DEFAULT]\n')
    stdebcfg.write('Package: f5-bigip-common\n')
    stdebcfg.write('Debian-Version: ' + release + '\n')
    stdebcfg.write('Depends: python-suds\n')
    stdebcfg.close()

if 'bdist_rpm' in sys.argv:
    setupcfg = open('setup.cfg', 'w')
    setupcfg.write('[bdist_rpm]\n')
    setupcfg.write('release=%s\n' % release)
    setupcfg.write('requires=python-suds > 0.3\n')
    setupcfg.close()

setup(name='f5-icontrol-rest',
      description='F5 Python REST client',
      long_description='F5 Python REST client',
      license='Apache License, Version 2.0',
      version='1.0.0',
      author='F5 DevCentral',
      author_email='devcentral@f5.com',
      url='http://devcentral.f5.com/openstack',
      py_modules=[
                  'icontrol.session',
      ],
      packages=['icontrol'],
      classifiers=['Development Status :: 5 - Production/Stable',
                   'License :: OSI Approved :: Apache Software License',
                   'Environment :: OpenStack',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Intended Audience :: System Administrators']
      )
