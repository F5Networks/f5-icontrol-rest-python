f5-icontrol-rest-python
=======================

|Build Status| |Documentation Status| |slack badge|

Introduction
------------

This generic python library allows programs and other modules to
interact with the BIG-IP® iControl® REST API.

Installation
------------

Using Pip
`````````

.. code:: bash

    $ pip install f5-icontrol-rest


Installing directly from GitHub
```````````````````````````````

**NOTE:** The example below installs the package at release v0.1.0.

.. code:: bash

    $ pip install git+ssh://git@github.com/F5Networks/f5-icontrol-rest@v0.1.0`


Configuration
-------------
N/A

Usage
-----

.. code:: python

    from icontrol.session import iControlRESTSession
    icr_session = iControlRESTSession('myuser', 'mypass')
    icr_session.get(
        'https://bigip.example.com/mgmt/tm/ltm/nat',
        name='mynat',
        partition='Common')


Documentation
-------------

See `Documentation <http://icontrol.readthedocs.org>`__.

Filing Issues
-------------

If you find an issue we would love to hear about it. Please let us know
by filing an issue in this repository and tell us as much as you can
about what you found and how you found it.

Contributing
------------

See `Contributing <CONTRIBUTING.md>`__.

Build
-----

To make a PyPI package:

.. code:: bash

    $ python setup.py sdist


Test
----
Before you open a pull request, your code must have passing `pytest <http://pytest.org>`__ unit tests. In addition, you should include a set of functional tests written to use a real BIG-IP® for testing. Information on how to run our set of tests is included below.

Unit Tests
``````````

We use pytest for our unit tests.

1. If you haven't already, install the required test packages listed in requirements.test.txt in your virtual
environment.

.. code:: shell

    $ pip install -r requirements.test.txt


2. Run the tests and produce a coverage report. The ``--cov-report=html``
   will create a ``htmlcov/`` directory that you can view in your browser to see the missing lines of code.

.. code:: shell

   $ py.test --cov ./icontrol --cov-report=html
   $ open htmlcov/index.html


Style Checks
````````````
We use the hacking module for our style checks (installed as part of
step 1 in the Unit Test section).

.. code:: shell

    $ flake8 ./

Copyright
---------
Copyright 2015-2016 F5 Networks Inc.

Support
-------
See `Support <SUPPORT.md>`_.

License
-------

Apache V2.0
```````````
Licensed under the Apache License, Version 2.0 (the "License"); you may
not use this file except in compliance with the License. You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Contributor License Agreement
`````````````````````````````
Individuals or business entities who contribute to this project must have completed and submitted the `F5 Contributor License Agreement <http://f5-openstack-docs.readthedocs.org/en/latest/cla_landing.html>`__ to Openstack\_CLA@f5.com prior to their code submission being included in this project.


.. |Build Status| image:: https://travis-ci.org/F5Networks/f5-icontrol-rest-python.svg?branch=develop
    :target: https://travis-ci.org/F5Networks/f5-icontrol-rest-python
.. |Documentation Status| image:: https://readthedocs.org/projects/icontrol/badge/?version=latest
   :target: http://icontrol.readthedocs.org/en/latest/?badge=latest
.. |slack badge| image:: https://f5-openstack-slack.herokuapp.com/badge.svg
    :target: https://f5-openstack-slack.herokuapp.com/
    :alt: Slack

