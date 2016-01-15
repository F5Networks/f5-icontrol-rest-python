.. f5-icontrol-rest documentation master file, created by
   sphinx-quickstart on Wed Jan 13 16:34:27 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

F5 Networks icontrol documentation
=================================================

Introduction
-------------
The F5 Networks :mod:`icontrol` module is used to send commands to the `BIGIP
iControl REST API <https://devcentral.f5.com/d/icontrol-rest-user-guide>`_.
The library maintains a HTTP session (which is a :class:`requests.Session`) and
does URL validation and logging.

Installation
-------------
Using Pip
+++++++++
.. code-block:: bash

    pip install icontrol

GitHub
++++++
`F5Networks/f5-icontrol-rest-python <https://github.com/F5Networks/f5-icontrol-rest-python>`_

Examples
--------
.. code-block:: python

    from icontrol.session import iControlRESTSession
    icr_session = iControlRESTSession('myuser', 'mypass')

    # GET to https://bigip.example.com/mgmt/tm/ltm/nat/~Common~mynat
    icr_session.get(
        'https://bigip.example.com/mgmt/tm/ltm/nat',
        instance_name='mynat',
        folder='Common')

    # GET to https://bigip.example.com/mgmt/tm/ltm/nat
    icr_session.get('https://bigip.example.com/mgmt/tm/ltm/nat')

    # POST with json data
    icr_session.post('https://bigip.example.com/mgmt/tm/ltm/nat', \
    json={'name': 'myname', 'partition': 'Common'})

Module Documentation
--------------------
.. toctree::
   :maxdepth: 4

   apidocs/modules


License
-------
Apache V2.0
+++++++++++
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Contributor License Agreement
+++++++++++++++++++++++++++++
Individuals or business entities who contribute to this project must have
completed and submitted the
`F5 Contributor License Agreement <http://f5networks.github.io/f5-openstack-docs/cla_landing/index.html>`_
to Openstack_CLA@f5.com prior to their code submission being included in this
project.

