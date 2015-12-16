<!--
Copyright 2015 F5 Networks Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# f5-icontrol-rest-python
[![Build Status](https://travis-ci.com/F5Networks/f5-icontrol-rest-python.svg?token=2gRRgdSNRf2z9jAftSpV)](https://travis-ci.com/F5Networks/f5-icontrol-rest-python)

## Introduction
Generic python library that allows programs and other modules to interact with the BIG-IP iControl REST API.

## Installation
You can install this package using pip.
```bash
pip install f5-icontrol-rest
```

If you want to install directly from github you can do so as well.  The example below installs the package at the release v0.1.0 tag.
```bash
pip install git+ssh://git@github.com/F5Networks/f5-icontrol-rest@v0.1.0`
```

## Configuration
N/A

## Usage
```python
from icontrol.session import iControlRESTSession
icr_session = iControlRESTSession('myuser', 'mypass')
icr_session.get(
    'https://bigip.example.com/mgmt/tm/ltm/nat',
    instance_name='mynat',
    folder='Common')
```

## Documentation
TODO: Point to the API docs

## Filing Issues
TODO: How to file bugs vs enhancements

## Contributing
See [Contributing](CONTRIBUTING.md)

## Build
To make a py-pi package run:
```bash
python setup.py sdist
```

## Test
All code must have passing [pytest](http://pytest.org) unit tests prior to
submitting a pull request.  In addition there should be a set of functional
tests that are written to use a real BIG-IP device for testing.  Below is
information on how to run our various tests.

#### Unit Tests
We use pytest for our unit tests
1. If you haven't already install the required test packages and the requirements.txt in your virtual environment.
```shell
$ pip install hacking pytest pytest-cov
$ pip install -r requirements.txt
```
2. Run the tests and produce a coverage repor.  The `--cov-report=html` will
create a `htmlcov/` directory that you can view in your browser to see the
missing lines of code.
```shell
py.test --cov ./icontrol --cov-report=html
open htmlcov/index.html
```

#### Style Checks
We use the hacking module for our style checks that you installed as part of
step 1 in the Unit Test section above.
```shell
flake8 ./
```

#### Functional Tests
TODO: Add the steps to run the functional tests

## Contact
<f5-icontrol-rest@f5.com>

## Copyright
Copyright 2015 F5 Networks Inc.

## License
See [License](LICENSE)

## Support
These modules are Free Software available under the Apache License
Version 2.0, and are provided without Warranty or Support under 
existing support contracts for F5 products.
