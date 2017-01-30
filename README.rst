srptools
========
https://github.com/idlesign/srptools

|release| |stats|  |lic| |ci| |coverage| |health|

.. |release| image:: https://img.shields.io/pypi/v/srptools.svg
    :target: https://pypi.python.org/pypi/srptools

.. |stats| image:: https://img.shields.io/pypi/dm/srptools.svg
    :target: https://pypi.python.org/pypi/srptools

.. |lic| image:: https://img.shields.io/pypi/l/srptools.svg
    :target: https://pypi.python.org/pypi/srptools

.. |ci| image:: https://img.shields.io/travis/idlesign/srptools/master.svg
    :target: https://travis-ci.org/idlesign/srptools

.. |coverage| image:: https://img.shields.io/coveralls/idlesign/srptools/master.svg
    :target: https://coveralls.io/r/idlesign/srptools

.. |health| image:: https://landscape.io/github/idlesign/srptools/master/landscape.svg?style=flat
    :target: https://landscape.io/github/idlesign/srptools/master


Description
-----------

*Tools to implement Secure Remote Password (SRP) authentication*


Server perspective:

.. code-block:: python

    from srptools import SRPContext, SRPServerSession

    ... todo


Client perspective:

.. code-block:: python

    from srptools import SRPContext, SRPClientSession

    ... todo



Links
-----
* rfc2945 - The SRP Authentication and Key Exchange System
    https://tools.ietf.org/html/rfc2945

* rfc5054 - Using the Secure Remote Password (SRP) Protocol for TLS Authentication
    https://tools.ietf.org/html/rfc5054


Documentation
-------------

http://srptools.readthedocs.org/
