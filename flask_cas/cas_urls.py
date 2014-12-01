# -*- coding: utf-8 -*-
"""
flask_cas.cas_urls

Functions for creating urls to access CAS.
"""

from __future__ import (with_statement, print_function, division,
                        unicode_literals, absolute_import)

from functools import reduce

try:
    from urllib import quote
    from urllib import urlencode
    from urlparse import urljoin
except ImportError:
    from urllib.parse import quote
    from urllib.parse import urljoin
    from urllib.parse import urlencode


def create_url(base, path=None, *query):
    """ Create a url.

    Creates a url by combining base, path, and the query's list of
    key/value pairs. Escaping is handled automatically. Any
    key/value pair with a value that is None is ignored.

    Keyword arguments:
    base -- The left most part of the url (ex. http://localhost:5000).
    path -- The path after the base (ex. /foo/bar or ['foo', 'bar']).
    query -- A list of key value pairs (ex. [('key', 'value')]).

    Example usage:
    >>> create_url(
    ...     'http://localhost:5000',
    ...     'foo/bar',
    ...     ('key1', 'value'),
    ...     ('key2', None),     # Will not include None
    ...     ('url', 'http://example.com'),
    ... )
    'http://localhost:5000/foo/bar?key1=value&url=http%3A%2F%2Fexample.com'
    >>> create_url('http://localhost:5000/', ['/foo/', '/bar/'])
    'http://localhost:5000/foo/bar/'
    >>> create_url('http://localhost:5000', ['foo', 'bar'])
    'http://localhost:5000/foo/bar'
    >>> create_url('http://localhost:5000', ['/foo/', '/bar/'])
    'http://localhost:5000/foo/bar/'
    >>> create_url('http://localhost:5000/', ['foo/', '/bar/'])
    'http://localhost:5000/foo/bar/'
    >>> create_url('http://localhost:5000/', ['foo/', None, '/bar/'])
    'http://localhost:5000/foo/bar/'
    """
    url = base
    # If path is a list remove all None values and reduce to a '/'
    # seperated string.
    if isinstance(path, list):
        path = filter(lambda x: bool(x), path)
        path = reduce(lambda l, r: '{}/{}'.format(l.rstrip('/'),
            r.lstrip('/')), path)
    # Add the path to the url if there is something to add.
    if path:
        url = urljoin(url, quote(path))
    # Remove key/value pairs with None values.
    query = filter(lambda pair: pair[1] is not None, query)
    # Add the query string to the url
    url = urljoin(url, '?{}'.format(urlencode(list(query))))
    return url


def create_cas_login_url(cas_url, cas_route_prefix, service, renew=None,
     gateway=None, method=None):
    """ Create a CAS login URL .

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    service -- (ex.  http://localhost:5000/login)
    renew -- "true" or "false"
    gateway -- "true" or "false"

    Example usage:
    >>> create_cas_login_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://localhost:5000',
    ... )
    'http://sso.pdx.edu/cas/login?service=http%3A%2F%2Flocalhost%3A5000'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'login'],
        ('service', service),
        ('renew', renew),
        ('gateway', gateway),
        ('method', method),
    )


def create_cas_logout_url(cas_url, cas_route_prefix, url=None, cas_version='1'):
    """ Create a CAS logout URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    url -- (ex.  http://localhost:5000/login)
    cas_version -- 1, 2 or 3

    Example usage:
    >>> create_cas_logout_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://localhost:5000',
    ...     '1'
    ... )
    'http://sso.pdx.edu/cas/logout?url=http%3A%2F%2Flocalhost%3A5000'
    """
    parameter_name = {'1': 'url', '2': 'service', '3': 'service'}
    return create_url(
        cas_url,
        [cas_route_prefix, 'logout'],
        (parameter_name[cas_version], url),
    )


def create_cas_validate_url(cas_url, cas_route_prefix, service, ticket,
                            renew=None, **kwargs):
    """ Create a CAS validate URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    service -- (ex.  http://localhost:5000/login)
    ticket -- (ex. 'ST-58274-x839euFek492ou832Eena7ee-cas')
    renew -- "true" or "false"

    Example usage:
    >>> create_cas_validate_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://localhost:5000/login',
    ...     'ST-58274-x839euFek492ou832Eena7ee-cas'
    ... )
    'http://sso.pdx.edu/cas/validate?
        service=http%3A%2F%2Flocalhost%3A5000%2Flogin&
        ticket=ST-58274-x839euFek492ou832Eena7ee-cas'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'validate'],
        ('service', service),
        ('ticket', ticket),
        ('renew', renew),
    )


def create_cas_serviceValidate_url(cas_url, cas_route_prefix, service, ticket,
    pgtUrl=None, renew=None):

    """ Create a CAS serviceValidate URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    service -- (ex.  http://localhost:5000/login)
    ticket -- (ex. 'ST-58274-x839euFek492ou832Eena7ee-cas')
    pgtUrl -- The url of the proxy callback
    renew -- "true" or "false"

    Example usage:
    >>> create_cas_serviceValidate_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://localhost:5000/login',
    ...     'ST-58274-x839euFek492ou832Eena7ee-cas'
    ... )
    'http://sso.pdx.edu/cas/serviceValidate?
        service=http%3A%2F%2Flocalhost%3A5000%2Flogin&
        ticket=ST-58274-x839euFek492ou832Eena7ee-cas'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'serviceValidate'],
        ('service', service),
        ('ticket', ticket),
        ('pgtUrl', pgtUrl),
        ('renew', renew),
    )


def create_cas_proxyValidate_url(cas_url, cas_route_prefix, service, ticket,
     pgtUrl=None, renew=None):

    """ Create a CAS proxyValidate URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    service -- (ex.  http://localhost:5000/login)
    ticket -- (ex. 'ST-58274-x839euFek492ou832Eena7ee-cas')
    pgtUrl -- The url of the proxy callback
    renew -- "true" or "false"

    Example usage:
    >>> create_cas_proxyValidate_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://localhost:5000/login',
    ...     'ST-58274-x839euFek492ou832Eena7ee-cas'
    ... )
    'http://sso.pdx.edu/cas/proxyValidate?
        service=http%3A%2F%2Flocalhost%3A5000%2Flogin&
        ticket=ST-58274-x839euFek492ou832Eena7ee-cas'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'proxyValidate'],
        ('service', service),
        ('ticket', ticket),
        ('pgtUrl', pgtUrl),
        ('renew', renew),
    )


def create_cas_proxy_url(cas_url, cas_route_prefix, pgt, targetService):

    """ Create a CAS proxy URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    pgt -- The proxy-granting ticket
    targetService -- The service identifier of the back-end service

    Example usage:
    >>> create_cas_proxy_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'PGT-490649-W81Y9Sa2vTM7hda7xNTkezTbVge4CUsybAr',
    ...     'http://www.service.com',
    ... )
    'http://sso.pdx.edu/cas/proxy?
        pgt=PGT-490649-W81Y9Sa2vTM7hda7xNTkezTbVge4CUsybAr&
        targetService=http%3A%2F%2Fwww.service.com'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'proxy'],
        ('pgt', pgt),
        ('targetService', targetService),
    )


def create_cas_samIValidate_url(cas_url, cas_route_prefix, target):

    """ Create a CAS samIValidate URL.

    Keyword arguments:
    cas_url -- The url to the CAS (ex. http://sso.pdx.edu)
    cas_route_prefix -- The prefix of the CAS endpoint (ex. /cas/)
    target -- The url of the back-end service

    Example usage:
    >>> create_cas_samIValidate_url(
    ...     'http://sso.pdx.edu',
    ...     'cas',
    ...     'http://www.target.com',
    ... )
    'http://sso.pdx.edu/cas/samIValidate?target=http%3A%2F%2Fwww.target.com'
    """
    return create_url(
        cas_url,
        [cas_route_prefix, 'samIValidate'],
        ('target', target),
    )
