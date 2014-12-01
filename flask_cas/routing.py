# -*- coding: utf-8 -*-

from __future__ import (with_statement, print_function, division,
                        unicode_literals, absolute_import)

import flask
import requests
from flask import current_app
from flask import request
from flask import url_for
from flask import session
from flask import redirect
from .cas_urls import create_cas_login_url
from .cas_urls import create_cas_logout_url
from .cas_urls import create_cas_validate_url
from .cas_urls import create_cas_serviceValidate_url


blueprint = flask.Blueprint('cas', __name__)

CACHE_PGT_PIOU_KEY = '%s_PIOU_PGT'
CACHE_PIOU_KEY = '%s_PIOU'
PROXY_CB_URL = '/proxy_cb'


@blueprint.route(PROXY_CB_URL)
def proxy_cb():
    ''' '''
    if request.scheme != 'https':
        return redirect(url_for('.proxy_cb', _external=True, _scheme='https'))

    proxy_gt = request.args.get('pgtId')
    proxy_iou = request.args.get('pgtIou')

    if proxy_gt and proxy_iou:
        key = CACHE_PGT_PIOU_KEY % proxy_iou
        current_app.cache.set(key, proxy_gt)

    return ''


@blueprint.route('/login/')
def login():
    """
    This route has two purposes. First, it is used by the user
    to login. Second, it is used by the CAS to respond with the
    `ticket` after the user logs in successfully.

    When the user accesses this url, they are redirected to the CAS
    to login. If the login was successful, the CAS will respond to this
    route with the ticket in the url. The ticket is then validated.
    If validation was successful the logged in username is saved in
    the user's session under the key `CAS_USERNAME_SESSION_KEY`.
    """

    cas_token_session_key = current_app.config['CAS_TOKEN_SESSION_KEY']

    redirect_url = create_cas_login_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_ROUTE_PREFIX'],
        url_for('.login', _external=True, _scheme='http'))

    if 'ticket' in request.args:
        session[cas_token_session_key] = request.args['ticket']

    if cas_token_session_key in session:

        if validate(session[cas_token_session_key]):
            redirect_url = url_for(current_app.config['CAS_AFTER_LOGIN'])

            if current_app.config['CAS_PROXY_CALLBACK']:
                key1 = CACHE_PIOU_KEY % session[
                    current_app.config['CAS_USERNAME_SESSION_KEY']]
                proxy_iou = current_app.cache.get(key1)
                key2 = CACHE_PGT_PIOU_KEY % proxy_iou
                proxy_gt = current_app.cache.get(key2)
                if proxy_gt:
                    session[current_app.config['CAS_PROXY_GRANTING_TICKET']] = \
                        proxy_gt
                    current_app.cache.delete(key1)
                    current_app.cache.delete(key2)

        else:
            del session[cas_token_session_key]


    current_app.logger.debug('Redirecting to: {}'.format(redirect_url))

    return redirect(redirect_url)


@blueprint.route('/logout/')
def logout():
    """
    When the user accesses this route they are logged out.
    """

    cas_username_session_key = current_app.config['CAS_USERNAME_SESSION_KEY']

    if cas_username_session_key in session:
        del session[cas_username_session_key]

    redirect_url = create_cas_logout_url(
        current_app.config['CAS_SERVER'],
        current_app.config['CAS_ROUTE_PREFIX'],
        current_app.config['CAS_LOGOUT_RETURN_URL'],
        current_app.config['CAS_VERSION'],
    )

    current_app.logger.debug('Redirecting to: {}'.format(redirect_url))
    return redirect(redirect_url)


def validate(ticket):
    """
    Will attempt to validate the ticket. If validation fails, then False
    is returned. If validation is successful, then True is returned
    and the validated username is saved in the session under the
    key `CAS_USERNAME_SESSION_KEY`.
    """

    CAS_VERSION = current_app.config['CAS_VERSION']
    current_app.logger.debug("validating token {}".format(ticket))

    _SERVICE_TICKET_VALIDATORS = {
        '1': create_cas_validate_url,
        '2': create_cas_serviceValidate_url,
        '3': create_cas_serviceValidate_url,
    }

    cas_validate_func = _SERVICE_TICKET_VALIDATORS[CAS_VERSION]

    pgtUrl = None
    if current_app.config['CAS_PROXY_CALLBACK']:
        pgtUrl = url_for('.proxy_cb', _external=True, _scheme='https')

    cas_validate_url = cas_validate_func(
        cas_url=current_app.config['CAS_SERVER'],
        cas_route_prefix=current_app.config['CAS_ROUTE_PREFIX'],
        service=url_for('.login', _external=True, _scheme='http'),
        ticket=ticket,
        pgtUrl=pgtUrl)

    current_app.logger.debug("Making GET request to {}".format(
        cas_validate_url))

    response = requests.get(cas_validate_url, verify=False)
    _PROTOCOLS = {'1': _validate_cas1, '2': _validate_cas2, '3': _validate_cas3}

    if CAS_VERSION not in _PROTOCOLS:
        raise ValueError('Unsupported CAS_VERSION %r' %
            current_app.config['CAS_VERSION'])

    _validate_func = _PROTOCOLS[current_app.config['CAS_VERSION']]
    is_valid = _validate_func(response)

    if is_valid:
        current_app.logger.debug("valid")
    else:
        current_app.logger.debug("invalid")

    return is_valid


def _validate_cas1(response):
    try:
        (is_valid, username) = response.text.split('')
        is_valid = True if is_valid.strip() == b'yes' else False
        if is_valid:
            cas_username_session_key = \
                current_app.config['CAS_USERNAME_SESSION_KEY']
            username = username.strip().decode('utf8', 'ignore')
            session[cas_username_session_key] = username
    except ValueError:
        current_app.logger.error("CAS returned unexpected result")
        is_valid = False

    return is_valid


def _validate_cas2(response):
    from xml.etree import ElementTree

    try:
        data = response.text
        tree = ElementTree.fromstring(data)
        user = tree.find('*/cas:user',
            namespaces=dict(cas='http://www.yale.edu/tp/cas'))
        proxy_iou_ticket = tree.find('*/cas:proxyGrantingTicket',
            namespaces=dict(cas='http://www.yale.edu/tp/cas'))

        is_valid = user is not None

        if is_valid:

            cas_username_session_key = \
                current_app.config['CAS_USERNAME_SESSION_KEY']
            username = user.text
            session[cas_username_session_key] = username

            if proxy_iou_ticket is not None:
                key = '%s_PIOU' % username
                current_app.cache.set(key, proxy_iou_ticket.text)

            return True
        else:
            error = tree.find('cas:authenticationFailure',
                namespaces=dict(cas='http://www.yale.edu/tp/cas'))
            if error is None:
                current_app.logger.error('Error: Unknown response, ' + data)
            else:
                current_app.logger.error('Error: %s, %s' %
                    (str(error.get('code')), error.text))
            return False
    except Exception as exc:
        current_app.logger.error(repr(exc))


def _validate_cas3(response):
    from xml.etree import ElementTree

    try:
        data = response.text
        tree = ElementTree.fromstring(data)
        user = tree.find('*/cas:user',
            namespaces=dict(cas='http://www.yale.edu/tp/cas'))
        proxy_iou_ticket = tree.find('*/cas:proxyGrantingTicket',
            namespaces=dict(cas='http://www.yale.edu/tp/cas'))
        is_valid = user is not None
        if is_valid:
            cas_username_session_key = \
                current_app.config['CAS_USERNAME_SESSION_KEY']
            cas_attributes_session_key = \
                current_app.config['CAS_ATTRIBUTES_SESSION_KEY']
            attributes = {}
            username = user.text

            if proxy_iou_ticket is not None:
                key = CACHE_PIOU_KEY % username
                current_app.cache.set(key, proxy_iou_ticket.text)

            attrs = tree.find('*/cas:attributes',
                namespaces=dict(cas='http://www.yale.edu/tp/cas')) or []
            for attr in attrs:
                tag = attr.tag.split("}").pop()
                if tag in attributes:
                    # found multiple value attribute
                    if isinstance(attributes[tag], list):
                        attributes[tag].append(attr.text)
                    else:
                        attributes[tag] = [attributes[tag], attr.text]
                else:
                    attributes[tag] = attr.text
            session[cas_username_session_key] = username
            session[cas_attributes_session_key] = attributes
            return True
        else:
            error = tree.find('cas:authenticationFailure',
                namespaces=dict(cas='http://www.yale.edu/tp/cas'))
            if error is None:
                current_app.logger.error('Error: Unknown response, ' + data)
            else:
                current_app.logger.error('Error: %s, %s' %
                    (str(error.get('code')), error.text))
            return False
    except Exception as exc:
        current_app.logger.error(repr(exc))
