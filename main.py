#!/usr/bin/env python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

import sys
import json
from imaplib import IMAP4
from ssl import SSLEOFError
from urllib.request import urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError
from argparse import ArgumentParser
from datetime import datetime, date
from configparser import ConfigParser

import imapclient
from imapclient import IMAPClient
from imapclient.config import get_oauth2_token
from imapclient.config import OAUTH2_REFRESH_URLS, _oauth2_cache


# Monkeypatch to return the refresh token too!
def refresh_oauth2_token_patched(hostname, client_id, client_secret, refresh_token):
    url = OAUTH2_REFRESH_URLS.get(hostname)
    if not url:
        raise ValueError("don't know where to refresh OAUTH2 token for %r" % hostname)

    post = dict(
        client_id=client_id.encode("ascii"),
        client_secret=client_secret.encode("ascii"),
        refresh_token=refresh_token.encode("ascii"),
        grant_type=b"refresh_token",
    )
    response = urlopen(url, urlencode(post).encode("ascii")).read()
    resp_json = json.loads(response.decode("ascii"))
    return resp_json["access_token"], resp_json.get("refresh_token")


# Monkeypatch function
imapclient.config.refresh_oauth2_token = refresh_oauth2_token_patched


def copy_emails(from_server, to_server, last_state, target_label, state_config_filename):
    last_date = last_state['last_date']
    last_uid = last_state['last_uid']
    if isinstance(last_date, date):
        last_date_query = ['SINCE', last_date]
    else:
        last_date_query = []
    if isinstance(last_uid, int):
        last_uid_query = ['UID', '{0}:*'.format(last_uid)]
    else:
        last_uid_query = []
    message_nums = from_server.search(criteria=last_date_query + last_uid_query)
    if len(message_nums) > 0 and isinstance(last_uid, int) and message_nums[0] == last_uid:
        message_nums = message_nums[1:]  # Do not fetch last_uid twice!
    print('Message UIDs to copy:',  message_nums, file=sys.stderr)
    for msg_num, msg_dict in from_server.fetch(message_nums, ['FLAGS', 'INTERNALDATE', 'BODY.PEEK[]']).items():
        copy_result = to_server.append('INBOX', msg_dict[b'BODY[]'], msg_dict[b'FLAGS'], msg_dict[b'INTERNALDATE'])
        if copy_result.endswith(b' (Success)'):
            print('OK', msg_num, copy_result, file=sys.stderr)
            new_uid = int(copy_result.decode('ASCII').split(']', maxsplit=1)[0].split(' ')[-1])
            to_server.add_gmail_labels(new_uid, target_label, silent=True)
            last_state['last_date'] = msg_dict[b'INTERNALDATE'].date()  # Update last state
            last_state['last_uid'] = msg_num
            last_state_config = ConfigParser()  # Write last succesful state to config
            last_state_config['last_sync'] = last_state
            with open(state_config_filename, 'w', encoding='UTF-8') as configfile:
                last_state_config.write(configfile)
        else:
            print('ERROR', msg_num, copy_result, file=sys.stderr)


def get_access_token_and_login(host, server_connection):
    from_token, from_new_refresh_token = get_oauth2_token(host['host'], host['client_id'], host['client_secret'],
                                                          host['refresh_token'])
    update_auth_conf = False
    if from_new_refresh_token is not None and host['refresh_token'] != from_new_refresh_token:
        print('Refresh token changed!', file=sys.stderr)
        host['refresh_token'] = from_new_refresh_token
        update_auth_conf = True
    server_connection.oauth2_login(host['username'], from_token)

    return update_auth_conf


def copy_emails_and_wait(from_server, to_server, idle_timeout, target_label, last_state, state_config_filename):
    connected = True
    while connected:
        copy_emails(from_server, to_server, last_state, target_label, state_config_filename)
        responses = []

        while connected and len(responses) == 0:
            """
            Note that IMAPClient does not handle low-level socket errors that can happen
             when maintaining long-lived TCP connections.
            Users are advised to renew the IDLE command every 10 minutes to avoid the connection
             from being abruptly closed.
            """
            try:
                from_server.idle()  # Start IDLE mode
                # Wait max idle_timeout seconds for response
                responses = from_server.idle_check(timeout=idle_timeout)
                from_server.idle_done()  # Must finish idle to send Keepalive
                from_server.noop()  # Keepalive for source
            except (SSLEOFError, IMAP4.abort) as e:
                print('FROM disconnected:', e, file=sys.stderr)
                connected = False

            try:
                to_server.noop()  # Keepalive for target
            except (SSLEOFError, IMAP4.abort) as e:
                print('TO disconnected:', e, file=sys.stderr)
                connected = False

        if not connected:
            print('Reconnecting...', file=sys.stderr)
            _oauth2_cache.clear()  # Hack: Remove expired access tokens to get a fresh one else geting LoginError!


def connect_imap_and_sync(user_config, auth_conf_filename, last_state, state_config_filename, idle_timeout=240):
    try:
        while True:
            from_host, to_host = user_config['FROM'], user_config['TO']
            with IMAPClient(from_host['host'], port=int(from_host['port'])) as from_server,\
                    IMAPClient(to_host['host'], port=int(to_host['port'])) as to_server:
                # Add tenant-specific refresh URL
                OAUTH2_REFRESH_URLS['outlook.office365.com'] = \
                    f'https://login.microsoftonline.com/{from_host["tenant"]}/oauth2/v2.0/token'

                # Get access tokens and log in to both servers
                print('Logging in to FROM', file=sys.stderr)
                update_auth_conf_from = get_access_token_and_login(from_host, from_server)
                print('Logging in to TO', file=sys.stderr)
                update_auth_conf_to = get_access_token_and_login(to_host, to_server)

                # Change to the specific folders
                # from_server.capabilities()
                from_server.select_folder(from_host['folder'], readonly=True)
                # to_server.capabilities()
                to_server.select_folder(to_host['folder'])

                # If we reach this point, the logins were successful. Actually write the updated conf.
                if update_auth_conf_from or update_auth_conf_to:
                    with open(auth_conf_filename, 'w', encoding='UTF-8') as configfile:
                        user_config.write(configfile)

                copy_emails_and_wait(from_server, to_server, idle_timeout, to_host['target_label'], last_state,
                                     state_config_filename)

    except KeyboardInterrupt:
        pass  # Exit normally
    except ValueError as e:  # Tirival errors...
        print('Unknown error:', e, file=sys.stderr)
        exit(1)
    except HTTPError as e:
        print('Known fatal error. Need to renew the token for Google!', e, file=sys.stderr)
        exit(1)
    except Exception:  # In case of any unhandled network or connection issue...
       print('Unknown error:', sys.exc_info()[:2], file=sys.stderr)
       exit(1)


def parse_config(auth_config_file, last_sync_state_config_file):
    auth_config = ConfigParser()
    auth_config.read(auth_config_file, encoding='UTF-8')
    last_sync_state_config = ConfigParser()
    last_sync_state_config.read(last_sync_state_config_file, encoding='UTF-8')
    last_sync_config = dict(last_sync_state_config['last_sync'])
    try:
        last_sync_config['last_date'] = datetime.strptime(last_sync_config['last_date'], '%Y-%m-%d').date()
    except ValueError:
        last_sync_config['last_date'] = None
    try:
        last_sync_config['last_uid'] = int(last_sync_config['last_uid'])
    except ValueError:
        last_sync_config['last_uid'] = None
    if last_sync_config['last_date'] is None and not isinstance(last_sync_config['last_uid'], int):
        last_sync_config['last_date'] = date.today()  # Make some sane default
    return auth_config, last_sync_config


def parse_args():
    parser = ArgumentParser(description='Sync emails between IMAP accounts continously')
    parser.add_argument('-a', '--auth', dest='auth_ini',
                        help='INI file contains auth information', metavar='AUTH.INI')
    parser.add_argument('-s', '--state', dest='state_ini',
                        help='INI file contains the last state (will be overwritten)', metavar='LAST_SYNC.INI')

    opts = {key: arg for key, arg in vars(parser.parse_args()).items() if arg is not None}
    if len(opts) == 0:
        parser.print_help(sys.stderr)
        exit(1)

    return opts['auth_ini'], opts['state_ini']


def main():
    auth_conf_filename, state_conf_filename = parse_args()
    user_config, last_sync_state = parse_config(auth_conf_filename, state_conf_filename)
    connect_imap_and_sync(user_config, auth_conf_filename, last_sync_state, state_conf_filename)


if __name__ == '__main__':
    main()
