#!/usr/bin/env python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

import sys
from argparse import ArgumentParser
from datetime import datetime, date
from configparser import ConfigParser

from imapclient import IMAPClient


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
            with open(state_config_filename, 'w') as configfile:
                last_state_config.write(configfile)
        else:
            print('ERROR', msg_num, copy_result, file=sys.stderr)


def connect_imap_and_sync(from_host, to_host, last_state, state_config_filename, idle_timeout=240):  # TODO wait more?
    with IMAPClient(from_host['host'], port=int(from_host['port'])) as from_server,\
            IMAPClient(to_host['host'], port=int(to_host['port'])) as to_server:
        from_server.login(from_host['username'], from_host['password'])
        to_server.login(to_host['username'], to_host['password'])
        # from_server.capabilities()
        from_server.select_folder('INBOX', readonly=True)
        # to_server.capabilities()
        to_server.select_folder('INBOX')
        while True:
            copy_emails(from_server, to_server, last_state, to_host['target_label'], state_config_filename)
            responses = []
            while len(responses) == 0:
                """
                Note that IMAPClient does not handle low-level socket errors that can happen 
                when maintaining long-lived TCP connections.
                Users are advised to renew the IDLE command every 10 minutes to avoid the connection
                from being abruptly closed.
                """
                from_server.idle()  # Start IDLE mode
                responses = from_server.idle_check(timeout=idle_timeout)  # Wait max idle_timeout seconds for response
                from_server.idle_done()  # Must finish idle to send Keepalive
                from_server.noop()       # Keepalive for source
                to_server.noop()         # Keepalive for target


def parse_config(auth_config_file, last_sync_state_config_file):
    auth_config = ConfigParser()
    auth_config.read(auth_config_file)
    last_sync_state_config = ConfigParser()
    last_sync_state_config.read(last_sync_state_config_file)
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


if __name__ == '__main__':
    auth_conf_filename, state_conf_filename = parse_args()
    user_config, last_sync_state = parse_config(auth_conf_filename, state_conf_filename)
    while True:
        try:
            connect_imap_and_sync(user_config['FROM'], user_config['TO'], last_sync_state, state_conf_filename)
        except (ValueError, KeyboardInterrupt) as e:  # Keyboard interrupt and tirival errors...
            print('Unknown error:', e, file=sys.stderr)
            break
        except Exception as e:  # In case of any network or connection issue...
            print('Unknown error:', e, file=sys.stderr)
            pass
