#!/usr/bin/env python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

import os
from urllib.parse import parse_qs
from argparse import ArgumentParser
from configparser import ConfigParser
from wsgiref.simple_server import make_server

from requests_oauthlib import OAuth2Session


def authorize_app_for_token(client_id, client_secret, redirect_uri, authorization_base_url, token_url, scope):
    session = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)

    # Redirect user to Google for authorization
    authorization_url, state = session.authorization_url(authorization_base_url,
                                                         # offline for refresh token
                                                         # force to always make user click authorize
                                                         access_type='offline', prompt='select_account')

    print('Please go here and authorize:', authorization_url)

    if redirect_uri == 'http://localhost':
        # Hack to piggyback the code out of the HTTP server
        piggyback = []
        def oauth2_redirect_url_handler(environ, start_response):
            status = '200 OK'
            headers = [('Content-type', 'text/plain; charset=utf-8')]

            returned_code = parse_qs(environ['QUERY_STRING'])['code'][0]
            piggyback.append(returned_code)

            start_response(status, headers)

            return [f'code: {returned_code}\n'.encode('UTF-8')]

        try:
            with make_server('', 80, oauth2_redirect_url_handler) as httpd:
                print('Serving HTTP on port 80...')
                # Serve one request, then exit
                httpd.handle_request()
                code = piggyback[0]
        except PermissionError:
            # INFO https://stackoverflow.com/questions/413807/is-there-a-way-for-non-root-processes-to-bind-to-privileged-ports-on-linux/27989419#27989419
            print('Cannot bind to port 80!\n\nUse\n'
                  'sudo setcap \'cap_net_bind_service=+ep\' /usr/bin/python3.10\n'
                  'command to allow Python to bind\n'
                  '(Revoke the right with\n'
                  'sudo setcap \'cap_net_bind_service=-ep\' /usr/bin/python3.10\n'
                  ') or setup authbind:\n'
                  '1. sudo touch /etc/authbind/byport/80\n'
                  '2. sudo chmod o+x /etc/authbind/byport/80\n'
                  'Run tis program: authbind ./venv/bin/python [THIS_FILE] [PARAMS]')
            exit(1)
    else:
        # Get the authorization verifier code from the callback URL
        code = input('Paste the authorization code: ')
        print()  # New line after the input line for the next print

    # Fetch the token
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    session.fetch_token(token_url, client_secret=client_secret, code=code)

    return session.token['access_token'], session.token['refresh_token']


def parse_args():
    parser = ArgumentParser(description='Get OAuth2 token by authorizing the app')
    # Credentials you get from registering a new application
    parser.add_argument('-c', '--client-id', dest='client_id', help='Client ID', metavar='CLIENT_ID',
                        required=True)
    parser.add_argument('-s', '--client-secret', dest='client_secret', help='Client secret', metavar='CLIENT_SECRET',
                        required=True)
    # To get a code istead redirecting
    parser.add_argument('-r', '--redirect-uri', dest='redirect_uri',
                        help='Redirect URI (default: http://localhost) use \'oob\' or other URL to get code'
                             ' instead of redirecting (if supported)!',
                        metavar='REDIRECT_URI', default='http://localhost')
    # OAuth endpoints (given in the Google API documentation)
    parser.add_argument('-b', '--base-url', dest='authorization_base_url',
                        help='Authorization base URL (default: https://accounts.google.com/o/oauth2/v2/auth)',
                        metavar='BASE_URL', default='https://accounts.google.com/o/oauth2/v2/auth')
    parser.add_argument('-t', '--token-url', dest='token_url',
                        help='Token URL (default: https://www.googleapis.com/oauth2/v4/token)',
                        metavar='TOKEN_URL', default='https://www.googleapis.com/oauth2/v4/token')
    # Scope for IMAP access
    parser.add_argument('--scope', dest='scope', nargs='+', default=['https://mail.google.com/'],
                        help='Scope (default: https://mail.google.com/)', metavar='SCOPE')
    # Write refresh token to INI file
    parser.add_argument('-f', '--auth-file', dest='auth_file',
                        help='The filename contains the configurations (default: auth.ini)',
                        metavar='FILENAME', default='auth.ini')
    parser.add_argument('-i', '--section', dest='section',
                        help='The filename contains the configurations (default: TO)',
                        metavar='SECTION', default='TO')

    return parser.parse_args()


def print_and_save_token(access_token, refresh_token, auth_file, section):
    auth_config = ConfigParser()
    auth_config.read(auth_file, encoding='UTF-8')
    auth_config[section]['refresh_token'] = refresh_token
    with open(auth_file, 'w', encoding='UTF-8') as configfile:
        auth_config.write(configfile)
    # Print the tokens
    print(f'Access token: {access_token}')
    print(f'Refresh token: {refresh_token}')
    print(f'Refresh token is written into: {auth_file} section {section}')


def main():
    args = parse_args()
    access_token, refresh_token = authorize_app_for_token(args.client_id, args.client_secret, args.redirect_uri,
                                                          args.authorization_base_url, args.token_url, args.scope)
    print_and_save_token(access_token, refresh_token, args.auth_file, args.section)


if __name__ == '__main__':
    main()
