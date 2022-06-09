#!/usr/bin/env python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

from argparse import ArgumentParser

from requests_oauthlib import OAuth2Session


def authorize_app_for_token(client_id, client_secret, redirect_uri, authorization_base_url, token_url, scope):
    session = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)

    # Redirect user to Google for authorization
    authorization_url, state = session.authorization_url(authorization_base_url,
                                                         # offline for refresh token
                                                         # force to always make user click authorize
                                                         access_type='offline', prompt='select_account')

    print('Please go here and authorize:', authorization_url)

    # Get the authorization verifier code from the callback URL
    code = input('Paste the authorization code: ')
    print()  # New line after the input line for the next print

    # Fetch the token
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
    parser.add_argument('-r', '--redirect-uri', dest='redirect_uri', help='Redirect URI (default: oob)',
                        metavar='REDIRECT_URI', default='oob')
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

    return parser.parse_args()


def main():
    args = parse_args()
    access_token, refresh_token = authorize_app_for_token(args.client_id, args.client_secret, args.redirect_uri,
                                                          args.authorization_base_url, args.token_url, args.scope)
    # Print the tokens
    print('Access token:', access_token)
    print('Refresh token:', refresh_token)


if __name__ == '__main__':
    main()
