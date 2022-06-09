# SyncIMAP

A small tool to continuously sync one IMAP account to another (one-way sync)

# Motivation

- As free Gmail has no option for retrieving new emails from another account, a little service
  in the middle must be implemented
- As in Outlook365 all redirections can be disabled (which eliminate freedom to choose UI),
  and the only way to get mail into Gmail is to act as an IMAP email client

# Usage

1. Install requirements in requirements.txt
2. [Create OAuth client ID credentials at Google Cloud Console](https://developers.google.com/workspace/guides/create-credentials#desktop-app)
3. Get the refresh token for your account by authorizing the app with [get_oauth2_token.py](get_oauth2_token.py)
4. Fill in `auth.ini` with the login data and `last_sync.ini` with known infos or Nones
5. Run the program and give the two config files as CLI arguments
   (it will save sync state in `last_sync.ini` after each successfully synced email)
6. Get emails copied into Gmail
7. Profit!

# Warning

__It is not secure to store passwords or refresh tokens in clean text format!__ One can implement OAuth2 on both sides.
This small demo is enough to fulfill my use case and easy to extend, do not expect it to be well-tested

# License

This program is licensed under the GPL 3.0 license
