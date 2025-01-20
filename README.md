# SyncIMAP

A small tool to continuously sync one IMAP account to another (one-way sync)

# Motivation

- As free Gmail has no option for retrieving new emails from another account, a little service
  in the middle must be implemented
- As in Outlook365 all redirections can be disabled (which eliminate freedom to choose UI),
  and the only way to get mail into Gmail is to act as an IMAP email client
- Both services disabled logging in with password in favour of OAuth2 tokens

Note: This program is just to get mail. For sending mail form Gmail as an Outlook365 user
I recommend [Email OAuth 2.0 Proxy](https://github.com/simonrob/email-oauth2-proxy) as Gmail have not implemented
OAuth2 for sending mail with alias address yet.

# Usage

1. Install requirements in requirements.txt
2. [Create OAuth client ID credentials at Google Cloud Console](https://developers.google.com/workspace/guides/create-credentials#desktop-app)
3. [Create OAuth client ID credentials at Azure by registering an application](https://learn.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
    - Choose web as platform with http://localhost as redirect URI
    - Check ID tokens and access tokens checkboxes
    - Client ID: "Application (client) ID"
    - Client Secret: "Certificates & secrets > Client secrets > New client secret > value"
    - Scopes: API permissions > Microsoft Graph > Delegated > IMAP.AccessAsUser.All, Mail.Read, offline_access, openid, User.Read
4. Fill in `auth.ini` with the login data and `last_sync.ini` with known infos or Nones
5. **Get the refresh token for your account** by authorizing the app with [get_oauth2_token.py](get_oauth2_token.py)
    - For the Outlook365 (besides client id and client secret parameters, **YOUR TENANT ID** must be customised):
      - `-b https://login.microsoftonline.com/{YOUR TENANT ID}/oauth2/v2.0/authorize`
      - `-t https://login.microsoftonline.com/{YOUR TENANT ID}/oauth2/v2.0/token`
      - `--scope https://outlook.office.com/IMAP.AccessAsUser.All offline_access`
      - `-i FROM`
6. Run the program ([main.py](main.py)) and give the two config files as CLI arguments
   (it will save sync state in `last_sync.ini` after each successfully synced email)
7. Get emails copied into Gmail
8. Profit!

# Warning

__It is not secure to store passwords or refresh tokens in clean text format!__ One can implement OAuth2 on both sides.
This small demo is enough to fulfill my use case and easy to extend, do not expect it to be well-tested

# License

This program is licensed under the GPL 3.0 license
