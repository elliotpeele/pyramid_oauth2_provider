pyramid_oauth2_provider README
==================

Getting Started
---------------

In an existing pyramid project you can take advantage of pyramid_oauth2_provider
by doing the following:

* Add config.include('pyramid_oauth2_provider') to your project setup. This will
  configure a /oauth2/token route for the token endpoint and an authentication
  policy that will support oauth2. If you want to be able to use both cookie
  auth and oauth2 at the same time, you should use the
  pyramid_oauth2_provider.authentication.OauthTktAuthenticationPolicy instead
  of the default.
* Define a implementation of the pyramid_oauth2_provider.interfaces.IAuthCheck
  interface that works against your current user authentication check mechanism.
* In your paster configuration configure which IAuthCheck implementation to use
  by specifying oauth2_provider.auth_check.
* In your development configuration, you may also want to disable ssl
  enforcement by specifying oauth2_provider.require_ssl = false.
* Generate client credentials using the create_client_credentials script,
  provided as part of pyramid_oauth2_provider.

Request Flow
------------
Let's start by laying out a few ground rules when it comes to oauth2:
1. All requests *must* be made via HTTPS.
2. All data is transfered in headers and the body of messages rather than
   through url parameters.

The token endpoint is provided as a way to obtain and rewnew access_tokens.

Example initial authentication request:

        POST /oauth2/token HTTP/1.1
        Host: server.example.com
        Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        Content-Type: application/x-www-form-urlencoded

        grant_type=password&username=johndoe&password=A3ddj3w

* The basic auth header is the client_id:client_secret base64 encoded.
* Content-Type must be application/x-www-form-urlencoded

