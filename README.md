# google-yubikey

Generate Google Service Account tokens with your YubiKey!

## Motivation

This is perhaps the most secure way to use Google credentials
outside of Google Cloud, since the private key never leaves the device,
and so it cannot be leaked or stolen without physically stealing the YubiKey.

Additionally, each operation is protected with a YubiKey PIN,
providing a 2nd factor of authentication as something a user knows
(in addition to something a user has, which is the YubiKey itself).

In this way, a single YubiKey can represent the identity
of a user across many Service Accounts, without the need
to send the private key material over the wire at any point.

This makes it even more secure than Service Account impersonation,
where a user's long-term refresh token has been traditionally
stored on their machine, and could thus be compromised.

## Requirements

YubiKey 4+

## Setup

```
pip3 install google-yubikey
```

## Usage

1.  Set up YubiKey PIN, as explained
    [here](https://developers.yubico.com/PIV/Guides/Device_setup.html).

2.  Run this only once to set up a private key on the YubiKey,
    or to renew it after expiration:

    ```
    google-yubikey generate-key
    ```

3.  Run this once to register YubiKey with each Service Account:

    ```
    google-yubikey upload-key -a <service_account_email>
    ```

4.  Run this every time you'd like to generate a Service Account token:

    ```
    google-yubikey token -a <service_account_email>
    ```

5.  Further customization options are available through:

    ```
    google-yubikey [<command>] -h
    ```

## Disclaimer

This tool is still early on in the development.
It works, but may have unusual edge cases that make it fail
for your setup. Please use with caution, and raise an issue
if you come across one.
