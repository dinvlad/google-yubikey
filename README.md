# google-yubikey

Generate Google Service Account tokens with your YubiKey!

This is perhaps the most secure way to use Google credentials
outside of Google Cloud, since the private key never leaves the device,
and so it cannot be leaked or stolen without physically stealing the YubiKey.

## Requirements

YubiKey 4+

## Setup

```
pip3 install google-yubikey
```

## Usage

1.  Run this only once to set up a private key on the YubiKey,
    or to renew it after expiration:

    ```
    google-yubikey private-key
    ```

2.  Run this once to register YubiKey with each Service Account:

    ```
    google-yubikey public-key -a <service_account_email>
    ```

3.  Run this every time you'd like to generate a Service Account token:

    ```
    google-yubikey token -a <service_account_email>
    ```

4.  Further customization options are available through:

    ```
    google-yubikey [<command>] -h
    ```
