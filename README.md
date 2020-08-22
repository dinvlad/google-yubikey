# google-yubikey

Generate Google Service Account tokens with your YubiKey!

## Motivation

This is perhaps the most secure way to use Google Service Account (SA) credentials
outside of Google Cloud, since the private key never leaves the device,
and so it cannot be leaked or stolen without physically stealing the YubiKey.

Additionally, each operation is protected with a YubiKey PIN,
providing a 2nd factor of authentication as something a user knows
(in addition to something a user has, which is the YubiKey itself).

In this way, a single YubiKey can represent the identity
of a user across many SAs, without the need
to send the private key material over the wire at any point.

This makes it even more secure than SA impersonation,
where a user's long-term refresh token has been traditionally
stored on their machine, and could thus be compromised.

## Requirements

Python 3.7+

YubiKey 4+, FIPS and NEO

The key must have **PIV** feature to be eligible.
For the specific list of compatible models, please see
[here](https://www.yubico.com/products/compare-products-series/)
and [here](https://www.yubico.com/products/compare-yubikey-4-neo/).

Please note that the private key is stored on one of the available
[PIV certificate slots](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html),
which does _NOT_ interfere with other functionality,
like web 2FA authentication or OpenPGP.
You can choose the slot freely (by default, it's `9a`).

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
    google-yubikey generate-key > yubikey.pem
    ```

    The output `yubikey.pem` key above is public - to be used in the next step.

3.  Install [Google Cloud SDK](https://cloud.google.com/sdk/install) and run:

    ```
    gcloud auth login
    gcloud beta iam service-accounts keys upload yubikey.pem \
        --iam-account <service_account_email>
    gcloud auth revoke # optional, but recommended
    ```

    This is needed only for setting up YubiKey with a SA.
    Your user account must have at least `Service Account Key Admin` role
    or `iam.serviceAccountKeys.create` permission
    on the target SA(s).

    As a good practice, the last command revokes your Google Cloud SDK credentials,
    which limits the potential for their exposure
    only to the time of the public key upload.

    Alernatively to step 3, you can upload `yubikey.pem` from step 2 via
    Google Cloud Console for the target SA(s):

    ![Uploading existing key to Google Cloud Console](https://raw.githubusercontent.com/dinvlad/google-yubikey/master/console.png)

4.  Run this every time you'd like to generate a SA token:

    ```
    google-yubikey token -a <service_account_email>
    ```

    By default, this command will generate a Google OAuth 2.0 _access token_.
    You can also generate an _ID token_ using `-t id`.

    The command prints the token to standard output, so it can
    be easily assigned to a variable for integration into your scripts.

5.  To use YubiKey for Google Cloud SDK or your **_existing applications_**,
    you can start a local metadata server that emulates
    Google Compute Engine (GCE) environment for token generation:

    ```
    sudo google-yubikey serve -a <service_account_email> -n <numeric_project_id>
    ```

    Unfortunately, this command needs to be run with _elevated privileges_,
    since it opens privileged port 80 on a _link-local alias IP_,
    to emulate GCE. However, according to security best practices,
    it drops privileges for the server workers.

    Once the server is running, you can use regular commands
    as if you were running them on a GCE instance (!), for example:

    ```
    gcloud config set account <service_account_email>
    gcloud auth list
    gsutil ls
    docker run --rm -it google/cloud-sdk:alpine bq ls
    node app.js # a JavaScript app that uses Google client libraries
    ```

    When these commands request a token from the metadata server (behind the scenes),
    it will ask you for the YubiKey PIN, and cache it
    and the token for a short time to improve user experience.

    As you can see, there's no need to download SA keys
    and set `GOOGLE_APPLICATION_CREDENTIALS` anymore!

6.  Further customization options are available through:

    ```
    google-yubikey [<command>] -h
    ```

## Disclaimer

This tool is still early on in the development.
It works, but may have unusual edge cases that make it fail
for your setup. Please use with caution, and raise an issue
if you come across one.
