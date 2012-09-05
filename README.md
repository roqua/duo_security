# DuoSecurity

This gem provides an API for integrating with DuoSecurity's two-factor
authentication system. It also comes with a shell script that allows you to
plug this into other systems, for example a FreeRadius server.

## Installation

    $ gem install duo_security

## Usage

The shell scripts depend upon three environment variables being set:

    DUO_HOST=api-XXXXXXXX.duosecurity.com
    DUO_SKEY=your_secret_key
    DUO_IKEY=your_integration_key

Then to attempt a login, run the following command:

    duo username

The script prints some output, and exits with status 0 if it is a successful login,
and status 1 otherwise.

## Contributing

Running the tests also depends upon the above three environment variables to be
set to an account of your choosing. Running the tests performs actual requests
to the account, although for the sake of speed they are cached in the
`fixtures/vcr` folder after the first run. 

When performing actual requests, the tests will tell you what you action you
need to take in the mobile application for the test case that's being executed
(e.g. approve).

The following workflow is advised:

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
