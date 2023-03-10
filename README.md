![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# Greenbone Security Assistant HTTP server <!-- omit in toc -->

[![GitHub releases](https://img.shields.io/github/release/greenbone/gsad.svg)](https://github.com/greenbone/gsad/releases)
[![Build and test C](https://github.com/greenbone/gsad/actions/workflows/ci-c.yml/badge.svg?branch=main)](https://github.com/greenbone/gsad/actions/workflows/ci-c.yml?query=branch%3Amain++)

The Greenbone Security Assistant HTTP Server is the server developed for the
communication with the [Greenbone Enterprise appliances](https://www.greenbone.net/en/product-comparison/).

It connects to the Greenbone Vulnerability Manager Daemon **gvmd** to provide a
full-featured HTTP interface for vulnerability management.

- [Releases](#releases)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Compiling](#compiling)
- [Logging Configuration](#logging-configuration)
- [Usage](#usage)
- [Support](#support)
- [Maintainer](#maintainer)
- [Contributing](#contributing)
- [License](#license)

## Releases

All [release files](https://github.com/greenbone/gsad/releases) are signed with
the [Greenbone Community Feed integrity key](https://community.greenbone.net/t/gcf-managing-the-digital-signatures/101).
This gpg key can be downloaded at https://www.greenbone.net/GBCommunitySigningKey.asc
and the fingerprint is `8AE4 BE42 9B60 A59B 311C  2E73 9823 FAA6 0ED1 E580`.

## Installation

If you are not familiar or comfortable building from source code, we recommend
that you use the Greenbone Security Manager TRIAL (GSM TRIAL), a prepared virtual
machine with a readily available setup. Information regarding the virtual machine
is available at <https://www.greenbone.net/en/testnow>.

This module can be configured, built and installed with following commands:

```bash
cd path/to/gsad
mkdir build && cd build
cmake ..
make install
```

Please note: The reference system used by most of the developers is Debian
GNU/Linux 'Buster' 10. The build might fail on any other system. Also, it is
necessary to install dependent development packages.

### Prerequisites

See at the end of this section how to easily install these prerequisites on
some supported platforms.

Prerequisites:
* libgvm_base, libgvm_util, libgvm_gmp >= 20.8.2
* gnutls >= 3.2.15
* libgcrypt
* cmake >= 3.0
* glib-2.0 >= 2.42
* libxml
* libmicrohttpd >= 0.9.0
* pkg-config
* gcc

Prerequisites for building documentation:
* Doxygen
* xmltoman (optional, for building man page)

Install prerequisites on Debian GNU/Linux:

```bash
apt-get install libmicrohttpd-dev libxml2-dev
```

### Compiling

If you have installed required libraries to a non-standard location, remember to
set the `PKG_CONFIG_PATH` environment variable to the location of you pkg-config
files before configuring:

```bash
export PKG_CONFIG_PATH=/your/location/lib/pkgconfig:$PKG_CONFIG_PATH
```
Create a build directory and change into it with:

```bash
mkdir build && cd build
```

Then configure the build with:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/path/to/your/installation ..
```

Or (if you want to use the default installation path /usr/local):

```bash
cmake ..
```

This only needs to be done once.

Thereafter, the following commands are useful:

    make                # build the scanner
    make doc            # build the documentation
    make doc-full       # build more developer-oriented documentation
    make install        # install the build
    make rebuild_cache  # rebuild the cmake cache

Please note that you may have to execute `make install` as root, especially if
you have specified a prefix for which your user does not have full permissions.

To clean up the build environment, simply remove the contents of the `build`
directory you created above.

In case you have installed the Greenbone Security Assistant Daemon into a path
different from the other GVM modules, you might need to set some paths
explicitly before running `cmake`. See the top-level CMakeLists.txt.

## Logging Configuration

By default, gsad writes logs to the file

    <install-prefix>/var/log/gvm/gsad.log

Logging is configured entirely by the file

    <install-prefix>/etc/gvm/gsad_log.conf

The configuration is divided into domains like this one

    [gsad main]
    prepend=%t %p
    prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
    file=/var/log/gvm/gsad.log
    level=128

The `level` field controls the amount of logging that is written.
The value of `level` can be:

      4  Errors.
      8  Critical situation.
     16  Warnings.
     32  Messages.
     64  Information.
    128  Debug.  (Lots of output.)

Enabling any level includes all the levels above it. So enabling Information
will include Warnings, Critical situations and Errors.

To get absolutely all logging, set the level to 128 for all domains in the
configuration file.

Logging to `syslog` can be enabled in each domain like:

    [gsad main]
    prepend=%t %p
    prepend_time_format=%Y-%m-%d %Hh%M.%S %Z
    file=syslog
    syslog_facility=daemon
    level=128

## Usage

In case everything was installed using the defaults, then starting the HTTP
daemon of the Greenbone Security Assistant can be done with this simple command:

    gsad

The daemon will listen on port 443, making the web interface
available in your network at `https://<your host>`.

If port 443 was not available or the user has no root privileges,
gsad tries to serve at port 9392 as a fallback (`https://<your host>:9392`).

To see all available command line options of gsad, enter this command:

    gsad --help

## Support

For any question on the usage of `gsad` please use the [Greenbone Community
Portal](https://community.greenbone.net/). If you found a problem with the
software, please [create an issue](https://github.com/greenbone/gsad/issues) on
GitHub. If you are a Greenbone customer you may alternatively or additionally
forward your issue to the Greenbone Support Portal.

## Maintainer

This project is maintained by [Greenbone Networks
GmbH](https://www.greenbone.net/).

## Contributing

Your contributions are highly appreciated. Please [create a pull
request](https://github.com/greenbone/gsad/pulls) on GitHub. Bigger changes need
to be discussed with the development team via the [issues section at
github](https://github.com/greenbone/gsad/issues) first.

## License

Copyright (C) 2009-2022 [Greenbone AG](https://www.greenbone.net/)

Licensed under the [GNU Affero General Public License v3.0 or later](LICENSE).
