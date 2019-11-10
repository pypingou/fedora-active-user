fedora-active-user
==================

[![Build Status](https://travis-ci.org/pypingou/fedora-active-user.svg?branch=master)](https://travis-ci.org/pypingou/fedora-active-user)

This script generates a small report of the recent activity
of a fellow Fedora contributor using either his FAS login
or his email address.

The script checks:
- Last login on a website using FAS
- Last builds on koji
- Last update on Bodhi (not yet implemented)
- Last update on bugzilla (takes a while and may not work on F16)
- Last email set to mailing lists
- Last actions recorded by fedmsg

The mailing lists considered are set at the top of the script, at
the moment, they are:
  fedora.devel
  fedora.artwork
  fedora.desktop
  fedora.epel.devel
  fedora.extras.packaging
  fedora.fonts
  fedora.general
  fedora.infrastructure
  fedora.kde
  fedora.perl
They are checked using gmane's function to search by sender's email.

This script depends on the [fedora-cert package](https://pagure.io/fedora-packager).
