---
language: en
layout: default
category: Documentation
title: --quick
---

[Documentation](documentation.html) > [Userspace Application Arguments](documentation.html#userspace-application-arguments) > \--quick

# \--quick

First, a little background information:

* [IPv6 prefix](usr-flags-pool6.html) _P_ owns [session entry](usr-flags-session.html) _S_ if _P_ is the prefix of _S_'s "local" IPv6 address.
* [pool4 entry](pool4.html) _A_ owns [BIB entry](bib.html) _B_ if _A_ contains _B_'s IPv4 transport address.

If you `--remove` or `--flush` an owner, its "slaves" become obsolete because the relevant packets are no longer going to be translated.

* If you omit `--quick` while removing owners, Jool will get rid of the newly orphaned slaves. This saves memory and keeps entry lookup efficient during packet translations.
* On the other hand, when you do issue `--quick`, Jool will only purge the owners.  You might want to do this if you want the operation to succeed quickly (maybe you have a HUGE amount of slaves), or more likely you plan to re-add the owner in the future (in which case the still-remaining slaves will become relevant and usable again).

Orphaned slaves will remain inactive in the database, and will eventually kill themselves once their normal removal conditions are met (eg. orphaned sessions will die once their timeout expires).

