# Coding Style

## Core

The project generally follows the kernel's coding style: https://www.kernel.org/doc/Documentation/CodingStyle. (So please don't freak out when you catch glimpse of those gotos :))

## Databases and tables

For the sake of clarity, all the databases in the project follow a convention, as if they were implementing an interface. There are variations, but in general, the "methods" they are all supposed to inherit are generally self explanatory, such as "find", "add", "rm", "count", "foreach", "put" and "get" (as in [`kref_put()` and `kref_get()`](https://www.kernel.org/doc/Documentation/kref.txt)).

There are two in particular that deserve special mention:

- "destroy" (usually private, called by "put") is intended to "delete" the database. It happens when the database must be released along with its entries.
- "flush" only means the database should be emptied. The database must end up clean but usable (and the entries released).

The distinction between "destroy" and "flush" actually transcends that. Calling one from the other is pretty much always a bug:

- "flush" is only called as handlers for userspace application requests, and as such can happen alongside packet translations. This means they MUST worry about concurrency but are allowed to sleep. (Process context.)
- "destroy" is the complete opposite. It can happen *during* packet translations (if the translating code is the last holding the reference) which means that, though they don't need to worry about concurrency, they are absolutely banned
from sleeping. (Interrupt context.)
