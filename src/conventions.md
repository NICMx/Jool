# Coding Style

## Core

The project generally follows the kernel's coding style: https://www.kernel.org/doc/Documentation/CodingStyle. (So please don't freak out when you catch glimpse of those gotos :))

## Initialization and cleanup

When naming initialization and cleanup functions, the convention is to use the following suffixes:

### `_setup` and `_teardown`

`_setup` indicates that the function should normally be called once in the entire runtime of the module. They do not initialize structures, but rather entire modules.

I had a problem in kernel 4.16 where some unit tests where calling these functions too much, and the kernel apparently had trouble with the quick deallocation and reallocation of slab caches. So just call them once.

A `_teardown` function reverts the work of the respective `_setup` function.

### `_alloc`, `_release`, `_get` and `_put`

An `_alloc` function is one that creates a structure on the heap and returns a pointer to it. The returned structure is expected to be initialized/usable and have a reference count of 1.

Up til now, these functions can only fail due to `ENOMEM` problems, which is the reason why they are pretty much the only ones allowed to return something that's not an error code in the entire project.

If there's no reference counting involved, calling code should destroy these structures with `_release`. Otherwise, calling code should destroy them with `_put`. Conversely, they can reserve references to them with `_get`. (The nomenclature for these two latter functions was based off the kernel's [kref API](https://www.kernel.org/doc/Documentation/kref.txt).)

In practice, the latest `_put` reverts the `_alloc` by means of `_release` (ie. "`kref_put(refs, db_release)`"). When `_put` exists, there is no reason to make `_release` visible to calling code.

### `_init` and `_clean`

`_init` initializes a structure that has already been allocated. These functions can technically be called from `_alloc`s, but in practice this never happens because all modules either declare `_alloc` or `_init`, and not both.

`_clean` reverts the corresponding `_init`. Though they are expected to _not_ release the structure itself, the referenced objects are expected to be `_put`'d.

`_clean` is not always needed to exist.

## Databases and tables

For the sake of clarity, all the databases in the project follow a convention, as if they were implementing an interface. There are variations, but in general, the "methods" they are all supposed to inherit are generally self explanatory, such as `_find`, `_add`, `_rm`, `_count`, `_foreach`, `_put` and `_get`.

There are two in particular that deserve special mention:

- `_release` (private, always called only by `_put`) is intended to "delete" the database. It happens when the database must be destroyed along with its entries.
- `_flush` only means the database should be emptied. The database must end up clean but usable (and the entries released).

The distinction between `_release` and `_flush` actually transcends that. Calling one from the other is pretty much always a bug:

- `_flush` is only called as handlers for userspace application requests, and as such can happen alongside packet translations. This means they MUST worry about concurrency but are allowed to sleep. (Process context.)
- `_release` is the complete opposite. It can happen *during* packet translations (if the translating code is the last holding the reference) which means that, though they don't need to worry about concurrency, they are absolutely banned from sleeping. (Interrupt context.)
