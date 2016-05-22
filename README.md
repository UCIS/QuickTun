Building
========

In general, you can customize the build by setting the `PROTOCOLS`
make variable to the list of protocols to include. For example, the
following will build a `quicktun` binary containing just the "salty"
and "nacltai" protocols:

    $ make PROTOCOLS="salty nacltai"

If you need to adjust compiler or linker flags, you can override the
`CPPFLAGS`, `CFLAGS` and `LDFLAGS` variables from the command
line. Please have a look at the `GNUmakefile` for their default
values, and OS-specific adjustments added to these variables.

On all platforms, you will need to have `libsodium` installed,
including its headers. For platform-specifc notes, please see below.

Supported make targets:

    $ make       # Will build quicktun and quicktun-keypair
    $ make all   # Ditto
    $ make clean # Remove build products
    $ make dist  # Create a source tarball

OpenBSD, NetBSD, FreeBSD
------------------------

You need to have gmake installed. If you want to create a tarball
using the "dist" make target, you also need to install gtar. Then you
should be set to compile:

    $ gmake
