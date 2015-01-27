**[Originally written somewhere around 2005]**

# TinyLDAP - very small and simple LDAP v1 reader implementation

This module serves as a very small standalone replacement
for basic functionality of the Net::LDAP module.
It is implemented in pure Perl, so it can be used in minimal
Perl installations. The only dependency is the standard `Socket`,
`Errno` and `Fcntl` modules (not `IO::Socket`) for the basic
socket operation functions.

Currently, anonymous or simple authentication can be used.
Only searching is supported.

