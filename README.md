# libp0f

Based on p0f 3.09b
------------------

This is an effort to modernize the code base of p0f. p0f is a wonderful and 
useful utility as a stand alone application. Unfortunately, its usage of 
compiler extensions and other non-portable implementation details have made
it difficult to integrate into other code bases. This repo is an attempt to
make p0f easier to work with and more portable.

All usage of compiler extensions have been factored out, the code compiles
as strict ANSI C99. (The only caveat so far is that `pcap.h` still depends
on some BSD types, I plan to find a good way to handle this at some point 
while still targetting more portability).

Additional efforts have be made to seperate out the application driving logic 
from the core logic, so that the core can be used as a library in existing
applications. Building this source tree will result in a library file and an
executable, which is functionally equivalent to the original p0f.

Please see the original README which has been preserved in this codebase as is
in the docs directory.
