# FreeBSD online kernel debugging

I wanted to see if online kernel debugging can be helpful during the development of exploits. These are my setup notes. I had to overcome a few hurdles, had some LLM help, but in the end managed to get online debugging working.

## References
* Relevant chapter of the FreeBSD Developers' Handbook (of course!): [ On-Line Kernel Debugging Using Remote GDB](https://docs.freebsd.org/en/books/developers-handbook/kerneldebug/#kerneldebug-online-gdb)
* [How to Use `kgdb` for Kernel Debugging on FreeBSD Operating System](https://www.siberoloji.com/how-to-use-kgdb-for-kernel-debugging-on-freebsd-operating-system/)
* [FreeBSD kernel debugging](https://census-labs.com/news/2009/01/19/freebsd-kernel-debugging/)

## Concept

The idea of online FreeBSD kernel debugging (as I have understood it) is that you need a second FreeBSD machine that runs the debugger on a copy of the kernel image of the target. In addition the FreeBSD source code must be available on the debugger machine so that you can set breakpoints in the C code and step through execution. The debugger machine connects to the target through a serial connection.

To be continued...
