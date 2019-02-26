# Debug
We have forked the debug/ folder from the standard library, to take direct control of the debug/elf, debug/macho, and debug/pe binary format parsers. To these parsers, we have added the ability to also generate executable files from the parsed intermediate data structures. This lets us load a file with debug parsers, make changes by interacting with the parser structures, and then write those changes back out to a new file.


## Read more about the project here:
https://www.symbolcrash.com/2019/02/23/introducing-symbol-crash/
