
The Tcl language has a glob function that reads in all files in a directory.

This can be used to put together tree traversal code, breadth-first, or depth-first, as usual. The issue is that as the glob function is an atomic operation, if there are many files in a single directory, there will be a delay in the gui as the program pauses while disk operation completes.

This C code maps natively to the Win32 api using FindFirstFile and FindNextFile, and thereby can look at single files at a time and periodically update the gui, without need for threading.

Threading can be reserved for other operations, and now a tree walk is a simple sequential operation that can update the gui while not needing the overhead of a lot more code.

