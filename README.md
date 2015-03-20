# aeslib-lua
A compiled aeslib.dll for use in lua and mushclient, including the source files.
We had some difficulty tracking down unmodifyed versions of source files, as currently cr0.net:8040/code/crypto is offline.
Archive.org was able to provide some files and others were gathered from trusted sources on the web; lua files were obtained from a lua 5.1 installation.

The DLL provided (when we compile it) will provide aes.encrypt, aes.decrypt, and aes.dh for use in scripts, plugins, triggers, timers, and aliases for mushclient.
see http://www.gammon.com.au for more information on mushclient, and
http://www.gammon.com.au/forum/?id=4988 for a discussion of this DLL and it's uses.

Update: I was able to obtain a compiled DLL from 
http://helllua.googlecode.com/svn/trunk/aeslib.dll
However it wasn't compiled with diffie hellman support, which means there is no aes.dh functionality.
For now, the limited aeslib.dll is coppied into this project. I plan on recompiling with diffie hellman added just as soon as i can fix a few compilation errors.

Update:
https://code.google.com/p/mushluamapper/source/browse/trunk/
Seems to have the files we're looking for (one of the previous ones had errors when compiling under cygwin), so i'll be coppying these files in to the project.
I'll make the needed changes to the source files so we'll have diffie hellman support, and attempt a compile.