# aeslib-lua
A compiled aeslib.dll for use in lua and mushclient, including the source files.
We had some difficulty tracking down unmodifyed versions of source files, as currently cr0.net:8040/code/crypto is offline.
Archive.org was able to provide some files and others were gathered from trusted sources on the web; lua files were obtained from a lua 5.1 installation.

The DLL provided (when we compile it) will provide aes.encrypt, aes.decrypt, and aes.dh for use in scripts, plugins, triggers, timers, and aliases for mushclient.
see http://www.gammon.com.au for more information on mushclient, and
http://www.gammon.com.au/forum/?id=4988 for a discussion of this DLL and it's uses.
