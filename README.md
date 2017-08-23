# OF32
A simple tool to find offsets needed in 32bit jailbreaks. Feel free to contribute.

### How to use
To build the tool simply use `make`. Then to use:
```
./OF32 [unencrypted_kernelcache_path]
```

### Notes
Only works on 32bit kernelcaches (obviously). Didn't do a lot of testing, so stuff may happen. Also not sure all offsets needed are included.
Pull requests are appreciated!

*Important:* will not work on dumps/runtime kernel as it is, since it relies on symbols that get stripped at runtime.
