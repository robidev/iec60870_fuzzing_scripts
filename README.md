# iec60870_fuzzing_scripts
A collection of basic fuzzing scripts using boofuzz and kitty/katnip for IEC 60870-5-104. These are intended to be expanded as needed.
Currently fuzzers that connect to a server (server/slave fuzzers) and client/master fuzzers have been implemented in limited fashion, but should be easy to be expanded.

the binaries are simple examples of a IEC 60870 master and slave(based on the lib60870 library; https://github.com/mz-automation/lib60870), that can be used for testing.

Dependencies:
boofuzz, kitty, katnip. All can be installed with pip. 

lib60870_mod.so and the binary example client/server can be recompiled from lib60870, by running `make dynlib` and `make` in the respective examples folders. 

However, I have modified the source in the included lib60870_mod.so to allow the size of a message to be modified, or a message not to be sent out alltogether to accomodate some fuzzing edge-cases. As it is not a nice modification with lots of side-effects, I will not publish this code. Feel free to drop me a message if you are interested in the exact modification I made.(hint: argument 'int size' has become 'int* size')
