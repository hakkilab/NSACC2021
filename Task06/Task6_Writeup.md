
# **Task 6**

## <ins>Topics:</ins>

Reverse Engineering

## <ins>Task Description<ins>

Now that we've found a malicious artifact, the next step is to understand what it's doing. Identify some characteristics of the communications between the malicious artifact and the LP.

## <ins>Provided Files<ins>

None

## <ins>Solution<ins>

### **1) Static anlysis of make binary**

To start the reverse engineering process, we get a copy of `make` using `sudo docker run panic-nightly-test cat /usr/bin/make > ./make`.

We create a Ghidra project using `File > New Project`, import the `make` binary with `File > Import File`, and then open CodeBrowser and run the analysis with default options.

Looking through the decompiled code, we see the following lines that look to set the values we are interested in:

`ip_00 = julmrgkpgrycp(0x13);`

`version_00 = julmrgkpgrycp(0x11);`

`pubKey = julmrgkpgrycp(0x12);`

### **2) Dynamic anlysis of make binary**

Using `sudo docker run -it panic-nightly-test /bin/sh` we can start another interactive shell in the docker image. We can then use `apk add gdb` to install `gdb` in the image and run `gdb /usr/bin/make` to start a `gdb` session.

In `gdb`, we can use `break main` and `run` to start the `make` program. Then, using `call julmrgkpgrycp(0x13)` and `call julmrgkpgrycp(0x11)` we can get the IP and version info we are interested in:

198.51.100.116

1.0.2.2-BTA

Since we are interested in the hex values for the public key, we need to use `p/x *julmrgkpgrycp(0x13)@32` in order to see a hex array of the 32 bytes of the public key. Manually putting those hex values together in a text editor gives us the following:

2d9fe394384908175d8b596d3be34846e87ff993757482e13c9e2c9624010f14