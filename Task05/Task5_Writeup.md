
# **Task 5**

## <ins>Topics:</ins>

Docker Analysis

## <ins>Task Description<ins>

A forensic analysis of the server you identified reveals suspicious logons shortly after the malicious emails were sent. Looks like the actor moved deeper into OOPS' network. Yikes.

The server in question maintains OOPS' Docker image registry, which is populated with images created by OOPS clients. The images are all still there (phew!), but one of them has a recent modification date: an image created by the Prevention of Adversarial Network Intrusions Conglomerate (PANIC).

Due to the nature of PANIC's work, they have a close partnership with the FBI. They've also long been a target of both government and corporate espionage, and they invest heavily in security measures to prevent access to their proprietary information and source code.

The FBI, having previously worked with PANIC, have taken the lead in contacting them. The FBI notified PANIC of the potential compromise and reminded them to make a report to DC3. During conversations with PANIC, the FBI learned that the image in question is part of their nightly build and test pipeline. PANIC reported that nightly build and regression tests had been taking longer than usual, but they assumed it was due to resourcing constraints on OOPS' end. PANIC consented to OOPS providing FBI with a copy of the Docker image in question.

Analyze the provided Docker image and identify the actor's techniques.

## <ins>Provided Files<ins>

<ul>
<li>PANIC Nightly Build + Test Docker Image (image.tar)</li>
</ul>

## <ins>Solution<ins>

### **1) Setting up the docker image**

We start by loading in the provided docker image with `sudo docker image load -i ./image.tar` and then outputting detailed info about the image using `sudo docker image inspect > inspect.json` (both implement in our script `setup_docker_image.sh`).

Opening `inspect.json` in a text editor allows us to find the email for the image maintainer:

mccarver.jane@panic.invalid

### **2) Inspecting what happens when the image runs**

We also see from `inspect.json` that when the image is run, it starts a script called `build_test.sh`.

We can start an interactive shell session in the image using `sudo docker run -it panic-nightly-test /bin/sh`. Using `cat build_test.sh` we see the following:

<code>
#!/bin/bash

git clone https://git-svr-10.prod.panic.invalid/hydraSquirrel/hydraSquirrel.git repo

cd /usr/local/src/repo

./autogen.sh

make -j 4 install

make check
</code>

From this we can see the git repo is being cloned from the following URL:

https://git-svr-10.prod.panic.invalid/hydraSquirrel/hydraSquirrel.git

Now we can run `sudo docker run panic-nightly-test` to see what happens. When we do so we get the following output:

<code>
Cloning into 'repo'...
fatal: unable to access 'https://git-svr-10.prod.panic.invalid/hydraSquirrel/hydraSquirrel.git/': Could not resolve host: git-svr-10.prod.panic.invalid
./build_test.sh: line 5: cd: /usr/local/src/repo: No such file or directory
./build_test.sh: line 7: ./autogen.sh: No such file or directory
ninja: *** No rule to make target 'install'.  Stop.
ninja: *** No rule to make target 'check'.  Stop.
</code>

We can see in actuality, `ninja` is being run, not `make`. Using `which make` we see the path for this `make` is `/usr/bin/make`. When we go to this directory and run `ldd make` we get the following output:

<code>
/lib/ld-musl-x86_64.so.1 (0x7f3a8e13c000)<br>
libgit2.so.1.1 => /usr/lib/libgit2.so.1.1 (0x7f3a8dfa7000)<br>
libstdc++.so.6 => /usr/lib/libstdc++.so.6 (0x7f3a8de05000)<br>
libgcc_s.so.1 => /usr/lib/libgcc_s.so.1 (0x7f3a8ddeb000)<br>
libc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x7f3a8e13c000)<br>
libssl.so.1.1 => /lib/libssl.so.1.1 (0x7f3a8dd6a000)<br>
libcrypto.so.1.1 => /lib/libcrypto.so.1.1 (0x7f3a8dae9000)<br>
libpcre.so.1 => /usr/lib/libpcre.so.1 (0x7f3a8da8d000)<br>
libhttp_parser.so.2.9 => /usr/lib/libhttp_parser.so.2.9 (0x7f3a8da81000)<br>
libz.so.1 => /lib/libz.so.1 (0x7f3a8da67000)<br>
libssh2.so.1 => /usr/lib/libssh2.so.1 (0x7f3a8da2f000)<br>
</code>

This is a malicious file, not the normal `make` program. So the path for the malicious file in this image is:

/usr/bin/make