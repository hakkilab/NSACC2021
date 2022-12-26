
# **Task 7**

## <ins>Topics:</ins>

Protocol Analysis

## <ins>Task Description<ins>

With the information provided, PANIC worked with OOPS to revert their Docker image to a build prior to the compromise. Both companies are implementing additional checks to prevent a similar attack in the future.

Meanwhile, NSA's Cybersecurity Collaboration Center is working with DC3 to put together a Cybersecurity Advisory (CSA) for the rest of the DIB. DC3 has requested additional details about the techniques, tools, and targets of the cyber actor.

To get a better understanding of the techniques being used, we need to be able to connect to the listening post. Using the knowledge and material from previous tasks, analyze the protocol clients use to communicate with the LP. Our analysts believe the protocol includes an initial crypt negotiation followed by a series of client-generated requests, which the LP responds to. Provide the plaintext a client would send to initialize a new session with the provided UUID.

## <ins>Provided Files<ins>

<ul>
<li>Victim ID to use in initialization message (victim_id)</li>
</ul>

## <ins>Solution<ins>

### **1) Static anlysis of make binary**

Looking through the decompiled code in Ghidra, we see a function called `hrjjzmwmxaybo` which builds the initialization message through a series of concatenations.

The string is built with global constants named `MAGIC_START`, `PARAM_CMD`, `COMMAND_INIT`, `PARAM_UUID`, and `MAGIC_END`. When converted to strings, `MAGIC_START` and `MAGIC_END` are allocated a size of 4 bytes, and the rest are allocated a size of 2 bytes.

Additionally, the initialization message contains a command length (with a value of 2) and UUID length (which will have a value of 16 for 16 UUID bytes) which are both represented as big endian 2 byte strings, so `0002` and `0010` in hex respectively.

So the final layout of the initialization message is as follows:

`MAGIC_START+PARAM_CMD+0002+COMMAND_INIT+PARAM_UUID+0010+victim_id+MAGIC_END`

Looking through the code in Ghidra, we can see the that global constants have the following values in hex:

`MAGIC_START = 14424073`

`PARAM_CMD = 4e00`

`COMMAND_INIT = 0002`

`PARAM_UUID = 4e08`

`MAGIC_END = e64f1495`

Putting it all together with the UUID in `victim_id`, we get the following initialization packet in hex:

144240734e00000200024e080010509d62934c2c414cbf7100c4763028f7e64f1495