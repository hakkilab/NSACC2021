
# **Task 10**

## <ins>Topics:</ins>

Protocol Analysis, Software Development, Exploit Development

## <ins>Task Description<ins>

NSA worked with FBI to notify all of the identified victims, who in turn notified DC3. Nicely done.

The final task is to uncover additional information about the actor's infrastructure.

Gain access to the LP. Provide the IP and port that the psuser account has transmitted data to. What lies behind the listening post?

## <ins>Provided Files<ins>

None

## <ins>Solution<ins>

### **1) Investigating the Listening Post**

Using the leaked contents of id_rsa and id_rsa.pub from the previous task, the listening post was accessed via ssh. Looking through the files, we see there is a binary called `powershell_lp` that is being run with the psuser account. Other files owned by psuser are inaccessible, so we will try and exploit this binary to get the info we need.

### **2) Binary Reverse Engineering**

Loading the binary in Ghidra, we quickly find that this program is stripped and statically compiled. In order to start understanding how the binary works, we use the [ApplySig](https://github.com/NWMonster/ApplySig) script to use the [IDA FLIRT signature database](https://github.com/push0ebp/sig-database). This identifies many standard c library functions to use for reverse engineering the binary.

Looking through the binary, it becomes apparent that there is a stack overflow vulnerability in the function `FUN_00108f6b` where a loop contains a call to recv() reading in the full length of bytes every time. So, if the amount of data recv() puts in the buffer is below the max length, another call to recv will be made that then still reads in the full length, so more data can overflow the buffer.

Further analysis shows that while the binary uses ASLR and stack canaries to protect against stack overflows, the binary also uses fork() to split off child processes for handling connections. This means that the stack canary and ASLR offset can be brute forced in a max of 256*8 = 2048 tries each, since fork() maintains these values between children.

Since the binary is statically compiled, there are many rop gadgets that can be used to exploit the binary. Using a brute-forced return address, we can also calculate the address offset for any function to use in our ROP chain attack. So, the plan for exploitation is to brute force find the canary, aslr, and return address values, then use ROP gadgets to exploit the binary. In this case, the ROP gadget payload will use open, read, and write calls to write the contents of arbitrary files controlled by psuser to files that lpuser can access, like ps_data.log.

### **3) Binary Exploitation**

Using ssh, a script for brute forcing the canary, aslr, and return address values on the stack (`brute_force_fork.py`) was run. Using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), ROP gadgets were found and combined to form a ROP chain that opens a file, reads the contents, and then writes to contents to ps_data.log on the listening post (`ropchain.py`).

Using the rop chain generator and the bruteforced values, an explot script was made (`leak_ps_file.py`) and used to leak the file contents of `/home/psuer/.ssh/config` and `/home/psuser/.bash_history` to find the ip address and port that data was forwarded to:

10.184.52.58

31194