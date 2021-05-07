# Linux-C-Dstributed-File-System
A configurable Linux DFS client & server program written in C. Implements basic user authentication and encryption.

Can reliably put and retrieve large files from remote DFS servers with fail-over protection. Files are stored encrypted (XOR encryption, as a proof of concept) and tied to a specific user.

# Usage
  
  
## Building
Requires openssl development libraries and pthreads. Make file provided.

## Client  
Client: ./dfc \<config file\>  
  
  provided config ex:  
  ./dfc dfc.conf   
  ./dfc dfc2.conf   
  
### Client Commands  
commands are case-sensitive and must be all lowercase. Filenames & directories can be any case and are case sensitive.  

- get \<file> \<opt. DIR\>
- put \<file> \<opt. DIR\>
- list \<opt. DIR\>
- mkdir \<DIR\>
 
If an <opt. DIR> directory argument is not supplied, file will default to user root directory on the servers.  
\<file\> must be just a file name located in the directory the client is running from. You can pass \<file\> but not \<dir/file\>.  

## Server  
  
Server: ./dfs \<svr name\> \<port\> \<config file\>  
  
  provided config ex:  
  ./dfs DFS1 10001 dfs.conf &  
   
  Will operate under svr_name/ directory  
  
# Config Structure  
  
## Client Config  
  
Client config must begin with 4 lines in the format of "Server \<str name\> ipv4addr:port".  
These lines are immediately followed by a line starting with "User " with the username following.  
That line is immediately followed by a "Pass " line with the password following.  
  
| = new file line
### Example:  
  
 
|Server DFS1 127.0.0.1:10001  
|Server DFS2 127.0.0.1:10002  
|Server DFS3 127.0.0.1:10003  
|Server DFS4 127.0.0.1:10004  
|User bob  
|Pass 12345  
  
## Server Config  
  
This config specifies valid username/password combinations of DFS clients.  
Config encodes user/pass combos in two lines, with the User in the 1st and the Pass in the 2nd with correct identifiers.  
Usernames and passwords are limited to 15 characters.  
Additional valid users are added on following lines in the same format.  
  
| = new file line
### Example:  
  

|User bob  
|Pass 12345  
|User alice  
|Pass pass123
