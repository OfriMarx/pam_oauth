# pam_oauth
PAM module for authenticating users through an oauth server

## PAM Module
### Building
Move to the pam directory and run `sudo make`. This should compile the pam modules and copy them to the right place in your system
```bash
cd pam_modules
sudo make
```
### Configuration
You need to edit the pam.d file of whatever program you want to authenticate through the new pam modules. PAM configuration files are usually at `/etc/pam.d`. This is an example of an sshd pam configuraion:
```
#%PAM-1.0
auth required <PAM_MODULE_NAME_HERE>
account include system-remote-login
password include system-remote-login
session include system-remote-login
```
## Certificate Configuration
### As an Authentication Sever
Generate an rsa key
```
openssl genrsa -out server.key 2048
```
Generate a CSR
```
openssl req -new -key server.key -out server.csr
```
### As a CA Server
Generate a new rsa key
```
openssl genrsa -out ca.key 2048
```
Generate a self signed certificate
```
openssl req -new -x509 -key ca.key -out ca.crt
```
Sign the CSR of the auth server
```
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt.signed
```
## OAUTH Server
### Configuration
Store usernames and passwords for authentication in the file `/etc/pasten.conf` in the format of \<username\>=\<password\>. Here is an example:
```
user1=p@ssw0rd
user2=1234568
```
Store the path to the keys used for generating tokens in the file `/etc/keys.conf` in the format of \<kid\>=\</path/to/key\>. Here is an example:
```
1=/home/user/keys/server1.crt.signed
2=/home/user/keys/server2.crt.signed
```
Finally, run the server.js file with the command `node server.js`
### Usage
Get a token through the /token end point on the server. Authentication is done with the creds in /etc/pasten.conf, through the HTTP Basic authentication method ([explanation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)).

Validate the token through the /validate end point. The token is passed using the HTTP authentication method, but this time with [Bearer](https://tools.ietf.org/html/rfc6750) authentication instead of Basic.
