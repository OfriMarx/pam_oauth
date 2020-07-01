# pam_oauth
PAM module for authenticating users through an oauth server

## building
Move to the pam directory and run `sudo make`. This should compile the pam modules and copy them to the right place in your system
```bash
cd pam_modules
sudo make
```
## PAM configuration
You need to edit the pam.d file of whatever program you want to authenticate through the new pam modules. PAM configuration files are usually at `/etc/pam.d`. This is an example of an sshd pam configuraion:
```
#%PAM-1.0
auth required <PAM_MODULE_NAME_HERE>
account include system-remote-login
password include system-remote-login
session include system-remote-login
```
## certificate configuration
### as an authentication sever
Generate an rsa key
```
openssl genrsa -out server.key 2048
```
Generate a CSR
```
openssl req -new -key server.key -out server.csr
```
### as a CA server
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
## OAUTH server configuration
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
