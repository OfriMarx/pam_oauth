# pam_oauth
pam module for authenticating users through an oauth server

## building
move to the pam directory and run `sudo make`. this should compile the pam modules and copy them to the right place in your system
```bash
cd pam_modules
sudo make
```
## pam configuration
You need to edit the pam.d file of whatever program you want to authenticate through the new pam modules. pam configuration files are usually at `/etc/pam.d`. This is an example of an sshd pam configuraion:
```
#%PAM-1.0
auth required <PAM_MODULE_NAME_HERE>
account include system-remote-login
password include system-remote-login
session include system-remote-login
```
## certificate configuration
### as an authentication sever
generate an rsa key
```
openssl genrsa -out server.key 2048
```
generate a CSR
```
openssl req -new -key server.key -out server.csr
```
### as a CA server
generate a new rsa key
```
openssl genrsa -out ca.key 2048
```
generate a self signed certificate
```
openssl req -new -x509 -key ca.key -out ca.crt
```
sign the CSR of the auth server
```
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt.signed
```
