/lib/security/pam_module.so: pam_module.c
	gcc -fPIC -shared -o /lib/security/pam_module.so pam_module.c
