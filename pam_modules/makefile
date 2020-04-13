.PHONY: all
	
all: /lib/security/pam_oauth.so

/lib/security/%.so: %.c
	gcc -fPIC -shared -o $@ $<
