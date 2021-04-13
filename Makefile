all: pam_cgclassify.so

pam_cgclassify.so: pam_cgclassify.c
	gcc -fPIC -c pam_cgclassify.c
	gcc -shared -o pam_cgclassify.so pam_cgclassify.o -lpam

install:
	sudo cp pam_cgclassify.so /lib/security/

pam:
	sudo bash -c "echo 'session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_cgclassify.so' >> /etc/pam.d/sshd"
