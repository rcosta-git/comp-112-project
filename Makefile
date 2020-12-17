all: project

# first run:
# brew install openssl
# find /usr/local/Cellar/ -name "libssl.*"
# then update the paths below with what you found
project: project.c
	gcc project.c -I/usr/local/Cellar//openssl@1.1/1.1.1g/include -L/usr/local/Cellar//openssl@1.1/1.1.1g/lib -lssl -lcrypto

run:
	./a.out 9010

runSSL:
	./a.out 9010 1

runDebug:
	./a.out 9010 0 1

runDebugSSL:
	./a.out 9010 1 1
