CFLAGS = -O3 -Wall

all:	sign

sign:	sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o

clean:
	rm -f sign sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o
test:
	prove t/*.t
