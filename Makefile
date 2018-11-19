CFLAGS = -O3

all:	sign

sign:	sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o sock.o clearsign.o

clean:
	rm -f sign sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o sock.o clearsign.o
test:
	prove t/*.t
