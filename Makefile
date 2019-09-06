CFLAGS = -O3 -Wall -D_FILE_OFFSET_BITS=64 -g

all:	sign

sign:	sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o sock.o clearsign.o appx.o zip.o

clean:
	rm -f sign sign.o hash.o base64.o pgp.o x509.o rpm.o appimage.o sock.o clearsign.o appx.o zip.o
test:
	prove t/*.t
