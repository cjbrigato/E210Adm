all: libzlib libminizip E210Adm

libzlib:
	$(MAKE) -C lib/zlib/
libminizip:
	$(MAKE) -C lib/minizip/
E210Adm:
	$(MAKE) -C src/
	mv src/E210Adm .
 
clean:
	rm -f ./E210Adm
	$(MAKE) -C lib/zlib/ clean
	$(MAKE) -C lib/minizip/ clean
	$(MAKE) -C src/ clean
