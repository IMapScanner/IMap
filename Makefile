.PHONY: switch imap-p4 imap server clean

switch: imap-p4 imap

imap-p4: src/switch/p4src/imap.p4 \
         src/switch/p4src/header.p4 src/switch/p4src/parser.p4
	$$SDE/p4_build.sh src/switch/p4src/imap.p4

imap: src/iconfig.h src/switch/iswitch.h src/switch/iswitch.c \
      src/switch/ichannel.h src/switch/ichannel.c \
      src/switch/iparser.h src/switch/iparser.c \
      src/switch/imap.h src/switch/imap.c
	gcc -I$$SDE_INSTALL/include -g -O2 -std=gnu11 \
		-L/usr/local/lib -L$$SDE_INSTALL/lib \
	    src/switch/iswitch.c src/switch/ichannel.c src/switch/iparser.c \
	    src/switch/imap.c -o imap \
	    -ldriver -lbfsys -lbfutils -lbf_switchd_lib -lm

server: src/iconfig.h src/server/common.h src/server/parser.c src/server/main.c
	cd src/server && make
	ln -sf src/server/build/imap-result-server .

clean:
	-rm -f imap imap-result-server bf_drivers.log* zlog-cfg-cur

.DEFAULT_GOAL :=
