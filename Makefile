CFLAGS=-I../include -I./ -L../cJSON/ -I../cJSON/
#LDFLAGS=-L../lib -lnorouter
CGILDFLAGS=$(LDFLAGS)
CC=mips-linux-gcc
#CC=mipsel-openwrt-linux-gcc 
OBJS= newmain.o cJSON.o get_file_config.o 
LIBS = -lpthread -ldl #-lcom -liw
LIBS += -lm -Wall
all: bycomm

bycomm: $(OBJS)
	$(CC) -o ./bycomm $(OBJS) $(LDFLAGS) $(CFLAGS) $(LIBS) 

clean:
	rm -f *.o
	rm -f bycomm


