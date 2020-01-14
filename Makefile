CC	   = g++
CFLAGS = -g -Wall
OBJS   = main.o
TARGET = pcap_stat

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

main.o: header.h main.cpp

clean:
	rm -rf *.o $(TARGET)