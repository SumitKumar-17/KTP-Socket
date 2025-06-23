# =====================================================================================================================
# Assignment 4 Submission 
# Name: Sumit Kumar 
# Roll number: 22CS30056
# Link of the pcap file: https://drive.google.com/file/d/1FW5PEmipQMQc6ik-mDaiQGYdnPoZ9dcI/view?usp=sharing
# =====================================================================================================================

# This Makefile is used to compile the files and run the executables
# Run as `make all` to compile all the files
# Run './initksocket' to start the server
# Run './user1' to start the first client
# Run './user2' to start the second client
# Run `make clean` to remove all the executables and object files

OUTPUT_FILE = output.txt

all:
	make -f libmake
	make -f initmake
	make -f usermake

check: 
	g++ -o checker checker.cpp
	./checker

.PHONY: clean

clean:
	make -f libmake clean
	make -f initmake clean
	make -f usermake clean
	rm -f $(OUTPUT_FILE)
	rm -rf checker
