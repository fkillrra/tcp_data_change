all : tcp_data_change

tcp_data_change: main.o
	g++ -g -o tcp_data_change main.o -lnetfilter_queue

main.o:
	g++ -g -std=c++11 -c -o main.o main.cpp

clean:
	rm -f tcp_data_change
	rm -f *.o


