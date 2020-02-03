SOURCE = ping.c
TARGET = main

run: access
	./$(TARGET) & ping localhost -c 1 > .temp

access: bin
	sudo setcap cap_net_admin,cap_net_raw=eip $(TARGET)

bin: $(SOURCE)
	gcc $(SOURCE) -o $(TARGET)