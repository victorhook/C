TARGET  = main
SOURCES = pinger.c
OBJECTS = $(SOURCES:.c=.o)

run: $(TARGET)
	@sudo setcap cap_net_admin,cap_net_raw=eip $(TARGET)
	@ rm -f $(OBJECTS)
	@./$(TARGET)

$(TARGET): $(OBJECTS)
	@gcc $^ -o $@

$(OBJECTS): $(SOURCES)
	@gcc -c $^ -o $@
