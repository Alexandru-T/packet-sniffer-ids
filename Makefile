CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -std=c++17 -Iinclude
LDFLAGS = -lpcap

TARGET = sniffer
SRCS = $(wildcard src/*.cpp)

all: check $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

check:
	cppcheck --enable=warning,style,performance --error-exitcode=1 src/