CXX = g++
CXXFLAGS = -std=c++11 -I/usr/include/cryptopp
LDFLAGS = -lcryptopp

SRC = aes.cpp
OUT = aes

all: $(OUT)

$(OUT): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

clean:
	rm -f $(OUT)

