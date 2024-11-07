# Имя исполнимого файла
TARGET = hash

# Исходный код
SRC = hash.cpp

# Папка с заголовочными файлами библиотеки Crypto++
INCLUDE = /usr/include/cryptopp

# Папка с библиотеками Crypto++
LIBS = /usr/lib

# Флаги компилятора
CXXFLAGS = -std=c++11 -I$(INCLUDE)

# Линковка с библиотекой Crypto++
LDFLAGS = -lcryptopp

# Правила для сборки
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Очистка промежуточных файлов
clean:
	rm -f $(TARGET)


