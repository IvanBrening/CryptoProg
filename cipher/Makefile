# Имя исполняемого файла
TARGET = hash_file

# Компилятор и флаги
CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto

# Список исходных файлов
SRC = hash_file.cpp

# Правило сборки
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Очистка
clean:
	rm -f $(TARGET)
