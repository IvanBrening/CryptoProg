# Имя исполняемого файла
TARGET = encrypt_decrypt_file

# Компилятор и флаги
CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto

# Список исходных файлов
SRC = encrypt_decrypt_file.cpp

# Правило сборки
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Очистка
clean:
	rm -f $(TARGET)
