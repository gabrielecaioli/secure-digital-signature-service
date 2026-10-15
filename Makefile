CXX      ?= g++
CXXFLAGS ?= -std=c++11
LDLIBS   := -lcrypto

# On macOS OpenSSL 3 is not in the default search path: take it from Homebrew
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(OPENSSL_PREFIX),)
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
endif

SRC   := src
BUILD := build
KEYS  := keys

.PHONY: all keys clean

all: $(BUILD)/server $(BUILD)/client

$(BUILD)/server: $(SRC)/server.cpp $(SRC)/utility.cpp $(SRC)/utility.h
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)/utility.cpp $(SRC)/server.cpp $(LDFLAGS) $(LDLIBS) -pthread

$(BUILD)/client: $(SRC)/client.cpp $(SRC)/utility.cpp $(SRC)/utility.h
	@mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)/utility.cpp $(SRC)/client.cpp $(LDFLAGS) $(LDLIBS)

# Generate the DSS master key and the server RSA key pair (existing files are kept)
keys: $(KEYS)/dss_master.key $(KEYS)/server_pub.pem

$(KEYS)/dss_master.key:
	@mkdir -p $(KEYS)
	openssl rand -out $@ 32

$(KEYS)/server_priv.pem:
	@mkdir -p $(KEYS)
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $@

$(KEYS)/server_pub.pem: $(KEYS)/server_priv.pem
	openssl rsa -pubout -in $< -out $@

clean:
	rm -rf $(BUILD)
