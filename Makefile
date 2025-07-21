ROOT_DIR := $(CURDIR)
USM_DIR := $(ROOT_DIR)/usm
TEMP_DIR := $(ROOT_DIR)/intermediate
OBJ_DIR := $(TEMP_DIR)/obj
ELF_IN := SLUS_208.70.ELF
ELF_OUT := USM.elf
LINKER_SCRIPT := linker.x

CXX := ee-g++
CC := ee-gcc
LD := ee-ld
WCC := wcc

CXXFLAGS := #-O2 -G0 -Wall -fno-exceptions -fno-rtti -nostdlib
CFLAGS := #-O2 -G0 -Wall -nostdlib
LDFLAGS := -T $(LINKER_SCRIPT) \
           -Ttext=0x00100000 \
           -Tbss=0x00805480 \
           -Tdata=0x727c00 \
           -Bstatic

SRC_CPP := $(wildcard $(USM_DIR)/*.cpp)
SRC_C := $(wildcard $(USM_DIR)/*.c)
SRC := $(SRC_CPP) $(SRC_C)
OBJS := $(patsubst $(USM_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SRC_CPP)) \
        $(patsubst $(USM_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_C))

USM_OBJ := $(OBJ_DIR)/usm.obj

.PHONY: all clean

all: $(ELF_OUT)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(USM_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(USM_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(USM_OBJ): $(ELF_IN) | $(OBJ_DIR)
	$(WCC) --original $(ELF_IN) -o $(USM_OBJ)

$(ELF_OUT): $(OBJS) $(USM_OBJ)
	$(LD) $(LDFLAGS) $^ -o $@

clean:
	rm -rf $(TEMP_DIR) $(ELF_OUT)
