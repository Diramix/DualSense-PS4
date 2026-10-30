CC := clang
LD := ld.lld
BUILD := .build
CFLAGS := -target x86_64-pc-freebsd12-elf -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -fPIC -mno-red-zone

all: DualSense-PS4.bin DualSense-PS4-stop.bin

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c src/dualsense.h src/version.h | $(BUILD)
	$(CC) $(CFLAGS) -Wno-unused-function -c $< -o $@

$(BUILD)/native.elf: $(BUILD)/native.o $(BUILD)/dualsense.o src/payload.ld
	$(LD) -nostdlib -static -T src/payload.ld $(BUILD)/native.o $(BUILD)/dualsense.o -o $@

$(BUILD)/stop.elf: $(BUILD)/stop.o src/payload.ld
	$(LD) -nostdlib -static -T src/payload.ld $(BUILD)/stop.o -o $@

DualSense-PS4.bin: $(BUILD)/native.elf
	objcopy -O binary $< $@

DualSense-PS4-stop.bin: $(BUILD)/stop.elf
	objcopy -O binary $< $@

clean:
	rm -rf $(BUILD)
