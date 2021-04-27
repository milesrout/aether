ifeq ($(BUILD),release)
	CFLAGS += -O3 -s -D_FORTIFY_SOURCE=2 -DNDEBUG -fno-delete-null-pointer-checks -march=native
else ifeq ($(BUILD),valgrind)
	CFLAGS += -Og -g -Werror -DÆTHER_USE_VALGRIND
else ifeq ($(BUILD),sanitise)
	CFLAGS += -Og -g -fsanitize=address -fsanitize=undefined #-Werror 
	LDFLAGS += -lasan -lubsan
else ifeq ($(BUILD),gdb)
	CFLAGS += -O0 -g #-Werror
else
	BUILD = debug
	CFLAGS += -Og -g #-Werror
endif

TARGET    := aether

#PC_DEPS   :=
#CFLAGS    += $(shell pkg-config --cflags $(PC_DEPS))
#LDLIBS    += $(shell pkg-config --static --libs $(PC_DEPS))

SRCS      := $(shell find src -name *.c -or -name *.S)
OBJS      := $(SRCS:%=build/$(BUILD)/%.o)
DEPS      := $(OBJS:%.o=%.d)

#INCS      := $(addprefix -I,$(shell find ./include -type d))
INCS      := -I./include

WARNINGS  += -pedantic -pedantic-errors -Wno-overlength-strings
WARNINGS  += -fmax-errors=2 -Wall -Wextra -Wdouble-promotion -Wformat=2
WARNINGS  += -Wformat-signedness -Wvla -Wformat-truncation=2 -Wformat-overflow=2
WARNINGS  += -Wnull-dereference -Winit-self -Wuninitialized
WARNINGS  += -Wimplicit-fallthrough=4 -Wstack-protector -Wmissing-include-dirs
WARNINGS  += -Wshift-overflow=2 -Wswitch-default -Wswitch-enum
WARNINGS  += -Wunused-parameter -Wunused-const-variable=2 -Wstrict-overflow=5
WARNINGS  += -Wstringop-overflow=4 -Wstringop-truncation -Walloc-zero -Walloca
WARNINGS  += -Warray-bounds=2 -Wattribute-alias=2 -Wlogical-op
WARNINGS  += -Wduplicated-branches -Wduplicated-cond -Wtrampolines -Wfloat-equal
WARNINGS  += -Wunsafe-loop-optimizations -Wbad-function-cast #-Wshadow
WARNINGS  += -Wcast-qual -Wcast-align -Wwrite-strings #-Wconversion
WARNINGS  += -Wpacked -Wdangling-else -Wparentheses #-Wsign-conversion
WARNINGS  += -Wdate-time -Wjump-misses-init -Wreturn-local-addr
WARNINGS  += -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes
WARNINGS  += -Wmissing-declarations -Wnormalized=nfkc -Wredundant-decls
WARNINGS  += -Wnested-externs -fanalyzer

CFLAGS    += -D_GNU_SOURCE $(INCS) -MMD -MP -std=c99
CFLAGS    += -fPIE -ftrapv -fstack-protector $(WARNINGS)

LDFLAGS   += -pie -fPIE
LDLIBS    += -lm

VALGRIND_FLAGS += -s --show-leak-kinds=all --leak-check=full

.PHONY: $(TARGET)
$(TARGET): build/$(BUILD)/$(TARGET)
	ln -sf build/$(BUILD)/$(TARGET) $(TARGET)

build/$(BUILD)/$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

build/$(BUILD)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $< -o $@

build/$(BUILD)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

tags: $(SRCS)
	gcc -M $(INCS) $(SRCS) | sed -e 's/[\ ]/\n/g' | \
		sed -e '/^$$/d' -e '/\.o:[ \t]*$$/d' | \
		ctags -L - $(CTAGS_FLAGS)


.PHONY: clean cleanall syntastic debug release valgrind sanitise
clean:
	$(RM) build/$(TARGET) $(OBJS) $(DEPS)

cleanall: clean
	$(RM) -r build/{debug,release,valgrind,sanitise,gdb}/*

syntastic:
	echo $(CFLAGS) | tr ' ' '\n' > .syntastic_c_config

release:
	-$(MAKE) "BUILD=release"
	./build/release/$(TARGET)

valgrind:
	-$(MAKE) "BUILD=valgrind"
	valgrind $(VALGRIND_FLAGS) ./build/valgrind/$(TARGET)

sanitise:
	-$(MAKE) "BUILD=sanitise"
	./build/sanitise/$(TARGET)

gdb:
	-$(MAKE) "BUILD=gdb"
	gdb ./build/gdb/$(TARGET)

debug:
	-$(MAKE)
	./build/debug/$(TARGET)

ifneq ($(MAKECMDGOALS),clean)
-include $(DEPS)
endif
