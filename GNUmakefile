ifeq ($(BUILD),release)
	CFLAGS += -Os -s -D_FORTIFY_SOURCE=2 -DNDEBUG -march=native
else ifeq ($(BUILD),musl)
	CFLAGS += -Os -s -D_FORTIFY_SOURCE=2 -DNDEBUG -march=native -static
	LDFLAGS += -static
	CC = musl-gcc
else ifeq ($(BUILD),musldebug)
	CFLAGS += -Og -g
	CC = musl-gcc
else ifeq ($(BUILD),valgrind)
	CFLAGS += -Og -g
else ifeq ($(BUILD),sanitise)
	CFLAGS += -Og -g -fsanitize=address -fsanitize=undefined
	LDFLAGS += -lasan -lubsan
else ifeq ($(BUILD),gdb)
	CFLAGS += -O0 -g
else
	BUILD = debug
	CFLAGS += -Og -g
endif

ifneq ($(BUILD),release)
	CFLAGS += -Werror
endif

CFLAGS    += -DBUILD_$(shell echo '$(BUILD)' | tr '[:lower:]' '[:upper:]')

TARGET    := aether

#PC_DEPS   :=
#CFLAGS    += $(shell pkg-config --cflags $(PC_DEPS))
#LDLIBS    += $(shell pkg-config --static --libs $(PC_DEPS))

SRCS      := $(shell find src -name *.c -or -name *.S)
OBJS      := $(SRCS:%=build/$(BUILD)/%.o)
DEPS      := $(OBJS:%.o=%.d)

INCS      := -iquote./include

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
WARNINGS  += -Wpacked -Wdangling-else -Wno-parentheses #-Wsign-conversion
WARNINGS  += -Wdate-time -Wjump-misses-init -Wreturn-local-addr -Wno-pointer-sign
WARNINGS  += -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes
WARNINGS  += -Wmissing-declarations -Wnormalized=nfkc -Wredundant-decls
WARNINGS  += -Wnested-externs -Wno-missing-field-initializers -fanalyzer

CFLAGS    += -D_GNU_SOURCE $(INCS) -MMD -MP -std=c99 -fPIE -fstack-protector
CFLAGS    += -ftrapv -fno-strict-aliasing -fno-delete-null-pointer-checks
CFLAGSNW  := $(CFLAGS)
CFLAGS    += $(WARNINGS)

LDFLAGS   += -pie -fPIE -flto
LDLIBS    += -lm

VALGRIND_FLAGS += -s --show-leak-kinds=all --leak-check=full --track-origins=yes

.PHONY: $(TARGET)
$(TARGET): build/$(BUILD)/$(TARGET)
	@echo '  SYMLINK ' $(TARGET) "->" build/$(BUILD)/$(TARGET)
	@ln -sf build/$(BUILD)/$(TARGET) $(TARGET)

build/$(BUILD)/$(TARGET): $(OBJS)
	@echo '  LD      ' $@
	@$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

build/$(BUILD)/src/monocypher.c.o: src/monocypher.c
	@mkdir -p $(dir $@)
	@echo '  CC      ' $<.o
	@$(CC) -c $(CFLAGSNW) $< -o $@

build/$(BUILD)/src/stb_ds.c.o: src/stb_ds.c
	@mkdir -p $(dir $@)
	@echo '  CC      ' $<.o
	@$(CC) -c $(CFLAGSNW) $< -o $@

build/$(BUILD)/%.c.o: %.c
	@mkdir -p $(dir $@)
	@echo '  CC      ' $<.o
	@$(CC) -c $(CFLAGS) $< -o $@

build/$(BUILD)/%.S.o: %.S
	@mkdir -p $(dir $@)
	@echo '  AS      ' $<.o
	@$(AS) $(ASFLAGS) $< -o $@

tags: $(SRCS)
	gcc -M $(INCS) $(SRCS) | sed -e 's/[\ ]/\n/g' | \
		sed -e '/^$$/d' -e '/\.o:[ \t]*$$/d' | \
		ctags -L - $(CTAGS_FLAGS)


.PHONY: clean cleanall syntastic debug release valgrind sanitise
clean:
	$(RM) -r build/$(BUILD)/*

cleanall: clean
	$(RM) -r build/*/*

syntastic:
	echo $(CFLAGS) | tr ' ' '\n' | sort | grep -v "MMD\|MP" | \
	grep -v "BUILD_$(shell echo '$(BUILD)' | tr '[:lower:]' '[:upper:]')" \
	> .syntastic_c_config

release:
	-$(MAKE) "BUILD=release"
	./build/release/$(TARGET) $(args)

musl:
	-$(MAKE) "BUILD=musl"
	./build/musl/$(TARGET) $(args)

musldebug:
	-$(MAKE) "BUILD=musldebug"
	./build/musldebug/$(TARGET) $(args)

valgrind:
	-$(MAKE) "BUILD=valgrind"
	valgrind $(VALGRIND_FLAGS) ./build/valgrind/$(TARGET) $(args)

sanitise:
	-$(MAKE) "BUILD=sanitise"
	./build/sanitise/$(TARGET) $(args)

gdb:
	-$(MAKE) "BUILD=gdb"
	gdb ./build/gdb/$(TARGET) $(args)

debug:
	-$(MAKE)
	./build/debug/$(TARGET) $(args)

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),cleanall)
-include $(DEPS)
endif
endif
