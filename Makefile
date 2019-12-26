DEV = /dev/ttyACM0
MPY_CROSS=../micropython/mpy-cross/mpy-cross


PY_FILES := $(wildcard ZbPy/*.py)
MPY_FILES = $(PY_FILES:.py=.mpy)

%.mpy: %.py
	$(MPY_CROSS) \
		-march=armv7m \
		-mno-unicode \
		-o $@ \
		$<

all: $(MPY_FILES)

pre-install:
	ampy -p "$(DEV)" mkdir ZbPy

%.install: %.mpy
	@echo $<
	ampy -p "$(DEV)" put $< $<

install: $(PY_FILES:.py=.install)

clean:
	$(RM) */*.mpy *.mpy
