.PHONY: build
build:
	[ -d build ] || cmake -B build
	cmake --build build --parallel

.PHONY: ninja
ninja:
	[ -d build ] || cmake -B build -G Ninja
	make build

.PHONY: release
release:
	[ -d build ] || cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cmake --build build --parallel

.PHONY: dist
dist: build
	cmake --install build --prefix dist

.PHONY: deb
deb: release
	cd build && cpack -G DEB

.PHONY: test
test: build
	cmake --build build --parallel -t retest
	build/test/retest -rv

.PHONY: clean
clean:
	@rm -Rf build dist CMakeCache.txt CMakeFiles


###############################################################################
#
# Documentation section
#
DOX_DIR=../re-dox

$(DOX_DIR):
	@mkdir $@

$(DOX_DIR)/Doxyfile: mk/Doxyfile Makefile
	@cp $< $@
	@perl -pi -e 's/PROJECT_NUMBER\s*=.*/PROJECT_NUMBER = $(VERSION)/' \
	$(DOX_DIR)/Doxyfile

.PHONY:
dox:	$(DOX_DIR) $(DOX_DIR)/Doxyfile
	@doxygen $(DOX_DIR)/Doxyfile 2>&1 | grep -v DEBUG_ ; true
	echo "Doxygen docs in $(DOX_DIR)"
