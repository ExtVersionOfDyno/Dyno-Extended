.PHONY: all, build-release, clean

conan_profile=dyno_release
clang_version=14.0

OS := $(shell uname -s)
ifeq ($(OS),Linux)
	CONAN_COMPILER := clang
	CC := "clang-${clang_version}"
	CXX := "clang++-${clang_version}"
else # MacOS
	CONAN_COMPILER := apple-clang
	CC := clang
	CXX := clang++
endif

all: build-release

build-release: | cmake-build-release
	cmake --build cmake-build-release

cmake-build-release: .conan_ready
	mkdir -p cmake-build-release
	cd cmake-build-release && CC=$(CC) CXX=$(CXX) conan install .. --profile=${conan_profile} --build=missing
	cd cmake-build-release && CC=$(CC) CXX=$(CXX) cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release

.conan_ready:
	conan profile new dyno_release --detect || true
	conan profile update settings.compiler=$(CONAN_COMPILER) ${conan_profile}
	conan profile update settings.compiler.version=${clang_version} ${conan_profile}
	conan profile update settings.compiler.libcxx=libc++ ${conan_profile}
	touch .conan_ready

clean:
	rm -rf cmake-build-release
