CPPFLAGS = 
CPPFLAGS += -I/usr/local/include
CPPFLAGS += -std=c++11 -O0 -g

.PHONY: package pypitest

all: gofer.so

gofer.so: gofer.cpp
	g++ $(CPPFLAGS) \
		-lbfd -liberty -lopcodes -lz \
		-shared -o gofer.so gofer.cpp \
		-Wl,-headerpad_max_install_names

package:
	python3 setup.py sdist bdist_wheel

pypitest:
	python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
	# https://test.pypi.org/project/sh4dis
	# pip install --index-url https://test.pypi.org/simple/ --no-deps sh4dis

pypi:
	python3 -m twine upload dist/*
	# https://pypi.org/project/sh4dis/
	# pip install sh4dis

clean:
	rm -f gofer.so
	rm -rf gofer.so.dSYM
	rm -rf dist build __pycache__ sh4dis.egg-info
