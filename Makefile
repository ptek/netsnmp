
all: build

build:
	cabal-dev install

ghci: build
	ghci -package-db cabal-dev/packages-7.*.conf

