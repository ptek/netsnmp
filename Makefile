
all: build

build:
	cabal-dev install

ghci: build
	ghci -XOverloadedStrings -package-db cabal-dev/packages-7.6.*.conf

