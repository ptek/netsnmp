
all: build

build:
	cabal-dev install

ghci: build
	ghci -XOverloadedStrings -package-conf cabal-dev/packages-7.*.conf

