
all: build

build:
	cabal-dev install

ghci: build
	ghci -package-conf cabal-dev/packages-7.0.4.conf

