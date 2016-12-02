
all: build

build:
	stack install

ghci: build
	stack ghci --ghc-options -XOverloadedStrings

test:
	stack test


