
all: build

init:
	cabal sandbox init
	cabal install --only-dependencies

build: init
	cabal install

ghci: build
	cabal repl --ghc-option -XOverloadedStrings

test:
	cabal install --enable-tests

