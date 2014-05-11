
all: build

init:
	@if [ ! -f cabal.sandbox.config ] ; then (cabal sandbox init); fi;
	cabal install --only-dependencies

build: init
	cabal install

ghci: build
	cabal repl --ghc-option -XOverloadedStrings

test: init
	cabal install --enable-tests
	cabal test


