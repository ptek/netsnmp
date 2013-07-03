module Main where

import Network.Protocol.NetSNMP
import System.Exit
import SystemTest.Platform (tests)
import Test.HUnit

main :: IO ()
main = runTestTT testSuites >>= testResultToExitCode

testSuites = test [
  "platform compliance" ~: SystemTest.Platform.tests
  ]


testResultToExitCode :: Counts -> IO ()
testResultToExitCode (Counts _ _ e f) =  if ((e+f) == 0) then exitSuccess else grandFailure

grandFailure :: IO ()
grandFailure = putStrLn xz >> exitFailure

xz = " ___\n" ++
     "{O,o}\n" ++
     "|)__)\n" ++
     "-\"-\"-\n" ++
     "O RLY?\n"
