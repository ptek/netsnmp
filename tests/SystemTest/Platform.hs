module SystemTest.Platform (tests) where

import Control.Exception.Base
import Network.Protocol.NetSNMP
import System.Cmd
import Test.HUnit

tests =
  test
    [ "snmpGet returns correct value" ~: do
        givenSnmpdRunning
        o <- (snmpGet snmp_version_2c "127.0.0.1:6161" "HSTEST" [1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1] >>= either error (return . value)) `finally` killSnmpd
        o @?= OctetString "GigabitEthernet" [71, 105, 103, 97, 98, 105, 116, 69, 116, 104, 101, 114, 110, 101, 116]
    ]

givenSnmpdRunning :: IO ()
givenSnmpdRunning = do
  system $ "cp -f tests/mock.snmpd.conf " ++ mockConfigFilePath
  system ("PATH=$PATH:/usr/sbin:/usr/local/sbin snmpd -r -C -c " ++ mockConfigFilePath ++ " 127.0.0.1:6161") >> return ()

killSnmpd :: IO ()
killSnmpd = rawSystem "pkill" ["-9", "-f", "snmpd"] >> return ()

mockConfigFilePath :: FilePath
mockConfigFilePath = "/tmp/Network.Protocol.NetSNMPtest.snmpd.conf"
