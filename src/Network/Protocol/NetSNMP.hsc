
{-# LANGUAGE CPP, DoAndIfThenElse, ForeignFunctionInterface, EmptyDataDecls, OverloadedStrings #-}

----------------------------------------------------------------------
-- |
-- Module      : Network.Protocol.NetSNMP
-- Copyright   : 2009 John Dorsey
-- 
-- Maintainer  : John Dorsey <haskell@colquitt.org>
-- Portability : portable
-- Stability   : provisional
-- 
-- This is a binding to Net-SNMP version 5, <http://www.net-snmp.org/>.

{- License: BSD3.  See included LICENSE and README files. -}

module Network.Protocol.NetSNMP (
  -- * Types
  ASNValue(..), SnmpResult(..), SnmpVersion(..), RawOID, OIDpart
  Hostname, Community,
  -- * Constants
  snmp_version_1, snmp_version_2c, snmp_version_3,
  -- * Functions
  -- ** Library Initialization
  initialize,
  -- ** Queries
  snmpGet, snmpNext, snmpWalk, snmpBulkWalk,
  -- ** Miscellany
  showASNValue,
  )
where

import           Control.Applicative
import           Control.Monad
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import           Data.List
import		 Data.String
import           Foreign
import           Foreign.C.String
import           Foreign.C.Types

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

--
-- types and constants
--

-- max length of description string returned from the library
-- this can be safely tweaked up or down
max_string_len = 1023

-- Haskell-land session info, including various C snmp_session pointers
-- and session parameters.  Meeting place for managing session memory.
data Session = Session
  { getVersion       :: SnmpVersion
  , getSessp         :: Ptr SnmpSession
  , getSptr          :: Ptr SnmpSession
  }

data SnmpSession                           -- C struct snmp_session
instance Storable SnmpSession where
  sizeOf    _ = #size struct snmp_session
  alignment _ = 16

data SnmpPDU                               -- C struct snmp_pdu
instance Storable SnmpPDU where
  sizeOf    _ = #size struct snmp_pdu
  alignment _ = 16

#ifdef EIGHTBIT_SUBIDS
type OIDpart = CUChar                      -- C typedef oid
#else
type OIDpart = CULong
#endif

type RawOID = [OIDpart]

showOid :: RawOID -> String
showOid = concatMap (('.':) . show)

oidToByteString :: RawOID -> ByteString
oidToByteString = fromString . showOid

-- I don't know whether (or which of) net-snmp's library functions
-- account for bytesex; there may be endian bugs lurking here.
data CVarList                           -- C struct variable_list

-- |Typed representation of atomic ASN.1 data types.  Some types are
--     returned in more than one format for different uses.  Some
--     include a descriptive string built by the underlying C library.
data ASNValue
  = OctetString ByteString [Word8] -- ^@ASN_OCTET_STR@ Returned as a character
                               --     string, and as opaque data.
  | OID ByteString ByteString [Word32] -- ^@ASN_OBJECT_ID@ Returned as the C library's
                               --     description, a dotted-decimal string, and
                               --     a numeric list
  | Integer32   Int32          -- ^@ASN_INTEGER@  32bit signed
  | Integer64   Int64          -- ^@ASN_INTEGER64@  64bit signed
  | Counter32   Word32         -- ^@ASN_COUNTER@ 32bit nondecreasing
  | Counter64   Word64         -- ^@ASN_COUNTER64@ 64bit nondecreasing
  | Unsigned32  Word32         -- ^@ASN_UNSIGNED@ 32bit unsigned
  | Unsigned64  Word64         -- ^@ASN_UNSIGNED64@ 64bit unsigned
  | Gauge32     Word32         -- ^@ASN_GAUGE@ 32bit signed with min and max
  | IpAddress   ByteString [Word8] -- ^@ASN_IPADDRESS@ IP address in string
                               --     and numeric form. Example:
                               --     (IpAddress \"1.2.3.4\" [1,2,3,4])
  | Opaque      [Word8]        -- ^@ASN_OPAQUE@ (Deprecated) application
                               --     specific data.  Use OctetString instead.
  | TimeTicks   ByteString Word32  -- ^@ASN_TIMETICKS@ Time interval in 1/100 sec
                               --     ticks.  The C library's description is
                               --     returned along with the raw value.
  | Boolean     Bool           -- ^@ASN_BOOLEAN@ Unimplemented.
  | IEEEFloat   Float          -- ^@ASN_FLOAT@ IEEE float. Unimplemented.
  | IEEEDouble  Double         -- ^@ASN_DOUBLE@ IEEE double. Unimplemented.
  | Null                       -- ^@ASN_NULL@ Null value
  | Unsupported Int ByteString -- ^Unsupported type from an agent.  Returns
                               --     the numeric type and the C library's
                               --     description of the value.
  deriving (Eq, Show)

-- |An SNMP value together with its OID.  Returned by the query
--     routines 'snmpGet', 'snmpNext', and 'snmpWalk'.
data SnmpResult  = SnmpResult {
  oid   :: RawOID,           -- ^Dotted-decimal ObjectId of the value
  value :: ASNValue            -- ^Typed representation of the value
  } deriving (Eq, Show)

-- |SNMP Protocol version.  It is recommended to use the constants
-- 'snmp_version_1', 'snmp_version_2c', and 'snmp_version_3'.
newtype SnmpVersion = SnmpVersion {
  unSnmpVersion :: CLong -- ^Numeric version.  Generally unneeded.
  } deriving (Eq, Show)

type Hostname  = ByteString
type Community = ByteString

-- SNMP protocol versions, omitting those that will never be supported
-- (see README)
-- I'd prefer to use the more compact #{enum} in place of multiple
-- #{const}'s, but I don't know how to mix #{enum} with haddock.
-- #{enum SnmpVersion, SnmpVersion
--   , snmp_version_1  = SNMP_VERSION_1
--   , snmp_version_2c = SNMP_VERSION_2c
--   , snmp_version_3  = SNMP_VERSION_3
--   }

-- |SNMPv1. The first SNMP standard, using cleartext passwords
--     (\"communities\")
snmp_version_1  :: SnmpVersion
snmp_version_1   = SnmpVersion #{const SNMP_VERSION_1  }

-- |SNMPv2c. Updated SMI and wire protocol, but still uses communities.
snmp_version_2c :: SnmpVersion
snmp_version_2c  = SnmpVersion #{const SNMP_VERSION_2c }

-- |SNMPv3. Same SMI and protocol as SNMPv2c; stronger authentication.
--     Unimplemented.
snmp_version_3  :: SnmpVersion
snmp_version_3   = SnmpVersion #{const SNMP_VERSION_3  }


-- |ASN.1 constants from snmp_impl.h and asn1.h
#{enum CUChar ,
  , asn_boolean      = ASN_BOOLEAN
  , asn_integer      = ASN_INTEGER
  , asn_bit_str      = ASN_BIT_STR
  , asn_octet_str    = ASN_OCTET_STR
  , asn_null         = ASN_NULL
  , asn_object_id    = ASN_OBJECT_ID
  , asn_sequence     = ASN_SEQUENCE
  , asn_set          = ASN_SET
  , asn_universal    = ASN_UNIVERSAL
  , asn_application  = ASN_APPLICATION
  , asn_context      = ASN_CONTEXT
  , asn_private      = ASN_PRIVATE
  , asn_primitive    = ASN_PRIMITIVE
  , asn_constructor  = ASN_CONSTRUCTOR
  , asn_long_len     = ASN_LONG_LEN
  , asn_extension_id = ASN_EXTENSION_ID
  , asn_bit8         = ASN_BIT8
  , asn_ipaddress    = ASN_IPADDRESS
  , asn_counter      = ASN_COUNTER
  , asn_gauge        = ASN_GAUGE
  , asn_unsigned     = ASN_UNSIGNED
  , asn_timeticks    = ASN_TIMETICKS
  , asn_opaque       = ASN_OPAQUE
  , asn_nsap         = ASN_NSAP
  , asn_counter64    = ASN_COUNTER64
  , asn_uinteger     = ASN_UINTEGER
  , asn_float        = ASN_FLOAT
  , asn_double       = ASN_DOUBLE
  , asn_integer64    = ASN_INTEGER64
  , asn_unsigned64   = ASN_UNSIGNED64
  }

-- PDUType:           used with:   v1   v2c    v3
-- SNMP_MSG_GET                   Yes   Yes   Yes
-- SNMP_MSG_GETNEXT               Yes   Yes   Yes
-- SNMP_MSG_RESPONSE              Yes   Yes   Yes
-- SNMP_MSG_SET                   Yes   Yes   Yes
-- SNMP_MSG_TRAP                  Yes    -     - 
-- SNMP_MSG_GETBULK                -    Yes   Yes
-- SNMP_MSG_INFORM                 -    Yes   Yes
-- SNMP_MSG_TRAP2                  -    Yes   Yes
-- SNMP_MSG_REPORT                 -     -    Yes
newtype SnmpPDUType = SnmpPDUType { unSnmpPDUType :: CInt }
#{enum SnmpPDUType, SnmpPDUType
  , snmp_msg_get      = SNMP_MSG_GET
  , snmp_msg_getnext  = SNMP_MSG_GETNEXT
  , snmp_msg_response = SNMP_MSG_RESPONSE
  , snmp_msg_set      = SNMP_MSG_SET
  , snmp_msg_trap     = SNMP_MSG_TRAP
  , snmp_msg_getbulk  = SNMP_MSG_GETBULK
  , snmp_msg_inform   = SNMP_MSG_INFORM
  , snmp_msg_trap2    = SNMP_MSG_TRAP2
  , snmp_msg_report   = SNMP_MSG_REPORT
  }

-- Miscellaneous return codes
-- NB: zero return is success in some functions, failure in others,
--   both within this api.

#{enum CInt,
  , snmp_stat_success = STAT_SUCCESS
  , snmp_stat_error   = STAT_ERROR
  , snmp_stat_timeout = STAT_TIMEOUT
  , snmp_err_noerror  = SNMP_ERR_NOERROR
  }

max_oid_len = #{const MAX_OID_LEN} :: CInt

--
-- The Haskell abstraction layer
--

-- |Initialize the Net-SNMP library.  This must be called before any
-- other NetSNMP functions, and before starting extra threads, as the
-- mib compiler is not thread-safe.
initialize :: IO ()
initialize = do
  withCString "Haskell bindings" c_init_snmp
  withCString "127.0.0.1" $ \localhost -> do
  withCString "public"    $ \public    -> do
  alloca                  $ \session   -> runTrouble $
    (readyCommunitySession snmp_version_2c localhost public session)
      >>= closeSession
  return ()

-- |Create an abstract session, suitable for reuse, responsible
-- for freeing the string components
readyCommunitySession
  :: SnmpVersion
  -> CString                 -- Hostname
  -> CString                 -- Community
  -> Ptr SnmpSession         -- "session"
  -> Trouble Session         -- return abstract session
readyCommunitySession version hostname community session = do
  community_len     <- t_strlen community
  t_snmp_sess_init  session
  pokeSessPeername  session hostname
  pokeSessVersion   session (unSnmpVersion version)
  pokeSessCommunity session community
  pokeSessCommLen   session community_len
  sessp <- t_snmp_sess_open    session
  sptr  <- t_snmp_sess_session sessp
  return $ Session version sessp sptr

-- |Immediately destroy/free the Session.
closeSession :: Session -> Trouble ()
-- frees the SnmpSession object allocated by readyCommunitySession
closeSession session = hoistT (c_snmp_sess_close (getSessp session))

-- |Simple community-authenticated SNMP get.  Returns the object
--     queried, or a descriptive error message.
--
-- Examples:
--
-- * snmpGet \"localhost\" \"public\" [1,3,6,1,2,1,1,1,0]
--
-- * snmpGet \"tcp:localhost:5161\" \"mypassword\" [1,3,6,1,2,1,1,1,0]
snmpGet
  :: SnmpVersion -- ^'snmp_version_1' or 'snmp_version_2c'
  -> Hostname    -- ^IP or hostname of the agent to be queried.  May have
                 --     prefix of @tcp:@ or suffix of @:port@
  -> Community   -- ^SNMP community (password)
  -> RawOID         -- ^OID to be queried
  -> IO (Either String SnmpResult)
snmpGet version hostname community oid =
  B.useAsCString hostname  $ \cshost  ->
  B.useAsCString community $ \cscomm  ->
  alloca                   $ \session ->
  runTrouble $ bracketT
    (readyCommunitySession version cshost cscomm session)
    closeSession
    (flip (mkSnmpGet snmp_msg_get) oid)

-- |Simple community-authenticated SNMP getnext.  Returns the first object
--     after the OID queried, or a descriptive error message.
--
-- Examples:
--
-- * snmpNext \"localhost\" \"public\" [1,3,6,1,2,1,1,1,0]
--
-- * snmpNext \"tcp:localhost:5161\" \"mypassword\" [1,3,6,1,2,1,1,1,0]
snmpNext
  :: SnmpVersion -- ^'snmp_version_1' or 'snmp_version_2c'
  -> Hostname    -- ^IP or hostname of the agent to be queried.  May have
                 --     prefix of @tcp:@ or suffix of @:port@
  -> Community   -- ^SNMP community (password)
  -> RawOID         -- ^OID to be queried
  -> IO (Either String SnmpResult)
snmpNext version hostname community oid =
  B.useAsCString hostname  $ \cshost  ->
  B.useAsCString community $ \cscomm  ->
  alloca                   $ \session ->
  runTrouble $ bracketT
    (readyCommunitySession version cshost cscomm session)
    closeSession
    (flip (mkSnmpGet snmp_msg_getnext) oid)

-- |Simple community-authenticated SNMP walk.  Returns a list of objects,
--     starting with the object after the OID queried, and continuing
--     through all objects underneath that OID in the mib tree.
--     On failure, returns a descriptive error message.
--
-- This implementation uses a series of next operations and is not very
-- ressource friendly. Consider using snmpBulkWalk for better performance
--
-- Examples:
--
-- * snmpWalk snmp_version_2c \"localhost\" \"public\" [1,3,6,1,2,1,1]
--
-- * snmpWalk snmp_version_2c \"tcp:localhost:5161\" \"mypassword\" [1,3,6,1,2,1,1]
snmpWalk
  :: SnmpVersion -- ^'snmp_version_1' or 'snmp_version_2c'
  -> Hostname    -- ^IP or hostname of the agent to be queried.  May have
                 --     prefix of @tcp:@ or suffix of @:port@
  -> Community   -- ^SNMP community (password)
  -> RawOID         -- ^OID to be queried
  -> IO (Either String [SnmpResult])
snmpWalk version hostname community walkoid =
    B.useAsCString hostname  $ \cshost  ->
    B.useAsCString community $ \cscomm  ->
    alloca                   $ \session ->
    runTrouble $ bracketT
      (readyCommunitySession version cshost cscomm session)
      closeSession
      (go walkoid . mkSnmpGet snmp_msg_getnext)
  where
    go :: RawOID -> (RawOID -> Trouble SnmpResult) -> Trouble [SnmpResult]
    go oid next = do
      v@(SnmpResult nextoid val) <- next oid
      case () of
        _ | nextoid == oid -> return [] -- throwT "end of mib" -- return []
          | walkoid `isPrefixOf` nextoid -> do
            vs <- go nextoid next
            return (v:vs)
          | otherwise -> return [] -- throwT "end of walk" -- return []


-- |Same as snmpWalk but implemented with bulk requests
--
-- Examples:
--
-- * snmpBulkWalk \"localhost\" \"public\" [1,3,6,1,2,1,1]
--
-- * snmpBulkWalk \"tcp:localhost:5161\" \"mypassword\" [1,3,6,1,2,1,1]
snmpBulkWalk 
  :: Hostname    -- ^IP or hostname of the agent to be queried.  May have
                 --     prefix of @tcp:@ or suffix of @:port@
  -> Community   -- ^SNMP community (password)
  -> RawOID         -- ^OID to be queried
  -> IO (Either String [SnmpResult])
snmpBulkWalk hostname community walkoid =
    B.useAsCString hostname  $ \cshost  ->
    B.useAsCString community $ \cscomm  ->
    alloca                   $ \session ->
    runTrouble $ bracketT
      (readyCommunitySession snmp_version_2c cshost cscomm session)
      closeSession
      (bulkWalk walkoid walkoid)
  where
    bulkWalk :: RawOID -> RawOID -> Session -> Trouble [SnmpResult]
    bulkWalk rootoid startoid session = do
      vals <- filter (\r -> (oid r) `isSubIdOf` rootoid) <$> mkSnmpBulkGet 0 50 startoid session
      case vals of
        [] -> return []
        rs -> (vals ++) <$> bulkWalk rootoid (oid (last rs)) session
    isSubIdOf :: RawOID -> RawOID -> Bool
    isSubIdOf oa ob = ob `isPrefixOf` oa
  
-- getbulk, using session info from a 'data Session' and
-- the supplied oid
-- It is the caller's obligation to ensure the session's validity.  
mkSnmpBulkGet :: CLong -> CLong -> RawOID -> Session -> Trouble [SnmpResult]
mkSnmpBulkGet non_repeaters max_repetitions oid session =
  allocaArrayT (fromIntegral max_oid_len) $ \oids -> do
  let version = getVersion session
  pdu_req <- buildPDU snmp_msg_getbulk oid oids version
  pokePDUNonRepeaters pdu_req non_repeaters
  pokePDUMaxRepetitions pdu_req max_repetitions
  dispatchSnmpReq pdu_req session

-- get or getnext, using session info from a 'data Session' and
-- the supplied oid
-- It is the caller's obligation to ensure the session's validity.
mkSnmpGet :: SnmpPDUType -> Session -> RawOID -> Trouble SnmpResult
mkSnmpGet pdutype session oid = do
  res <- (allocaArrayT (fromIntegral max_oid_len) $ \oids -> do
         let version = getVersion session
         pdu_req <- buildPDU pdutype oid oids version
         dispatchSnmpReq pdu_req session)
  if (res == []) then throwT ("Could not get the snmp value at " ++ (showOid oid))
  else return $ head res

dispatchSnmpReq :: Ptr SnmpPDU -> Session -> Trouble [SnmpResult]
dispatchSnmpReq pdu_req session = do
  allocaT $ \response_ptr -> do
  let sessp = getSessp session
  let sptr = getSptr session
  pokeT response_ptr nullPtr
  handleT
    (\s -> do
      pdu_resp <- peekT response_ptr
      unless (pdu_resp == nullPtr) $ t_snmp_free_pdu pdu_resp
      throwT s)
    (do
      t_snmp_sess_synch_response sessp sptr pdu_req response_ptr
      pdu_resp <- peekT response_ptr
      errstat <- peekPDUErrstat pdu_resp
      when (errstat /= snmp_err_noerror) (throwT "response PDU error")
      rawvars <- peekPDUVariables pdu_resp
      vars <- extractVars rawvars
      unless (pdu_resp == nullPtr) $ t_snmp_free_pdu pdu_resp
      return vars)  

-- caller is obliged to ensure rv is valid and non-null
vlist2oid :: Ptr CVarList -> Trouble RawOID
vlist2oid rv = do
  oidptr <- peekVariableName rv
  len    <- peekVariableLen  rv
  peekArrayT (fromIntegral len) oidptr

extractVars :: Ptr CVarList -> Trouble [SnmpResult]
extractVars rv
  | rv == nullPtr = return []
  | otherwise = do
    v <- extractVar rv
    nextrv <- peekVariableNext rv
    vs <- extractVars nextrv
    return (v : vs)

extractVar :: Ptr CVarList -> Trouble SnmpResult
extractVar rv = do
  oid <- vlist2oid rv
  t <- peekVariableType rv
  v <- case () of
    _ | t == asn_octet_str    -> extractOctetStr     rv
    _ | t == asn_ipaddress    -> extractIpAddress    rv
    _ | t == asn_counter      -> extractIntegralType rv Counter32
    _ | t == asn_gauge        -> extractIntegralType rv Gauge32
    _ | t == asn_timeticks    -> extractTimeTicks    rv
    _ | t == asn_opaque       -> extractOpaque       rv
    _ | t == asn_integer      -> extractIntegralType rv Integer32
    _ | t == asn_unsigned     -> extractIntegralType rv Unsigned32
    _ | t == asn_counter64    -> extractIntegral64Type rv Counter64
    _ | t == asn_integer64    -> extractIntegral64Type rv Integer64
    _ | t == asn_unsigned64   -> extractIntegral64Type rv Unsigned64
    _ | t == asn_object_id    -> extractOID          rv
    _ | t == asn_null         -> return Null
    _ -> do
          descr <- rawvar2cstring rv
          return $ Unsupported (fromIntegral t) descr
  return (SnmpResult oid v)

extractOctetStr rv = do
  ptr <- peekVariableValString rv
  len <- peekVariableValLen rv
  s <- peekCStringLenT (ptr , (fromIntegral len))
  octets <- peekArrayT (fromIntegral len) (castPtr ptr)
  return (OctetString s octets)

extractOpaque rv = do
  ptr <- peekVariableValBits rv
  len <- peekVariableValLen rv
  arr <- peekArrayT (fromIntegral len) ptr
  return (Opaque (map fromIntegral arr))

extractIntegralType rv constructor = do
  intptr <- peekVariableValInt rv
  n <- fromIntegral <$> peekT intptr
  return (constructor n)

extractIntegral64Type rv constructor = do
  ptr <- peekVariableValInt rv
  (high:low:[]) <- peekArrayT 2 (castPtr ptr) :: Trouble [Word64]
  return (constructor (fromIntegral ((high * (2 ^ 32) + low) :: Word64)))

extractIpAddress rv = do
  ptr <- peekVariableValInt rv
  octets <- peekArrayT 4 (castPtr ptr) :: Trouble [Word8]
  let str = B.intercalate "." (map (fromString . show) octets)
  return (IpAddress str octets)

extractOID :: Ptr CVarList -> Trouble ASNValue
extractOID rv = do
  oidptr <- peekVariableValObjid rv :: Trouble (Ptr OIDpart)
  len <- peekVariableValLen rv
  let oidlen = (fromIntegral len) `div` #{size oid}
  oid <- peekArrayT oidlen oidptr :: Trouble RawOID
  let str = oidToByteString oid
  descr <- rawvar2cstring rv
  return (OID descr str (map fromIntegral oid))

extractTimeTicks rv = do
  intptr <- peekVariableValInt rv
  ticks <- fromIntegral <$> peekT intptr
  descr <- rawvar2cstring rv
  return (TimeTicks descr ticks)

-- |Show ASNValue contents in a simple string, losing type differentiation.
--     Callers should not rely on the format of the message returned,
--     and this function may disappear in a future version.
showASNValue :: ASNValue -> String
showASNValue v = case v of
  OctetString s _     -> show s
  IpAddress   s _     -> show s
  Counter32   c       -> show c 
  Gauge32     c       -> show c 
  OID         d os ol -> show os
  Opaque      cs      -> show cs
  Integer32   c       -> show c
  Unsigned32  c       -> show c 
  Counter64   c       -> show c 
  Integer64   c       -> show c
  Unsigned64  c       -> show c 
  TimeTicks   s _     -> show s
  Boolean     c       -> show c
  IEEEDouble  c       -> show c
  IEEEFloat   c       -> show c
  Null                -> "ASN_NULL"
  Unsupported t s     -> "Unknown type " ++ show t ++ ": " ++ show s

-- allocates space for the pdu request; snmp_sess_synch_response
-- appears to free the request pdu
buildPDU
  :: SnmpPDUType  -- eg. snmp_msg_get
  -> RawOID       -- eg. [1,3,6,1,2,1,1,1,0]
  -> Ptr OIDpart  -- OIDpart array passed in b/c I don't know when it dallocs
  -> SnmpVersion  -- eg. snmp_version_1 or snmp_version_2c
  -> Trouble (Ptr SnmpPDU) -- returns pdu and oid length
buildPDU pdutype oid oids version =
  withCStringT (showOid oid) $ \oid_cstr   ->
  allocaT                    $ \oidlen_ptr -> do
    pdu_req <- t_snmp_pdu_create pdutype
    pokePDUVersion pdu_req (unSnmpVersion version)
    pokePDUCommand pdu_req (unSnmpPDUType pdutype)
    pokeT oidlen_ptr (fromIntegral max_oid_len)
    t_read_objid oid_cstr oids oidlen_ptr    -- or t_get_node
    oidlen <- peekT oidlen_ptr
    t_snmp_add_null_var pdu_req oids oidlen
    return pdu_req

rawvar2cstring :: Ptr CVarList -> Trouble ByteString
rawvar2cstring rv =
  allocaArray0T max_string_len $ \buf -> do
  rc <- t_snprint_by_type buf (fromIntegral max_string_len) rv
          nullPtr nullPtr nullPtr
  peekCStringT buf

allocaT :: (Storable a) => (Ptr a -> Trouble b) -> Trouble b
allocaT f = Trouble $ alloca $ \p -> runTrouble (f p)

allocaArrayT :: (Storable a) => Int -> (Ptr a -> Trouble b) -> Trouble b
allocaArrayT n f = Trouble $ allocaArray n $ \p -> runTrouble (f p)

allocaArray0T :: (Storable a) => Int -> (Ptr a -> Trouble b) -> Trouble b
allocaArray0T n f = Trouble $ allocaArray0 n $ \p -> runTrouble (f p)

withCStringT :: String -> (CString -> Trouble b) -> Trouble b
withCStringT s f = Trouble $ withCString s $ \p -> runTrouble (f p)

peekCStringT    = hoistT1 B.packCString
peekCStringLenT = hoistT1 B.packCStringLen

peekT :: (Storable a) => Ptr a -> Trouble a
peekT = hoistT1 peek

pokeT :: (Storable a) => Ptr a -> a -> Trouble ()
pokeT = hoistT2 poke

peekArrayT :: (Storable a) => Int -> Ptr a -> Trouble [a]
peekArrayT = hoistT2 peekArray

peekPDUErrstat :: Ptr SnmpPDU -> Trouble CInt
peekPDUErrstat p = hoistT $ #{peek struct snmp_pdu , errstat} p

peekPDUVariables :: Ptr SnmpPDU -> Trouble (Ptr CVarList)
peekPDUVariables p = hoistT $ #{peek struct snmp_pdu , variables} p

peekVariableName :: Ptr CVarList -> Trouble (Ptr OIDpart)
peekVariableName rv = hoistT $ #{peek struct variable_list , name} rv

peekVariableLen :: Ptr CVarList -> Trouble CSize
peekVariableLen rv = hoistT $ #{peek struct variable_list , name_length} rv

peekVariableNext :: Ptr CVarList -> Trouble (Ptr CVarList)
peekVariableNext rv = hoistT $ #{peek struct variable_list , next_variable} rv

peekVariableType :: Ptr CVarList -> Trouble CUChar
peekVariableType rv = hoistT $ #{peek struct variable_list , type} rv

peekVariableValBits :: Ptr CVarList -> Trouble (Ptr CUChar)
peekVariableValBits rv = hoistT $ #{peek struct variable_list, val.bitstring} rv

peekVariableValInt :: Ptr CVarList -> Trouble (Ptr CLong)
peekVariableValInt rv = hoistT $ #{peek struct variable_list, val.integer} rv

peekVariableValString :: Ptr CVarList -> Trouble CString
peekVariableValString rv = hoistT $ #{peek struct variable_list, val.string} rv

peekVariableValObjid :: Ptr CVarList -> Trouble (Ptr OIDpart)
peekVariableValObjid rv = hoistT $ #{peek struct variable_list, val.objid} rv

peekVariableValLen :: Ptr CVarList -> Trouble CSize
peekVariableValLen rv = hoistT $ #{peek struct variable_list, val_len} rv

pokeSessPeername  :: Ptr SnmpSession -> CString -> Trouble ()
pokeSessPeername s h  = hoistT $ #{poke struct snmp_session , peername} s h

pokeSessVersion   :: Ptr SnmpSession -> CLong   -> Trouble ()
pokeSessVersion s v   = hoistT $ #{poke struct snmp_session , version} s v

pokeSessCommunity :: Ptr SnmpSession -> CString -> Trouble ()
pokeSessCommunity s c = hoistT $ #{poke struct snmp_session , community} s c

pokeSessCommLen   :: Ptr SnmpSession -> CSize   -> Trouble ()
pokeSessCommLen s l = hoistT $ #{poke struct snmp_session , community_len} s l

pokePDUVersion :: Ptr SnmpPDU -> CLong -> Trouble ()
pokePDUVersion p v = hoistT $ #{poke struct snmp_pdu , version} p v

pokePDUCommand :: Ptr SnmpPDU -> CInt -> Trouble ()
pokePDUCommand p t = hoistT $ #{poke struct snmp_pdu , command} p t

pokePDUNonRepeaters :: Ptr SnmpPDU -> CLong -> Trouble ()
pokePDUNonRepeaters p n = hoistT $ #{poke struct snmp_pdu , non_repeaters} p n

pokePDUMaxRepetitions :: Ptr SnmpPDU -> CLong -> Trouble ()
pokePDUMaxRepetitions p r = hoistT $ #{poke struct snmp_pdu , max_repetitions} p r

--
-- The C library layer
--
-- FFI C import statements, together with wrappers to put them
-- in the (Trouble a) exception handling monad
--

-- initialize the library
-- This must be called before any other library functions, and before
-- any threads are forked, because the initialization is not thread-safe,
-- specifically the mib tree compiler.
foreign import ccall unsafe "net-snmp/net-snmp-includes.h init_snmp"
    c_init_snmp :: CString -> IO ()

-- "init session"
-- JD: Apparently this only sets parameters in the struct snmp_session.
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_init"
    c_snmp_sess_init :: Ptr SnmpSession -> IO ()

t_snmp_sess_init = hoistT1 c_snmp_sess_init

-- "open session".  How does this differ from the above?  I haven't
-- found any clarifying api docs.
-- JD: Apparently this allocates a socket for UDP, or opens a TCP connection.
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_open"
    c_snmp_sess_open :: Ptr SnmpSession -> IO (Ptr SnmpSession)

t_snmp_sess_open = hoistTE1
  (predToMaybe (== nullPtr) "snmp_sess_open failed") c_snmp_sess_open

-- Third and final session initialization routine.
-- JD: This seems to be used to coordinate asynchronous queries in the
-- (thread safe) session, and in error tracking/reporting.
--
-- from session_api.h: Do NOT free memory returned by snmp_sess_session
--
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_session"
    c_snmp_sess_session :: Ptr SnmpSession -> IO (Ptr SnmpSession)

t_snmp_sess_session = hoistTE1
  (predToMaybe (== nullPtr) "snmp_sess_session failed") c_snmp_sess_session

-- Create PDU structure with defaults by type
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_pdu_create"
    c_snmp_pdu_create :: SnmpPDUType -> IO (Ptr SnmpPDU)

t_snmp_pdu_create = hoistTE1
  (predToMaybe (== nullPtr) "snmp_pdu_create failed")
  c_snmp_pdu_create

-- Parse string argument as OID; populate OIDpart array and size
foreign import ccall unsafe "net-snmp/net-snmp-includes.h get_node"
    c_get_node :: CString -> Ptr OIDpart -> Ptr CSize -> IO CInt

t_get_node = hoistTE3
  (predToMaybe (not . (>0)) "get_node failed")
  -- (\i -> if (i <= 0) then Just "get_node failed" else Nothing)
  c_get_node

-- OID parser/builder script.  How does this differ from get_node?
foreign import ccall unsafe "net-snmp/net-snmp-includes.h read_objid"
    c_read_objid :: CString -> Ptr OIDpart -> Ptr CSize -> IO CInt

t_read_objid = hoistTE3
  (predToMaybe (not . (>0)) "read_objid failed")
  -- (\i -> if (i <= 0) then Just "read_objid failed" else Nothing)
  c_read_objid

-- OID parser/builder script.  How does this differ from get_node?
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_parse_oid"
    c_snmp_parse_oid :: CString -> Ptr OIDpart -> Ptr CSize -> IO CInt

t_snmp_parse_oid = hoistTE3
  (predToMaybe (not . (>0)) "snmp_parse_oid failed")
  -- (\i -> if (i <= 0) then Just "snmp_parse_oid failed" else Nothing)
  c_snmp_parse_oid

-- Add oid with void result; suitable for building a query
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_add_null_var"
    c_snmp_add_null_var :: Ptr SnmpPDU -> Ptr OIDpart -> CSize -> IO ()

t_snmp_add_null_var = hoistT3 c_snmp_add_null_var

-- Send request PDU and wait for response.
foreign import ccall safe
    "net-snmp/net-snmp-includes.h snmp_sess_synch_response"
    c_snmp_sess_synch_response :: Ptr SnmpSession -> Ptr SnmpPDU
        -> Ptr (Ptr SnmpPDU) -> IO CInt

-- improved (?) version with fuller error handling
t_snmp_sess_synch_response :: Ptr SnmpSession -> Ptr SnmpSession
  -> Ptr SnmpPDU -> Ptr (Ptr SnmpPDU) -> Trouble ()
t_snmp_sess_synch_response sessp sptr pdu_req response_ptr = Trouble $ do
  success <- c_snmp_sess_synch_response sessp pdu_req response_ptr
  -- snmpSessError was giving bus errors on x86_64
  if (success == snmp_stat_success)
    then return (Right ())
    else Left <$> snmpError sptr
  -- return $ case () of
  --   _ | success == snmp_stat_success -> Right ()
  --     | success == snmp_stat_error   -> Left "snmp_sess_synch_response error"
  --     | success == snmp_stat_timeout -> Left "snmp_sess_synch_response timeout"
  --     | otherwise -> Left
  --         ("snmp_sess_synch_response unknown error code " ++ show success)

-- Deallocate PDU struct
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_free_pdu"
    c_snmp_free_pdu :: Ptr SnmpPDU -> IO ()

t_snmp_free_pdu = hoistT1 c_snmp_free_pdu

-- Deallocate session and free associated resources.
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_close"
    c_snmp_sess_close :: Ptr SnmpSession -> IO ()

t_snmp_sess_close = hoistT1 c_snmp_sess_close

-- Send and enqueue request PDU for asynch use, not currently supported.
-- foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_send"
--     c_snmp_sess_send :: Ptr SnmpSession -> Ptr SnmpPDU -> IO CInt

-- Print result value to stdout
foreign import ccall safe "net-snmp/net-snmp-includes.h print_variable"
    c_print_variable :: Ptr OIDpart -> CSize -> Ptr CVarList -> IO ()

t_print_variable = hoistT3 c_print_variable

-- t_print_variable :: Ptr OIDpart -> CSize -> Ptr CVarList -> Trouble ()
-- t_print_variable o s r = Trouble $ Right <$> c_print_variable o s r


-- Return library error description
-- This one should only be used for failure of snmp_sess_open; use
-- the (void *) return by that function at other times.
-- library/snmp_api.h
-- void snmp_error(netsnmp_session *, int *, int *, char **);
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_error"
    c_snmp_error :: Ptr SnmpSession -> Ptr CInt -> Ptr CInt
      -> Ptr CString -> IO ()

snmpError :: Ptr SnmpSession -> IO String
snmpError p = do
  alloca $ \libp -> do  -- pointer to library error code
  alloca $ \sysp -> do  -- pointer to system error code
  alloca $ \errp -> do  -- pointer to error CString
  c_snmp_error p libp sysp errp
  liberr <- peek libp
  syserr <- peek sysp
  cserr  <- peek errp
  err    <- peekCString cserr
  free cserr
  return $ "snmpError: lib:" ++ show liberr ++ " ; sys:" ++ show syserr
           ++ " ; " ++ err

-- Return library error description
-- This one is preferred for all single-session api failures except
-- snmp_sess_open failure.  
-- library/snmp_api.h
-- void snmp_sess_error(void *, int *, int *, char **);
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snmp_sess_error"
    c_snmp_sess_error :: Ptr SnmpSession -> Ptr CInt -> Ptr CInt
      -> Ptr CString -> IO ()

-- Using abbreviated error routine because th c_snmp_sess_error
-- call appears to be giving bus errors on my x86_64 test machine.
snmpSessError :: Ptr SnmpSession -> IO String
snmpSessError sptr =
  return ("disabled snmp_sess_error check; sptr=" ++ show sptr)

_snmpSessError :: Ptr SnmpSession -> IO String
_snmpSessError sptr | sptr == nullPtr = return "snmp error; null sptr"
_snmpSessError sptr = do
  alloca $ \libp -> do  -- pointer to library error code
  alloca $ \sysp -> do  -- pointer to system error code
  alloca $ \errp -> do  -- pointer to error CString
  c_snmp_sess_error sptr libp sysp errp
  liberr <- peek libp :: IO CInt
  syserr <- peek sysp :: IO CInt
  cserr  <- peek errp
  err    <- peekCString cserr
  free cserr
  return $ "snmpSessError: lib:" ++ show liberr ++ " ; sys:" ++ show syserr
           ++ " ; " ++ err

-- int snprint_by_type(char *buf, size_t buf_len, netsnmp_variable_list * var,
--   const struct enum_list *enums, const char *hint, const char *units);
foreign import ccall unsafe "net-snmp/net-snmp-includes.h snprint_by_type"
    c_snprint_by_type :: CString -> CSize -> Ptr CVarList ->
       Ptr () -> Ptr () -> Ptr () -> IO CInt

t_snprint_by_type = hoistT6 c_snprint_by_type

foreign import ccall unsafe "string.h strlen"
    c_strlen :: Ptr CChar -> IO CSize

t_strlen = hoistT1 c_strlen

--
-- Trouble a
--
-- A simple exception handling monad
--

-- Better would be to use ErrorT from the mtl (or other transformer
-- library) but I don't want the dependency before the dust has settled
-- between them; it smells like a compatibility tarpit.
-- type Trouble = ErrorT String IO

newtype Trouble a = Trouble { runTrouble :: IO (Either String a) }

instance Functor Trouble where
  fmap f m = Trouble $ do
    r <- runTrouble m
    case r of (Left s)  -> return (Left s)
              (Right v) -> return (Right (f v))

instance Monad Trouble where
  return a = Trouble $ return (Right a)
  m >>= f  = Trouble $ do
    r <- runTrouble m
    case r of (Left s)  -> return (Left s)
              (Right v) -> runTrouble (f v)

throwT :: String -> Trouble a
throwT s = Trouble $ return (Left s)

catchT :: Trouble a -> (String -> Trouble a) -> Trouble a
catchT m h = Trouble $ do
  r <- runTrouble m
  case r of (Left s)  -> runTrouble (h s)
            (Right v) -> return r

handleT :: (String -> Trouble a) -> Trouble a -> Trouble a
handleT = flip catchT

-- _bracketT :: Trouble a -> (a -> Trouble b) -> (a -> Trouble c) -> Trouble c
-- _bracketT before after thing = do
--   a <- before
--   handleT (\s -> after a >> throwT s) $ do
--     result <- thing a
--     after a
--     return result

bracketT :: Trouble a -> (a -> Trouble b) -> (a -> Trouble c) -> Trouble c
bracketT before after thing = do
  a <- before
  result <- handleT (\s -> after a >> throwT s) (thing a)
  after a
  return result

-- Routines to 'hoist' anything with IO return type into the
-- equivalent with (Trouble a) ie. IO (Either String a) return type.

hoistT  :: IO t -> Trouble t
hoistT  f = Trouble $ Right <$> f

hoistT1 :: (a -> IO t) -> a -> Trouble t
hoistT1 f a = hoistT  (f a)
hoistT2 f a = hoistT1 (f a)
hoistT3 f a = hoistT2 (f a)
hoistT4 f a = hoistT3 (f a)
hoistT5 f a = hoistT4 (f a)
hoistT6 f a = hoistT5 (f a)

-- hoist from IO with success check(s)
hoistTE0 :: (t -> Maybe String) -> IO t -> Trouble t
hoistTE0 e f = Trouble $ do
  t <- f
  return $ maybe (Right t) Left (e t)

hoistTE1 e f a = hoistTE0 e (f a)
hoistTE2 e f a = hoistTE1 e (f a)
hoistTE3 e f a = hoistTE2 e (f a)
hoistTE4 e f a = hoistTE3 e (f a)
hoistTE5 e f a = hoistTE4 e (f a)
hoistTE6 e f a = hoistTE5 e (f a)

predToMaybe :: (a -> Bool) -> b -> a -> Maybe b
predToMaybe p b a = if (p a) then Just b else Nothing
