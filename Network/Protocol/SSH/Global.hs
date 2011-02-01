module Network.Protocol.SSH.Global (GlobalRequest(..),
                                    GlobalResponse(..))
  where

import Data.Word


data GlobalRequest
  = GlobalRequestTCPIPForwarding {
      globalRequestAddressToBind :: String,
      globalRequestPortToBind :: Word32
    }
  | GlobalRequestCancelTCPIPForwarding {
      globalRequestAddressToBind :: String,
      globalRequestPortToBind :: Word32
    }
  deriving (Show)


data GlobalResponse
  = GlobalResponseTCPIPForwardingPortBound {
      globalResponsePortBound :: Word32
    }
  | GlobalResponseNone {
    }
  deriving (Show)
