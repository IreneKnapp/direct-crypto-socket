module Network.Protocol.SSH.Global (GlobalRequest(..),
                                    GlobalResponse(..),
                                    streamReadRequestFields,
                                    streamReadResponseFields)
  where

import Data.Maybe
import Data.Word

import Internal.AbstractStreams
import Network.Protocol.SSH.Internal


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


streamReadRequestFields :: AbstractStream
                        -> String
                        -> IO (Maybe GlobalRequest)
streamReadRequestFields stream requestName = do
  case requestName of
    "tcpip-forward" -> do
      maybeAddressToBind <- streamReadString stream
      maybePortToBind <- streamReadWord32 stream
      case maybePortToBind of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         GlobalRequestCancelTCPIPForwarding {
                             globalRequestAddressToBind
                               = fromJust maybeAddressToBind,
                             globalRequestPortToBind
                               = fromJust maybePortToBind
                           }
    "cancel-tcpip-forward" -> do
      maybeAddressToBind <- streamReadString stream
      maybePortToBind <- streamReadWord32 stream
      case maybePortToBind of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         GlobalRequestTCPIPForwarding {
                             globalRequestAddressToBind
                               = fromJust maybeAddressToBind,
                             globalRequestPortToBind
                               = fromJust maybePortToBind
                           }
    _ -> error "Unknown SSH global request."


streamReadResponseFields :: AbstractStream
                         -> String
                         -> GlobalRequest
                         -> IO (Maybe GlobalResponse)
streamReadResponseFields stream requestName request = do
  case requestName of
    "tcpip-forward" -> do
      case globalRequestPortToBind request of
        0 -> do
          maybePortBound <- streamReadWord32 stream
          case maybePortBound of
            Nothing -> return Nothing
            Just _ -> return $ Just
                             GlobalResponseTCPIPForwardingPortBound {
                                 globalResponsePortBound
                                   = fromJust maybePortBound
                               }
        _ -> return $ Just GlobalResponseNone { }
    "cancel-tcpip-forward" -> do
      return $ Just GlobalResponseNone { }
    _ -> error "Unknown SSH global response."
