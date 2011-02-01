module Network.Protocol.SSH.Authentication (AuthenticationRequest(..),
                                            streamReadMethodFields)
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Maybe

import Internal.AbstractStreams
import Network.Protocol.SSH.Internal


data AuthenticationRequest
  = AuthenticationRequestPublicKeyQuery {
      -- Includes a ghost field set to False
      authenticationRequestAlgorithmName :: String,
      authenticationRequestBlob :: ByteString
    }
  | AuthenticationRequestPublicKeyActual {
      -- Includes a ghost field set to True
      authenticationRequestAlgorithmName :: String,
      authenticationRequestPublicKey :: ByteString,
      authenticationRequestSignature :: ByteString
    }
  | AuthenticationRequestPassword {
      -- Includes a ghost field set to False
      authenticationRequestPassword :: String
    }
  | AuthenticationRequestPasswordChange {
      -- Includes a ghost field set to True
      authenticationRequestOldPassword :: String,
      authenticationRequestNewPassword :: String
    }
  deriving (Show)


streamReadMethodFields :: AbstractStream
                       -> String
                       -> IO (Maybe AuthenticationRequest)
streamReadMethodFields stream methodName = do
  case methodName of
    "publickey" -> do
      maybeSubtype <- streamReadBoolean stream
      case maybeSubtype of
        Nothing -> return Nothing
        Just False -> do
          maybeAlgorithmName <- streamReadString stream
          maybeBlob <- streamReadBinaryString stream
          case maybeBlob of
            Nothing -> return Nothing
            Just _ -> return $ Just
                             AuthenticationRequestPublicKeyQuery {
                                 authenticationRequestAlgorithmName
                                   = fromJust maybeAlgorithmName,
                                 authenticationRequestBlob
                                   = fromJust maybeBlob
                               }
        Just True -> do
          maybeAlgorithmName <- streamReadString stream
          maybePublicKey <- streamReadBinaryString stream
          maybeSignature <- streamReadBinaryString stream
          case maybeSignature of
            Nothing -> return Nothing
            Just _ -> return $ Just
                             AuthenticationRequestPublicKeyActual {
                                 authenticationRequestAlgorithmName
                                   = fromJust maybeAlgorithmName,
                                 authenticationRequestPublicKey
                                   = fromJust maybePublicKey,
                                 authenticationRequestSignature
                                   = fromJust maybeSignature
                               }
    "password" -> do
      maybeSubtype <- streamReadBoolean stream
      case maybeSubtype of
        Nothing -> return Nothing
        Just False -> do
          maybePassword <- streamReadString stream
          case maybePassword of
            Nothing -> return Nothing
            Just _ -> return $ Just
                             AuthenticationRequestPassword {
                                 authenticationRequestPassword
                                   = fromJust maybePassword
                               }
        Just True -> do
          maybeOldPassword <- streamReadString stream
          maybeNewPassword <- streamReadString stream
          case maybeNewPassword of
            Nothing -> return Nothing
            Just _ -> return $ Just
                             AuthenticationRequestPasswordChange {
                                 authenticationRequestOldPassword
                                   = fromJust maybeOldPassword,
                                 authenticationRequestNewPassword
                                   = fromJust maybeNewPassword
                               }
    _ -> error "Unknown SSH authentication method."
