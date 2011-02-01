module Network.Protocol.SSH.Authentication (AuthenticationRequest(..))
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS


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
      authenticationRequestSignature :: String
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
