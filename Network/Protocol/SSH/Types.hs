{-# LANGUAGE DeriveDataTypeable #-}
module Network.Protocol.SSH.Types (
                                   SSHMode(..),
                                   SSHExpecting(..),
                                   SSHTransportState(..),
                                   SSHChannelState(..),
                                   SSHUserAuthenticationMode(..),
                                   SSHMessage(..)
                                  )
  where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Word
import Data.Dynamic

import qualified Network.Protocol.SSH.Authentication as Authentication
import qualified Network.Protocol.SSH.Channels as Channels
import qualified Network.Protocol.SSH.Global as Global
import qualified Network.Protocol.SSH.MAC as MAC


data SSHMode = SSHClient
             | SSHServer
             deriving (Show)


data SSHExpecting = SSHAnything
                  | SSHNothing String


data SSHTransportState = SSHTransportState {
    sshTransportStateMode :: SSHMode,
    sshTransportStateExpecting :: SSHExpecting,
    sshTransportStateUserAuthenticationMode :: Maybe SSHUserAuthenticationMode,
    sshTransportStateGlobalRequestsPendingSelfAsSender :: [SSHMessage],
    sshTransportStateGlobalRequestsPendingSelfAsRecipient :: [SSHMessage],
    sshTransportStateChannelOpensPendingSelfAsSender :: [SSHMessage],
    sshTransportStateChannelOpensPendingSelfAsRecipient :: [SSHMessage],
    sshTransportStateChannelsByLocalID :: Map Word32 SSHChannelState,
    sshTransportStateChannelsByRemoteID :: Map Word32 SSHChannelState
  }


data SSHChannelState = SSHChannelState {
    sshChannelStateLocalID :: Word32,
    sshChannelStateRemoteID :: Word32,
    sshChannelStateRequestsPendingSelfAsSender :: [SSHMessage],
    sshChannelStateRequestsPendingSelfAsRecipient :: [SSHMessage]
  }


data SSHUserAuthenticationMode
  = SSHUserAuthenticationModePublicKey
  | SSHUserAuthenticationModePassword


data SSHMessage
  = SSHMessageDisconnect {
      sshMessageReasonCode :: Word32,
      sshMessageDescription :: String,
      sshMessageLanguageTag :: String
    }
  | SSHMessageIgnore {
      sshMessageData :: ByteString
    }
  | SSHMessageUnimplemented {
      sshMessagePacketSequenceNumber :: Word32
    }
  | SSHMessageDebug {
      sshMessageAlwaysDisplay :: Bool,
      sshMessageText :: String,
      sshMessageLanguageTag :: String
    }
  | SSHMessageServiceRequest {
      sshMessageServiceName :: String
    }
  | SSHMessageServiceAccept {
      sshMessageServiceName :: String
    }
  | SSHMessageKeyExchangeInit {
      sshMessageCookie :: ByteString,
      sshMessageKeyExchangeAlgorithms :: [String],
      sshMessageServerHostKeyAlgorithms :: [String],
      sshMessageEncryptionAlgorithmsClientToServer :: [String],
      sshMessageEncryptionAlgorithmsServerToClient :: [String],
      sshMessageMACAlgorithmsClientToServer :: [String],
      sshMessageMACAlgorithmsServerToClient :: [String],
      sshMessageCompressionAlgorithmsClientToServer :: [String],
      sshMessageCompressionAlgorithmsServerToClient :: [String],
      sshMessageLanguagesClientToServer :: [String],
      sshMessageLanguagesServerToClient :: [String],
      sshMessageFirstKeyExchangePacketFollows :: Bool
    }
  | SSHMessageNewKeys {
    }
  | SSHMessageUserAuthenticationRequest {
      sshMessageUserName :: String,
      sshMessageServiceName :: String,
      sshMessageMethodName :: String,
      sshMessageMethodFields :: Authentication.AuthenticationRequest
    }
  | SSHMessageUserAuthenticationFailure {
      sshMessageAuthenticationMethods :: [String],
      sshMessagePartialSuccess :: Bool
    }
  | SSHMessageUserAuthenticationSuccess {
    }
  | SSHMessageUserAuthenticationBanner {
      sshMessageText :: String,
      sshMessageLanguageTag :: String
    }
  | SSHMessageUserAuthenticationPublicKeyOkay {
      sshMessageAlgorithmName :: String,
      sshMessageBlob :: ByteString
    }
  | SSHMessageUserAuthenticationPasswordChangeRequest {
      sshMessageText :: String,
      sshMessageLanguageTag :: String
    }
  | SSHMessageGlobalRequest {
      sshMessageRequestName :: String,
      sshMessageWantReply :: Bool,
      sshMessageRequestFields :: Global.GlobalRequest
    }
  | SSHMessageRequestSuccess {
      sshMessageResponseFields :: Global.GlobalResponse
    }
  | SSHMessageRequestFailure {
    }
  | SSHMessageChannelOpen {
      sshMessageChannelType :: String,
      sshMessageSenderChannel :: Word32,
      sshMessageInitialWindowSize :: Word32,
      sshMessageMaximumPacketSize :: Word32,
      sshMessageChannelOpenFields :: Channels.ChannelOpen
    }
  | SSHMessageChannelOpenConfirmation {
      sshMessageRecipientChannel :: Word32,
      sshMessageSenderChannel :: Word32,
      sshMessageInitialWindowSize :: Word32,
      sshMessageMaximumPacketSize :: Word32,
      sshMessageChannelOpenConfirmationFields
        :: Channels.ChannelOpenConfirmation
    }
  | SSHMessageChannelOpenFailure {
      sshMessageRecipientChannel :: Word32,
      sshMessageReasonCode :: Word32,
      sshMessageDescription :: String,
      sshMessageLanguageTag :: String
    }
  | SSHMessageChannelWindowAdjust {
      sshMessageRecipientChannel :: Word32,
      sshMessageBytesToAdd :: Word32
    }
  | SSHMessageChannelData {
      sshMessageRecipientChannel :: Word32,
      sshMessageData :: ByteString
    }
  | SSHMessageChannelExtendedData {
      sshMessageRecipientChannel :: Word32,
      sshMessageDataTypeCode :: Word32,
      sshMessageData :: ByteString
    }
  | SSHMessageChannelEOF {
      sshMessageRecipientChannel :: Word32
    }
  | SSHMessageChannelClose {
      sshMessageRecipientChannel :: Word32
    }
  | SSHMessageChannelRequest {
      sshMessageRecipientChannel :: Word32,
      sshMessageRequestType :: String,
      sshMessageWantReply :: Bool,
      sshMessageChannelRequestFields :: Channels.ChannelRequest
    }
  | SSHMessageChannelSuccess {
      sshMessageRecipientChannel :: Word32
    }
  | SSHMessageChannelFailure {
      sshMessageRecipientChannel :: Word32
    }
  deriving (Show, Typeable)
