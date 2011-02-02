module Network.Protocol.SSH.Channels (ChannelOpen(..),
                                      ChannelOpenConfirmation(..),
                                      ChannelRequest(..),
                                      streamReadChannelOpenFields,
                                      streamReadChannelOpenConfirmationFields,
                                      streamReadChannelRequestFields)
  where

import Data.Maybe
import Data.Word

import Internal.AbstractStreams
import Network.Protocol.SSH.Internal


data ChannelOpen
  = ChannelOpenSession {
    }
  | ChannelOpenX11 {
      channelOpenOriginatorAddress :: String,
      channelOpenOriginatorPort :: Word32
    }
  | ChannelOpenForwardedTCPIP {
      channelOpenAddressConnected :: String,
      channelOpenPortConnected :: Word32,
      channelOpenOriginatorAddress :: String,
      channelOpenOriginatorPort :: Word32
    }
  | ChannelOpenDirectTCPIP {
      channelOpenAddressToConnect :: String,
      channelOpenPortToConnect :: Word32,
      channelOpenOriginatorAddress :: String,
      channelOpenOriginatorPort :: Word32
    }
  deriving (Show)


data ChannelOpenConfirmation
  = ChannelOpenConfirmationNone {
    }
  deriving (Show)


data ChannelRequest
  = ChannelRequestPTY {
      channelRequestTerminalType :: String,
      channelRequestTerminalWidthCharacters :: Word32,
      channelRequestTerminalHeightCharacters :: Word32,
      channelRequestTerminalWidthPixels :: Word32,
      channelRequestTerminalHeightPixels :: Word32,
      channelRequestTerminalModes :: String
    }
  | ChannelRequestX11 {
      channelRequestSingleConnection :: Bool,
      channelRequestX11AuthenticationProtocol :: String,
      channelRequestX11AuthenticationCookie :: String,
      channelRequestX11ScreenNumber :: Word32
    }
  | ChannelRequestEnvironment {
      channelRequestVariableName :: String,
      channelRequestVariableValue :: String
    }
  | ChannelRequestShell {
    }
  | ChannelRequestExecute {
      channelRequestCommand :: String
    }
  | ChannelRequestSubsystem {
      channelRequestSubsystemName :: String
    }
  | ChannelRequestWindowChange {
      channelRequestTerminalWidthCharacters :: Word32,
      channelRequestTerminalHeightCharacters :: Word32,
      channelRequestTerminalWidthPixels :: Word32,
      channelRequestTerminalHeightPixels :: Word32
    }
  | ChannelRequestXonXoff {
      channelRequestClientCanDo :: Bool
    }
  | ChannelRequestSignal {
      channelRequestSignalName :: String
    }
  | ChannelRequestExitStatus {
      channelRequestExitStatus :: Word32
    }
  | ChannelRequestExitSignal {
      channelRequestSignalName :: String,
      channelRequestCoreDumped :: Bool,
      channelRequestMessage :: String,
      channelRequestLanguageTag :: String
    }
  deriving (Show)


streamReadChannelOpenFields :: AbstractStream
                            -> String
                            -> IO (Maybe ChannelOpen)
streamReadChannelOpenFields stream channelType = do
  case channelType of
    "session" -> do
      return $ Just ChannelOpenSession { }
    "x11" -> do
      maybeOriginatorAddress <- streamReadString stream
      maybeOriginatorPort <- streamReadWord32 stream
      case maybeOriginatorPort of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelOpenX11 {
                             channelOpenOriginatorAddress
                               = fromJust maybeOriginatorAddress,
                             channelOpenOriginatorPort
                               = fromJust maybeOriginatorPort
                           }
    "forwarded-tcpip" -> do
      maybeAddressConnected <- streamReadString stream
      maybePortConnected <- streamReadWord32 stream
      maybeOriginatorAddress <- streamReadString stream
      maybeOriginatorPort <- streamReadWord32 stream
      case maybeOriginatorPort of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelOpenForwardedTCPIP {
                             channelOpenAddressConnected
                               = fromJust maybeAddressConnected,
                             channelOpenPortConnected
                               = fromJust maybePortConnected,
                             channelOpenOriginatorAddress
                               = fromJust maybeOriginatorAddress,
                             channelOpenOriginatorPort
                               = fromJust maybeOriginatorPort
                           }
    "direct-tcpip" -> do
      maybeAddressToConnect <- streamReadString stream
      maybePortToConnect <- streamReadWord32 stream
      maybeOriginatorAddress <- streamReadString stream
      maybeOriginatorPort <- streamReadWord32 stream
      case maybeOriginatorPort of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelOpenDirectTCPIP {
                             channelOpenAddressToConnect
                               = fromJust maybeAddressToConnect,
                             channelOpenPortToConnect
                               = fromJust maybePortToConnect,
                             channelOpenOriginatorAddress
                               = fromJust maybeOriginatorAddress,
                             channelOpenOriginatorPort
                               = fromJust maybeOriginatorPort
                           }
    _ -> error "Unknown SSH channel type."


streamReadChannelOpenConfirmationFields :: AbstractStream
                                        -> String
                                        -> ChannelOpen
                                        -> IO (Maybe ChannelOpenConfirmation)
streamReadChannelOpenConfirmationFields stream channelType channelOpen = do
  case channelType of
    "session" -> do
      return $ Just ChannelOpenConfirmationNone { }
    "x11" -> do
      return $ Just ChannelOpenConfirmationNone { }
    "forwarded-tcpip" -> do
      return $ Just ChannelOpenConfirmationNone { }
    "direct-tcpip" -> do
      return $ Just ChannelOpenConfirmationNone { }
    _ -> error "Unknown SSH channel type."


streamReadChannelRequestFields :: AbstractStream
                               -> String
                               -> IO (Maybe ChannelRequest)
streamReadChannelRequestFields stream requestType = do
  case requestType of
    "pty-req" -> do
      maybeTerminalType <- streamReadString stream
      maybeTerminalWidthCharacters <- streamReadWord32 stream
      maybeTerminalHeightCharacters <- streamReadWord32 stream
      maybeTerminalWidthPixels <- streamReadWord32 stream
      maybeTerminalHeightPixels <- streamReadWord32 stream
      maybeTerminalModes <- streamReadString stream
      case maybeTerminalModes of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestPTY {
                             channelRequestTerminalType
                               = fromJust maybeTerminalType,
                             channelRequestTerminalWidthCharacters
                               = fromJust maybeTerminalWidthCharacters,
                             channelRequestTerminalHeightCharacters
                               = fromJust maybeTerminalHeightCharacters,
                             channelRequestTerminalWidthPixels
                               = fromJust maybeTerminalWidthPixels,
                             channelRequestTerminalHeightPixels
                               = fromJust maybeTerminalHeightPixels,
                             channelRequestTerminalModes
                               = fromJust maybeTerminalModes
                           }
    "x11-req" -> do
      maybeSingleConnection <- streamReadBoolean stream
      maybeX11AuthenticationProtocol <- streamReadString stream
      maybeX11AuthenticationCookie <- streamReadString stream
      maybeX11ScreenNumber <- streamReadWord32 stream
      case maybeX11ScreenNumber of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestX11 {
                             channelRequestSingleConnection
                               = fromJust maybeSingleConnection,
                             channelRequestX11AuthenticationProtocol
                               = fromJust maybeX11AuthenticationProtocol,
                             channelRequestX11AuthenticationCookie
                               = fromJust maybeX11AuthenticationCookie,
                             channelRequestX11ScreenNumber
                               = fromJust maybeX11ScreenNumber
                           }
    "env" -> do
      maybeVariableName <- streamReadString stream
      maybeVariableValue <- streamReadString stream
      case maybeVariableValue of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestEnvironment {
                             channelRequestVariableName
                               = fromJust maybeVariableName,
                             channelRequestVariableValue
                               = fromJust maybeVariableValue
                           }
    "shell" -> do
      return $ Just ChannelRequestShell { }
    "exec" -> do
      maybeCommand <- streamReadString stream
      case maybeCommand of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestExecute {
                             channelRequestCommand
                               = fromJust maybeCommand
                           }
    "subsystem" -> do
      maybeSubsystemName <- streamReadString stream
      case maybeSubsystemName of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestSubsystem {
                             channelRequestSubsystemName
                               = fromJust maybeSubsystemName
                           }
    "window-change" -> do
      maybeTerminalWidthCharacters <- streamReadWord32 stream
      maybeTerminalHeightCharacters <- streamReadWord32 stream
      maybeTerminalWidthPixels <- streamReadWord32 stream
      maybeTerminalHeightPixels <- streamReadWord32 stream
      case maybeTerminalHeightPixels of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestWindowChange {
                             channelRequestTerminalWidthCharacters
                               = fromJust maybeTerminalWidthCharacters,
                             channelRequestTerminalHeightCharacters
                               = fromJust maybeTerminalHeightCharacters,
                             channelRequestTerminalWidthPixels
                               = fromJust maybeTerminalWidthPixels,
                             channelRequestTerminalHeightPixels
                               = fromJust maybeTerminalHeightPixels
                           }
    "xon-xoff" -> do
      maybeClientCanDo <- streamReadBoolean stream
      case maybeClientCanDo of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestXonXoff {
                             channelRequestClientCanDo
                               = fromJust maybeClientCanDo
                           }
    "signal" -> do
      maybeSignalName <- streamReadString stream
      case maybeSignalName of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestSignal {
                             channelRequestSignalName
                               = fromJust maybeSignalName
                           }
    "exit-status" -> do
      maybeExitStatus <- streamReadWord32 stream
      case maybeExitStatus of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestExitStatus {
                             channelRequestExitStatus
                               = fromJust maybeExitStatus
                           }
    "exit-signal" -> do
      maybeSignalName <- streamReadString stream
      maybeCoreDumped <- streamReadBoolean stream
      maybeMessage <- streamReadString stream
      maybeLanguageTag <- streamReadString stream
      case maybeLanguageTag of
        Nothing -> return Nothing
        Just _ -> return $ Just
                         ChannelRequestExitSignal {
                             channelRequestSignalName
                               = fromJust maybeSignalName,
                             channelRequestCoreDumped
                               = fromJust maybeCoreDumped,
                             channelRequestMessage
                               = fromJust maybeMessage,
                             channelRequestLanguageTag
                               = fromJust maybeLanguageTag
                           }
    _ -> error "Unknown SSH channel-request type."
