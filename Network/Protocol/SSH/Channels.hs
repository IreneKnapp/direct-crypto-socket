module Network.Protocol.SSH.Channels (ChannelOpen(..),
                                      ChannelOpenConfirmation(..),
                                      ChannelRequest(..))
  where


data ChannelOpen
  = ChannelOpenX11 {
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
  | 
  deriving (Show)
