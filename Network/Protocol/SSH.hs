module Network.Protocol.SSH (
                             startSSH
                            )
  where

import Control.Concurrent.MVar
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word

import Internal.AbstractStreams
import qualified Network.Protocol.SSH.MAC as MAC


data SSHStream = SSHStream {
    sshStreamUnderlyingStream :: AbstractStream,
    sshStreamOpen :: MVar Bool,
    sshStreamSendMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamSendSequenceNumber :: MVar Word32,
    sshStreamRecvMACAlgorithm :: MVar MAC.Algorithm,
    sshStreamRecvSequenceNumber :: MVar Word32
  }


startSSH :: AbstractStream -> IO AbstractStream
startSSH underlyingStream = do
  openMVar <- newMVar True
  sendSequenceNumberMVar <- newMVar 0
  sendMACAlgorithmMVar <- newMVar MAC.None
  recvSequenceNumberMVar <- newMVar 0
  recvMACAlgorithmMVar <- newMVar MAC.None
  let sshStream = SSHStream {
                    sshStreamUnderlyingStream = underlyingStream,
                    sshStreamOpen = openMVar,
                    sshStreamSendSequenceNumber = sendSequenceNumberMVar,
                    sshStreamSendMACAlgorithm = sendMACAlgorithmMVar,
                    sshStreamRecvSequenceNumber = recvSequenceNumberMVar,
                    sshStreamRecvMACAlgorithm = recvMACAlgorithmMVar
                  }
  readBufferMVar <- newMVar BS.empty
  return $ AbstractStream {
             streamSend = sshStreamSend sshStream,
             streamRecv = sshStreamRecv sshStream,
             streamClose = sshStreamClose sshStream,
             streamReadBuffer = readBufferMVar
           }


sshStreamSend :: SSHStream -> ByteString -> IO ()
sshStreamSend sshStream bytestring = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  macAlgorithm <- readMVar $ sshStreamSendMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamSendSequenceNumber sshStream
  putMVar (sshStreamSendSequenceNumber sshStream) $ sequenceNumber + 1


sshStreamRecv :: SSHStream -> Int -> IO ByteString
sshStreamRecv sshStream count = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  let stream = sshStreamUnderlyingStream sshStream
  macAlgorithm <- readMVar $ sshStreamRecvMACAlgorithm sshStream
  sequenceNumber <- takeMVar $ sshStreamRecvSequenceNumber sshStream
  putMVar (sshStreamRecvSequenceNumber sshStream) $ sequenceNumber + 1
  maybePacketLength <- streamRecvWord32 stream
  case maybePacketLength of
    Nothing -> return BS.empty
    Just packetLength -> do
      maybePaddingLength <- streamRecvWord8 stream
      case maybePaddingLength of
        Nothing -> return BS.empty
        Just paddingLength -> do
          maybePayload
            <- streamRecvByteString stream
                $ fromIntegral $ packetLength - (fromIntegral paddingLength) - 1
          case maybePayload of
            Nothing -> return BS.empty
            Just payload -> do
              maybePadding
                <- streamRecvByteString stream $ fromIntegral paddingLength
              case maybePadding of
                Nothing -> return BS.empty
                Just _ -> do
                  let macLength = MAC.algorithmCodeLength macAlgorithm
                  maybeMAC <- streamRecvByteString stream macLength
                  case maybeMAC of
                    Nothing -> return BS.empty
                    Just mac -> do
                      let correctMAC =
                            MAC.algorithmComputeCode macAlgorithm
                                                     sequenceNumber
                                                     payload
                      if mac == correctMAC
                        then return payload
                        else do
                          _ <- takeMVar $ sshStreamOpen sshStream
                          streamClose stream
                          putMVar (sshStreamOpen sshStream) False
                          return BS.empty


sshStreamClose :: SSHStream -> IO ()
sshStreamClose sshStream = do
  isOpen <- readMVar $ sshStreamOpen sshStream
  if not isOpen
    then error "SSH stream already closed."
    else return ()
  streamClose $ sshStreamUnderlyingStream sshStream
