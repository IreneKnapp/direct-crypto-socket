module Internal.AbstractStreams (AbstractStream(..),
                                 connectToHostname,
                                 streamRecvCRLF,
                                 streamRecvByteString,
                                 streamRecvWord32,
                                 streamRecvWord8
                                )
  where

import Control.Concurrent.MVar
import Data.Bits
import Data.Char
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import Data.Word
import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString


data AbstractStream = AbstractStream {
    streamSend :: ByteString -> IO (),
    streamRecv :: Int -> IO ByteString,
    streamClose :: IO (),
    streamReadBuffer :: MVar ByteString
  }


connectToHostname :: String -> IO AbstractStream
connectToHostname hostname = do
  addressInfoList <- getAddrInfo (Just defaultHints) (Just hostname) Nothing
  case addressInfoList of
    [] -> error "Host not found."
    (AddrInfo { addrAddress = address } : _) -> do
      address <- do
        case address of
          SockAddrInet _ hostAddress ->
            return $ SockAddrInet 22 hostAddress
          SockAddrInet6 _ flowInfo hostAddress scopeID ->
            return $ SockAddrInet6 22 flowInfo hostAddress scopeID
          _ -> error "Address family not supported."
      socket <- do
        case address of
          SockAddrInet _ _ -> socket AF_INET Stream defaultProtocol
          SockAddrInet6 _ _ _ _ -> socket AF_INET6 Stream defaultProtocol
      connect socket address
      readBufferMVar <- newMVar BS.empty
      let stream = AbstractStream {
                         streamSend = sendAll socket,
                         streamRecv = recv socket,
                         streamClose = sClose socket,
                         streamReadBuffer = readBufferMVar
                       }
      return stream


streamRecvCRLF :: AbstractStream -> IO (Maybe ByteString)
streamRecvCRLF stream = do
  readBuffer <- takeMVar $ streamReadBuffer stream
  (readBuffer, atEOF) <- moreBufferIfNull stream readBuffer
  loop readBuffer atEOF
  where loop :: ByteString -> Bool -> IO (Maybe ByteString)
        loop readBuffer atEOF = do
          let (before, after) = BS.breakSubstring (UTF8.fromString "\n")
                                                  readBuffer
          if BS.null after
            then do
              let readBuffer = before
              if atEOF
                then do
                  putMVar (streamReadBuffer stream) readBuffer
                  return Nothing
                else do
                  (readBuffer, atEOF) <- moreBuffer stream readBuffer
                  loop readBuffer atEOF
            else do
              let (result, readBuffer) = (before, BS.drop 2 after)
              putMVar (streamReadBuffer stream) readBuffer
              if BS.null result
                then return $ Just result
                else if BS.last result == (fromIntegral $ ord '\r')
                       then return $ Just
                                      $ BS.take (BS.length result - 1) result
                       else return $ Just result


streamRecvByteString :: AbstractStream -> Int -> IO (Maybe ByteString)
streamRecvByteString stream desiredLength = do
  readBuffer <- takeMVar $ streamReadBuffer stream
  (readBuffer, atEOF) <- moreBufferIfNull stream readBuffer
  loop readBuffer atEOF
  where loop :: ByteString -> Bool -> IO (Maybe ByteString)
        loop readBuffer atEOF = do
          if BS.length readBuffer < desiredLength
            then do
              if atEOF
                then do
                  putMVar (streamReadBuffer stream) readBuffer
                  return Nothing
                else do
                  (readBuffer, atEOF) <- moreBuffer stream readBuffer
                  loop readBuffer atEOF
            else do
              (result, readBuffer)
                <- return $ BS.splitAt desiredLength readBuffer
              putMVar (streamReadBuffer stream) readBuffer
              return $ Just result


streamRecvWord32 :: AbstractStream -> IO (Maybe Word32)
streamRecvWord32 stream = do
  maybeBytestring <- streamRecvByteString stream 4
  return $ fmap (\bytestring ->
                   let [a1, a2, a3, a4] = BS.unpack bytestring
                   in shiftL (fromIntegral a1) 24
                      + shiftL (fromIntegral a2) 16
                      + shiftL (fromIntegral a3) 8
                      + shiftL (fromIntegral a4) 0)
                maybeBytestring


streamRecvWord8 :: AbstractStream -> IO (Maybe Word8)
streamRecvWord8 stream = do
  maybeBytestring <- streamRecvByteString stream 1
  return $ fmap (\bytestring ->
                   let [a1] = BS.unpack bytestring
                   in shiftL (fromIntegral a1) 0)
                maybeBytestring


moreBufferIfNull :: AbstractStream -> ByteString -> IO (ByteString, Bool)
moreBufferIfNull stream readBuffer = do
  if BS.null readBuffer
    then moreBuffer stream readBuffer
    else return (readBuffer, False)


moreBuffer :: AbstractStream -> ByteString -> IO (ByteString, Bool)
moreBuffer stream readBuffer = do
  newData <- streamRecv stream 4096
  if BS.null newData
    then return (readBuffer, True)
    else return (BS.concat [readBuffer, newData], False)
