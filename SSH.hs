module Main (main) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import System.Environment
import System.Random

import Internal.AbstractStreams
import Network.Protocol.SSH
import qualified Network.Protocol.SSH.KeyExchange as KeyExchange
import qualified Network.Protocol.SSH.MAC as MAC
import qualified Network.Protocol.SSH.ServerHostKey as ServerHostKey
import qualified Network.Protocol.SSH.Encryption as Encryption
import qualified Network.Protocol.SSH.Compression as Compression


main :: IO ()
main = do
  arguments <- getArgs
  case arguments of
    [hostname] -> sshClient hostname
    _ -> usage


usage :: IO ()
usage = do
  programName <- getProgName
  putStrLn $ "Usage: " ++ programName ++ " hostname"


sshClient :: String -> IO ()
sshClient hostname = do
  putStrLn $ "Connecting..."
  stream <- connectToHostname hostname
  putStrLn $ "Initiating session..."
  streamSend stream $ UTF8.fromString "SSH-2.0-directssh1.0\r\n"
  let loopForIdentification :: IO (Maybe ByteString)
      loopForIdentification = do
        maybeIdentificationOrMOTD <- streamReadCRLF stream
        case maybeIdentificationOrMOTD of
          Nothing -> return Nothing
          Just identificationOrMOTD ->
            if BS.isPrefixOf (UTF8.fromString "SSH-") identificationOrMOTD
              then return $ Just identificationOrMOTD
              else loopForIdentification
  maybeIdentification <- loopForIdentification
  case maybeIdentification of
    Nothing -> error "SSH identification string not received."
    Just identification -> do
      (stream, transportState) <- startSSH stream
      cookie <- generateCookie
      streamSendSSHMessage stream
       $ SSHMessageKeyExchangeInit {
                             sshMessageCookie = cookie,
                             sshMessageKeyExchangeAlgorithms =
                               KeyExchange.knownAlgorithmNames,
                             sshMessageServerHostKeyAlgorithms =
                               ServerHostKey.knownAlgorithmNames,
                             sshMessageEncryptionAlgorithmsClientToServer =
                               Encryption.knownAlgorithmNames,
                             sshMessageEncryptionAlgorithmsServerToClient =
                               Encryption.knownAlgorithmNames,
                             sshMessageMACAlgorithmsClientToServer =
                               MAC.knownAlgorithmNames,
                             sshMessageMACAlgorithmsServerToClient =
                               MAC.knownAlgorithmNames,
                             sshMessageCompressionAlgorithmsClientToServer =
                               Compression.knownAlgorithmNames,
                             sshMessageCompressionAlgorithmsServerToClient =
                               Compression.knownAlgorithmNames,
                             sshMessageLanguagesClientToServer = [],
                             sshMessageLanguagesServerToClient = [],
                             sshMessageFirstKeyExchangePacketFollows = False
                           }
      maybeResult <- streamReadSSHMessage stream transportState
      case maybeResult of
        Nothing -> error "Unexpectedly disconnected."
        Just (keyExchangeMessage, maybeOriginalMessage, transportState) -> do
          putStrLn $ show keyExchangeMessage
          putStrLn $ "Connected."
          putStrLn $ "Disconnecting."
          streamClose stream


generateCookie :: IO ByteString
generateCookie = do
  mapM (\_ -> getStdRandom random) [1..16] >>= return . BS.pack


knownServerHostKeyAlgorithmNames :: [String]
knownServerHostKeyAlgorithmNames = []


knownEncryptionAlgorithmNames :: [String]
knownEncryptionAlgorithmNames = []


knownCompressionAlgorithmNames :: [String]
knownCompressionAlgorithmNames = []
