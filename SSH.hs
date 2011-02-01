module Main (main) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as UTF8
import System.Environment

import Internal.AbstractStreams
import Network.Protocol.SSH


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
  stream <- connectToHostname hostname
  putStrLn $ "Initiating session..."
  streamSend stream $ UTF8.fromString "SSH-2.0-directssh1.0\r\n"
  let loopForIdentification :: IO (Maybe ByteString)
      loopForIdentification = do
        maybeIdentificationOrMOTD <- streamRecvCRLF stream
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
      putStrLn $ "Connected."
  putStrLn $ "Disconnecting."
  streamClose stream
