{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Data.Binary (encode, decode, Binary(..))
import GHC.Generics (Generic)
import Data.TrustChain
import Data.Merge
import Cropty
import System.Exit (exitFailure)
import Control.Monad (forM_)
import Data.Map (Map)
import Data.Text (Text)
import qualified Data.Map.Strict as Map
import Data.Set (Set)
import qualified Data.Set as Set

requires :: String -> [Bool] -> IO ()
requires msg = mapM_ (uncurry go) . zip [1..] where
  go x y = if y then pure () else putStrLn (msg <> ": " <> show x) >> exitFailure

eq :: (Eq a, Show a) => String -> [(a, a)] -> IO ()
eq msg = mapM_ (uncurry go) . zip [1..] where
  go x (a, b) = if a == b then pure () else putStrLn (msg <> ": " <> show x <> ": " <> show a <> " /= " <> show b) >> exitFailure

main :: IO ()
main = do
  privateKey0 <- generatePrivateKey KeySize256
  privateKey1 <- generatePrivateKey KeySize256
  let trustChain0 :: TrustChain [] String = Trustless "Hello"
  trustChain1 <- mkTrustProxy privateKey0 [mkTrustless "Hi", trustChain0]
  trustChain2 <- mkTrustProxy privateKey1 [mkTrustless "Hey", trustChain1]
  let roundTrip f g x = (x, f (g x))
  requires "validTrustChain"
    [ validTrustChain trustChain0
    , validTrustChain trustChain1
    , validTrustChain trustChain2
    ]
  eq "claimants"
    [ (claimants id (claims trustChain0),  Map.fromList [("Hello", Map.fromList [("Hello", Set.singleton [])])]) ]
  eq "claims"
    [ (claims trustChain0, [Claim [] "Hello"])
    , (claims trustChain1, [Claim [privateToPublic privateKey0] "Hi", Claim [privateToPublic privateKey0] "Hello"])
    , (claims trustChain2, [Claim [privateToPublic privateKey1] "Hey", Claim [privateToPublic privateKey1, privateToPublic privateKey0] "Hi", Claim [privateToPublic privateKey1, privateToPublic privateKey0] "Hello"])
    ]
  eq "assignments"
    [ (assignments id (required @[String] id .? ["bad id"]) (claims trustChain0), Right (Map.fromList [("Hello", "Hello")]))
    ]
  eq "encode/decode" $ map (roundTrip decode encode) [trustChain0, trustChain1, trustChain2]
  person

type Time = Integer

data Person = Person
  { pubKey :: PublicKey
  , legalName :: Maybe Text
  , emails :: Set Text
  , posts :: Set (Time, Text)
  }
  deriving (Eq, Ord, Binary, Generic, Show, Read)

mergePerson :: Merge [String] Person Person
mergePerson =
  Person
  <$> required pubKey
  <*> optional legalName
  <*> combine emails
  <*> combine posts

person :: IO ()
person = do
  privateKey0 <- generatePrivateKey KeySize256
  privateKey1 <- generatePrivateKey KeySize256
  let myself = Person (privateToPublic privateKey0) (Just "Samuel Schlesinger") (Set.fromList ["sgschlesinger@gmail.com", "samuel@simspace.com"]) (Set.fromList [])
  let myfriend = Person (privateToPublic privateKey1) (Just "My Friend") (Set.fromList ["friend@friendly.com"]) Set.empty
  let partialfriend = Person (privateToPublic privateKey1) Nothing Set.empty Set.empty
  tc0 <- mkTrustProxy privateKey0 [Trustless myself, Trustless partialfriend]
  tc1 <- mkTrustProxy privateKey1 [Trustless myfriend]
  tc0' <- mkTrustProxy privateKey0 [tc0, tc1]
  tc1' <- mkTrustProxy privateKey1 [tc0, tc1]
  eq "person"
    [ (assignments pubKey mergePerson (claims tc1'), assignments pubKey mergePerson (claims tc0'))
    , (assignments pubKey mergePerson (claims tc0'), Right (Map.fromList [(privateToPublic privateKey0, myself), (privateToPublic privateKey1, myfriend)]))
    ]
