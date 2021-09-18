{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE QuantifiedConstraints #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
module Data.TrustChain
  ( 
    -- * Trust Chains
    TrustChain (..)
  , validTrustChain
    -- * Extensions
  , Extension (..)
  , extend
    -- * Claims
  , Claim (..)
  , addClaimant
  , claims
    -- * Index and Merge
  , assignments 
    -- * Inconsistencies
  , Inconsistency (..)
    -- * Re-Exports from Cropty
  , PublicKey
  , PrivateKey
  , Signed(..)
    -- * Re-Exports from Data.Merge
  , Merge
  ) where

import Data.Text (Text)
import Data.Set (Set)
import Data.Typeable (Typeable)
import qualified Data.Set as Set
import Data.Map (Map)
import qualified Data.Map.Strict as Map
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as LBS
import Data.Functor.Identity (Identity (..))
import Data.Binary (Binary (..))
import qualified Data.Binary as Binary
import GHC.Generics (Generic)
import Data.Semigroup (All(All, getAll))
import Cropty
import Data.Merge

encode :: Binary a => a -> ByteString
encode a = LBS.toStrict $ Binary.encode a

-- | A tree of trust of the given shape, where each internal node of the
-- tree is signed by potentially different keys.
data TrustChain f a =
    Trustless a
  | TrustProxy (Signed (f (TrustChain f a)))
  deriving (Generic, Typeable)

deriving instance (Show a, forall a. Show a => Show (f a)) => Show (TrustChain f a)
deriving instance (Read a, forall a. Read a => Read (f a)) => Read (TrustChain f a)
deriving instance (Eq a, forall a. Eq a => Eq (f a)) => Eq (TrustChain f a)
deriving instance (Binary a, forall a. Binary a => Binary (f a)) => Binary (TrustChain f a)

-- | Check that the trust chain has been legitimately signed.
validTrustChain :: (Binary a, forall x. Binary x => Binary (f x), Foldable f) => TrustChain f a -> Bool
validTrustChain (Trustless _) = True
validTrustChain (TrustProxy s) = verifySigned s && getAll (foldMap (All . validTrustChain) (signed s))

-- | Describes extensions to a 'TrustChain'
data Extension c f a = Extension
  { newChains :: c (TrustChain f a)
  , newItems :: c a
  }

-- | Extend the trust chain with new subchains and new items.
extend :: (Traversable f, Binary a, forall a. Binary a => Binary (f a), forall a. Monoid (f a), Applicative f) => PrivateKey -> Extension f f a -> TrustChain f a -> IO (TrustChain f a)
extend privateKey ext originalTrustChain = do
  let signed = newChains ext <> fmap Trustless (newItems ext) <> pure originalTrustChain
  s <- mkSigned privateKey signed
  pure $ TrustProxy s

-- |
-- A path through the trust chain.
data Claim a = Claim [PublicKey] a
  deriving (Eq, Ord, Typeable, Generic, Binary)

-- |
-- Add a new claimant to a 'Claim'.
addClaimant :: PublicKey -> Claim a -> Claim a
addClaimant p (Claim ps a) = Claim (p : ps) a

-- |
-- An inconsistency with the various accounts in the trust chain
data Inconsistency e a =
    IncompatibleClaim e (Claim a) [Claim a]
  deriving (Eq, Ord, Typeable, Generic, Binary)

-- |
-- Extract all of the claims from the trust chain.
claims :: (Eq a, Ord a, Foldable f) => TrustChain f a -> [Claim a]
claims = \case
  Trustless a -> [Claim [] a]
  TrustProxy s -> addClaimant (signedBy s) <$> foldMap claims (signed s)

-- | 
-- Extract all of the assignments from the trust chain, unifying information contained
-- within them. This is where we might find potential inconsistencies.
assignments :: (Ord k, Eq a, Ord a, Foldable f) => (a -> k) -> Merge e a a -> TrustChain f a -> Either (Inconsistency e a) (Map k a)
assignments getKey f tc = go Map.empty (claims tc) where
  go as [] = Right (Map.map fst as)
  go as (Claim ps a : xxs) =
    case Map.lookup (getKey a) as of
      Just (a', pss) -> case runMerge f a a' of
        Success a'' -> go (Map.adjust (\_ -> (a'', Claim ps a : pss)) (getKey a) as) xxs
        Error e -> Left (IncompatibleClaim e (Claim ps a) pss)
      Nothing -> go (Map.insert (getKey a) (a, [Claim ps a]) as) xxs
