# Trust Chain

An implementation of a trust chain parameterized on structure and content. As an example:

```haskell
type Time = Integer

data Person = Person
  { pubKey :: PublicKey
  , legalName :: Maybe Text
  , emails :: Set Text
  , posts :: Set (Time, Text)
  }
  deriving (Eq, Ord, Binary, Generic)

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
  requires "person"
    [ assignments pubKey mergePerson (claims tc1') == assignments pubKey mergePerson (claims tc0')
    , assignments pubKey mergePerson (claims tc0') == Right (Map.fromList [(privateToPublic privateKey0, myself), (privateToPublic privateKey1, myfriend)])
    ]
```
