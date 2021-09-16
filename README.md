# Trust Chain

An implementation of a trust chain parameterized on structure and content.

```haskell
data Person = Person
  { pubKey :: PublicKey
  , name :: Maybe Text
  }

trustChain :: TrustChain [] User
trustChain = ...

people :: Either (Inconsistency Person) (Map PublicKey Person)
people = assignments pubKey (Person <$> required pubKey <*> optional name) trustChain
```
