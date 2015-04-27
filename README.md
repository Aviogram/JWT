# JWT
Json Web Token

Example - Create Token
----------------------
```php
use Aviogram\JWT\JWT;

$token = JWT::encode(
    JWT::createClaimSet()->setNbf(new DateTime('NOW + 1 DAY')),
    JWT::createEncryptionList()->addHS512Key('mysecret')
);
```

Example - Verify Token
----------------------
```php
use Aviogram\JWT\JWT;

$claimSet = JWT::decode(
    $token
    JWT::createEncryptionList()->addHS512Key('mysecret')
);
```

Algorithm Support
--------------------------------

| Algorithm  | Type       | Engine   | Support |
| -----------| ---------- | -------------------|
| HS256      | Symmetric  | HMAC     | Yes     |
| HS384      | Symmetric  | HMAC     | Yes     |
| HS512      | Symmetric  | HMAC     | Yes     |
| RS256      | Asymmetric | OpenSSL  | Yes     |
| RS384      | Asymmetric | OpenSSL  | Yes     |
| RS512      | Asymmetric | OpenSSL  | Yes     |
| ES256      | Asymmetric | X        | No      |
| ES384      | Asymmetric | X        | No      |
| ES512      | Asymmetric | X        | No      |
