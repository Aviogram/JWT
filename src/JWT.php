<?php
namespace Aviogram\JWT;

use Aviogram\Common\Base64;
use Aviogram\Common\Hydrator\ByClassMethods;
use Aviogram\JWT\Encryption\EncryptionList;
use DateTime;

class JWT
{
    /**
     * A list of exceptions that can be thrown
     *
     * @var array
     */
    private static $exceptions = array(
        1  => 'Needs at least 1 encryption key to encode',
        2  => 'Could not JSON encode the header',
        3  => 'Could not JSON encode the claimSet',
        4  => 'Could not Base64::encode the header',
        5  => 'Could not Base64::encode the claimSet',
        6  => 'Could not Base64::encode the signature',
        7  => 'Could not create a signature',
        8  => 'Could not create a signature, because the encryption algorithm is not supported',
        9  => 'JWT is not correctly formatted',
        10 => 'Needs at least 1 encryption key to encode',
        11 => 'Could not JSON decode the header',
        12 => 'Could not JSON decode the claimSet',
        13 => 'Could not Base64::decode the header',
        14 => 'Could not Base64::decode the claimSet',
        15 => 'Could not Base64::decode the signature',
        16 => 'The JWT is invalid',
        17 => 'The JWT is not active yet',
        18 => 'The JWT has been expired',
        19 => 'The JWT issuer does not match',
        20 => 'The JWT audience does not match',
        21 => 'The Algorithm from the header does not match with the encryption defined',
        22 => 'The key defined in the header is not defined',
        23 => 'The JWT type does not match',
        24 => 'The JWT has been issued in the future',
        25 => 'Could not validate the signature',
        26 => 'Could not validate the signature, because the encryption algorithm is not supported',
    );

    /**
     * Create an options object for the decode and encode methods. Use ::addKey for adding keys
     *
     *
     * @return EncryptionList
     */
    public static function createEncryptionList()
    {
        return new EncryptionList();
    }

    /**
     * @return JWTClaimSet
     */
    public static  function createClaimSet()
    {
        return new JWTClaimSet();
    }

    /**
     * @param JWTClaimSet    $claimSet
     * @param EncryptionList $encryptionList
     *
     * @return string
     * @throws Exception\EncodeFailed
     */
    public static function encode(JWTClaimSet $claimSet, EncryptionList $encryptionList)
    {
        if ($encryptionList->count() === 0) {
            throw new Exception\EncodeFailed(static::$exceptions[1], 1);
        }

        // Fetch the latest encryption key available
        $encryptionOffset = $encryptionList->count() - 1;
        $encryption       = $encryptionList->offsetGet($encryptionOffset);

        // Create the JWT Header
        $header = new JWTHeader();
        $header->setTyp('JWT')->setAlg($encryption->getName())->setKid($encryptionOffset)->addCustomHeader('jesper', 'boe');

        // Encode the Header according the specs
        $encodedHeader = json_encode($header);
        if ($encodedHeader === false) {
            throw new Exception\EncodeFailed(static::$exceptions[2], 2);
        }

        $encodedHeader = Base64::encodeURLSafe($encodedHeader);
        if ($encodedHeader === false) {
            throw new Exception\EncodeFailed(static::$exceptions[4], 4);
        }

        // Encode the JWT claims according the specs
        $encodedClaimSet = json_encode($claimSet);
        if ($encodedClaimSet === false) {
            throw new Exception\EncodeFailed(static::$exceptions[3], 3);
        }

        $encodedClaimSet = Base64::encodeURLSafe($encodedClaimSet);
        if ($encodedClaimSet === false) {
            throw new Exception\EncodeFailed(static::$exceptions[5], 5);
        }

        try {
            // Create a signature based on the JWT header and claimSet
            $payload   = "{$encodedHeader}.{$encodedClaimSet}";
            $signature = Base64::encodeURLSafe($encryption->sign($payload));

            if ($signature === false) {
                throw new Exception\EncodeFailed(static::$exceptions[6], 6);
            }
        } catch (Exception\EncryptionFailed $e) {
            throw new Exception\EncodeFailed(static::$exceptions[7], 7, $e);
        } catch (Exception\EncryptionNotSupported $e) {
            throw new Exception\EncodeFailed(static::$exceptions[8], 8, $e);
        }

        return "{$payload}.{$signature}";
    }

    /**
     * Decode a given token and return the ClaimSet data
     *
     * @param string         $jwt
     * @param EncryptionList $encryptionList        A list with keys
     * @param JWTClaimSet    $claimSetVerification  The token will be matched against this claimset
     *
     * @return JWTClaimSet
     * @throws Exception\DecodeFailed
     */
    public static function decode($jwt, EncryptionList $encryptionList, JWTClaimSet $claimSetVerification = null)
    {
        $parts = explode('.', $jwt);
        if (count($parts) <> 3) {
            throw new Exception\DecodeFailed(static::$exceptions[9], 9);
        }

        list($encodedHeader, $encodedClaimSet, $encodedSignature) = $parts;

        $headerData = Base64::decodeURLSafe($encodedHeader);
        if ($headerData === false) {
            throw new Exception\DecodeFailed(static::$exceptions[13], 13);
        }

        $headerData = json_decode($headerData, true);
        if (is_array($headerData) === false) {
            throw new Exception\DecodeFailed(static::$exceptions[11], 11);
        }

        $signature = Base64::decodeURLSafe($encodedSignature);
        if ($signature === false) {
            throw new Exception\DecodeFailed(static::$exceptions[15], 15);
        }

        $hydrator  = new ByClassMethods();
        $header    = new JWTHeader();
        $remainder = array();

        // Hydrate the array data on the Header object
        $hydrator->hydrate($header, $headerData, false, $remainder);

        // Add the remainder on the custom section
        foreach ($remainder as $field => $value) {
            $header->addCustomHeader($field, $value);
        }

        // Check if the encryption has been defined
        if ($encryptionList->offsetExists($header->getKid()) === false) {
            throw new Exception\DecodeFailed(static::$exceptions[22], 22);
        }

        // Fetch the encryption service and check if it matches with the header information
        $encryption = $encryptionList->offsetGet($header->getKid());
        if ($encryption->getName() !== $header->getAlg()) {
            throw new Exception\DecodeFailed(static::$exceptions[21], 21);
        }

        try {
            // Check if the JWT is valid
            if ($encryption->verify("{$encodedHeader}.{$encodedClaimSet}", $signature) === false) {
                throw new Exception\DecodeFailed(static::$exceptions[16], 16);
            }
        } catch (Exception\EncryptionFailed $e) {
            throw new Exception\DecodeFailed(static::$exceptions[25], 25, $e);
        } catch (Exception\EncryptionNotSupported $e) {
            throw new Exception\DecodeFailed(static::$exceptions[26], 26, $e);
        }

        // Decode the base64 encoded string
        $claimSetData = Base64::decodeURLSafe($encodedClaimSet);
        if ($claimSetData === false) {
            throw new Exception\DecodeFailed(static::$exceptions[14], 14);
        }

        // Decode the JSON string
        $claimSetData = json_decode($claimSetData, true);
        if (is_array($claimSetData) === false) {
            throw new Exception\DecodeFailed(static::$exceptions[12], 12);
        }

        foreach ($claimSetData as $offset => $value) {
            switch ($offset) {
                case 'iat':
                case 'nbf':
                case 'exp':
                    $claimSetData[$offset] = (new Datetime())->setTimestamp($value);
                    break;
            }
        }

        $claimSet  = new JWTClaimSet();
        $remainder = array();

        // Hydrate the array data on the ClaimSet object
        $hydrator->hydrate($claimSet, $claimSetData, false, $remainder);

        // Set the remainder of the data in the custom section
        foreach ($remainder as $field => $value) {
            $claimSet->addCustomClaim($field, $value);
        }

        // If no verification input has been given, make it empty
        if ($claimSetVerification === null) {
            $claimSetVerification = new JWTClaimSet();
        }

        $now = new Datetime();

        // Check if the issue at timestamp is correct
        if ($claimSet->getIat() !== null && $claimSet->getIat() > $now) {
            throw new Exception\DecodeFailed(static::$exceptions[24], 24);
        }

        // Check if the claim is not expired
        if ($claimSet->getExp() !== null && $claimSet->getExp() < $now) {
            throw new Exception\DecodeFailed(static::$exceptions[18], 18);
        }

        // Check if the claim can be used or not
        if ($claimSet->getNbf() !== null && $claimSet->getNbf() > $now) {
            throw new Exception\DecodeFailed(static::$exceptions[17], 17);
        }

        // Check if the issuer match
        if ($claimSet->getIss() !== $claimSetVerification->getIss()) {
            throw new Exception\DecodeFailed(static::$exceptions[19], 19);
        }

        // Check if the audience match
        if ($claimSet->getAud() !== $claimSetVerification->getAud()) {
            throw new Exception\DecodeFailed(static::$exceptions[20], 20);
        }

        // Check if the typ match
        if ($claimSet->getTyp() !== $claimSetVerification->getTyp()) {
            throw new Exception\DecodeFailed(static::$exceptions[23], 23);
        }

        return $claimSet;
    }
}
