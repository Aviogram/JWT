<?php
namespace Aviogram\JWT\Encryption\Asymmetric;

use Aviogram\JWT\Encryption\EncryptionInterface;
use Aviogram\JWT\Exception\EncryptionFailed;
use Aviogram\JWT\Exception\EncryptionNotSupported;

abstract class AbstractOpenSSL implements EncryptionInterface
{
    /**
     * @var string
     */
    protected $publicKey;

    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $privateKeyPassword;

    /**
     * @var resource
     */
    protected $privateKeyInstance;

    /**
     * @var resource
     */
    protected $publicKeyInstance;

    /**
     * @param string $publicKey
     * @param null   $privateKey
     * @param null   $privateKeyPassword
     */
    public function __construct($publicKey, $privateKey = null, $privateKeyPassword = null)
    {
        if (extension_loaded('openssl') === false) {
            throw new EncryptionNotSupported('Extension OpenSSL is required.');
        }

        $this->publicKey          = $publicKey;
        $this->privateKey         = $privateKey;
        $this->privateKeyPassword = $privateKeyPassword;
    }

    /**
     * Fetch the private key
     *
     * @return resource
     */
    protected function loadPrivateKey()
    {
        if ($this->privateKeyInstance !== null) {
            return $this->privateKeyInstance;
        }

        if ($this->privateKey === null) {
            throw new EncryptionFailed('For signing is the private key is required.');
        }

        $key = openssl_pkey_get_private($this->privateKey, $this->privateKeyPassword ?: '');
        if ($key === false) {
            throw new EncryptionFailed(openssl_error_string());
        }

        return $this->privateKeyInstance = $key;
    }

    /**
     * Fetch the public key
     *
     * @return resource
     */
    protected function loadPublicKey()
    {
        if ($this->publicKeyInstance !== null) {
            return $this->publicKeyInstance;
        }

        $key = openssl_get_publickey($this->publicKey);
        if ($key === false) {
            throw new EncryptionFailed(openssl_error_string());
        }

        return $this->publicKeyInstance = $key;
    }

    /**
     * @return string
     * @throws EncryptionNotSupported
     */
    protected function getOpenSSLAlgorithm()
    {
        $algorithms = openssl_get_md_methods();
        $algorithm  = $this->getAlgorithm();

        if (in_array($algorithm, $algorithms) === false) {
            throw new EncryptionNotSupported("Algorithm {$algorithm} is not supported.");
        }

        return $algorithm;
    }

    /**
     * Encrypt the payload and returns a signature
     *
     * @param  string $payload
     *
     * @return string
     */
    public function sign($payload)
    {
        $key = $this->loadPrivateKey();

        if (openssl_sign($payload, $signature, $key, $this->getOpenSSLAlgorithm()) === false) {
            throw new EncryptionFailed('Could not sign the payload.');
        }

        return $signature;
    }

    /**
     * Verifies if the payload is valid or not
     *
     * @param $payload
     * @param $signature
     *
     * @return boolean
     */
    public function verify($payload, $signature)
    {
        $key = $this->loadPublicKey();

        return openssl_verify($payload, $signature, $key, $this->getOpenSSLAlgorithm());
    }

    /**
     * Returns the algorithm to use
     *
     * @return string
     */
    abstract protected function getAlgorithm();
}
