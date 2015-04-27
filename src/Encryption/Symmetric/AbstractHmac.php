<?php
namespace Aviogram\JWT\Encryption\Symmetric;

use Aviogram\JWT\Encryption\EncryptionInterface;
use Aviogram\JWT\Exception\EncryptionNotSupported;

abstract class AbstractHmac implements EncryptionInterface
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @param string $secret
     */
    public function __construct($secret)
    {
        $this->secret = $secret;
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
        return hash_hmac($this->getHmacAlgorithm(), $payload, $this->secret, true);
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
        $hash   = $this->sign($payload);
        $length = min(strlen($hash), strlen($signature));

        $status = 0;
        for ($i = 0; $i < $length; $i++) {
            $status |= ord($signature[$i]) ^ ord($hash[$i]);
        }

        $status |= strlen($signature) ^ strlen($hash);

        return ($status === 0);
    }

    /**
     * Get the algorithm
     *
     * @return string
     * @throws EncryptionNotSupported
     */
    private function getHmacAlgorithm()
    {
        $algorithms = hash_algos();
        $algorithm  = $this->getAlgorithm();

        if (in_array($algorithm, $algorithms) === false) {
            throw new EncryptionNotSupported("Encryption {$this->getName()} with algorithm {$algorithm} is not supported.");
        }

        return $algorithm;
    }

    /**
     * Returns the algorithm
     *
     * @return string
     */
    abstract protected function getAlgorithm();
}
