<?php
namespace Aviogram\JWT\Encryption;

class None implements EncryptionInterface
{
    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName()
    {
        return 'none';
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
        return '';
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
        return $signature === '';
    }
}
