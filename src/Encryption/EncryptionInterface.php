<?php
namespace Aviogram\JWT\Encryption;

interface EncryptionInterface
{
    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName();

    /**
     * Sign the payload and returns a signature
     *
     * @param  string $payload
     *
     * @return string
     */
    public function sign($payload);

    /**
     * Verifies if the payload is valid or not
     *
     * @param $payload
     * @param $signature
     *
     * @return boolean
     */
    public function verify($payload, $signature);
}
