<?php
namespace Aviogram\JWT\Encryption\Asymmetric;

class RS512 extends AbstractOpenSSL
{
    /**
     * Returns the algorithm to use
     *
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'SHA512';
    }

    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName()
    {
        return 'RS512';
    }
}
