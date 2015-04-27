<?php
namespace Aviogram\JWT\Encryption\Symmetric;

class HS384 extends AbstractHmac
{
    /**
     * Returns the algorithm
     *
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha384';
    }

    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName()
    {
        return 'HS384';
    }
}
