<?php
namespace Aviogram\JWT\Encryption\Symmetric;

class HS256 extends AbstractHmac
{
    /**
     * Returns the algorithm
     *
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'sha256';
    }

    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName()
    {
        return 'HS256';
    }
}
