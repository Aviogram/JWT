<?php
namespace Aviogram\JWT\Encryption\Asymmetric;

class RS384 extends AbstractOpenSSL
{
    /**
     * Returns the algorithm to use
     *
     * @return string
     */
    protected function getAlgorithm()
    {
        return 'SHA384';
    }

    /**
     * Returns the name of the encryption
     *
     * @return string
     */
    public function getName()
    {
        return 'RS384';
    }
}
