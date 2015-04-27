<?php
namespace Aviogram\JWT\Encryption;

use Aviogram\Common\AbstractCollection;

/**
 * @method EncryptionInterface current()
 * @method EncryptionInterface offsetGet($offset)
 */
class EncryptionList extends AbstractCollection
{
    /**
     * Determines of the value is a valid collection value
     *
     * @param  mixed $value
     * @return boolean
     */
    protected function isValidValue($value)
    {
        return ($value instanceof EncryptionInterface);
    }

    /**
     * This encryption method will add an empty signature
     *
     * @return $this
     */
    public function addEmptyKey()
    {
        $this->append(new None());

        return $this;
    }

    /**
     * @param  string $secret
     *
     * @return $this
     */
    public function addHS256Key($secret)
    {
        $this->append(new Symmetric\HS256($secret));

        return $this;
    }

    /**
     * @param  string $secret
     *
     * @return $this
     */
    public function addHS384Key($secret)
    {
        $this->append(new Symmetric\HS384($secret));

        return $this;
    }

    /**
     * @param  string $secret
     *
     * @return $this
     */
    public function addHS512Key($secret)
    {
        $this->append(new Symmetric\HS512($secret));

        return $this;
    }

    /**
     * @param string      $publicKey
     * @param string|null $privateKey
     * @param string|null $password
     *
     * @return $this
     */
    public function addRS256Key($publicKey, $privateKey = null, $password = null)
    {
        $this->append(new Asymmetric\RS256($publicKey, $privateKey, $password));

        return $this;
    }

    /**
     * @param string      $publicKey
     * @param string|null $privateKey
     * @param string|null $password
     *
     * @return $this
     */
    public function addRS384Key($publicKey, $privateKey = null, $password = null)
    {
        $this->append(new Asymmetric\RS384($publicKey, $privateKey, $password));

        return $this;
    }

    /**
     * @param string      $publicKey
     * @param string|null $privateKey
     * @param string|null $password
     *
     * @return $this
     */
    public function addRS512Key($publicKey, $privateKey = null, $password = null)
    {
        $this->append(new Asymmetric\RS512($publicKey, $privateKey, $password));

        return $this;
    }
}
