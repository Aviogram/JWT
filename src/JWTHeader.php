<?php
namespace Aviogram\JWT;

class JWTHeader implements \JsonSerializable
{
    /**
     * @var string
     */
    protected $typ;

    /**
     * @var string
     */
    protected $cty;

    /**
     * @var string
     */
    protected $kid;

    /**
     * @var string
     */
    protected $alg;

    /**
     * @var array
     */
    protected $custom = array();

    /**
     * @return string
     */
    public function getTyp()
    {
        return $this->typ;
    }

    /**
     * @param string $typ
     *
     * @return $this
     */
    public function setTyp($typ)
    {
        $this->typ = $typ;

        return $this;
    }

    /**
     * @return string
     */
    public function getCty()
    {
        return $this->cty;
    }

    /**
     * @param string $cty
     *
     * @return $this
     */
    public function setCty($cty)
    {
        $this->cty = $cty;

        return $this;
    }

    /**
     * @return string
     */
    public function getKid()
    {
        return $this->kid;
    }

    /**
     * @param string $kid
     *
     * @return $this
     */
    public function setKid($kid)
    {
        $this->kid = $kid;

        return $this;
    }

    /**
     * @return string
     */
    public function getAlg()
    {
        return $this->alg;
    }

    /**
     * @param string $alg
     *
     * @return $this
     */
    public function setAlg($alg)
    {
        $this->alg = $alg;

        return $this;
    }

    /**
     * @return array
     */
    public function getCustomHeaders()
    {
        return $this->custom;
    }

    /**
     * @param array $custom
     *
     * @return $this
     */
    public function setCustomHeaders(array $custom)
    {
        $this->custom = $custom;

        return $this;
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return $this
     */
    public function addCustomHeader($key, $value)
    {
        if (property_exists($this, $key) === true) {
            throw new Exception\ReservedHeader("Header with the name {$key} is reserved.");
        }

        $this->custom[$key] = $value;
    }

    /**
     * @param string $key
     * @param null   $default
     *
     * @return null
     */
    public function getCustomHeader($key, $default = null)
    {
        if (array_key_exists($key, $this->custom) === false) {
            return $default;
        }

        return $this->custom[$key];
    }

    /**
     * (PHP 5 &gt;= 5.4.0)<br/>
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     */
    function jsonSerialize()
    {
        $data = get_object_vars($this);
        unset($data['custom']);

        foreach ($data as $offset => $value) {
            if ($value === null) {
                unset($data[$offset]);
            }
        }

        return array_merge($data, $this->getCustomHeaders());
    }
}
