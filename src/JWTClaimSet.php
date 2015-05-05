<?php
namespace Aviogram\JWT;

use DateTime;

class JWTClaimSet implements \JsonSerializable
{
    /**
     * @var string
     */
    protected $iss;
    /**
     * @var string
     */
    protected $sub;

    /**
     * @var string
     */
    protected $aud;

    /**
     * @var Datetime
     */
    protected $exp;

    /**
     * @var Datetime
     */
    protected $nbf;

    /**
     * @var Datetime
     */
    protected $iat;

    /**
     * @var string
     */
    protected $jti;

    /**
     * @var string
     */
    protected $typ;

    /**
     * @var array
     */
    protected $custom = array();

    /**
     * @return string
     */
    public function getIss()
    {
        return $this->iss;
    }

    /**
     * @param string $iss
     *
     * @return $this
     */
    public function setIss($iss)
    {
        $this->iss = $iss;

        return $this;
    }

    /**
     * @return string
     */
    public function getSub()
    {
        return $this->sub;
    }

    /**
     * @param string $sub
     *
     * @return $this
     */
    public function setSub($sub)
    {
        $this->sub = $sub;

        return $this;
    }

    /**
     * @return string
     */
    public function getAud()
    {
        return $this->aud;
    }

    /**
     * @param string $aud
     *
     * @return $this
     */
    public function setAud($aud)
    {
        $this->aud = $aud;

        return $this;
    }

    /**
     * @return Datetime | NULL
     */
    public function getExp()
    {
        return $this->exp;
    }

    /**
     * The time that the token should expire
     *
     * @param Datetime $exp
     *
     * @return $this
     */
    public function setExp(Datetime $exp)
    {
        $this->exp = $exp;

        return $this;
    }

    /**
     * @return Datetime | NULL
     */
    public function getNbf()
    {
        return $this->nbf;
    }

    /**
     * Set the time when the token will be valid to use
     *
     * @param Datetime $nbf
     *
     * @return $this
     */
    public function setNbf(Datetime $nbf)
    {
        $this->nbf = $nbf;

        return $this;
    }

    /**
     * @return Datetime | NULL
     */
    public function getIat()
    {
        return $this->iat;
    }

    /**
     * Set the time when the token was issued
     *
     * @param Datetime $iat
     *
     * @return $this
     */
    public function setIat(Datetime $iat)
    {
        $this->iat = $iat;

        return $this;
    }

    /**
     * @return string
     */
    public function getJti()
    {
        return $this->jti;
    }

    /**
     * @param string $jti
     *
     * @return $this
     */
    public function setJti($jti)
    {
        $this->jti = $jti;

        return $this;
    }

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
     * @param  string $name
     * @param  mixed  $value
     *
     * @return $this
     * @throws Exception\ReservedClaim
     */
    public function addCustomClaim($name, $value)
    {
        if (property_exists($this, $name) === true) {
            throw new Exception\ReservedClaim("Claim with the name {$name} is reserved.");
        }

        $this->custom[$name] = $value;

        return $this;
    }

    /**
     * @param  string $name
     * @param  null   $default  Value will be returned when the claim has not been set
     *
     * @return mixed
     */
    public function getCustomClaim($name, $default = null)
    {
        if (array_key_exists($name, $this->custom) === false) {
            return $default;
        }

        return $this->custom[$name];
    }

    /**
     * @return array
     */
    public function getCustomClaims()
    {
        return $this->custom;
    }

    /**
     * (PHP 5 &gt;= 5.4.0)<br/>
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     */
    public function jsonSerialize()
    {
        $data = get_object_vars($this);
        unset($data['custom']);

        foreach ($data as $index => $value) {

            if ($value === null) {
                unset($data[$index]);

                continue;
            }

            if ($value instanceof DateTime) {
                $data[$index] = $value->getTimestamp();
            }
        }

        return array_merge($data, $this->custom);;
    }
}
