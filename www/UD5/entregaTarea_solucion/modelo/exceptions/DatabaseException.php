<?php

class DatabaseException extends Exception {
    private $method;
    private $sql;

    public function __construct($message, $code = 0, Exception $previous = null, $method = '', $sql = '') {
        parent::__construct($message, $code, $previous);
        $this->method = $method;
        $this->sql = $sql;
    }

    public function getMethod() {
        return $this->method;
    }

    public function getSql() {
        return $this->sql;
    }
}
?>