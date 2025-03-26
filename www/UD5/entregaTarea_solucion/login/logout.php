<?php
    require_once('../modelo/entity/Usuario.php');
    require_once('../modelo/entity/Rol.php');
    session_start();
    $_SESSION = array();
    session_destroy();
    header("Location: login.php");
?>