<?php
require_once(__DIR__ . '/../modelo/entity/Rol.php');
require_once(__DIR__ . '/../modelo/entity/Usuario.php');
session_start();
$url_sesiones = str_replace($_SERVER['DOCUMENT_ROOT'], '', __DIR__);


if (!checkSession()) {	
    redirectLogin();
}

function checkSession()
{
    return isset($_SESSION['usuario']);
}

function redirectLogin()
{
    global $url_sesiones;
    header("Location: $url_sesiones/login.php?redirect=true");
    exit();
}

function checkAdmin()
{
    return (checkSession() && $_SESSION['usuario']->getRol() == Rol::ADMIN);
}

function redirectIndex()
{
    global $url_sesiones;
    header("Location: $url_sesiones/../index.php?redirect=true");
    exit();
}