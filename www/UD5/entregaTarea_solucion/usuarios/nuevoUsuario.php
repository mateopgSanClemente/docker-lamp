<?php
require_once('../login/sesiones.php');
if (!checkAdmin()) redirectIndex();
    
require_once('../utils.php');
$nombre = $_POST['nombre'];
$apellidos = $_POST['apellidos'];
$username = $_POST['username'];
$contrasena = $_POST['contrasena'];
$rol = $_POST['rol'];
$response = 'error';
$messages = array();

require_once('../modelo/entity/Usuario.php');
require_once('../modelo/entity/Rol.php');

$errores = Usuario::validate($_POST);

if (empty($errores))
{
    $usuario = new Usuario(filtraCampo($nombre), filtraCampo($apellidos), filtraCampo($username), $contrasena, Rol::from((int)$rol));

    require_once('../modelo/pdo.php');
    $resultado = nuevoUsuario($usuario);
    if ($resultado[0])
    {
        $messages = ['Usuario guardado correctamente.'];
        $response = 'success';
    }
    else
    {
        $messages = ['Ocurrió un error guardando el usuario: ' . $resultado[1]];
    }
}
else
{
    $messages = $errores;
}

$_SESSION['status'] = $response;
$_SESSION['messages'] = $messages;
header("Location: nuevoUsuarioForm.php");

