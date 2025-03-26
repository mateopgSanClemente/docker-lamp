<?php
require_once('../login/sesiones.php');
if (!checkAdmin()) redirectIndex();

$message = 'Error borrando el usuario.';
$error = true;

require_once('../modelo/pdo.php');

if (!empty($_GET))
{
    $id = $_GET['id'];
    if (!empty($id))
    {
        $resultado = borraUsuario($id);
        if ($resultado[0])
        {
            $message = 'Usuario borrado correctamente.';
            $error = false;
        }
        else
        {
            $message = 'No se pudo borrar el usuario.';
        }
    }
    else
    {
        $message = 'No se pudo recuperar la información del usuario.';
    }
}
else
{
    $message = 'Debes acceder a través del listado de usuarios.';
}

$status = $error ? 'error' : 'success';
header("Location: usuarios.php?status=$status&message=$message");
