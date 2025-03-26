<?php
require_once('../login/sesiones.php');
require_once('../utils.php');
require_once('../modelo/mysqli.php');
require_once('../modelo/entity/Tarea.php');
require_once('../modelo/entity/Estado.php');
require_once('../modelo/entity/Usuario.php');

$titulo = $_POST['titulo'];
$descripcion = $_POST['descripcion'];
$estado = $_POST['estado'];
$id_usuario = $_POST['id_usuario'];
$_POST['usuario'] = $id_usuario;

$response = 'error';
$messages = array();
$location = 'nuevaForm.php';

if (!checkAdmin()) $id_usuario = $_SESSION['usuario']->getId();

$errores = Tarea::validate($_POST);

if (empty($errores))
{
    $usuario = buscaUsuarioMysqli($id_usuario);
    $tarea = new Tarea(filtraCampo($titulo), filtraCampo($descripcion), $usuario, Estado::from($estado));
    $resultado = nuevaTarea($tarea);
    if ($resultado[0])
    {
        $response = 'success';
        array_push($messages, 'Tarea guardada correctamente.');
    }
    else
    {
        $response = 'error';
        array_push($messages, 'Ocurrió un error guardando la tarea: ' . $resultado[1] . '.');
    }
}
else
{
    $messages = $errores;
}

$_SESSION['status'] = $response;
$_SESSION['messages'] = $messages;

header("Location: $location");