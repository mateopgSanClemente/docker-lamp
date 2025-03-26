<?php
require_once('../login/sesiones.php');
require_once('../utils.php');
require_once('../modelo/mysqli.php');
require_once('../modelo/entity/Tarea.php');

$id = $_POST['id'];
$titulo = $_POST['titulo'];
$descripcion = $_POST['descripcion'];
$estado = $_POST['estado'];
$id_usuario = $_POST['id_usuario'];
$_POST['usuario'] = $id_usuario;

$response = 'error';
$messages = array();

$location = 'editaTareaForm.php?id=' . $id;

if (!checkAdmin()) $id_usuario = $_SESSION['usuario']->getId();

$errores = Tarea::validate($_POST);

if (empty($errores))
{
    
    $usuario = buscaUsuarioMysqli($id_usuario);
    $tarea = new Tarea(filtraCampo($titulo), filtraCampo($descripcion), $usuario, Estado::from($estado));
    $tarea->setId($id);
    $resultado = actualizaTarea($tarea);
    if ($resultado[0])
    {
        $response = 'success';
        array_push($messages, 'Tarea actualizada correctamente.');
        $location = 'tareas.php';
    }
    else
    {
        array_push($messages, 'Ocurrió un error actualizando la tarea: ' . $resultado[1] . '.');
    }
}
else
{
    $messages = $errores;
}

$_SESSION['status'] = $response;
$_SESSION['messages'] = $messages;

header("Location: $location");
                   