<?php
require_once('../login/sesiones.php');
require_once('../modelo/FicherosDBImp.php');
require_once('../modelo/entity/Fichero.php');
require_once('../exceptions/DatabaseException.php');

$status = 'error';
$messages = array();
$id_tarea = 0;

if (!empty($_GET))
{
    $id = $_GET['id'];

    /** @var FicherosDBInt $ficherosDB */
    $ficherosDB = new FicherosDBImp();
    $archivo = null;
    try{
        $archivo = $ficherosDB->buscaFichero($id);
    }
    catch (DatabaseException $e)
    {
        array_push($messages, $e->getMessage());
    }
    
    if (!empty($id) && $archivo)
    {
        $id_tarea = $archivo->getTarea()->getId();
        if (checkAdmin() || esPropietarioTarea($_SESSION['usuario']->getId(), $archivo->getTarea()->getId()))
        {
            $ruta = '../' . $archivo->getFile();
            $borrado = borrarArchivo($ruta);
            try
            {
                if ($borrado) $borrado = $ficherosDB->borraFichero($archivo->getId());

                if ($borrado)
                {
                    $status = 'success';
                    array_push($messages, 'Archivo borrado correctamente.');
                }
                else
                {
                    array_push($messages, 'No se pudo borrar el archivo.');
                }
            }
            catch (DatabaseException $e)
            {
                array_push($messages, $e->getMessage());
            }

        }
        else
        {
            array_push($messages, 'No tienes permisos sobre este archivo.');
        }
    }
    else
    {
        array_push($messages, 'No se pudo recuperar la información del archivo.');
    }
}
else
{
    array_push($messages, 'Debes acceder a través del listado de tareas.');
}


$_SESSION['status'] = $status;
$_SESSION['messages'] = $messages;
header("Location: ../tareas/tarea.php?id=" . $id_tarea);

function borrarArchivo($archivo)
{
    return (file_exists($archivo) && unlink($archivo));
}

