<?php

require_once('../login/sesiones.php');
require_once('../modelo/entity/Fichero.php');
require_once('../modelo/pdo.php');
require_once('../modelo/FicherosDBImp.php');
require_once('../exceptions/DatabaseException.php');

$directorioDestino = "files/"; // Carpeta donde se guardarán los archivos --> revisar permisos si da error

$location = '../tareas.php';
$response = 'error';
$messages = array();

$error = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
    $nombreArchivo = $_POST['nombre'] ?? '';
    $descripcion = $_POST['descripcion'] ?? '';
    $archivo = $_FILES['archivo'] ?? null;
    $id_tarea = $_POST['id_tarea'] ?? '';
    $_POST['tarea'] = $id_tarea;
    $_POST['file'] = $archivo;

    $location = 'subidaFichForm.php?id=' . $id_tarea;

    $errores = Fichero::validate($_POST);

    if (empty($errores))
    {
        $codigoAleatorio = bin2hex(random_bytes(8)); // 16 caracteres alfanuméricos

        $extension = pathinfo($archivo['name'], PATHINFO_EXTENSION);

        $nombreFinal = $codigoAleatorio . '.' . $extension;

        $rutaDestino = $directorioDestino . $nombreFinal;

        if (!is_writable('../' . $directorioDestino))
        {
            array_push($messages, "No hay permisos de escritura en la carpeta destino.");
            $error = true;
        }
    
        // Mover el archivo al directorio de destino
        if (!$error)
        {
            if (move_uploaded_file($archivo['tmp_name'], '../' . $rutaDestino))
            {
                /** @var FicherosDBInt $ficherosDB */
                $ficherosDB = new FicherosDBImp();
                try
                {
                    $tarea = buscaTarea($id_tarea);
                    $fichero = new Fichero($nombreArchivo, $rutaDestino, $descripcion, $tarea);
                    $resultado = $ficherosDB->nuevoFichero($fichero);

                    if ($resultado)
                    {
                        $response = 'success';
                        array_push($messages, 'Archivo subido correctamente.');
                        $location = '../tareas/tarea.php?id=' . $id_tarea;
                    }
                    else
                    {
                        array_push($messages, 'Ocurrió un error guardando el fichero.');
                    }
                }
                catch (DatabaseException $e)
                {
                    array_push($messages, $e->getMessage());
                }
            }
            else
            {
                array_push($messages, 'Error al guardar el archivo.');
            }
        }
    }
    else
    {
        $messages = $errores;
    }    
}
else
{
    array_push($messages, 'Método de solicitud no válido.');
}

$_SESSION['status'] = $response;
$_SESSION['messages'] = $messages;
header("Location: " . $location);