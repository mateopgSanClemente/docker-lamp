<?php

require_once __DIR__ . '/FicherosDBInt.php';
require_once __DIR__ . '/mysqli.php';
require_once __DIR__ . '/pdo.php';
require_once __DIR__ . '/entity/Fichero.php';
require_once __DIR__ . '/exceptions/DatabaseException.php';

class FicherosDBImp implements FicherosDBInt
{

    public function listaFicheros(int $id_tarea): array
    {
        try
        {
            $con = conectaPDO();
            $sql = 'SELECT * FROM ficheros WHERE id_tarea = :id_tarea';
            $stmt = $con->prepare($sql);
            $stmt->bindParam(':id_tarea', $id_tarea, PDO::PARAM_INT);
            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $ficheros = array();
            while ($row = $stmt->fetch())
            {
                $fichero = new Fichero($row['nombre'], $row['file'], $row['descripcion']);
                $tarea = buscaTarea($row['id_tarea']);
                $fichero->setTarea($tarea);
                $fichero->setId($row['id']);
                
                array_push($ficheros, $fichero);
            }
            return $ficheros;
        }
        catch (PDOException $e)
        {
            throw new DatabaseException('Error al listar los ficheros: ' . $e->getMessage(), 0, $e, __METHOD__, $sql);
        }
        finally
        {
            $con = null;
        }
    }

    public function buscaFichero(int $id): Fichero
    {
        try
        {
            $con = conectaPDO();
            $sql = 'SELECT * FROM ficheros WHERE id = ' . $id;
            $stmt = $con->prepare($sql);
            $stmt->execute();

            $stmt->setFetchMode(PDO::FETCH_ASSOC);
            $fichero = null;
            if ($row = $stmt->fetch())
            {
                $fichero = new Fichero($row['nombre'], $row['file'], $row['descripcion']);
                $tarea = buscaTarea($row['id_tarea']);
                $fichero->setTarea($tarea);
                $fichero->setId($row['id']);
            }
            return $fichero;
        }
        catch (PDOException $e)
        {
            throw new DatabaseException('Error al buscar el fichero: ' . $e->getMessage(), 0, $e, __METHOD__, $sql);
        }
        finally
        {
            $con = null;
        }
    }

    public function borraFichero(int $id): bool
    {
        try
        {
            $con = conectaPDO();
            $sql = 'DELETE FROM ficheros WHERE id = ' . $id;
            $stmt = $con->prepare($sql);
            $stmt->execute();

            return true;
        }
        catch (PDOException $e)
        {
            throw new DatabaseException('Error al borrar el fichero: ' . $e->getMessage(), 0, $e, __METHOD__, $sql);
        }
        finally
        {
            $con = null;
        }
    }

    public function nuevoFichero(Fichero $fichero): bool 
    {
        try
        {
            $con = conectaPDO();
            $stmt = $con->prepare("INSERT INTO ficheros (nombre, file, descripcion, id_tarea) VALUES (:nombre, :file, :descripcion, :idTarea)");
            $file = $fichero->getFile();
            $nombre = $fichero->getNombre();
            $descripcion = $fichero->getDescripcion();
            $idTarea = $fichero->getTarea()->getId();
            $stmt->bindParam(':file', $file);
            $stmt->bindParam(':nombre', $nombre);
            $stmt->bindParam(':descripcion', $descripcion);
            $stmt->bindParam(':idTarea', $idTarea);
            $stmt->execute();
            
            $stmt->closeCursor();

            return true;
        }
        catch (PDOExcetion $e)
        {
            throw new DatabaseException('Error al crear el fichero: ' . $e->getMessage(), 0, $e, __METHOD__, $stmt->queryString);
        }
        finally
        {
            $con = null;
        }
    }
}
