<?php

require_once __DIR__ . '/entity/Fichero.php';

/**
 * Interface FicherosDBInt
 * 
 * Esta interfaz define los métodos para gestionar archivos en la base de datos.
 * 
 * @author marco@iessanclemente
 */
interface FicherosDBInt {
    /**
     * Recupera una lista de archivos asociados a una tarea específica.
     *
     * @param int $id_tarea El ID de la tarea.
     * @return array Un array de archivos asociados a la tarea.
     */
    public function listaFicheros(int $id_tarea): array;

    /**
     * Busca un archivo por su ID.
     *
     * @param int $id El ID del archivo.
     * @return Fichero El objeto archivo correspondiente al ID dado.
     */
    public function buscaFichero(int $id): Fichero;

    /**
     * Elimina un archivo por su ID.
     *
     * @param int $id El ID del archivo a eliminar.
     * @return bool True si el archivo fue eliminado con éxito, false en caso contrario.
     */
    public function borraFichero(int $id): bool;

    /**
     * Añade un nuevo archivo a la base de datos.
     *
     * @param Fichero $fichero El objeto archivo a añadir.
     * @return bool True si el archivo fue añadido con éxito, false en caso contrario.
     */
    public function nuevoFichero(Fichero $fichero): bool;
}