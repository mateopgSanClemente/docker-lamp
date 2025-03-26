<?php

require_once __DIR__ . '/Tarea.php';

class Fichero
{
    private int $id;
    private string $nombre;
    private string $file;
    private string $descripcion;
    private Tarea $tarea;

    public const FORMATOS = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'image/jpeg', 'image/png'];
    public const MAX_SIZE = 10485760; // 10MB

    public function __construct(string $nombre, string $file, string $descripcion, Tarea $tarea = null)
    {
        $this->id = 0;
        $this->nombre = $nombre;
        $this->file = $file;
        $this->descripcion = $descripcion;
        if ($tarea) $this->tarea = $tarea;
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function setId(int $id): void
    {
        $this->id = $id;
    }

    public function getNombre(): string
    {
        return $this->nombre;
    }

    public function setNombre(string $nombre): void
    {
        $this->nombre = $nombre;
    }

    public function getFile(): string
    {
        return $this->file;
    }

    public function setFile(string $file): void
    {
        $this->file = $file;
    }

    public function getDescripcion(): string
    {
        return $this->descripcion;
    }

    public function setDescripcion(string $descripcion): void
    {
        $this->descripcion = $descripcion;
    }

    public function getTarea(): Tarea
    {
        return $this->tarea;
    }

    public function setTarea(Tarea $tarea): void
    {
        $this->tarea = $tarea;
    }

    public static function validate(array $data): array
    {
        $errores = [];

        if (empty($data['nombre'])) 
        {
            $errores['nombre'] = 'El nombre es obligatorio.';
        } 
        elseif (strlen($data['nombre']) <= 3) 
        {
            $errores['nombre'] = 'El nombre debe tener más de 3 caracteres.';
        }

        if (empty($data['file'])) 
        {
            $errores['file'] = 'El archivo es obligatorio.';
        } 
        elseif (!in_array($data['file']['type'], self::FORMATOS)) 
        {
            $errores['file'] = 'El formato del archivo no es válido. Solo se aceptan archivos PDF, DOC, DOCX, JPG y PNG.';
        } 
        elseif ($data['file']['size'] > self::MAX_SIZE)
        {
            $errores['file'] = 'El archivo excede el tamaño máximo permitido.';
        }

        if (empty($data['descripcion'])) 
        {
            $errores['descripcion'] = 'La descripción es obligatoria.';
        }

        if (empty($data['tarea'])) 
        {
            $errores['tarea'] = 'La tarea es obligatoria.';
        }

        return $errores;
    }
}
?>