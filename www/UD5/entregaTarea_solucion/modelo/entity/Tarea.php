<?php

require_once __DIR__ . '/Estado.php';
require_once __DIR__ . '/Usuario.php';

class Tarea 
{
    private int $id;
    private string $titulo;
    private string $descripcion;
    private Estado $estado;
    private Usuario $usuario;

    public function __construct(string $titulo, string $descripcion, Usuario $usuario, Estado $estado = Estado::PENDIENTE) 
    {
        $this->id = 0;
        $this->titulo = $titulo;
        $this->descripcion = $descripcion;
        $this->estado = $estado;
        $this->usuario = $usuario;
    }

    public function getId(): int 
    {
        return $this->id;
    }

    public function getTitulo(): string 
    {
        return $this->titulo;
    }

    public function getDescripcion(): string 
    {
        return $this->descripcion;
    }

    public function getEstado(): Estado 
    {
        return $this->estado;
    }

    public function getUsuario(): Usuario 
    {
        return $this->usuario;
    }

    public function setId(int $id): void 
    {
        $this->id = $id;
    }

    public function setTitulo(string $titulo): void 
    {
        $this->titulo = $titulo;
    }

    public function setDescripcion(string $descripcion): void 
    {
        $this->descripcion = $descripcion;
    }

    public function setEstado(Estado $estado): void 
    {
        $this->estado = $estado;
    }

    public function setUsuario(Usuario $usuario): void 
    {
        $this->usuario = $usuario;
    }

    public static function validate(array $data): array 
    {
        $errors = [];

        if (empty($data['titulo'])) 
        {
            $errors['titulo'] = 'El título no puede estar vacío.';
        } 
        elseif (strlen($data['titulo']) < 3) 
        {
            $errors['titulo'] = 'El título debe tener al menos 3 caracteres.';
        }

        if (empty($data['descripcion'])) 
        {
            $errors['descripcion'] = 'La descripción no puede estar vacía.';
        } 
        elseif (strlen($data['descripcion']) < 3) 
        {
            $errors['descripcion'] = 'La descripción debe tener al menos 3 caracteres.';
        }

        $valores = array_map(fn($estado) => $estado->value, Estado::cases());
        if (!isset($data['estado']) || !in_array($data['estado'], $valores))
        {
            $errors['rol'] = 'El estado no es válido.';
        }

        if (empty($data['usuario'])) 
        {
            $errors['usuario'] = 'El usuario no puede estar vacío.';
        }

        return $errors;
    }
}
?>
