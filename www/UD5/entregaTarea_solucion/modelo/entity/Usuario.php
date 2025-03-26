<?php

require_once __DIR__ . '/Rol.php';

class Usuario 
{
    private int $id;
    private String $username;
    private String $nombre;
    private String $apellidos;
    private String $contrasena;
    private Rol $rol;

    public function __construct(String $username = '', String $nombre = '', String $apellidos = '', String $contrasena = '', Rol $rol = Rol::USER) 
    {
        $this->id = 0;
        $this->username = $username;
        $this->nombre = $nombre;
        $this->apellidos = $apellidos;
        $this->contrasena = $contrasena;
        $this->rol = $rol;
    }

    public function getId(): int 
    {
        return $this->id;
    }

    public function setId(int $id): void 
    {
        $this->id = $id;
    }

    public function getUsername(): String 
    {
        return $this->username;
    }

    public function setUsername(String $username): void 
    {
        $this->username = $username;
    }

    public function getNombre(): String 
    {
        return $this->nombre;
    }

    public function setNombre(String $nombre): void 
    {
        $this->nombre = $nombre;
    }

    public function getApellidos(): String 
    {
        return $this->apellidos;
    }

    public function setApellidos(String $apellidos): void 
    {
        $this->apellidos = $apellidos;
    }

    public function getContrasena(): String 
    {
        return $this->contrasena;
    }

    public function setContrasena(String $contrasena): void 
    {
        $this->contrasena = $contrasena;
    }

    public function getRol(): Rol 
    {
        return $this->rol;
    }

    public function setRol(Rol $rol): void 
    {
        $this->rol = $rol;
    }

    public static function validate(array $data): array 
    {
        $errors = [];

        if (empty($data['username'])) 
        {
            $errors['username'] = 'El nombre de usuario no puede estar vacío';
        } 
        elseif (strlen($data['username']) < 4) 
        {
            $errors['username'] = 'El nombre de usuario debe tener al menos 3 caracteres';
        }

        if (empty($data['nombre'])) 
        {
            $errors['nombre'] = 'El nombre no puede estar vacío';
        } 
        elseif (strlen($data['nombre']) < 4) 
        {
            $errors['nombre'] = 'El nombre debe tener al menos 2 caracteres';
        }

        if (empty($data['apellidos'])) 
        {
            $errors['apellidos'] = 'Los apellidos no pueden estar vacíos';
        } 
        elseif (strlen($data['apellidos']) < 4) 
        {
            $errors['apellidos'] = 'Los apellidos deben tener al menos 2 caracteres';
        }

        if (empty($data['contrasena'])) 
        {
            $errors['contrasena'] = 'La contraseña no puede estar vacía';
        } 
        elseif (strlen($data['contrasena']) < 6) 
        {
            $errors['contrasena'] = 'La contraseña debe tener al menos 6 caracteres';
        }

        $valores = array_map(fn($rol) => $rol->value, Rol::cases());
        if (!isset($data['rol']) || !in_array($data['rol'], $valores))
        {
            $errors['rol'] = 'El rol no es válido';
        }

        return $errors;
    }
    
    public static function validateWithoutPassword(array $data): array 
    {
        $errors = self::validate($data);
        unset($errors['contrasena']);
        return $errors;
    }
}
?>