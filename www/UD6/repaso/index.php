<?php

declare(strict_types=1);

require_once 'flight/Flight.php';
// require 'flight/autoload.php';

Flight::route('/', function () {
    echo 'hello world!';
});

// ------ Registrar instancia PDO ------
/*
 * Registramos el servicio 'db' en Flight:
 * - Crea una instancia única de PDO para MySQL usando:
 *      'mysql:host=db;dbname=agenda': DSN (tipo de base de datos MySQL, host 'db', base 'agenda')
 *        host:     db  (nombre del servicio Docker)
 *        dbname:   agenda
 *        usuario:  root
 *        clave:    test
 * - Permite obtener la conexión luego con Flight::db()
 */
Flight::register('db', 'PDO', array('mysql:host=db;dbname=agenda', 'root', 'test'));

// ------ Rutas ------

/**
 *  Rutas para el registro de usuario en la tabla 'usuarios'.
 */
Flight::route('POST /register', function() {
    try {
        // Recoger datos de la solicitud HTTP
        $nombre = Flight::request()->data->nombre;
        $email = Flight::request()->data->email;
        $password = Flight::request()->data->password;

        // La contraseña debe encriptarse anter de ser guardada en la base de datos. Utiliza el algoritmo bcrypt para generar el hash.
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        // Sentencia SQL
        $sql = "INSERT INTO usuarios(nombre, email, password) VALUES (:nombre, :email, :password);";

        // Preparar sentencia SQL
        $stmt = Flight::db()->prepare($sql);

        // Enlazar parámetros a la sentenia (bind params)
        $stmt->bindParam(':nombre', $nombre);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $passwordHash);

        //Validación básica
        if(empty($nombre) || empty($email) || empty($password)){
            Flight::json(['error' => 'Faltan campos obligatorios.'], 400); // Status code 400 "Bad Request": El servidor no puede procesar la solicitud debido a un error del cliente <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/400> 
            return;
        }

        // Ejecutar las sentencia
        $stmt->execute();

        // Mensajes de error o éxito en formarto JSON
        Flight::json(['success' => 'Usuario registrado correctamente.'], 201); // Status code 201 "Created": La solitudad ha tenido he sito y se ha creado un recurso. <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/201>
    } catch (PDOException $e) {
        // Error específico si el mail ya existe (clave única).
        if ($e->getCode() === 23000) {
            Flight::json(['error' => 'El email ya está registrado'], 409); // Status code 409 "Conflict": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/409>
        } else {
            // Otros errores
            Flight::json(['error' => 'Error al registrar el usuario.'], 500); // Status code 500 "Internal server error": Se dió una circunstancia inesperada que hace que el servidor sea incapaz de procesar la solicitud. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
        }
    }
});

Flight::start();
