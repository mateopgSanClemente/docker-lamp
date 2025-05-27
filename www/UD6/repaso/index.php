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
        // Recoger datos del body la solicitud HTTP
        $nombre = Flight::request()->data->nombre;
        $email = Flight::request()->data->email;
        $password = Flight::request()->data->password;

        //Validación básica
        if(empty($nombre) || empty($email) || empty($password)){
            Flight::json(['error' => 'Faltan campos obligatorios.'], 400); // Status code 400 "Bad Request": El servidor no puede procesar la solicitud debido a un error del cliente <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/400> 
            return;
        }

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

        // Ejecutar las sentencia
        $stmt->execute();

        // Mensajes de error o éxito en formarto JSON
        Flight::json(['success' => 'Usuario registrado correctamente.'], 201); // Status code 201 "Created": La solitudad ha tenido exito y se ha creado un recurso. <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/201>
    } catch (PDOException $e) {
        // Error específico, el usuario no se puede registrar con un email que ya se encuentra en la base de datos. (clave única).
        if ($e->getCode() === 23000) {
            Flight::json(['error' => 'El email ya está registrado'], 409); // Status code 409 "Conflict": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/409>
        } else {
            // Otros errores
            Flight::json(['error' => 'Error al registrar el usuario.'], 500); // Status code 500 "Internal server error": Se dió una circunstancia inesperada que hace que el servidor sea incapaz de procesar la solicitud. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
        }
    }
});

/* ------ Login ------*/
/** Login (/login): recibe email y password, verifica las credenciales.
 *  Si son correctas, genera y devuelve un token simple. Si no, devuelve el error correspondiente.
 */

 Flight::route ('POST /login', function () {
    try {
        // Recoger variables del body de la solicitud HTTP. Recoger email y password
        $email = Flight::request()->data->email; // También podría usar el operador ?? 'Null coalescing' para la validar. Qué metodo es mejor?
        $password = Flight::request()->data->password;

        //Validación básica
        if(empty($email) || empty($password)){
            Flight::json(['error' => 'Faltan campos obligatorios.'], 400); // Status code 400 "Bad Request": El servidor no puede procesar la solicitud debido a un error del cliente <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/400> 
            return;
        }

        // Verifico con la base de datos que las credenciales son las correctas
        // COnsulta SQL
        $sql = "SELECT id, nombre, email, password FROM usuarios WHERE email = :email LIMIT 1;";

        // Preparamos la consulta
        $stmt = Flight::db()->prepare($sql);

        // Vinculamos parámetros (evita inyección SQL)
        $stmt->bindParam(':email', $email);

        // Ejecutamos la consulta
        $stmt->execute();

        // Recoger resultado de la consulta
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Mensaje de error en caso de que el email proporcionado por la solicitud no se corresponda con el almacenado en la base de datos.
        if (!$usuario) {
            Flight::json(['error' => "El email no está registrado en la base de datos."], 404); // Status code 404 "Not Found": El servidor no pudo encontrar el email en la base de datos. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/404>
            return;
        }

        // Comprobar que la contraseña coincide con la base de datos
        if (!password_verify($password, $usuario['password'])){
            Flight::json(['error' => 'La contraseña no es correcta.'], 401); // Status code 401 "Unauthorized": Las credenciales no son válidas para el recurso solicitado. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/401>
            return;
        }

        // En caso de que la credenciales para el login sean las correctas, se crea un token de autenticación y se guarda en la tabla 'usuarios'
        $token = bin2hex(random_bytes(32));

        // Sentencia SQL para guardar el token
        $sql = "UPDATE usuarios SET token=:token WHERE id=:id;";

        // Preparamos la consulta
        $stmt = Flight::db()->prepare($sql);

        // Vinculamos los parámetros. Evita inyección SQL
        $stmt->bindParam(':token', $token);
        $stmt->bindParam(':id', $usuario['id']);

        // Ejecuto la sentencia
        $stmt->execute();

        // Sería necesario eliminar el hash?
        unset($usuario['password']);
        $usuario['toke'] = $token; // Agrego la clave 'token' junto con su valor al array con los datos de usuario.
        // Lo guardo en el array privado propio de Flight para poder usarlo más tarde. (¿No se borra al terminar el script?).
        Flight::set('usuario', $usuario);

        // Mensaje de éxito
        Flight::json([
            'success' => 'Login correcto.',
            'token' => $token,
            'usuario' => [
                'id' => $usuario['id'],
                'email' => $usuario['email'],
                'nombre' => $usuario['nombre'] ?? null
            ]
        ], 200);

    } catch (PDOException $e) {
        Flight::json(['error' => $e->getMessage()], 500); // Status code 500 "Internal server error": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
    }
 });

Flight::start();
