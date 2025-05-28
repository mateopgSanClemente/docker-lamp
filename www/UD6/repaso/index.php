<?php

declare(strict_types=1);

require_once 'flight/Flight.php';
// require 'flight/autoload.php';

Flight::route('/', function () {
    echo 'hello world!';
});

// ------ Middlewares ------
require_once 'middlewares/middlewares.php';

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
        // 1. Aplicar el middleware para la validación de datos de registro
        validarUsuario();

        // 2. Recojo los datos validados para el registro de usuario. Están guardados en Flight
        $usuarioDatosRegistro = Flight::get('usuarioDatosRegistro');

        // 3. Sentencia SQL
        $sql = "INSERT INTO usuarios(nombre, email, password) VALUES (:nombre, :email, :password);";

        // 4. Preparar sentencia SQL
        $stmt = Flight::db()->prepare($sql);

        // 5. Enlazar parámetros a la sentencia (bind params)
        $stmt->bindParam(':nombre', $usuarioDatosRegistro['nombre']);
        $stmt->bindParam(':email', $usuarioDatosRegistro['email']);
        $stmt->bindParam(':password', $usuarioDatosRegistro['password']);

        // 6. Ejecutar las sentencia
        $stmt->execute();

        // 7. Mensajes de error o éxito en formarto JSON
        Flight::json([
            'success' => true,
            'message' => 'Usuario registrado correctamente.'
        ], 201); // Status code 201 "Created": La solitudad ha tenido exito y se ha creado un recurso. <https://developer.mozilla.org/es/docs/Web/HTTP/Reference/Status/201>
    } catch (PDOException $e) {
        // Error específico, el usuario no se puede registrar con un email que ya se encuentra en la base de datos. (clave única).
        if ($e->getCode() === 23000) {
            Flight::json([
                'success' => false,
                'error'   => 'El email ya está registrado'
            ], 409); // Status code 409 "Conflict": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/409>
        } else {
            // Otros errores
            Flight::json([
                'success' => false,
                'error'   => 'Error al registrar el usuario.'
            ], 500); // Status code 500 "Internal server error": Se dió una circunstancia inesperada que hace que el servidor sea incapaz de procesar la solicitud. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
        }
    }
});

/* ------ Login ------*/
/** Login (/login): recibe email y password, verifica las credenciales mediante middleware.
 *  Si son correctas, genera y devuelve un token simple. Si no, devuelve el error correspondiente.
 */

Flight::route ('POST /login', function () {
    try {
        // 1. Utilzar un middleware compruebe las credenciales enviadas desde la solicutd http
        validarLogin();

        // 2. Si las credenciales son correctas, recupero el token de autenticación creado por el middleware
        $usuario = Flight::get('usuarioToken');

        // 3. Autentico al usuario mediante token, guardando este en la base de datos

        // Sentencia SQL para guardar el token
        $sql = "UPDATE usuarios SET token=:token WHERE id=:id;";

        // Preparamos la consulta
        $stmt = Flight::db()->prepare($sql);

        // Vinculamos los parámetros. Evita inyección SQL
        $stmt->bindParam(':token', $usuario['token']);
        $stmt->bindParam(':id', $usuario['id']);

        // Ejecuto la sentencia
        $stmt->execute();

        // Mensaje de éxito
        Flight::json([
            'success' => true,
            'message' => 'Usuario logeado correctamente.'
        ], 200);

    } catch (PDOException $e) {
        Flight::json(['error' => $e->getMessage()], 500); // Status code 500 "Internal server error": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
    }
});

/**
 * Listar contactos (/contactos): devuelve todos los contactos del usuario autenticado. 
 * Además, opcionalmente, tendrá que devolver solo un contacto obtenido a partir de su ID,
 * teniendo en cuenta que debe pertenecer al usuario autenticado.
 */
Flight::route('GET /contactos(/@id_contacto)', function ($id_contacto = null) {
    try {
        // Recoger de la cabecera de la petición HTTP el token 'X-Token'
        $token = Flight::request()->getHeader('X-Token');
        
        // Devolver un error en caso de que no se envíe el token en la cabecera
        if (!$token) {
            Flight::json(['error' => 'Falta el token de autenticación en la cabecera de la HTTP request.', 401]);
            return;
        }

        // Comprobar que el token de autenticación existe en la base de datos
        $sql = "SELECT id FROM usuarios WHERE token = :token";

        // Preparar la consulta
        $stmt = Flight::db()->prepare($sql);

        // Vincular parámetros
        $stmt->bindParam(':token', $token);

        // Ejecutar la consulta
        $stmt->execute();

        // Recoger el resultado
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

        // En caso de que no exista el token, devolver un mensaje de error
        if(!$usuario){
            Flight::json(['error' => 'El token no es válido.'], 401); // Status code 401 "Unauthorized"
            return;
        }

        // Obtener contacto por su id
        if ($id_contacto){

            // Sentencia SQL para obtener un contacto por su id
            $sql = "SELECT * FROM contactos WHERE usuario_id = :usuario_id AND id = :id";

            // Prepararo la sentecia
            $stmt = Flight::db()->prepare($sql);

            // Vinculo parámetros
            $stmt->bindParam(':usuario_id', $usuario['id']);
            $stmt->bindParam(':id', $id_contacto);

            // Ejecuto la sentencia
            $stmt->execute();

            // Resultados
            $contactos = $stmt->fetch(PDO::FETCH_ASSOC);

            // Respuesta JSON. No se encontró contacto
            if (!$contactos) {
                Flight::json(['error' => 'No se encontró el contacto'], 404); // Status Code 404 "Not Found"
            } else {
                // Respuesta JSON. Se encontró el contacto
                Flight::json([
                    'success' => 'Contacto encontrado',
                    'contactos' => $contactos
                ], 200); // Status Code 200 "Ok".
            }
        } else {
            // Sentencia SQL para obtener TODOS los contactos del usuario autenticado
            $sql = "SELECT * FROM contactos WHERE usuario_id = :usuario_id";

            // Preparo la sentencia
            $stmt = Flight::db()->prepare($sql);

            // Vincular parámetros
            $stmt->bindParam(':usuario_id', $usuario['id']);

            // Ejecuto consulta
            $stmt->execute();

            // Recojo el resultado
            $contactos = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Respuesta JSON. No se encuentró contacto
            if(!$contactos) {
                Flight::json(['error' => 'No se encontró el contacto'], 404); // Status Code 404 "Not Found"
            } else {
                // Respuesta JSON. Se encontró el contacto
                Flight::json([
                    'success' => 'Contacto encontrado',
                    'contactos' => $contactos
                ], 200); // Status Code 200 "Ok".
            }
        }

    } catch (PDOException $e) {
        return Flight::json(['error' => $e->getMessage()], 500); // Status code 500 "Internal server error".
    }
});

/**
 * Añadir contacto (/contactos): recibe nombre, telefono, email, y lo guarda, devolviendo la confirmación.
 */
Flight::route ('POST /contactos', function(){
    try {
        // Comprobar que el usuario se encuentra autenticado a través del token enviado en la cabecera de la soliciutd HTTP. X-Token
        $token = Flight::request()->getHeader('X-Token');
        if(!$token){
            Flight::json(['error' => 'Falta el token de autenticación de la cabecera de la solicitud HTTP.'], 401); // Status Code 401 "Unauthorized".
            return;
        }

        // Recoger los valores necesarios para el registro del body de la solicitud HTTP.
        $nombre = Flight::request()->data->nombre;
        $telelfono = Flight::request()->data->telefono;
        $email = Flight::request()->data->email;

        // Validar datos de la solicitud
        if (empty($nombre) || empty($telelfono) || empty($email)) {
            Flight::json(['error' => 'Faltan datos de la solicitud'], 400); // Status code 400 "Bad Request".
            return;
        }

        // Comprueba que el usuario está autenticado, para ello utilizo el token para comprobar que existe en la base de datos.
        $sql = "SELECT id FROM usuarios WHERE token = :token";

        // Preparo la consulta
        $stmt = Flight::db()->prepare($sql);

        // Vinculo parámetros
        $stmt->bindParam(':token', $token);

        // Ejecuto consulta
        $stmt->execute();

        // Defino como quiero que se me devuelvan los datos
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

        // Si no tengo resultados el usuario no está autenticado
        if(!$usuario) {
            Flight::json(['error' => 'El token no es válido.'], 401); // Status Code 401 "Unauthorized".
            return;
        }

        // Si la autenticación es correcta, procedemos a registrar el contacto en la bd
        $sql = "INSERT INTO contactos (nombre, telefono, email, usuario_id) VALUES (:nombre, :telefono, :email, :usuario_id)";

        // Preparo la consulta SQL
        $stmt = Flight::db()->prepare($sql);
        
        // Vinculo parámetros
        $stmt->bindParam(':nombre', $nombre);
        $stmt->bindParam(':telefono', $telelfono);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':usuario_id', $usuario['id']);

        // Ejecuto consulta
        $stmt->execute();

        // Devolver mensaje de confirmación
        Flight::json(['success' => 'El contacto se guardo correctamente.'], 201); // Status code 201 "Created": indicates that the HTTP request has led to the creation of a resource.
    } catch (PDOException $e) {
        Flight::json(['error' => $e->getMessage()], 500); // Status code 500 "Internal Server Error".
    }
});

Flight::start();
