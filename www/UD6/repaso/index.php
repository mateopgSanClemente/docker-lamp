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
        $usuario = Flight::get('usuario');

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

        // 4. HTTP Response
        Flight::json([
            'success' => true,
            'message' => 'Usuario logeado correctamente.'
        ], 200);

    } catch (PDOException $e) {
        Flight::json([
            'success' => false,
            'error' => $e->getMessage()
        ], 500); // Status code 500 "Internal server error": <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/500>
    }
});

/**
 * Listar contactos (/contactos): devuelve todos los contactos del usuario autenticado. 
 * Además, opcionalmente, tendrá que devolver solo un contacto obtenido a partir de su ID,
 * teniendo en cuenta que debe pertenecer al usuario autenticado.
 */
Flight::route('GET /contactos(/@id_contacto)', function ($id_contacto = null) {
    try {
        // 1. Middleware: Validar token y obtener usuario autenticado
        validarToken();
        $usuario_id = Flight::get('usuario')['id'];

        // 2. Construir una consulta SQL dinámica según si se quiere un contacto o todos
        if ($id_contacto !== null){
            $sql = "SELECT * FROM contactos WHERE id = :id LIMIT 1";
            $stmt = Flight::db()->prepare($sql);
            $stmt->bindParam(':id', $id_contacto, PDO::PARAM_INT);

        } else {
            $sql = "SELECT * FROM contactos WHERE usuario_id = :usuario_id";
            $stmt = Flight::db()->prepare($sql);
            $stmt->bindParam(':usuario_id', $usuario_id, PDO::PARAM_INT);
        }

        // 3. Ejecutar consulta
        $stmt->execute();
        $contactos = $id_contacto !== null
            ? $stmt->fetch(PDO::FETCH_ASSOC)
            : $stmt->fetchAll(PDO::FETCH_ASSOC);

        // 4. Generar respuesta HTTP. Formato JSON
        // Generar una respuesta HTTP en caso de que el contacto al que se quiere acceder no pertenezca al usuario autenticado.
        if (isset($contactos['usuario_id']) && $contactos['usuario_id'] != $usuario_id){
            Flight::halt(403, json_encode([
                'success' => false,
                'error' => 'El contacto no pertenece al usuario.'
            ]));
        }

        if(!$contactos) {
            Flight::halt(404, json_encode([ // Status Code 404 "Not Found"
                'success' => false,
                'error' => 'No se encontró el contacto'
            ]));
        }  

        // 5. Generar respuesta HTTP
        Flight::json([
            'success' => true,
            'data' => $contactos
        ], 200); // Status Code 200 "Ok".
    } catch (PDOException $e) {
        return Flight::json([
            'success' => false,
            'error' => $e->getMessage()
        ], 500); // Status code 500 "Internal server error".
    }
});

/**
 * Añadir contacto (/contactos): recibe nombre, telefono, email, y lo guarda, devolviendo la confirmación.
 */
Flight::route ('POST /contactos', function(){
    try {
        // Comprobar que el usuario se encuentra autenticado a través del token (X-Token) enviado en la cabecera de la soliciutd HTTP. 
        $token = Flight::request()->getHeader('X-Token');
        if(!$token){
            Flight::json(['error' => 'Falta el token de autenticación de la cabecera de la solicitud HTTP.'], 401); // Status Code 401 "Unauthorized".
            return;
        }

        // Recoger los valores necesarios para el registro del body de la solicitud HTTP.
        $nombre = Flight::request()->data->nombre;
        $telelfono = Flight::request()->data->telefono;
        $email = Flight::request()->data->email;

        // Validar datos de la solicitud. Sería buena idea hacerlo mediante expresiones regulares
        if (!$nombre || !$telelfono || !$email) {
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
