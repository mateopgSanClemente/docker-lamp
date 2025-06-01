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
Flight::route('GET /contactos(/@contacto_id)', function ($contacto_id = null) {
    try {
        // 1. Middleware: Validar token y obtener usuario autenticado
        validarToken();
        $usuario_id = Flight::get('usuario')['id'];

        // 2. Construir una consulta SQL dinámica según si se quiere un contacto o todos
        if ($contacto_id !== null){
            $sql = "SELECT * FROM contactos WHERE id = :id LIMIT 1";
            $stmt = Flight::db()->prepare($sql);
            $stmt->bindParam(':id', $contacto_id, PDO::PARAM_INT);

        } else {
            $sql = "SELECT * FROM contactos WHERE usuario_id = :usuario_id";
            $stmt = Flight::db()->prepare($sql);
            $stmt->bindParam(':usuario_id', $usuario_id, PDO::PARAM_INT);
        }

        // 3. Ejecutar consulta
        $stmt->execute();
        $contactos = $contacto_id !== null
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
        // 1. Validar token y obtener id de usuario
        validarToken();
        $usuario_id = Flight::get('usuario')['id'];

        // 2. Recoger, validar y sanear data para el registro de contacto de la petición HTTP.
        validarContacto();
        $contacto = Flight::get('contacto');

        // 3. Si la autenticación es correcta, registrar el contacto en la bd
        $sql = "INSERT INTO contactos (nombre, telefono, email, usuario_id) VALUES (:nombre, :telefono, :email, :usuario_id)";

        // Preparo la consulta SQL
        $stmt = Flight::db()->prepare($sql);
        
        // Vinculo parámetros
        $stmt->bindParam(':nombre', $contacto['nombre']);
        $stmt->bindParam(':telefono', $contacto['telefono']);
        $stmt->bindParam(':email', $contacto['email']);
        $stmt->bindParam(':usuario_id', $usuario_id);

        // Ejecuto consulta
        $stmt->execute();

        // Devolver mensaje de confirmación
        Flight::json([
            'success' => true,
            'message' => 'El contacto se guardo correctamente.'
        ], 201); // Status code 201 "Created": indicates that the HTTP request has led to the creation of a resource.
    } catch (PDOException $e) {
        Flight::json(['error' => $e->getMessage()], 500); // Status code 500 "Internal Server Error".
    }
});

/**
 * Editar contacto (/contactos): permite modificar un contacto, asegurando que sea del usuario autenticado.
 */
Flight::route('PUT /contactos/@contacto_id', function($contacto_id){
    try {
        // 1. Validar usuario autenticado y recoger sus datos
        validarToken();
        $usuario = Flight::get('usuario');

        // 2. Validar datos para la modicación del contacto
        validarContactoModificar();
        $nuevosDatos = Flight::get('contacto');

        // 3. Recoger los datos originales del contacto
        $sql = "SELECT * FROM contactos WHERE id = :id";
        $stmt = Flight::db()->prepare($sql);
        $stmt->execute([
            ':id' => $contacto_id
        ]);
        $contactoOriginal = $stmt->fetch(PDO::FETCH_ASSOC);

        // 4. Mensaje de error en caso de que el contacto no exista. Status Code 404 Not Found
        if (empty($contactoOriginal)) {
            Flight::jsonHalt([
                'success' => false,
                'error' => 'Contacto no encontrado.'
            ], 404);
        }

        // 5. Mensaje de error en caso de que el contacto a modificar no pertenezca al usuario autenticado. Statud Code 403 Forbiden
        if ($usuario['id'] != $contactoOriginal['usuario_id']) {
            Flight::halt(403, json_encode([
                'success' => false,
                'error' => 'El usuario no tiene permiso para modificar este contacto.'
            ]));
        }

        /**
         *  6. Preparar actualización selectiva
         *  - NOTA: Debería convertir este bloque de código en un middleware??
         */ 
        // Campos que es posible actualizar
        $camposPermitidos = [
            'nombre',
            'telefono',
            'email'
        ];

        // Campos que se van a actualizar
        $camposUpdateSQL = [];

        // Valores para los campos que se van a actualizar. Este array se pasará como argumento de la función execute().
        $valores = [':id' => $contacto_id];

        foreach ($camposPermitidos as $campo) {
            if (!empty($nuevosDatos[$campo])) {
                $valor = $nuevosDatos[$campo];
                $placeholder = ":$campo";
                $camposUpdateSQL[] = "$campo = $placeholder";
                $valores[$placeholder] = $valor;
            }
        }

        // Comprobar que hay cambios, si no los hay, enviar un mensaje
        if (empty($camposUpdateSQL)){
            Flight::json([
                'success' => true,
                'message' => 'No hubo cambios en la tabla "clientes"'
            ]);
        }

        $sql = "UPDATE contactos SET " . implode(",", $camposUpdateSQL) . " WHERE id=:id";
        $stmt = Flight::db()->prepare($sql);
        $stmt->execute($valores);

        Flight::json([
            'success' => true
        ], 200);
    } catch (PDOException $e) {
        Flight::json([
            'success' => false,
            'error' => $e->getMessage()], 500); // Status code 500 "Internal Server Error".
    }
});

Flight::route('DELETE /contactos/@contacto_id', function($contacto_id){
    try{
        // 1. Validar token de usuario autenticado
        validarToken();
        $usuario = Flight::get('usuario');

        // 2. Comprobar que el contacto existe en la BD
        $sql = "SELECT * FROM contactos WHERE id=:id LIMIT 1";
        $stmt = Flight::db()->prepare($sql);
        $stmt->execute([":id" => $contacto_id]);
        $contacto = $stmt->fetch(PDO::FETCH_ASSOC);

        // 2.1. Si el contacto no existe. Status Code 404 Not Found.
        if(empty($contacto)){
            Flight::jsonHalt([
                'success' => false,
                'error' => "El contacto no existe en la base en la base de datos."
            ], 404);
        }

        // 2.2. Si el contacto existe pero no pertenece al usuario. Status Code 403 Forbiden.
        if($usuario['id'] != $contacto['usuario_id']){
            Flight::jsonHalt([
                'success' => false,
                'error' => 'El usuario no tiene permiso para borrar este contacto.'
            ], 403);
        }

        // 3. Si el contacto existe en la base de datos, eliminarlo
        $sql = "DELETE FROM contactos WHERE id=:id";
        $stmt = Flight::db()->prepare($sql);
        $stmt->execute([":id" => $contacto_id]);

        Flight::json([
            'success' => true,
            'message' => 'El contacto se eliminó correctamente.'
        ]);
    } catch (PDOException $e) {
        Flight::jsonHalt([
            'success' => false,
            'error' => $e->getMessage()
        ], 500);
    }
});

Flight::start();
