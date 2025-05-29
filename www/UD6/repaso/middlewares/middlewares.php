<?php

/**
 * Middleware para la validación de datos de usuario
 * @return void
 */
function validarUsuario(): void {
    // 1. Recoger datos del body la solicitud HTTP y sanear
    $nombre     = trim(Flight::request()->data->nombre  ?? '');
    $email      = trim(Flight::request()->data->email   ?? '');
    $password   = Flight::request()->data->password     ?? '';

    // 2. Campos obligatorios (validación)
    if(!$nombre || !$email || !$password){
        Flight::halt(400, json_encode([
            'success'   => false,
            'error'     => 'Faltan campos obligatorios: nombre, email y password'
        ]));
    }

    // 3. Validar email
    if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
        Flight::halt(400, json_encode([
            'success'   => false,
            'error'     => 'El formato del email no es válido'
        ]));
    }

    /** 4. La contraseña debe encriptarse antes de ser guardada en la base de datos.
     *  Utilizo el algoritmo bcrypt para generar el hash.
     *  - NOTA: La contaseña no necesita de unas caracterísitcas mínimas (ej: nº min de caracteres), lo hago para simplificar.
     */
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // 5. Guardo los datos de usuario en Flight para utilizarlos después en la ruta
    Flight::set ('usuarioDatosRegistro', [
        'nombre' => $nombre,
        'email' => $email,
        'password' => $passwordHash
    ]);
}

/**
 * Middleware para la validación del login de usuario
 */
function validarLogin(): void {
    // 1. Recoger datos para el registro de contacto de la petición HTTP y saneamiento muy básico mediante trim
    $email = trim(Flight::request()->data->email ?? '');
    $password = Flight::request()->data->password ?? '';

    // 2. Verifica que se introdujeron email y contraseña
    if(!$email || !$password) {
        Flight::halt(400, json_encode([ // Flight::halt(): Detiene inmediatamente la ejecución de Flight, envía la respuesta HTTP con el código y el cuerpo que indiques, y no procesa nada más
            'success' => false,
            'error'   => 'Faltan campos obligatorios: email y password'
        ]));
    }

    // 3. Valida email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)){
        Flight::halt(400, json_encode([
            'success' => false,
            'error'   => 'El formato del email no es válido'
        ]));
    }

    // 4. Verifico en la base de datos que las credenciales son las correctas.
    $sql = "SELECT id, password FROM usuarios WHERE email = :email";

    $stmt = Flight::db()->prepare($sql);
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

    // 4.1. El email no existe en la base de datos
    if (!$usuario) {
        Flight::halt(404, json_encode ([
            'success' => false,
            'error'   => 'El email no existe en la base de datos.'
        ]));
    }

    // 4.2. La contraseña no es correcta
    if (!password_verify($password, $usuario['password'])) {
        Flight::halt(401, json_encode([
            'success' => false,
            'error'   => 'La contraseña no es correcta.' 
        ]));
    }

    // Sería necesario eliminar el hash?
    unset($usuario['password']);

    // 5. Si todo es correcto, creo un token y lo guardo en Flight
    $token = bin2hex(random_bytes(32));
    Flight::set('usuario', [
        'token' => $token,
        'id'    => $usuario['id']
    ]);
}

function validarToken(): void {
    // 1. Recoger de la cabecera de la petición HTTP el token 'X-Token'
    $token = trim(Flight::request()->getHeader('X-Token'));
    
    // 2. Devolver un error en caso de que no se envíe el token en la cabecera
    if (!$token) {
        Flight::halt(401, json_encode([
            'success' => false,
            'error' => 'Falta el token de autenticación en la cabecera de la HTTP request.'
        ]));
    }

    // 3. Comprobar que el token de autenticación existe en la base de datos
    $sql = "SELECT id FROM usuarios WHERE token = :token LIMIT 1";

    // Preparar la consulta
    $stmt = Flight::db()->prepare($sql);

    // Vincular parámetros
    $stmt->bindParam(':token', $token, PDO::PARAM_STR);

    // Ejecutar la consulta
    $stmt->execute();

    // 4. Recoger el resultado
    $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

    // 5. En caso de que no exista el token, devolver un mensaje de error
    if(!$usuario){
        Flight::halt(401, json_encode([
            'success' => false,
            'error'   => 'El token no es válido.'
        ])); // Status code 401 "Unauthorized"
    }

    // 6.En caso de que el usuario esté logeado, guardar el usuario en Flight
    Flight::set('usuario', $usuario);
}

function validarContacto() {
    // 1. Recoger los valores necesarios para el registro del body de la solicitud HTTP.
    $data = Flight::request()->data;

    $nombre = trim($data->nombre);
    $telefono = trim($data->telefono);
    $email = trim($data->email);

    // 2. Validar datos de la solicitud.
    // Sería buena idea hacerlo mediante expresiones regulares, pero por simplificar lo haré de esta forma.
    if (!$nombre || !$telefono || !$email) {
        Flight::halt(400, json_encode([
            'success' => false,
            'error' => 'Faltan datos obligatorios: nombre, telefono, email.'
        ])); // Status code 400 "Bad Request".
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)){
        Flight::halt(400, json_encode([
            'success' => false,
            'error' => 'El formato de email no es valido.'
        ]));
    }

    // 3. Si los datos son correctos, los guardo en Flight
    Flight::set('contacto', [
        'nombre' => $nombre,
        'telefono' => $telefono,
        'email' => $email
    ]);
}
