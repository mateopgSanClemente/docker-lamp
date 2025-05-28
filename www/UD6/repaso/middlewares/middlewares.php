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