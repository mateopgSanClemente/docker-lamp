<?php

/**
 * Middleware para la validación de datos de usuario
 */
function validarUsuario () {
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
    ])
}