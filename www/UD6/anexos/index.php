<?php

// Recuerda descargar el framework Flight

require_once 'flight/Flight.php';

$host = $_ENV['DATABASE_HOST'];
$name = $_ENV['DATABASE_TEST'];
$user = $_ENV['DATABASE_USER'];
$pass = $_ENV['DATABASE_PASSWORD'];

Flight::register('db', 'PDO', array("mysql:host=$host;dbname=$name", $user, $pass));

Flight::route('GET /clientes(/@id)', function($id = null) {
    if ($id)
    {
        $sentencia = Flight::db()->prepare("SELECT * FROM clientes WHERE id = :id");
        $sentencia->bindParam(':id', $id);
        $sentencia->execute();
        $datos = $sentencia->fetch();
    }
    else
    {
        $sentencia = Flight::db()->prepare("SELECT * FROM clientes");
        $sentencia->execute();
        $datos = $sentencia->fetchAll();
    }
    Flight::json($datos);
});

Flight::route('POST /clientes', function(){
    $nombre = Flight::request()->data->nombre;
    $apellidos = Flight::request()->data->apellidos;
    $email = Flight::request()->data->email;
    $edad = Flight::request()->data->edad;
    $telefono = Flight::request()->data->telefono;

    $sql = 'INSERT INTO clientes(nombre, apellidos, email, edad, telefono) VALUES (?, ?, ?, ?, ?)';

    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $apellidos);
    $sentencia->bindParam(3, $email);
    $sentencia->bindParam(4, $edad);
    $sentencia->bindParam(5, $telefono);

    $sentencia->execute();

    Flight::jsonp(['Cliente guardado correctamente.']);

});

Flight::route('DELETE /clientes', function(){
    $id = Flight::request()->data->id;

    $sql = 'DELETE FROM clientes WHERE id=:id';

    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(':id', $id);

    $sentencia->execute();

    Flight::jsonp(["Cliente $id borrado correctamente"]);

});

Flight::route('PUT /clientes', function(){
    $id = Flight::request()->data->id;
    $nombre = Flight::request()->data->nombre;
    $apellidos = Flight::request()->data->apellidos;
    $email = Flight::request()->data->email;
    $edad = Flight::request()->data->edad;
    $telefono = Flight::request()->data->telefono;

    $sql = "UPDATE clientes SET nombre=?, apellidos=?, email=?, edad=?, telefono=? WHERE id=?";
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $apellidos);
    $sentencia->bindParam(3, $email);
    $sentencia->bindParam(4, $edad);
    $sentencia->bindParam(5, $telefono);
    $sentencia->bindParam(6, $id);

    $sentencia->execute();

    Flight::jsonp(["Cliente $id actualizado correctamente"]);

});

Flight::route('GET /hoteles(/@id)', function($id = null) {
    if ($id) {
        $sentencia = Flight::db()->prepare("SELECT * FROM hoteles WHERE id = :id");
        $sentencia->bindParam(':id', $id);
        $sentencia->execute();
        $datos = $sentencia->fetch();
    } else {
        $sentencia = Flight::db()->prepare("SELECT * FROM hoteles");
        $sentencia->execute();
        $datos = $sentencia->fetchAll();
    }
    Flight::json($datos);
});

Flight::route('POST /hoteles', function() {
    $hotel = Flight::request()->data->hotel;
    $direccion = Flight::request()->data->direccion;
    $telefono = Flight::request()->data->telefono;
    $email = Flight::request()->data->email;

    $sql = 'INSERT INTO hoteles(hotel, direccion, telefono, email) VALUES (?, ?, ?, ?)';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $hotel);
    $sentencia->bindParam(2, $direccion);
    $sentencia->bindParam(3, $telefono);
    $sentencia->bindParam(4, $email);

    $sentencia->execute();

    Flight::jsonp(['Hotel guardado correctamente.']);
});

Flight::route('DELETE /hoteles', function() {
    $id = Flight::request()->data->id;

    $sql = 'DELETE FROM hoteles WHERE id=:id';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(':id', $id);

    $sentencia->execute();

    Flight::jsonp(["Hotel $id borrado correctamente"]);
});

Flight::route('PUT /hoteles', function() {
    $id = Flight::request()->data->id;
    $direccion = Flight::request()->data->direccion;
    $telefono = Flight::request()->data->telefono;
    $email = Flight::request()->data->email;

    $sql = "UPDATE hoteles SET direccion=?, telefono=?, email=? WHERE id=?";
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $direccion);
    $sentencia->bindParam(2, $telefono);
    $sentencia->bindParam(3, $email);
    $sentencia->bindParam(4, $id);

    $sentencia->execute();

    Flight::jsonp(["Hotel $id actualizado correctamente"]);
});

Flight::route('GET /reservas(/@id)', function($id = null) {
    if ($id) {
        $sql = "SELECT r.*, c.nombre AS cliente, h.hotel AS hotel 
                FROM reservas r 
                JOIN clientes c ON r.id_cliente = c.id 
                JOIN hoteles h ON r.id_hotel = h.id 
                WHERE r.id = :id";
        $sentencia = Flight::db()->prepare($sql);
        $sentencia->bindParam(':id', $id);
        $sentencia->execute();
        $datos = $sentencia->fetch();
    } else {
        $sql = "SELECT r.*, c.nombre AS cliente, h.hotel AS hotel 
                FROM reservas r 
                JOIN clientes c ON r.id_cliente = c.id 
                JOIN hoteles h ON r.id_hotel = h.id";
        $sentencia = Flight::db()->prepare($sql);
        $sentencia->execute();
        $datos = $sentencia->fetchAll();
    }
    Flight::json($datos);
});

Flight::route('POST /reservas', function() {
    $id_cliente = Flight::request()->data->id_cliente;
    $id_hotel = Flight::request()->data->id_hotel;
    $fecha_reserva = Flight::request()->data->fecha_reserva;
    $fecha_entrada = Flight::request()->data->fecha_entrada;
    $fecha_salida = Flight::request()->data->fecha_salida;

    $checkHotel = Flight::db()->prepare('SELECT COUNT(*) FROM hoteles WHERE id = ?');
    $checkHotel->bindParam(1, $id_hotel);
    $checkHotel->execute();
    $hotelExists = $checkHotel->fetchColumn();

    if (!$hotelExists) {
        Flight::json(['error' => 'El hotel especificado no existe.'], 400);
        // Bad Request (400) -> de esta forma en lugar de devovler una respuesta en formato JSON correcta (200), devolvemos un error también formato JSON
        return;
    }

    $checkClient = Flight::db()->prepare('SELECT COUNT(*) FROM clientes WHERE id = ?');
    $checkClient->bindParam(1, $id_cliente);
    $checkClient->execute();
    $clientExists = $checkClient->fetchColumn();

    if (!$clientExists) {
        Flight::json(['error' => 'El cliente especificado no existe.'], 400);
        // Bad Request (400) -> de esta forma en lugar de devovler una respuesta en formato JSON correcta (200), devolvemos un error también formato JSON
        return;
    }

    $sql = 'INSERT INTO reservas(id_cliente, id_hotel, fecha_reserva, fecha_entrada, fecha_salida) VALUES (?, ?, ?, ?, ?)';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $id_cliente);
    $sentencia->bindParam(2, $id_hotel);
    $sentencia->bindParam(3, $fecha_reserva);
    $sentencia->bindParam(4, $fecha_entrada);
    $sentencia->bindParam(5, $fecha_salida);

    $sentencia->execute();

    Flight::jsonp(['Reserva guardada correctamente.']);
});

Flight::route('DELETE /reservas', function() {
    $id = Flight::request()->data->id;

    $sql = 'DELETE FROM reservas WHERE id=:id';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(':id', $id);

    $sentencia->execute();

    Flight::jsonp(["Reserva $id borrada correctamente"]);
});

Flight::route('PUT /reservas', function() {
    $id = Flight::request()->data->id;
    $fecha_entrada = Flight::request()->data->fecha_entrada;
    $fecha_salida = Flight::request()->data->fecha_salida;

    $sql = "UPDATE reservas SET fecha_entrada=?, fecha_salida=? WHERE id=?";
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $fecha_entrada);
    $sentencia->bindParam(2, $fecha_salida);
    $sentencia->bindParam(3, $id);

    $sentencia->execute();

    Flight::jsonp(["Reserva $id actualizada correctamente"]);
});

Flight::route('/', function () {
    echo 'API HOTELES';
});

Flight::start();
