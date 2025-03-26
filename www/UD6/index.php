<?php

require 'flight/Flight.php';
Flight::register('db', 'PDO', array('mysql:host=db;dbname=myDBPDO','root','test'));

Flight::route('GET /clientes', function () {
    $setencia = Flight::db()->prepare("SELECT * from clientes");
     $setencia->execute();
     $datos=$setencia->fetchAll();
     Flight::json($datos);
});


Flight::route('POST /clientes', function () {

    $nombre = Flight::request()->data->nombre;
    $apellido = Flight::request()->data->apellido;
    $email = Flight::request()->data->email;
    $sql ="INSERT INTO clientes(nombre, apellido, email) VALUES (?, ?, ?)";
    //Preparamos la sentencia sql
    $sentencia = Flight::db()->prepare($sql);
    //Preparamos los datos obtenidos de la sentencia 
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $apellido);
    $sentencia->bindParam(3, $email);
    //Ejecutamos la sentencia INSERT
    $sentencia->execute();
   
    //Devolvememos en formato JSON una sentencia que nos indique que todo fue correctamente. 
    Flight::jsonp(["Cliente agregado correctamente."]);
   
   });



    Flight::route('DELETE /clientes', function () {

        $id = Flight::request()->data->id;
       
        $sql ="DELETE FROM clientes WHERE id=?";
        //Preparamos la sentencia sql
        $sentencia = Flight::db()->prepare($sql);
        //Pasamos el id 
        $sentencia->bindParam(1, $id);
        //Ejecutamos la sentencia INSERT
        $sentencia->execute();
       
        //Devolvememos en formato JSON parado una sentencia que nos indique que todo fue correctamente. 
        Flight::jsonp(["Cliente eliminado con id: $id"]);
       
       });

    Flight::route('PUT /clientes', function () {

        $id = Flight::request()->data->id;
        $apellido = Flight::request()->data->apellido;
        $email = Flight::request()->data->email;
       
       
        $sql ="UPDATE clientes set apellido=?, email=? WHERE id=?";
        //Preparamos la sentencia sql
        $sentencia = Flight::db()->prepare($sql);
        //Preparamos los datos obtenidos de la sentencia 
        $sentencia->bindParam(1, $apellido);
        $sentencia->bindParam(2, $email);
        $sentencia->bindParam(3, $id);
        //Ejecutamos la sentencia INSERT
        $sentencia->execute();
       
        //Devolvememos en formato JSON parado una sentencia que nos indique que todo fue correctamente. 
        Flight::jsonp(["Cliente actualizado correctamente."]);
       
       });
       
Flight::start();


