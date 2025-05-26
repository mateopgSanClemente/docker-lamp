# REPASO UD6: SERVICIOS WEB

## TAREA

### CONFIGURACIÓN DEL ENTORNO

Para el desarrollo de esta tarea se hará uso del framework [Flight](https://docs.flightphp.com/es/v3/). Para ello descargamos el contenido del framework en la carpeta de nuestro proyecto. En esta misma incluimos el fichero de configuración para Apache **.htaccess** con el siguiente contenido:

```apache
# Habilita el motor de reescritura de URLs
RewriteEngine On

# Si la solicitud NO es un archivo existente (!-f)...
RewriteCond %{REQUEST_FILENAME} !-f

# ...y NO es un directorio existente (!-d)
RewriteCond %{REQUEST_FILENAME} !-d

# Redirige todas las rutas a index.php (conservando parámetros QSA y evitando más reglas L)
RewriteRule ^(.*)$ index.php [QSA,L]
```

El framework Flight incluye en un contenido un fichero index.php con el siguiente contenido:


```php
<?php

declare(strict_types=1);

require_once 'flight/Flight.php';
// require 'flight/autoload.php';

Flight::route('/', function () {
    echo 'hello world!';
});

Flight::start();
```

Será aquí donde se escriba el contenido php para la realización la tarea.

### VARIABLES DE ENTORNO

En el fichero **.env** se guardan las variables de entorno para poder utilizarlas en ficheros como **docker-compose.yml** y scripts PHP mediante la variable global **$_ENV**. Recuerda recoger el fichero **.env** en el archivo **.gitignore**. Se subirá al repositorio un fichero de ejemplo llamado **.env.example**:

```ini
# ====== BASE DE DATOS ======
MYSQL_DATABASE=agenda
MYSQL_USER=agenda
MYSQL_PASSWORD=agenda
MYSQL_ROOT_PASSWORD=test
MYSQL_PORT=3306     # Puerto expuesto en nuestro host

# ====== APP / PHP ======
DB_HOST=db      # Nombre del servicio MySQL en la red interna
DB_PORT=3306
DB_NAME=${MYSQL_DATABASE}
DB_USER=${MYSQL_USER}
DB_PASS=${MYSQL_PASSWORD}

# ====== PHPMYADMIN ======
MYSQL_USER=root
MYSQL_PASSWORD=test
MYSQL_ROOT_PASSWORD=test
PHPMYADMIN_PORT=8000

# ====== EXTAS ======
PHP_VERSION=8.3     # Se usa como ARG al construir la imagen PHP
MYSQL_VERSION=9.0.1   # 9.0.1-innovation si quieres probar bleeding-edge
WEB_PORT=80       # Puerto externo para la web
```

### BASE DE DATOS

Trabajaremos sobre una base de datos cuyo script SQL para su creación irá dentro de la carpeta **/dump**. Este fichero SQL presenta el siguiente contenido:

```sql
-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: db
-- Generation Time: Mar 27, 2025 at 10:42 AM
-- Server version: 9.0.1
-- PHP Version: 8.2.27

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `agenda`
--
CREATE DATABASE IF NOT EXISTS agenda
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE agenda;
-- --------------------------------------------------------

--
-- Table structure for table `contactos`
--

CREATE TABLE `contactos` (
  `id` int NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `telefono` varchar(15) DEFAULT NULL,
  `email` varchar(150) DEFAULT NULL,
  `usuario_id` int NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- --------------------------------------------------------

--
-- Table structure for table `usuarios`
--

CREATE TABLE `usuarios` (
  `id` int NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `password` varchar(255) NOT NULL,
  `token` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `contactos`
--
ALTER TABLE `contactos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indexes for table `usuarios`
--
ALTER TABLE `usuarios`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `token` (`token`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `contactos`
--
ALTER TABLE `contactos`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `usuarios`
--
ALTER TABLE `usuarios`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `contactos`
--
ALTER TABLE `contactos`
  ADD CONSTRAINT `contactos_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuarios` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
```

La carpeta **/dump** debe estar montada en /docker-entrypoint-initdb.d/. Esto lo podemos configurar en el archivo docker-compose.yml, cuyo contenido es el siguiente para los **servicios de bases de datos**:

```yml
db:
    image: mysql:9.0.1
    ports: 
        - "3306:3306"
    #command: --default-authentication-plugin=mysql_native_password
    environment:
        MYSQL_DATABASE: agenda
        MYSQL_USER: agenda
        MYSQL_PASSWORD: agenda
        MYSQL_ROOT_PASSWORD: test 
    volumes:
        - ./dump:/docker-entrypoint-initdb.d # La línea en cuestión
        - ./conf:/etc/mysql/conf.d
        - persistent:/var/lib/mysql
    networks:
        - default
```

Para cargar el script SQL es necesario primero regenerar la memoria persistente. Para ello podemos usar el comando:

```bash
docker compose down -v
```

Volvemos a cargar el stack de contenedores mediante el comando:
```bash
docker compose up -d
```

### REQUISITOS DE LA APLICACIÓN

1. Autenticación
- Registro de usuario (/register): recibe nombre, email, password (hashed) y devuelve un mensaje de éxito o un error en caso de fallo.
- Login (/login): recibe email y password, verifica las credenciales. Si son correctas, genera y devuelve un token simple. Si no, devuelve el error correspondiente.

Para comenzar es necesario realizar la conexión con la base de datos:

```php
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
```
