<?php
    $temaBootstrap = isset($_COOKIE['tema']) ? $_COOKIE['tema'] : "light";
?>
<!DOCTYPE html>
<html lang="es" data-bs-theme="<?php echo $temaBootstrap; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UD5. Tarea</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>

<header class="bg-primary text-white text-center py-3">
    <h1>Gestión de tareas</h1>
    <p>Solución tarea unidad 5 de DWCS</p>
</header>
