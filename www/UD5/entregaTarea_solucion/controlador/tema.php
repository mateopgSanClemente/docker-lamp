<?php

function temaValido($tema)
{
    return ($tema == 'dark' || $tema = 'light' || $tema == 'auto');
}

$origen = $_SERVER['HTTP_REFERER'];

//Comprobar si se reciben los datos
if($_SERVER["REQUEST_METHOD"]=="POST"){
    $tema = $_POST["tema"];
    
    if (empty($tema) || !temaValido($tema))
    {
        header('Location: ' . $origen . '?error=true&message=Debes indicar un tema válido.');
    }

    setcookie('tema', $tema, time() + (86400 * 30), "/");
    header('Location: ' . $origen);
}
else
{
    header('Location: ' . $origen . '?error=true&message=Debes indicar un tema válido.');
}