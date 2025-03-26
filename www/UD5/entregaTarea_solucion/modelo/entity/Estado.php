<?php

enum Estado: string
{
    case PENDIENTE = 'pendiente';
    case EN_PROCESO = 'en_proceso';
    case COMPLETADA = 'completada';

    public function descripcion(): string
    {
        return match($this) {
            self::PENDIENTE => 'Pendiente',
            self::EN_PROCESO => 'En proceso',
            self::COMPLETADA => 'Completada',
        };
    }
}
?>