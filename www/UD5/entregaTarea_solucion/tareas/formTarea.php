<?php require_once('../modelo/entity/Estado.php'); ?>
<?php require_once('../modelo/entity/Usuario.php'); ?>
<div class="mb-3">
    <label for="titulo" class="form-label">Título</label>
    <input type="text" class="form-control" id="titulo" name="titulo" value="<?php echo isset($titulo) ? ($titulo) : '' ?>" required>
</div>
<div class="mb-3">
    <label for="descripcion" class="form-label">Descripción</label>
    <input type="text" class="form-control" id="descripcion" name="descripcion" value="<?php echo isset($descripcion) ? ($descripcion) : '' ?>" required>
</div>
<div class="mb-3">
    <label for="estado" class="form-label">Estado</label>
    <select class="form-select" id="estado" name="estado" required>
        <option value="" <?php echo isset($estado) ? '' : 'selected' ?> disabled>Seleccione el estado</option>
        <option value="<?php echo ESTADO::EN_PROCESO->value; ?>" <?php echo isset($estado) && $estado == ESTADO::EN_PROCESO ? 'selected' : '' ?>><?php echo ESTADO::EN_PROCESO->descripcion(); ?></option>
        <option value="<?php echo ESTADO::PENDIENTE->value; ?>" <?php echo isset($estado) && $estado == ESTADO::PENDIENTE ? 'selected' : '' ?>><?php echo ESTADO::PENDIENTE->descripcion(); ?></option>
        <option value="<?php echo ESTADO::COMPLETADA->value; ?>" <?php echo isset($estado) && $estado == ESTADO::COMPLETADA ? 'selected' : '' ?>><?php echo ESTADO::COMPLETADA->descripcion(); ?></option>
    </select>
</div>
<?php
if (checkAdmin())
{
?>
    <div class="mb-3">
        <label for="id_usuario" class="form-label">Usuario</label>
        <select class="form-select" id="id_usuario" name="id_usuario" required>
            <option value="" <?php echo isset($id_usuario) ? '' : 'selected' ?> disabled>Seleccione el usuario</option>
            <?php
                require_once('../modelo/pdo.php');
                $usuarios = listaUsuarios()[1];
                foreach ($usuarios as $usuario) { ?>
                    <option value="<?php echo ($usuario->getId()); ?>" <?php echo isset($id_usuario) && $id_usuario == $usuario->getId() ? 'selected' : '' ?> >
                        <?php echo $usuario->getUsername(); ?>
                    </option>
            <?php } ?>
        </select>
    </div>
<?php
}
else
{
    $idSes = $_SESSION['usuario']->getId();
    echo '<input type="hidden" name="id_usuario" id="id_usuario" value="' . $idSes . '">';
}
?>