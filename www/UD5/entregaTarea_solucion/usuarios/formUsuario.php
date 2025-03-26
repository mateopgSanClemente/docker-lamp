<?php require_once('../modelo/entity/Rol.php'); ?>

<div class="mb-3">
    <label for="nombre" class="form-label">Nombre</label>
    <input type="text" class="form-control" id="nombre" name="nombre" value="<?php echo isset($nombre) ? ($nombre) : '' ?>" required>
</div>
<div class="mb-3">
    <label for="apellidos" class="form-label">Apellidos</label>
    <input type="text" class="form-control" id="apellidos" name="apellidos" value="<?php echo isset($apellidos) ? ($apellidos) : '' ?>" required>
</div>
<div class="mb-3">
    <label for="rol" class="form-label">Rol</label>
    <select class="form-select" id="rol" name="rol" required>
        <option value="" <?php echo isset($rol) ? '' : 'selected' ?> disabled>Seleccione tipo de usuario</option>
        <option value="0" <?php echo isset($rol) && $rol == Rol::USER ? 'selected' : '' ?>><?php echo Rol::USER->descripcion(); ?></option>
        <option value="1" <?php echo isset($rol) && $rol == Rol::ADMIN ? 'selected' : '' ?>><?php echo Rol::ADMIN->descripcion(); ?></option>
    </select>
</div>
<div class="mb-3">
    <label for="username" class="form-label">Username</label>
    <input type="text" class="form-control" id="username" name="username" value="<?php echo isset($username) ? ($username) : '' ?>" required>
</div>