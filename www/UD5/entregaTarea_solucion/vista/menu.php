<?php $base_url = str_replace($_SERVER['DOCUMENT_ROOT'], '', __DIR__); ?>
<nav class="col-md-3 col-lg-2 d-md-block sidebar <?php echo $temaBootstrap == 'dark' ? '' : 'bg-light'; ?> ">
    <div class="position-sticky">
        <ul class="nav flex-column">
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../index.php">
                    Home
                </a>
            </li>
            <!--Menú admin-->
            <?php
            if (checkAdmin())
            {
            ?>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../init.php">
                    Inicializar
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../usuarios/usuarios.php">
                    Lista de usuarios
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../usuarios/nuevoUsuarioForm.php">
                    Nuevo usuario
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../tareas/buscaTareas.php">
                   Buscador de tareas
                </a>
            </li>
            <?php
            }
            ?>
            <!--Menú registrados-->
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../tareas/nuevaForm.php">
                    Nueva tarea
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../tareas/tareas.php">
                    Lista de tareas
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="<?php echo $base_url ?>/../login/logout.php">
                   Salir
                </a>
            </li>
            
        </ul>
    </div>
    <?php $valorTema = isset($_COOKIE['tema']) ? $_COOKIE['tema'] : "light"; ?>
    <form class="m-3 w-50" action="<?php echo $base_url ?>/../controlador/tema.php" method="post">
        <select id="tema" name="tema" class="form-select mb-2" aria-label="Selector de tema">
            <option value="light" <?php echo $valorTema=='light' ? 'selected' : ''; ?> > Claro</option>
            <option value="dark" <?php echo $valorTema=='dark' ? 'selected' : ''; ?> >Oscuro</option>
            <option value="auto" <?php echo $valorTema=='auto' ? 'selected' : ''; ?> >Automático</option>
        </select>
        <button type="submit" class="btn btn-primary w-100">Aplicar</button>
    </form>
</nav>