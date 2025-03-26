<?php
    require_once('../login/sesiones.php');
    require_once('../modelo/mysqli.php');
?>
    <?php include_once('../vista/header.php'); ?>

    <div class="container-fluid">
        <div class="row">
            
            <?php include_once('../vista/menu.php'); ?>

            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="container justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h2>Adjuntar archivo</h2>
                    <?php include_once ('../vista/erroresSession.php'); ?>
                </div>

                <div class="container justify-content-between">
                    <form action="subidaFichProc.php" method="POST" class="mb-5" enctype="multipart/form-data">
                    <?php
                        if (!empty($_GET))
                        {
                            $id = $_GET['id'];
                            if (!empty($id)) {
                                if (checkAdmin() || esPropietarioTarea($_SESSION['usuario']->getId(), $id))
                                {
                    ?>
                                <input type="hidden" name="id_tarea" id="file" value="<?php echo $id ?>">
                                <div class="mb-3">
                                    <label for="nombre" class="form-label">Nombre</label>
                                    <input type="text" class="form-control" id="nombre" name="nombre" rows="3" placeholder="Introduce un nombre" required>
                                </div>
                                <div class="mb-3">
                                    <label for="descripcion" class="form-label">Descripción</label>
                                    <textarea class="form-control" id="descripcion" name="descripcion" rows="3" placeholder="Introduce una descripción" required></textarea>
                                </div>
                                <div class="mb-3">
                                    <label for="archivo" class="form-label">Seleccionar archivo</label>
                                    <input class="form-control" type="file" id="archivo" name="archivo" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Subir archivo</button>  
                    <?php
                                }
                                else
                                {
                                    echo '<div class="alert alert-danger" role="alert">No tienes permisos sobre esta tarea.</div>';
                                }
                            }
                            else
                            {
                                echo '<div class="alert alert-danger" role="alert">No se pudo recuperar la información de la tarea.</div>';
                            }
                        }
                        else
                        {
                            echo '<div class="alert alert-danger" role="alert">Debes acceder a través del listado de tareas.</div>';
                        }
                        ?>
                    </form>
                </div>
            </main>
        </div>
    </div>

    <?php include_once('../vista/footer.php'); ?>
    
</body>
</html>
