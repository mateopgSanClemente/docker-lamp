<?php
    require_once('../login/sesiones.php');
?>
    <?php include_once('../vista/header.php'); ?>

    <div class="container-fluid">
        <div class="row">
            
            <?php include_once('../vista/menu.php'); ?>

            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                
                <div class="container justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h2>Tareas</h2>
                    <?php include_once ('../vista/erroresSession.php'); ?>
                </div>

                <div class="container justify-content-between">
                <?php

                    //Si es admin, permitimos sin restricciones todo
                    //Si es usuario registrado, recuperamos el id de sesión
                    $resultado = null;
                    require_once('../modelo/pdo.php');
                    if (!checkAdmin()){
                        $id_registrado = $_SESSION['usuario']->getId();
                        $resultado = listaTareasPDO($id_registrado, null);
                    }
                    elseif (!empty($_GET))
                    {
                        $estado = isset($_GET['estado']) ? $_GET['estado'] : null;
                        $id_usuario = $_GET['id_usuario'];
                        $resultado = listaTareasPDO($id_usuario, $estado);
                    }
                    else
                    {
                        require_once('../modelo/mysqli.php');
                        $resultado = listaTareas();
                    }
                    
                    if ($resultado && $resultado[0])
                    {
                ?>
                    <div class="table">
                        <table class="table table-sm table-striped table-hover">
                            <thead class="thead">
                                <tr>                            
                                    <th>ID</th>
                                    <th>Título</th>
                                    <th>Descripción</th>
                                    <th>Estado</th>
                                    <th>Usuario</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                    $lista = $resultado[1];
                                    if (count($lista) > 0)
                                    {
                                        foreach ($lista as $tarea)
                                        {
                                            echo '<tr>';
                                            echo '<td>' . $tarea->getId() . '</td>';
                                            echo '<td>' . $tarea->getTitulo() . '</td>';
                                            echo '<td>' . $tarea->getDescripcion() . '</td>';
                                            echo '<td>' . $tarea->getEstado()->descripcion() . '</td>';
                                            echo '<td>' . $tarea->getUsuario()->getUsername() . '</td>';
                                            echo '<td>';
                                            echo '<a class="btn btn-sm btn-outline-primary ms-2" href="tarea.php?id=' . $tarea->getId() . '" role="button">Mostrar</a>';
                                            echo '<a class="btn btn-sm btn-outline-success ms-2" href="editaTareaForm.php?id=' . $tarea->getId() . '" role="button">Editar</a>';
                                            echo '<a class="btn btn-sm btn-outline-danger ms-2" href="borraTarea.php?id=' . $tarea->getId() . '" role="button">Borrar</a>';
                                            echo '</td>';
                                            echo '</tr>';
                                        }
                                    }
                                    else
                                    {
                                        echo '<tr><td colspan="100">No hay tareas</td></tr>';
                                    }
                                ?>
                            </tbody>
                        </table>
                    </div>
                <?php
                    }
                    else
                    {
                        echo '<div class="alert alert-warning" role="alert">' . $resultado[1] . '</div>';
                    }
                ?>
                </div>
            </main>
        </div>
    </div>

    <?php include_once('../vista/footer.php'); ?>
    
</body>
</html>
