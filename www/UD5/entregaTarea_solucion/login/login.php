<?php
    session_start();
    if (isset($_SESSION['usuario']))
    {
        header("Location: ../index.php?redirect=true");
        exit();
    }
?>

<?php include_once('../vista/header.php'); ?>
    
    <main class="d-flex justify-content-center align-items-center flex-grow-1 p-4 m-4" style="background-image: url('../portada.webp'); background-size: cover; background-position: center;">
        <div class="position-absolute top-0 start-0 w-100 h-100 bg-light" style="opacity: 0.6;"></div>
        <div class="card shadow p-4 w-100" style="max-width:400px">
            
            <h2 class="text-center mb-4">Iniciar sesión</h2>

            <?php
            //Comprobar si se reciben datos
            $redirect = isset($_GET['redirect']) ? true : false;
            $error = isset($_GET['error']) ? true : false;
            $message = isset($_GET['message']) ? $_GET['message'] : null;
            if ($redirect)
            {
                echo '<div class="alert alert-danger" role="alert">Debes iniciar sesión para acceder.</div>';
            }
            elseif ($error)
            {
                if ($message)
                {
                    echo '<div class="alert alert-danger" role="alert">Error: ' . $message . '</div>';
                }
                else
                {
                    echo '<div class="alert alert-danger" role="alert">Usuario y contraseña incorrectos.</div>';
                }
            }
            ?>

            <form action="loginAuth.php" method="POST" class="needs-validation text-center">
                <div class="mb-3">
                    <input name="username" id="username" type="text" class="form-control" placeholder="usuario" required>
                </div>
                <div class="mb-3">
                    <input name="pass" id="pass" type="password" class="form-control" placeholder="contraseña" required>
                </div>
                <button type="submit" class="btn btn-primary">Iniciar sesión</button>
            </form>
            
        </div>
    
    </main>

    <?php include_once('../vista/footer.php'); ?>

</body>
</html>