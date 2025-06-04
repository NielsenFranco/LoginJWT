<?php
function conectar()
{
    $con = mysqli_connect("localhost","root","","login_jwt");
    if (mysqli_connect_errno()) {
        printf("Falló la conexión: %s\n", mysqli_connect_error());
        return false;
    } else {
        $con->set_charset("utf8");
        return $con;  // Devuelve el objeto mysqli
    }
}

function desconectar($con)
{
    if ($con) {
        mysqli_close($con);
    }
}
?>
