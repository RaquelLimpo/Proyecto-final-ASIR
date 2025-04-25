<?php
ini_set('max_execution_time', 700); // aumenta tiempo de ejecución si metes muchos sino da error
$conexion = new mysqli("localhost", "root", "", "wishield");

if ($conexion->connect_error) {
    die("Error de conexión: " . $conexion->connect_error);
}

$TOTAL = 100; // Cambia este número a 100, 500, 1000...

$roles = ['invitado', 'estudiante', 'admin'];
$dispositivos = ['Laptop', 'Smartphone', 'Tablet', 'Smart TV', 'Smartwatch', 'Consola de videojuegos'];
$redes = ['Red Estudiantes', 'Red Invitados', 'Red Administrativa'];
$severidades = ['baja', 'media', 'alta', 'crítica'];

function generarMAC() {
    $mac = [];
    for ($i = 0; $i < 6; $i++) {
        $mac[] = strtoupper(str_pad(dechex(rand(0, 255)), 2, '0', STR_PAD_LEFT));
    }
    return implode(':', $mac);
}

function generarIP() {
    return '192.168.' . rand(1, 3) . '.' . rand(10, 250);
}

function nombreFalso() {
    $nombres = ["Ana", "Carlos", "Lucía", "Jorge", "Valentina", "Raúl", "Marina", "David", "Paula", "Sergio", "Raquel", "Abraham", "Luisa", "Marivega", "Antonio", "Mercé", "Vanesa", "Javier", "Marina", "Abril", "MariCarmen","Sara", "Diana", "Andrea", "Felix", "Silvia", "Irantzu", "Arturo", "Kristin", "Nacho", "Ricard", "Elena", "Ben", "Aritz", "John", "Rosa", "Rúben", "Isabel", "Jezabella", "Carmen", "Armando", "Blanca", "Lidia", "Andrés", "Covadonga", "Renee", "Bojan", "Sonia", "Alba", "Jerson", "Edurne", "Diego", "Duncan", "Sandra", "Alexandra", "Alejandro", "Sandro", "Xavier", "Samuel", "Nick", "Miles", "Louis", "Thais","Eire", "Isaac", "Iria", "Mikel", "Nicolas", "Gemma", "Patxi", "Pascu", "Alyona", "Leiona", "Leo", "Marc", "Marcos", "Mark","Elvira", "Fermin", "Dolores", "Pere", "Pedro", "Peter", "Altagracia","Amadora", "Apolinario", "Arnulfo", "Arsenio", "Bonifacio", "Burgundófora", "Cipriniano", "Cojoncio", "Digna", "Diosnelio", "Dombina", "Escolástico", "Estanislada", "Expiración", "Froilana", "Froilán", "Fulgencio", "Fulgencia", "Ruperta", "Gumersindo", "Diogenes", "Hermógenes", "Montse", "Hierónides", "Hercules", "Iluminado","Ladislao", "Elsa", "Elso", "Elba", "Luzdivino", "Marciana", "Marcial", "Oristila", "Pantaleona", "Pantaleón", "Yorinda", "Yoringel", "Piedrasantas", "Protasio", "Segismundo", "Tesifonte", "Penitencia", "Paz", "Renata", "Aitor", "Iker", "Markel", "Eneko", "Oier", "Xaiba", "Argi", "Abba", "Brais", "Drac", "Eilán", "Elm", "Jofre", "Guifré", "Enzo", "Eros", "Jano, Elian", "Eros", "Milos", "Anne", "Serge","Uriel", "Otto", "Zigor", "Salomón", "Ezequiel", "Aaron", "Georgina", "Laia", "Obdulia", "William", "James", "John", "Robert", "Michael", "Thomas", "David", "George", "Jane", "Sarah", "April", "Emily", "Rachel", "Amber", "Charlotte", "Madison", "Brooke", "Amy","Hunter", "Martin", "Bernard", "Thomas", "Petit", "Robert", "Richard", "Durand", "Dubois", "Moreau", "Laurent", "Lambert", "Leroy"," Dupont", "Gabriel", "Colin", "Lemaire", "Fontaine", "Blanchard", "Faure", "Chevalier", "Mathieu", "Morin", "Legrand", "Robin", "Nicolas", "Blanc", "Masson", "Marchand", "Etsuko", "Hoshiko", "Izumi", "Kagumi", "Kagome", "Kaoru", "Hana", "Sakura", "Himari", "Rin", "Kaguya", "Yuna", "Kenshin", "Aki", "Akihito", "Hiro", "Akihiro", "Daiki", "Ryu", "Ryota", "Masaru", "Hiroshi", "Shinosuke", "Hina", "Seitaro", "Kanako", "Nobunaga", "Hideyoshi", "Shingen", "Yoshimoto", "Masamune", "Ieyasu"];
    
    $apellidos = ["García", "López", "Sánchez", "Martínez", "Ruiz", "Gómez", "Díaz", "Pérez", "Torres", "de la Vega",
"Valentino", "Abril", "del Carmen", "Artemisa", "Botelli", "de la Marina", "Silvo", "Irantzu", "Aritz", 
"Armandez", "Nieve", "de Covadonga", "Kermit", "Bojan", "Albar", "Jetson", "Dhu", "Sandro", "Miles", "Lioncourt", 
"Eire", "Patel", "Alyona", "Leona", "Fermin", "Altagracia", "Amadora", "Apolinario", "Arnulfo", "Arsenio", "Bonifacio", "Burgundófora", "Cipriniano", "Cojoncio", "Digna", "Diosnelio", "Dombina", "Escolástico", "Estanislada", "Expiración", "Froilana", "Gumersindo", "Diogenes", "Hermógenes", "Hierónides", "Hercules", "Iluminado","Ladislao", "Elsa", "Elso", "Elba", "Luzdivino", "Marciana", "Marcial", "Oristila", "Pantaleona", "Pantaleón", "Yorinda", "Yoringel", "Piedrasantas", "Protasio", "Segismundo", "Tesifonte", "de la Penitencia", "de la Paz", "de Cabeza", "de Barriga", "Bronca", "Segura", "Fina", "Delano", "Gil", "de Dios", "Surero", "Cremento", "Montada", "Trozado", "Tresado", "Mento", "Mingo", "Busado", "Fermizo", "Japón", "Masdeu", "Cuesta", "Mogollón", "Amor", "Jurado", "Arrimadas", "Seisdedos", "Pieplano", "Gol", "Gordo", "Nito", "del Bosque", "del Pozo", "Salido", "Campofrío", "Ladrón", "Honesto", "Diezhandino", "Honrado", "Calavera", "Cortada", "del Rosal", "Alegre", "Pieldelobo", "Bonachera", "Zas", "Perroverde", "Alcoholado", "Gandula", "Chinchurreta", "de la Repolla", "Parahoy", "Paramí", "Verdugo", "Pichilengue", "Karamoko", "Moto", "Vergassola", "Esario", "Osario", "Flores", "Golon", "Smith", "Jones", "Williams", "Brown", "Hunter", "Martin", "Bernard", "Thomas", "Petit", "Robert", "Richard", "Durand", "Dubois", "Moreau", "Laurent", "Lambert", "Leroy"," Dupont", "Gabriel", "Colin", "Lemaire", "Fontaine", "Blanchard", "Faure", "Chevalier", "Mathieu", "Morin", "Legrand", "Robin", "Nicolas", "Blanc", "Masson", "Marchand", "Tanaka", "Yamada", "Nakamura", "Ishikawa", "Yamamoto", "Yamagawa", "Yoshida", "Suzuki", "Kimura",  "Nishimura", "Madarame", "Matsudaira"," Mihura", "Minagawa", "Minami", "Miyake", "Mizoguchi"," Mori", "Murakami", "Date", "Oda", "Toyotoma", "Ueda", "Tokugawa", "Takeda", "Imagawa"];
    return $nombres[array_rand($nombres)] . ' ' . $apellidos[array_rand($apellidos)];
}

// Generador masivo
for ($i = 0; $i < $TOTAL; $i++) {
    $nombre = nombreFalso();
    $email = strtolower(str_replace(' ', '.', $nombre)) . $i . '@test.com';
    $rol = $roles[array_rand($roles)];

    $stmt = $conexion->prepare("INSERT INTO usuarios (nombre, email, rol) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $nombre, $email, $rol);
    $stmt->execute();
    $usuario_id = $conexion->insert_id;
    $stmt->close();

    // Crear dispositivo
    $mac = generarMAC();
    $ip = generarIP();
    $tipo = $dispositivos[array_rand($dispositivos)];

    $stmt = $conexion->prepare("INSERT INTO Dispositivos (usuario_id, mac_address, ip_address, tipo_dispositivo) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("isss", $usuario_id, $mac, $ip, $tipo);
    $stmt->execute();
    $dispositivo_id = $conexion->insert_id;
    $stmt->close();

    // Crear sesión de conexión aleatoria
    $inicio = date("Y-m-d H:i:s", strtotime("-" . rand(0, 10) . " days " . rand(0, 23) . " hours"));
    $fin = rand(0, 1) ? date("Y-m-d H:i:s", strtotime($inicio . " + " . rand(1, 3) . " hours")) : null;
    $red = $redes[array_rand($redes)];

    $stmt = $conexion->prepare("INSERT INTO Sesiones_Conexion (dispositivo_id, timestamp_inicio, timestamp_fin, red) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("isss", $dispositivo_id, $inicio, $fin, $red);
    $stmt->execute();
    $stmt->close();

    // Posiblemente añadir una vulnerabilidad
    if (rand(0, 3) === 0) { // ~25% de los dispositivos
        $tipo_vuln = "Simulada: " . ['Puerto abierto', 'Fuga de datos', 'Malware', 'Acceso no autorizado'][rand(0, 3)];
        $severidad = $severidades[array_rand($severidades)];
        $fecha = date("Y-m-d", strtotime("-" . rand(1, 7) . " days"));

        $stmt = $conexion->prepare("INSERT INTO Vulnerabilidades (dispositivo_id, tipo_vulnerabilidad, severidad, fecha_deteccion) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $dispositivo_id, $tipo_vuln, $severidad, $fecha);
        $stmt->execute();
        $stmt->close();
    }
}
$csv = fopen("usuarios_generados.csv", "w");
fputcsv($csv, ["nombre", "email", "rol", "contraseña_plana"]);

for ($i = 0; $i < $TOTAL; $i++) {
    $nombre = nombreFalso();
    $email = strtolower(str_replace(' ', '.', $nombre)) . $i . '@test.com';
    $rol = $roles[array_rand($roles)];

    // ⚡ Contraseña generada (simple para pruebas, puedes mejorarla)
    $pass_plana = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 8);
    $pass_hash = password_hash($pass_plana, PASSWORD_BCRYPT);

    // Guardar en BD
    $stmt = $conexion->prepare("INSERT INTO usuarios (nombre, email, rol, contraseña) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $nombre, $email, $rol, $pass_hash);
    $stmt->execute();
    $usuario_id = $conexion->insert_id;
    $stmt->close();

    // Guardar en CSV
    fputcsv($csv, [$nombre, $email, $rol, $pass_plana]);

    // El resto del script (dispositivos, sesiones, etc.) igual...
}
fclose($csv);


echo "<h2>✅ $TOTAL usuarios insertados con sus dispositivos, sesiones y vulnerabilidades aleatorias.</h2>";

$conexion->close();
?>
