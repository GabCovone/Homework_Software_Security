<?php
  $cspheader = "Content-Security-Policy:".
               "default-src 'self';".
               "script-src 'self' 'unsafe-hashes' 'nonce-111-111-111' 'nonce-222-222-222' *.example60.com *.example70.com
               'sha256-UISXgyJVFGiiCMFL7tH5xg8YRVyG48+Fp94Rvf8fDuU='
               'sha256-fEdJ+6TgZ3aLd+BgzuJsvfcaFH6+u3Rc7Qmz4HocdQI='
               'sha256-GL0n8OQRund1ocRZuAWunOQ1j/7fDr73ZHnB3yn/vMQ='".
               "";
  header($cspheader);
?>

<?php include 'index.html';?>
